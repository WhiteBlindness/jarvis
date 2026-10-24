//! Session behaviour over in-memory pipes: the worker side of each test
//! writes raw frames, exactly as an untrusted worker could. Decisions on
//! approvals are made through the store and the hub, the same calls the RPC
//! server makes for a local client.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jarvis_core::config::Limits;
use jarvis_core::config::SessionAgentConfig;
use jarvis_core::gateway::Gateway;
use jarvis_core::hub::Hub;
use jarvis_core::policy::Policy;
use jarvis_core::session::{SessionContext, SessionEnd, SessionError, SessionReport, run_session};
use jarvis_core::session_agent::{Launched, Launcher, ProcessLauncher, SessionAgent};
use jarvis_core::store::{ApprovalError, ApprovalRecord, Store, now_ms};
use jarvis_protocol::{
    AgentReport, ApprovalStatus, AuditEventKind, Capability, ClipboardText, ClipboardWritten,
    CoreMessage, ErrorCode, Fingerprint, Goal, JobId, JobStatus, PolicyDecision, Summary,
    TaskStatus, ToolCall, ToolOutcome, ToolResult, decode_core_message,
};
use jarvis_tools::{FixtureRoot, ToolExecutor, ToolFuture, Toolbox, WorkspaceRoot};
use serde_json::{Value, json};
use sha2::Digest;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Wraps the real toolbox, counts executions, and can be told to hang.
#[derive(Debug)]
struct Probe {
    inner: Toolbox,
    calls: Arc<AtomicUsize>,
    hang: bool,
}

impl ToolExecutor for Probe {
    fn execute(&self, call: ToolCall) -> ToolFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hang {
            return Box::pin(std::future::pending());
        }
        self.inner.execute(call)
    }
}

struct Options {
    policy: Vec<(Capability, PolicyDecision)>,
    limits: Limits,
    hang: bool,
    handshake_timeout: Duration,
    approval_ttl: Duration,
    job_timeout: Duration,
    /// Capacity of the pipe from the Core to the worker.
    reply_buffer: usize,
    session_agent: Option<Arc<SessionAgent>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy: vec![
                (Capability::SystemInfo, PolicyDecision::Allow),
                (Capability::FilesystemReadFixture, PolicyDecision::Allow),
                (
                    Capability::WorkspaceWrite,
                    PolicyDecision::RequireConfirmation,
                ),
            ],
            limits: Limits {
                tool_timeout: Duration::from_secs(10),
                ..Limits::default()
            },
            hang: false,
            handshake_timeout: Duration::from_secs(10),
            approval_ttl: Duration::from_secs(60),
            job_timeout: Duration::from_secs(120),
            reply_buffer: 1 << 20,
            session_agent: None,
        }
    }
}

struct Harness {
    dir: tempfile::TempDir,
    store: Store,
    hub: Arc<Hub>,
    calls: Arc<AtomicUsize>,
    shutdown: CancellationToken,
    to_core: Option<DuplexStream>,
    from_core: Lines<BufReader<DuplexStream>>,
    session: JoinHandle<Result<SessionReport, SessionError>>,
    job: Option<JobId>,
}

impl Harness {
    fn start(options: Options) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fixtures = dir.path().join("fixtures");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&fixtures).unwrap();
        std::fs::create_dir_all(workspace.join("notes")).unwrap();
        std::fs::write(fixtures.join("welcome.txt"), "hello\n").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "do not read").unwrap();

        let store = Store::open(&dir.path().join("jarvis.db")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = Probe {
            inner: Toolbox::new(
                "test",
                FixtureRoot::open(&fixtures, 1024).unwrap(),
                WorkspaceRoot::open(&workspace, 1024).unwrap(),
            ),
            calls: Arc::clone(&calls),
            hang: options.hang,
        };
        let policy: BTreeMap<_, _> = options.policy.into_iter().collect();
        let hub = Arc::new(Hub::default());
        let ctx = SessionContext {
            store: store.clone(),
            policy: Policy::new(policy),
            gateway: Gateway::new(
                Arc::new(probe),
                options.limits.tool_timeout,
                options.limits.max_result_bytes(),
            ),
            limits: options.limits,
            handshake_timeout: options.handshake_timeout,
            approval_ttl: options.approval_ttl,
            job_timeout: options.job_timeout,
            core_version: "test",
            hub: Arc::clone(&hub),
            session_agent: options.session_agent,
        };

        let (to_core, core_reader) = tokio::io::duplex(1 << 20);
        let (core_writer, from_core) = tokio::io::duplex(options.reply_buffer);
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let session =
            tokio::spawn(async move { run_session(&ctx, core_reader, core_writer, &token).await });
        Self {
            dir,
            store,
            hub,
            calls,
            shutdown,
            to_core: Some(to_core),
            from_core: BufReader::new(from_core).lines(),
            session,
            job: None,
        }
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        let pipe = self.to_core.as_mut().unwrap();
        pipe.write_all(bytes).await.unwrap();
        pipe.write_all(b"\n").await.unwrap();
    }

    async fn send(&mut self, value: Value) {
        self.send_raw(&serde_json::to_vec(&value).unwrap()).await;
    }

    async fn recv(&mut self) -> CoreMessage {
        let line = tokio::time::timeout(Duration::from_secs(10), self.from_core.next_line())
            .await
            .expect("no reply from the Core")
            .unwrap()
            .expect("the Core closed the stream");
        decode_core_message(line.as_bytes()).expect("the Core sent an invalid frame")
    }

    async fn hello(&mut self) {
        self.send(json!({"protocol": 3, "type": "hello", "worker": "test", "worker_version": "1"}))
            .await;
        assert!(matches!(self.recv().await, CoreMessage::Welcome(_)));
    }

    /// Queue a job as a client would and wait for the Core to hand it over.
    async fn job(&mut self, goal: &str) -> JobId {
        let goal = Goal::try_from(goal.to_owned()).unwrap();
        let submitted = self.store.submit_job(&goal, "test client").unwrap();
        self.hub.jobs.notify_one();
        match self.recv().await {
            CoreMessage::Job(job) => {
                assert_eq!(job.job_id, submitted.job_id);
                assert_eq!(job.goal, goal);
                self.job = Some(job.job_id);
                job.job_id
            }
            other => panic!("expected a job, got {other:?}"),
        }
    }

    /// Handshake and take one job, the state most tests start from.
    async fn ready(&mut self) {
        self.hello().await;
        self.job("test").await;
    }

    /// Queue a clipboard job as a client would and wait for the Core to hand
    /// it over. Returns the arguments a planner derives from its goal.
    async fn clipboard_job(&mut self, text: &str) -> Value {
        let text = ClipboardText::try_from(text.to_owned()).unwrap();
        let submitted = self
            .store
            .submit_clipboard_job(&text, "test client")
            .unwrap();
        self.hub.jobs.notify_one();
        match self.recv().await {
            CoreMessage::Job(job) => {
                assert_eq!(job.job_id, submitted.job_id);
                self.job = Some(job.job_id);
                let rest = job.goal.as_str().strip_prefix("copy payload:").unwrap();
                let (payload_id, sha256) = rest.split_once(':').unwrap();
                json!({"payload_id": payload_id, "sha256": sha256})
            }
            other => panic!("expected a job, got {other:?}"),
        }
    }

    fn job_id(&self) -> JobId {
        self.job.expect("no job")
    }

    async fn send_request(&mut self, id: &str, tool: &str, args: Value) {
        let job_id = self.job_id();
        self.send(json!({
            "protocol": 3, "type": "tool_request", "request_id": id, "job_id": job_id,
            "tool": tool, "args": args
        }))
        .await;
    }

    async fn response(&mut self, id: &str) -> ToolOutcome {
        match self.recv().await {
            CoreMessage::ToolResponse(response) => {
                assert_eq!(response.request_id.as_str(), id);
                let task = self.store.task(response.task_id).unwrap().unwrap();
                assert_eq!(task.request_id.as_str(), id);
                assert_eq!(task.job_id, self.job);
                response.outcome
            }
            other => panic!("expected a tool_response, got {other:?}"),
        }
    }

    async fn request(&mut self, id: &str, tool: &str, args: Value) -> ToolOutcome {
        self.send_request(id, tool, args).await;
        self.response(id).await
    }

    async fn finish_job(&mut self, outcome: &str, summary: &str) {
        let job_id = self.job.take().expect("no job");
        self.send(json!({
            "protocol": 3, "type": "job_result", "job_id": job_id,
            "outcome": outcome, "summary": summary
        }))
        .await;
    }

    async fn expect_error(&mut self, code: ErrorCode, fatal: bool) {
        match self.recv().await {
            CoreMessage::Error(error) => {
                assert_eq!(error.error.code, code, "{}", error.error.message);
                assert_eq!(error.fatal, fatal);
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// Wait until the session asks a person, and return the approval.
    async fn pending_approval(&self) -> ApprovalRecord {
        for _ in 0..500 {
            if let Some(record) = self.store.pending_approvals().unwrap().pop() {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no approval was requested");
    }

    /// What the RPC server does for `approve`.
    fn grant(
        &self,
        record: &ApprovalRecord,
        fingerprint: &Fingerprint,
    ) -> Result<(), ApprovalError> {
        let result = self
            .store
            .grant_approval(record.approval_id, fingerprint, "test client", now_ms())
            .map(|_| ());
        self.hub.approvals.notify(record.approval_id);
        self.hub.changed();
        result
    }

    /// What the RPC server does for `deny`.
    fn deny(&self, record: &ApprovalRecord, reason: &str) -> Result<(), ApprovalError> {
        let reason = Summary::try_from(reason.to_owned()).unwrap();
        let result = self
            .store
            .deny_approval(record.approval_id, &reason, "test client", now_ms())
            .map(|_| ());
        self.hub.approvals.notify(record.approval_id);
        self.hub.changed();
        result
    }

    fn approval_status(&self, record: &ApprovalRecord) -> ApprovalStatus {
        self.store
            .approval(record.approval_id)
            .unwrap()
            .unwrap()
            .status
    }

    fn workspace_file(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.path().join("workspace").join(name)).ok()
    }

    /// Close the worker's side and wait for the session to end.
    async fn finish(mut self) -> (SessionReport, Store, Arc<AtomicUsize>) {
        self.to_core.take();
        let report = tokio::time::timeout(Duration::from_secs(10), self.session)
            .await
            .expect("session did not end")
            .unwrap()
            .unwrap();
        (report, self.store, self.calls)
    }

    /// Wait for the session to end with a Core error. The directory is
    /// returned so that the workspace can still be inspected.
    async fn fails(mut self) -> (SessionError, Store, Arc<AtomicUsize>, tempfile::TempDir) {
        self.to_core.take();
        let result = tokio::time::timeout(Duration::from_secs(10), self.session)
            .await
            .expect("session did not end")
            .unwrap();
        (result.unwrap_err(), self.store, self.calls, self.dir)
    }

    fn statuses(&self) -> Vec<TaskStatus> {
        let mut tasks = self.store.tasks(100).unwrap();
        tasks.reverse();
        tasks.into_iter().map(|task| task.status).collect()
    }

    fn kinds(store: &Store) -> Vec<&'static str> {
        store
            .audit_events(None, 1000)
            .unwrap()
            .into_iter()
            .map(|event| event.event.name())
            .collect()
    }

    fn task_kinds(store: &Store) -> Vec<&'static str> {
        store
            .audit_events(None, 1000)
            .unwrap()
            .into_iter()
            .filter(|event| event.task_id.is_some())
            .map(|event| event.event.name())
            .collect()
    }
}

fn write_args(path: &str, content: &str) -> Value {
    json!({"path": path, "content": content})
}

/// A second connection adds a trigger that rejects one kind of audit event,
/// as a full disk would reject that write.
fn fail_audit_writes_of(path: &std::path::Path, kind: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(&format!(
        "CREATE TRIGGER fail_{kind} BEFORE INSERT ON audit_events
         WHEN NEW.kind = '{kind}'
         BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END;"
    ))
    .unwrap();
}

// --- jobs ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_job_queued_before_the_worker_is_ready_is_dispatched_after_the_handshake() {
    let mut h = Harness::start(Options::default());
    let goal = Goal::try_from("system".to_owned()).unwrap();
    let job = h.store.submit_job(&goal, "test client").unwrap();
    h.hello().await;
    match h.recv().await {
        CoreMessage::Job(assigned) => assert_eq!(assigned.job_id, job.job_id),
        other => panic!("expected a job, got {other:?}"),
    }
    h.job = Some(job.job_id);
    h.finish_job("completed", "nothing to do").await;
    let (report, store, _) = h.finish().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
    let done = store.job(job.job_id).unwrap().unwrap();
    assert_eq!(done.status, JobStatus::Completed);
    assert_eq!(done.summary.unwrap().as_str(), "nothing to do");
    assert_eq!(
        Harness::kinds(&store),
        [
            "job_submitted",
            "session_opened",
            "job_started",
            "job_finished",
            "session_closed"
        ]
    );
}

#[tokio::test]
async fn jobs_are_handed_out_one_at_a_time() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    let first = h.job("first").await;
    let goal = Goal::try_from("second".to_owned()).unwrap();
    let second = h.store.submit_job(&goal, "test client").unwrap();
    h.hub.jobs.notify_one();
    // Nothing else arrives while the first job runs.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), h.from_core.next_line())
            .await
            .is_err()
    );
    h.finish_job("failed", "").await;
    match h.recv().await {
        CoreMessage::Job(job) => assert_eq!(job.job_id, second.job_id),
        other => panic!("expected the second job, got {other:?}"),
    }
    let (_, store, _) = h.finish().await;
    assert_eq!(store.job(first).unwrap().unwrap().status, JobStatus::Failed);
    assert_eq!(
        store.job(second.job_id).unwrap().unwrap().status,
        JobStatus::Queued,
        "the worker left in the middle of the second job, which waits for the next worker"
    );
}

#[tokio::test]
async fn requests_and_results_must_belong_to_the_current_job() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    let stranger = JobId::new();
    // No job yet.
    h.send(
        json!({"protocol": 3, "type": "tool_request", "request_id": "r1",
        "job_id": stranger, "tool": "system.info", "args": {}}),
    )
    .await;
    h.expect_error(ErrorCode::UnexpectedMessage, false).await;
    h.job("test").await;
    h.send(
        json!({"protocol": 3, "type": "tool_request", "request_id": "r2",
        "job_id": stranger, "tool": "system.info", "args": {}}),
    )
    .await;
    h.expect_error(ErrorCode::UnexpectedMessage, false).await;
    h.send(
        json!({"protocol": 3, "type": "job_result", "job_id": stranger,
        "outcome": "completed", "summary": ""}),
    )
    .await;
    h.expect_error(ErrorCode::UnexpectedMessage, false).await;
    assert!(
        h.statuses().is_empty(),
        "no task for a request outside its job"
    );
    let (_, _, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_job_that_runs_too_long_ends_the_session() {
    let mut h = Harness::start(Options {
        job_timeout: Duration::from_millis(300),
        ..Options::default()
    });
    h.ready().await;
    let job = h.job_id();
    let session = h.session;
    let report = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::JobTimedOut(job));
    assert_eq!(h.store.job(job).unwrap().unwrap().status, JobStatus::Failed);
}

// --- allowed, denied, rejected ------------------------------------------------------------------

#[tokio::test]
async fn valid_allowed_request_completes_and_is_recorded() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let outcome = h.request("r1", "system.info", json!({})).await;
    let ToolOutcome::Completed {
        result: ToolResult::SystemInfo(info),
    } = outcome
    else {
        panic!("expected system info, got {outcome:?}");
    };
    assert_eq!(info.os, std::env::consts::OS);

    let task = h.store.tasks(1).unwrap().remove(0);
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.decision, Some(PolicyDecision::Allow));
    assert_eq!(task.capabilities, Some(vec![Capability::SystemInfo]));
    let stored: Value = serde_json::from_str(task.result.as_deref().unwrap()).unwrap();
    assert_eq!(stored["os"], std::env::consts::OS);

    let (report, store, calls) = h.finish().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
    assert_eq!(report.requests, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        Harness::task_kinds(&store),
        [
            "request_received",
            "policy_evaluated",
            "execution_started",
            "execution_finished",
        ]
    );
}

#[tokio::test]
async fn denied_capability_never_executes() {
    let mut h = Harness::start(Options {
        policy: vec![(Capability::SystemInfo, PolicyDecision::Deny)],
        ..Options::default()
    });
    h.ready().await;
    let outcome = h.request("r1", "system.info", json!({})).await;
    assert!(
        matches!(&outcome, ToolOutcome::Denied { capabilities, .. } if capabilities == &[Capability::SystemInfo]),
        "{outcome:?}"
    );
    // Unlisted capabilities are denied as well.
    for (id, tool, args) in [
        (
            "r2",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"}),
        ),
        ("r3", "workspace.write_file", write_args("a.txt", "x")),
    ] {
        let outcome = h.request(id, tool, args).await;
        assert!(matches!(outcome, ToolOutcome::Denied { .. }), "{outcome:?}");
    }
    assert_eq!(h.statuses(), [TaskStatus::Denied; 3]);
    assert!(h.store.pending_approvals().unwrap().is_empty());

    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!Harness::kinds(&store).contains(&"execution_started"));
}

#[tokio::test]
async fn malformed_frames_are_answered_and_session_continues() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    for frame in [
        &b"not json"[..],
        b"[1, 2, 3]",
        b"{}",
        br#"{"protocol":3,"type":"shell","command":"id"}"#,
        br#"{"protocol":3,"type":"tool_request","request_id":"r1","tool":"system.info","args":{}}"#,
        br#"{"protocol":3,"type":"job","job_id":"01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b","goal":"x"}"#,
        br#"{"protocol":3,"type":"job_result","job_id":"01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b","outcome":"approved","summary":""}"#,
        b"\xff\xfe\xfd",
    ] {
        h.send_raw(frame).await;
        h.expect_error(ErrorCode::MalformedFrame, false).await;
    }
    assert!(h.statuses().is_empty(), "malformed frames create no tasks");
    let outcome = h.request("r1", "system.info", json!({})).await;
    assert!(matches!(outcome, ToolOutcome::Completed { .. }));
    let (report, _, _) = h.finish().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
}

#[tokio::test]
async fn unknown_tool_is_rejected_and_recorded() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let outcome = h
        .request("r1", "shell.exec", json!({"command": "rm -rf /"}))
        .await;
    let ToolOutcome::Rejected { error } = outcome else {
        panic!("expected rejection");
    };
    assert_eq!(error.code, ErrorCode::UnknownTool);
    let task = h.store.tasks(1).unwrap().remove(0);
    assert_eq!(task.status, TaskStatus::Rejected);
    assert_eq!(task.tool, "shell.exec");
    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!Harness::kinds(&store).contains(&"policy_evaluated"));
}

#[tokio::test]
async fn invalid_arguments_are_rejected_before_policy() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let cases = [
        ("system.info", json!({"verbose": true})),
        ("system.info", json!([])),
        ("system.info", json!(null)),
        ("filesystem.read_fixture", json!({})),
        ("filesystem.read_fixture", json!({"path": 5})),
        (
            "filesystem.read_fixture",
            json!({"path": "welcome.txt", "follow_symlinks": true}),
        ),
        ("workspace.write_file", json!({"path": "a.txt"})),
        (
            "workspace.write_file",
            json!({"path": "a.txt", "content": 1}),
        ),
        (
            "workspace.write_file",
            json!({"path": "a.txt", "content": "x", "mode": "append"}),
        ),
    ];
    for (i, (tool, args)) in cases.into_iter().enumerate() {
        let outcome = h.request(&format!("r{i}"), tool, args).await;
        assert!(
            matches!(&outcome, ToolOutcome::Rejected { error } if error.code == ErrorCode::InvalidArguments),
            "{outcome:?}"
        );
    }
    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!Harness::kinds(&store).contains(&"policy_evaluated"));
    assert!(!Harness::kinds(&store).contains(&"approval_requested"));
}

#[tokio::test]
async fn path_traversal_is_rejected_for_reads_and_writes() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let mut n = 0;
    for path in [
        "../secret.txt",
        "notes/../../secret.txt",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "..\\secret.txt",
        ".ssh/id_rsa",
        "CON",
        "a/./b",
        "file.txt:stream",
    ] {
        for (tool, args) in [
            ("filesystem.read_fixture", json!({"path": path})),
            ("workspace.write_file", write_args(path, "x")),
        ] {
            n += 1;
            let outcome = h.request(&format!("r{n}"), tool, args).await;
            assert!(
                matches!(&outcome, ToolOutcome::Rejected { error } if error.code == ErrorCode::InvalidArguments),
                "{tool} {path}: {outcome:?}"
            );
        }
    }
    assert!(
        h.store.pending_approvals().unwrap().is_empty(),
        "an invalid path never reaches a person"
    );
    let (_, _, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tool_failure_is_recorded_without_corrupting_history() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    assert!(matches!(
        h.request("r1", "system.info", json!({})).await,
        ToolOutcome::Completed { .. }
    ));
    let first = h.store.tasks(1).unwrap().remove(0);

    let outcome = h
        .request(
            "r2",
            "filesystem.read_fixture",
            json!({"path": "missing.txt"}),
        )
        .await;
    assert!(
        matches!(&outcome, ToolOutcome::Failed { error } if error.code == ErrorCode::ToolFailed),
        "{outcome:?}"
    );
    assert!(matches!(
        h.request(
            "r3",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"})
        )
        .await,
        ToolOutcome::Completed { .. }
    ));

    assert_eq!(
        h.statuses(),
        [
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Completed
        ]
    );
    assert_eq!(
        h.store.task(first.task_id).unwrap().unwrap(),
        first,
        "earlier task unchanged"
    );
    h.finish().await;
}

#[tokio::test]
async fn tool_timeout_is_recorded() {
    let mut h = Harness::start(Options {
        hang: true,
        limits: Limits {
            tool_timeout: Duration::from_millis(100),
            ..Limits::default()
        },
        ..Options::default()
    });
    h.ready().await;
    let outcome = h.request("r1", "system.info", json!({})).await;
    assert!(
        matches!(&outcome, ToolOutcome::Failed { error } if error.code == ErrorCode::Timeout),
        "{outcome:?}"
    );
    assert_eq!(h.statuses(), [TaskStatus::TimedOut]);
    // The session is still usable after a timeout.
    let outcome = h.request("r2", "shell.exec", json!({})).await;
    assert!(matches!(outcome, ToolOutcome::Rejected { .. }));
    h.finish().await;
}

#[tokio::test]
async fn shutdown_cancels_running_tool() {
    let mut h = Harness::start(Options {
        hang: true,
        ..Options::default()
    });
    h.ready().await;
    let job = h.job_id();
    h.send_request("r1", "system.info", json!({})).await;
    // Wait until the decision is recorded and the tool is running.
    for _ in 0..200 {
        if h.statuses() == [TaskStatus::Executing] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(h.statuses(), [TaskStatus::Executing]);

    h.shutdown.cancel();
    let outcome = h.response("r1").await;
    assert!(
        matches!(&outcome, ToolOutcome::Failed { error } if error.code == ErrorCode::Cancelled),
        "{outcome:?}"
    );
    let (report, store, _) = h.finish().await;
    assert_eq!(report.end, SessionEnd::Shutdown);
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Cancelled);
    assert_eq!(
        store.job(job).unwrap().unwrap().status,
        JobStatus::Interrupted
    );
}

#[tokio::test]
async fn duplicate_request_id_is_rejected() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    assert!(matches!(
        h.request("r1", "system.info", json!({})).await,
        ToolOutcome::Completed { .. }
    ));
    h.send_request("r1", "system.info", json!({})).await;
    match h.recv().await {
        CoreMessage::Error(error) => {
            assert_eq!(error.error.code, ErrorCode::DuplicateRequest);
            assert_eq!(error.request_id.map(String::from).as_deref(), Some("r1"));
        }
        other => panic!("expected an error, got {other:?}"),
    }
    assert_eq!(h.statuses().len(), 1);
    let (report, _, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a replay never executes");
    assert_eq!(report.requests, 1);
}

// --- protocol rules -----------------------------------------------------------------------------

#[tokio::test]
async fn another_protocol_version_closes_the_session() {
    for version in [1, 2, 4] {
        let mut h = Harness::start(Options::default());
        h.send(json!({"protocol": version, "type": "hello", "worker": "w", "worker_version": "9"}))
            .await;
        h.expect_error(ErrorCode::UnsupportedProtocolVersion, true)
            .await;
        let (report, _, _) = h.finish().await;
        assert!(!report.opened);
        assert!(
            matches!(report.end, SessionEnd::Terminated(ref e) if e.code == ErrorCode::UnsupportedProtocolVersion)
        );
    }
}

#[tokio::test]
async fn version_change_mid_session_closes_session() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let job = h.job_id();
    h.send(json!({
        "protocol": 4, "type": "tool_request", "request_id": "r1", "job_id": job,
        "tool": "system.info", "args": {}
    }))
    .await;
    h.expect_error(ErrorCode::UnsupportedProtocolVersion, true)
        .await;
    let (report, store, calls) = h.finish().await;
    assert!(matches!(report.end, SessionEnd::Terminated(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.job(job).unwrap().unwrap().status,
        JobStatus::Failed,
        "a job whose worker broke the protocol is not retried (ADR 0015)"
    );
}

#[tokio::test]
async fn request_before_hello_is_fatal() {
    let mut h = Harness::start(Options::default());
    h.send(json!({
        "protocol": 3, "type": "tool_request", "request_id": "r1", "job_id": JobId::new(),
        "tool": "system.info", "args": {}
    }))
    .await;
    h.expect_error(ErrorCode::HandshakeRequired, true).await;
    let (report, store, calls) = h.finish().await;
    assert!(!report.opened);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(store.tasks(10).unwrap().is_empty());
}

#[tokio::test]
async fn second_hello_is_unexpected() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    h.send(json!({"protocol": 3, "type": "hello", "worker": "again", "worker_version": "1"}))
        .await;
    h.expect_error(ErrorCode::UnexpectedMessage, false).await;
    h.finish().await;
}

#[tokio::test]
async fn worker_cannot_smuggle_authority() {
    let mut h = Harness::start(Options {
        policy: vec![
            (Capability::SystemInfo, PolicyDecision::Deny),
            (
                Capability::WorkspaceWrite,
                PolicyDecision::RequireConfirmation,
            ),
        ],
        ..Options::default()
    });
    h.ready().await;
    let job = h.job_id();
    let base = json!({
        "protocol": 3, "type": "tool_request", "request_id": "r1", "job_id": job,
        "tool": "workspace.write_file", "args": write_args("a.txt", "x")
    });
    for (key, value) in [
        ("capabilities", json!(["workspace.write"])),
        ("approved", json!(true)),
        ("approval", json!({"approved": true})),
        ("approval_id", json!("01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c")),
        ("fingerprint", json!("a".repeat(64))),
        ("decision", json!("allow")),
        ("task_id", json!("01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c")),
        ("session_id", json!("01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b")),
    ] {
        let mut frame = base.clone();
        frame[key] = value;
        h.send(frame).await;
        h.expect_error(ErrorCode::MalformedFrame, false).await;
    }
    assert!(h.statuses().is_empty());
    // The plain request is still evaluated against policy.
    let outcome = h.request("r2", "system.info", json!({})).await;
    assert!(matches!(outcome, ToolOutcome::Denied { .. }));
    let (_, _, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn error_budget_closes_session() {
    let mut h = Harness::start(Options {
        limits: Limits {
            max_protocol_errors: 2,
            ..Limits::default()
        },
        ..Options::default()
    });
    h.hello().await;
    h.send_raw(b"x").await;
    h.expect_error(ErrorCode::MalformedFrame, false).await;
    h.send_raw(b"x").await;
    h.expect_error(ErrorCode::MalformedFrame, false).await;
    h.send_raw(b"x").await;
    h.expect_error(ErrorCode::LimitExceeded, true).await;
    let (report, _, _) = h.finish().await;
    assert!(
        matches!(report.end, SessionEnd::Terminated(ref e) if e.code == ErrorCode::LimitExceeded)
    );
}

#[tokio::test]
async fn request_cap_closes_session() {
    let mut h = Harness::start(Options {
        limits: Limits {
            max_requests_per_session: 2,
            ..Limits::default()
        },
        ..Options::default()
    });
    h.ready().await;
    h.request("r1", "system.info", json!({})).await;
    h.request("r2", "system.info", json!({})).await;
    h.send_request("r3", "system.info", json!({})).await;
    h.expect_error(ErrorCode::LimitExceeded, true).await;
    let (report, store, calls) = h.finish().await;
    assert_eq!(report.requests, 2);
    assert_eq!(store.tasks(10).unwrap().len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn oversized_frame_is_rejected_and_session_continues() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let huge = format!(
        r#"{{"protocol":3,"type":"tool_request","request_id":"r1","job_id":"{}","tool":"system.info","args":{{"pad":"{}"}}}}"#,
        h.job_id(),
        "x".repeat(Limits::default().max_frame_bytes)
    );
    h.send_raw(huge.as_bytes()).await;
    h.expect_error(ErrorCode::FrameTooLarge, false).await;
    assert!(matches!(
        h.request("r2", "system.info", json!({})).await,
        ToolOutcome::Completed { .. }
    ));
    h.finish().await;
}

#[tokio::test]
async fn handshake_timeout_ends_session() {
    let h = Harness::start(Options {
        handshake_timeout: Duration::from_millis(100),
        ..Options::default()
    });
    let session = h.session;
    let report = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::HandshakeTimeout);
    assert!(!report.opened);
}

/// Invariant: decide, record, then act. A store that cannot record the start
/// of execution must stop the tool from running at all.
#[tokio::test]
async fn no_audit_means_no_action() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    fail_audit_writes_of(&h.dir.path().join("jarvis.db"), "execution_started");
    h.send_request("r1", "system.info", json!({})).await;
    // The worker is told the Core cannot continue, without the details.
    h.expect_error(ErrorCode::Internal, true).await;
    let (error, store, calls, _dir) = h.fails().await;
    assert!(matches!(error, SessionError::Store(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the tool must not run");
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Received);
}

#[tokio::test]
async fn every_task_reaches_exactly_one_terminal_state() {
    let mut h = Harness::start(Options {
        policy: vec![
            (Capability::SystemInfo, PolicyDecision::Allow),
            (
                Capability::WorkspaceWrite,
                PolicyDecision::RequireConfirmation,
            ),
        ],
        ..Options::default()
    });
    h.ready().await;
    h.request("a", "system.info", json!({})).await;
    h.request("b", "nope.tool", json!({})).await;
    h.send_request("c", "workspace.write_file", write_args("c.txt", "x"))
        .await;
    h.pending_approval().await;
    // The worker leaves while the write waits for a person.
    let (_, store, _) = h.finish().await;
    for task in store.tasks(10).unwrap() {
        assert!(task.status.is_terminal(), "{:?}", task.status);
        let finals = store
            .audit_events(Some(task.task_id), 100)
            .unwrap()
            .into_iter()
            .filter(|event| {
                matches!(
                    event.event,
                    AuditEventKind::ExecutionFinished { .. }
                        | AuditEventKind::RequestRejected { .. }
                        | AuditEventKind::TaskExpired { .. }
                )
            })
            .count();
        assert_eq!(finals, 1, "task {} ({:?})", task.task_id, task.status);
    }
}

/// A worker that stops reading must not stall the Core: once the pipe is
/// full, the write times out and the session ends.
#[tokio::test]
async fn worker_that_stops_reading_cannot_stall_the_core() {
    let mut h = Harness::start(Options {
        reply_buffer: 1024,
        limits: Limits {
            write_timeout: Duration::from_millis(200),
            ..Limits::default()
        },
        ..Options::default()
    });
    h.ready().await;
    for i in 0..50 {
        h.send_request(&format!("r{i}"), "system.info", json!({}))
            .await;
    }
    // Never read the replies. The session must end on its own.
    let session = h.session;
    let report = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .expect("the Core stalled on a worker that does not read")
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::WorkerGone);
    assert!(report.requests < 50);
    for task in h.store.tasks(100).unwrap() {
        assert!(task.status.is_terminal(), "{:?}", task.status);
    }
}

/// Worker-supplied text (here an unknown field name) is quoted in error
/// messages; control characters in it must not reach logs, the audit log or
/// the CLI unescaped.
#[tokio::test]
async fn worker_text_in_errors_is_escaped() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let hostile = "\u{1b}[31mX\nINFO forged line\u{7}";

    let outcome = h.request("r1", "system.info", json!({ hostile: 1 })).await;
    let ToolOutcome::Rejected { error } = outcome else {
        panic!("expected rejection");
    };
    assert!(
        !error.message.chars().any(char::is_control),
        "{}",
        error.message
    );
    let stored = h.store.tasks(1).unwrap().remove(0).error.unwrap();
    assert!(
        !stored.message.chars().any(char::is_control),
        "{}",
        stored.message
    );

    let mut frame = json!({"protocol": 3, "type": "tool_request", "request_id": "r2",
        "job_id": h.job_id(), "tool": "system.info", "args": {}});
    frame[hostile] = json!(1);
    h.send(frame).await;
    h.expect_error(ErrorCode::MalformedFrame, false).await;

    let (_, store, _) = h.finish().await;
    for event in store.audit_events(None, 1000).unwrap() {
        if let AuditEventKind::FrameRejected { error, .. }
        | AuditEventKind::RequestRejected { error } = &event.event
        {
            assert!(
                !error.message.chars().any(char::is_control),
                "{}",
                error.message
            );
        }
    }
}

// --- approvals ----------------------------------------------------------------------------------

#[tokio::test]
async fn an_approved_write_runs_exactly_once_after_the_approval_is_consumed() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request(
        "w1",
        "workspace.write_file",
        write_args("notes/today.md", "buy milk\n"),
    )
    .await;
    let approval = h.pending_approval().await;
    assert_eq!(approval.tool.as_str(), "workspace.write_file");
    assert_eq!(approval.capabilities, [Capability::WorkspaceWrite]);
    assert_eq!(approval.request_id.as_str(), "w1");
    assert_eq!(approval.job_id, h.job);
    assert_eq!(h.statuses(), [TaskStatus::AwaitingConfirmation]);
    assert_eq!(
        h.calls.load(Ordering::SeqCst),
        0,
        "nothing runs before a decision"
    );
    assert_eq!(h.workspace_file("notes/today.md"), None);

    h.grant(&approval, &approval.fingerprint).unwrap();
    let outcome = h.response("w1").await;
    let ToolOutcome::Completed {
        result: ToolResult::Written(written),
    } = outcome
    else {
        panic!("expected a completed write, got {outcome:?}");
    };
    assert_eq!(written.path.as_str(), "notes/today.md");
    assert_eq!(written.bytes, 9);
    assert!(written.created);
    assert_eq!(
        h.workspace_file("notes/today.md").as_deref(),
        Some("buy milk\n")
    );
    assert_eq!(h.approval_status(&approval), ApprovalStatus::Consumed);

    // A consumed approval is spent: neither the person nor the session can use it again.
    assert!(matches!(
        h.grant(&approval, &approval.fingerprint),
        Err(ApprovalError::NotPending(ApprovalStatus::Consumed))
    ));
    assert!(matches!(
        h.store
            .consume_approval(approval.approval_id, &approval.fingerprint, now_ms(), &[]),
        Err(ApprovalError::NotGranted(ApprovalStatus::Consumed))
    ));

    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Completed);
    assert_eq!(
        Harness::task_kinds(&store),
        [
            "request_received",
            "policy_evaluated",
            "approval_requested",
            "approval_granted",
            "approval_consumed",
            "execution_started",
            "execution_finished",
        ]
    );
}

#[tokio::test]
async fn the_same_write_again_needs_a_new_approval() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let first = h.pending_approval().await;
    h.grant(&first, &first.fingerprint).unwrap();
    assert!(matches!(
        h.response("w1").await,
        ToolOutcome::Completed { .. }
    ));

    h.send_request("w2", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let second = h.pending_approval().await;
    assert_ne!(second.approval_id, first.approval_id);
    assert_ne!(
        second.fingerprint, first.fingerprint,
        "bound to another task"
    );
    assert!(
        matches!(
            h.grant(&second, &first.fingerprint),
            Err(ApprovalError::FingerprintMismatch)
        ),
        "an old fingerprint does not approve a new request"
    );
    h.deny(&second, "once is enough").unwrap();
    assert!(matches!(
        h.response("w2").await,
        ToolOutcome::Declined { .. }
    ));
    let (_, _, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_denied_write_never_runs() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    h.deny(&approval, "not today").unwrap();
    let outcome = h.response("w1").await;
    assert_eq!(
        outcome,
        ToolOutcome::Declined {
            approval_id: approval.approval_id,
            reason: Summary::try_from("not today".to_owned()).unwrap(),
        }
    );
    assert_eq!(h.statuses(), [TaskStatus::Denied]);
    assert_eq!(h.workspace_file("a.txt"), None);
    assert!(h.grant(&approval, &approval.fingerprint).is_err());
    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!Harness::kinds(&store).contains(&"execution_started"));
    assert!(Harness::kinds(&store).contains(&"approval_denied"));
}

#[tokio::test]
async fn a_wrong_fingerprint_does_not_approve() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    let other = Fingerprint::from_digest(&[0xab; 32]);
    assert!(matches!(
        h.grant(&approval, &other),
        Err(ApprovalError::FingerprintMismatch)
    ));
    // The session looked again and is still waiting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.approval_status(&approval), ApprovalStatus::Pending);
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
    h.deny(&approval, "wrong request").unwrap();
    assert!(matches!(
        h.response("w1").await,
        ToolOutcome::Declined { .. }
    ));
    h.finish().await;
}

#[tokio::test]
async fn an_approval_nobody_decides_on_expires() {
    let mut h = Harness::start(Options {
        approval_ttl: Duration::from_millis(300),
        ..Options::default()
    });
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    let outcome = h.response("w1").await;
    assert_eq!(
        outcome,
        ToolOutcome::Expired {
            approval_id: approval.approval_id
        }
    );
    assert_eq!(h.approval_status(&approval), ApprovalStatus::Expired);
    assert_eq!(h.statuses(), [TaskStatus::Expired]);
    assert!(
        h.grant(&approval, &approval.fingerprint).is_err(),
        "too late to approve"
    );
    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(Harness::kinds(&store).contains(&"approval_expired"));
}

#[tokio::test]
async fn the_worker_leaving_while_waiting_expires_the_approval() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    let job = h.job_id();
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    let store = h.store.clone();
    let (report, _, calls) = h.finish().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
    let record = store.approval(approval.approval_id).unwrap().unwrap();
    assert_eq!(record.status, ApprovalStatus::Expired);
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Expired);
    assert_eq!(
        store.job(job).unwrap().unwrap().status,
        JobStatus::Queued,
        "nothing ran, so the job waits for the next worker"
    );
    // A person who approves after the worker left changes nothing.
    assert!(matches!(
        store.grant_approval(
            approval.approval_id,
            &approval.fingerprint,
            "late",
            now_ms()
        ),
        Err(ApprovalError::NotPending(ApprovalStatus::Expired))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn shutdown_while_waiting_expires_the_approval() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    h.shutdown.cancel();
    assert!(matches!(
        h.response("w1").await,
        ToolOutcome::Expired { .. }
    ));
    let (report, store, calls) = h.finish().await;
    assert_eq!(report.end, SessionEnd::Shutdown);
    assert_eq!(
        store
            .approval(approval.approval_id)
            .unwrap()
            .unwrap()
            .status,
        ApprovalStatus::Expired
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn frames_sent_while_waiting_are_handled_afterwards_in_order() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    h.send_request("r2", "system.info", json!({})).await;
    h.send_raw(b"not json").await;
    // Nothing runs while the first request waits.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
    h.grant(&approval, &approval.fingerprint).unwrap();
    assert!(matches!(
        h.response("w1").await,
        ToolOutcome::Completed { .. }
    ));
    assert!(matches!(
        h.response("r2").await,
        ToolOutcome::Completed { .. }
    ));
    h.expect_error(ErrorCode::MalformedFrame, false).await;
    let (_, _, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn too_many_frames_while_waiting_end_the_session() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    for i in 0..17 {
        h.send_request(&format!("r{i}"), "system.info", json!({}))
            .await;
    }
    assert!(matches!(
        h.response("w1").await,
        ToolOutcome::Expired { .. }
    ));
    h.expect_error(ErrorCode::LimitExceeded, true).await;
    let (report, store, calls) = h.finish().await;
    assert!(matches!(report.end, SessionEnd::Terminated(_)));
    assert_eq!(
        store
            .approval(approval.approval_id)
            .unwrap()
            .unwrap()
            .status,
        ApprovalStatus::Expired
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Crash before consumption: if the transaction that consumes the approval
/// cannot commit, the tool never runs and the approval is never used. After
/// a restart, recovery expires it.
#[tokio::test]
async fn a_store_failure_before_consumption_never_runs_the_tool() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    fail_audit_writes_of(&h.dir.path().join("jarvis.db"), "approval_consumed");
    h.grant(&approval, &approval.fingerprint).unwrap();
    h.expect_error(ErrorCode::Internal, true).await;
    let (error, store, calls, dir) = h.fails().await;
    assert!(matches!(error, SessionError::Store(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!dir.path().join("workspace").join("a.txt").exists());
    let record = store.approval(approval.approval_id).unwrap().unwrap();
    assert_eq!(record.status, ApprovalStatus::Granted, "never consumed");
    assert_eq!(
        store.tasks(1).unwrap()[0].status,
        TaskStatus::AwaitingConfirmation
    );
    // What the next start-up does.
    let recovered = store.recover(Limits::default().max_job_attempts).unwrap();
    assert_eq!(recovered.approvals, 1);
    assert_eq!(
        store
            .approval(approval.approval_id)
            .unwrap()
            .unwrap()
            .status,
        ApprovalStatus::Expired
    );
}

/// Crash after the tool ran but before its result was recorded: the side
/// effect happened, the approval is consumed and can never be used again,
/// and recovery marks the task interrupted. The Core guarantees the approval
/// is used at most once, not that the side effect happens exactly once.
#[tokio::test]
async fn a_store_failure_after_the_tool_ran_leaves_a_consumed_approval() {
    let mut h = Harness::start(Options::default());
    h.ready().await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    fail_audit_writes_of(&h.dir.path().join("jarvis.db"), "execution_finished");
    h.grant(&approval, &approval.fingerprint).unwrap();
    h.expect_error(ErrorCode::Internal, true).await;
    let (error, store, calls, dir) = h.fails().await;
    assert!(matches!(error, SessionError::Store(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let written = dir.path().join("workspace").join("a.txt");
    assert_eq!(std::fs::read_to_string(written).unwrap(), "x");
    assert_eq!(
        store
            .approval(approval.approval_id)
            .unwrap()
            .unwrap()
            .status,
        ApprovalStatus::Consumed
    );
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Executing);
    store.recover(Limits::default().max_job_attempts).unwrap();
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Interrupted);
    assert!(
        store
            .consume_approval(approval.approval_id, &approval.fingerprint, now_ms(), &[])
            .is_err()
    );
}

/// The job time limit also applies while a request waits for a person, so a
/// worker cannot keep a job alive past it by queueing writes nobody approves.
#[tokio::test]
async fn the_job_time_limit_applies_while_waiting_for_a_person() {
    let mut h = Harness::start(Options {
        job_timeout: Duration::from_millis(400),
        approval_ttl: Duration::from_secs(60),
        ..Options::default()
    });
    h.ready().await;
    let job = h.job_id();
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    assert!(matches!(
        h.response("w1").await,
        ToolOutcome::Expired { .. }
    ));
    let store = h.store.clone();
    let session = h.session;
    let report = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::JobTimedOut(job));
    assert_eq!(
        store
            .approval(approval.approval_id)
            .unwrap()
            .unwrap()
            .status,
        ApprovalStatus::Expired
    );
    assert_eq!(store.job(job).unwrap().unwrap().status, JobStatus::Failed);
}

/// Requests buffered while one waited are not a way around the limit either:
/// each would wait for its own approval, but the job ends at its deadline.
#[tokio::test]
async fn buffered_requests_do_not_extend_a_job_past_its_limit() {
    let mut h = Harness::start(Options {
        job_timeout: Duration::from_millis(700),
        approval_ttl: Duration::from_millis(200),
        ..Options::default()
    });
    h.ready().await;
    let job = h.job_id();
    for i in 0..5 {
        h.send_request(
            &format!("w{i}"),
            "workspace.write_file",
            write_args("a.txt", "x"),
        )
        .await;
    }
    let store = h.store.clone();
    let session = h.session;
    let report = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::JobTimedOut(job));
    assert!(
        store.tasks(10).unwrap().len() < 5,
        "the job ended before every buffered request was handled"
    );
    assert_eq!(store.job(job).unwrap().unwrap().status, JobStatus::Failed);
    for task in store.tasks(10).unwrap() {
        assert!(task.status.is_terminal(), "{:?}", task.status);
    }
}

// --- Session Agent -------------------------------------------------------------------------------

fn agent_policy() -> Vec<(Capability, PolicyDecision)> {
    let mut policy = Options::default().policy;
    policy.push((
        Capability::SessionAgentHealthcheck,
        PolicyDecision::RequireConfirmation,
    ));
    for capability in Capability::ALL.iter().filter(|c| c.is_desktop()) {
        policy.push((*capability, PolicyDecision::Deny));
    }
    policy
}

fn agent_config(timeout: Duration, max_starts: u32) -> SessionAgentConfig {
    SessionAgentConfig {
        program: None,
        timeout,
        grant_ttl: Duration::from_secs(10),
        max_starts,
    }
}

/// The real `jarvis-session-agent` executable, started as a trusted helper.
fn real_agent() -> Arc<SessionAgent> {
    let launcher = ProcessLauncher::new(env!("CARGO_BIN_EXE_jarvis-session-agent").into());
    Arc::new(SessionAgent::new(
        Arc::new(launcher),
        &agent_config(Duration::from_secs(10), 4),
    ))
}

/// How a fake agent behaves after it announced itself (or instead of it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fake {
    /// Never announces itself.
    Silent,
    /// Reads the operation and exits without answering.
    ExitAfterPerform,
    /// Answers for a grant it was not given.
    WrongGrant,
    /// Reads the operation and never answers.
    Hang,
    /// Answers with a frame that is not a valid reply.
    Garbage,
    /// Refuses the grant as already seen.
    Refuse,
    /// Performs one operation, then exits while idle.
    OnceThenExit,
    /// Reports a clipboard write of the text it was sent.
    Clipboard,
    /// Refuses a clipboard write because the clipboard is in use.
    ClipboardBusy,
    /// Reports that a clipboard write may be incomplete.
    ClipboardFault,
    /// Reports a clipboard write of a different length.
    ClipboardWrongLength,
}

/// Launches in-memory agents that misbehave as told, counting launches and
/// the operations they received.
#[derive(Debug)]
struct FakeLauncher {
    behaviour: Fake,
    launches: Arc<AtomicUsize>,
    performs: Arc<AtomicUsize>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Launcher for FakeLauncher {
    fn launch(&self) -> std::io::Result<Launched> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        let (core_writer, agent_reader) = tokio::io::duplex(64 * 1024);
        let (agent_writer, core_reader) = tokio::io::duplex(64 * 1024);
        let behaviour = self.behaviour;
        let performs = Arc::clone(&self.performs);
        let task = tokio::spawn(async move {
            let mut lines = BufReader::new(agent_reader).lines();
            let mut out = agent_writer;
            if behaviour == Fake::Silent {
                std::future::pending::<()>().await;
            }
            out.write_all(b"{\"type\":\"ready\",\"v\":1,\"agent_version\":\"fake\"}\n")
                .await
                .unwrap();
            while let Ok(Some(line)) = lines.next_line().await {
                performs.fetch_add(1, Ordering::SeqCst);
                let frame: Value = serde_json::from_str(&line).unwrap();
                let grant = frame["grant_id"].clone();
                let units = frame["operation"]["text"]
                    .as_str()
                    .map_or(0, |text| text.encode_utf16().count());
                let reply = match behaviour {
                    Fake::Silent | Fake::ExitAfterPerform => return,
                    Fake::Hang => std::future::pending().await,
                    Fake::WrongGrant => json!({"type": "result", "v": 1,
                        "grant_id": jarvis_protocol::ApprovalId::new(),
                        "outcome": {"status": "done", "report": {"op": "healthcheck", "label": "ping", "performed": 1}}}),
                    Fake::Garbage => json!({"type": "result", "v": 1, "grant_id": grant,
                        "outcome": {"status": "done", "report": {"op": "healthcheck", "label": "ping", "performed": 1,
                        "screen": "AAAA"}}}),
                    Fake::Refuse => json!({"type": "result", "v": 1, "grant_id": grant,
                        "outcome": {"status": "refused", "reason": "replayed_grant"}}),
                    Fake::OnceThenExit => json!({"type": "result", "v": 1, "grant_id": grant,
                        "outcome": {"status": "done", "report": {"op": "healthcheck", "label": "ping", "performed": 1}}}),
                    Fake::Clipboard => json!({"type": "result", "v": 1, "grant_id": grant,
                        "outcome": {"status": "done",
                        "report": {"op": "write_clipboard_text", "utf16_units": units}}}),
                    Fake::ClipboardBusy => json!({"type": "result", "v": 1, "grant_id": grant,
                        "outcome": {"status": "refused", "reason": "clipboard_busy"}}),
                    Fake::ClipboardFault => json!({"type": "result", "v": 1, "grant_id": grant,
                        "outcome": {"status": "faulted", "reason": "clipboard_incomplete"}}),
                    Fake::ClipboardWrongLength => {
                        json!({"type": "result", "v": 1, "grant_id": grant,
                        "outcome": {"status": "done",
                        "report": {"op": "write_clipboard_text", "utf16_units": units + 1}}})
                    }
                };
                let mut bytes = serde_json::to_vec(&reply).unwrap();
                bytes.push(b'\n');
                out.write_all(&bytes).await.unwrap();
                if behaviour == Fake::OnceThenExit {
                    return;
                }
            }
        });
        Ok(Launched {
            reader: Box::new(core_reader),
            writer: Box::new(core_writer),
            pid: None,
            image_sha256: None,
            keep: Box::new(AbortOnDrop(task)),
        })
    }
}

fn fake_agent(
    behaviour: Fake,
    timeout: Duration,
    max_starts: u32,
) -> (Arc<SessionAgent>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let launches = Arc::new(AtomicUsize::new(0));
    let performs = Arc::new(AtomicUsize::new(0));
    let launcher = FakeLauncher {
        behaviour,
        launches: Arc::clone(&launches),
        performs: Arc::clone(&performs),
    };
    let agent = SessionAgent::new(Arc::new(launcher), &agent_config(timeout, max_starts));
    (Arc::new(agent), launches, performs)
}

fn agent_options(agent: Option<Arc<SessionAgent>>) -> Options {
    Options {
        policy: agent_policy(),
        session_agent: agent,
        ..Options::default()
    }
}

fn healthcheck(label: &str) -> Value {
    json!({ "label": label })
}

/// The agent policy, with clipboard writes enabled as an owner would: each
/// one still needs a person's approval.
fn clipboard_options(agent: Option<Arc<SessionAgent>>) -> Options {
    let mut options = agent_options(agent);
    for (capability, decision) in &mut options.policy {
        if *capability == Capability::DesktopClipboardWrite {
            *decision = PolicyDecision::RequireConfirmation;
        }
    }
    options
}

/// Text with a line end, a tab, a backslash and a letter outside the BMP:
/// what the person is shown must be all of it, with layout made visible.
const CLIPBOARD_TEXT: &str = "Demo: hello\n\tfrom the Session Agent \\ caf\u{e9} \u{20000}";

/// Request a clipboard write with the arguments a planner derives from a
/// clipboard job (`Harness::clipboard_job`) and approve it after checking
/// what the person is shown.
async fn approved_clipboard_write(
    h: &mut Harness,
    id: &str,
    args: Value,
    text: &str,
) -> ToolOutcome {
    h.send_request(id, "desktop.write_clipboard_text", args)
        .await;
    let approval = h.pending_approval().await;
    assert_eq!(approval.capabilities, [Capability::DesktopClipboardWrite]);
    let shown = jarvis_core::approval::view(&approval, now_ms(), &h.store);
    assert!(shown.arguments["action"].contains("clipboard"), "{shown:?}");
    assert_eq!(
        shown.arguments["text"],
        jarvis_core::approval::display_safe(text, usize::MAX)
    );
    assert_eq!(
        shown.arguments["characters"],
        text.chars().count().to_string()
    );
    h.grant(&approval, &approval.fingerprint).unwrap();
    h.response(id).await
}

#[tokio::test]
async fn an_approved_clipboard_write_is_shown_in_full_and_sent_once() {
    let (agent, launches, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let args = h.clipboard_job(CLIPBOARD_TEXT).await;
    let outcome = approved_clipboard_write(&mut h, "c1", args, CLIPBOARD_TEXT).await;
    let ToolOutcome::Completed {
        result: ToolResult::AgentReceipt(receipt),
    } = outcome
    else {
        panic!("expected a receipt, got {outcome:?}");
    };
    assert_eq!(receipt.agent_operation, "desktop.write_clipboard_text");
    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing ran in the Core");
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    assert_eq!(performs.load(Ordering::SeqCst), 1);
    let task = &store.tasks(10).unwrap()[0];
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(
        task.result.as_deref(),
        Some(r#"{"agent_operation":"desktop.write_clipboard_text"}"#)
    );
    let (kinds, report) = agent_events(&store);
    assert_eq!(
        kinds,
        [
            "session_agent_started",
            "session_agent_dispatched",
            "session_agent_completed",
        ]
    );
    assert_eq!(
        report,
        Some(AgentReport::WriteClipboardText(ClipboardWritten {
            utf16_units: u32::try_from(CLIPBOARD_TEXT.encode_utf16().count()).unwrap(),
        }))
    );
}

#[tokio::test]
async fn a_busy_clipboard_is_refused_and_never_retried() {
    let (agent, _, performs) = fake_agent(Fake::ClipboardBusy, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let args = h.clipboard_job("hello").await;
    let outcome = approved_clipboard_write(&mut h, "c1", args, "hello").await;
    let ToolOutcome::Failed { error } = outcome else {
        panic!("expected a failure, got {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::ToolFailed);
    let (_, store, _) = h.finish().await;
    assert_eq!(performs.load(Ordering::SeqCst), 1);
    let events = store.audit_events(None, 1000).unwrap();
    assert!(events.iter().any(|event| matches!(&event.event,
        AuditEventKind::SessionAgentRefused { reason, .. } if reason.contains("clipboard_busy"))));
}

#[tokio::test]
async fn an_unconfirmed_clipboard_write_fails_closed() {
    for behaviour in [Fake::ClipboardFault, Fake::ClipboardWrongLength] {
        let (agent, launches, performs) = fake_agent(behaviour, Duration::from_secs(5), 4);
        let mut h = Harness::start(clipboard_options(Some(agent)));
        h.hello().await;
        let args = h.clipboard_job("hello").await;
        let outcome = approved_clipboard_write(&mut h, "c1", args, "hello").await;
        let ToolOutcome::Failed { error } = outcome else {
            panic!("{behaviour:?}: expected a failure, got {outcome:?}");
        };
        assert_eq!(error.code, ErrorCode::Internal, "{behaviour:?}");
        let (_, store, _) = h.finish().await;
        assert_eq!(launches.load(Ordering::SeqCst), 1, "{behaviour:?}");
        assert_eq!(
            performs.load(Ordering::SeqCst),
            1,
            "{behaviour:?}: sent once"
        );
        assert_eq!(
            agent_events(&store).0,
            [
                "session_agent_started",
                "session_agent_dispatched",
                "session_agent_stopped",
                "session_agent_outcome_unknown",
            ],
            "{behaviour:?}"
        );
        let task = &store.tasks(10).unwrap()[0];
        assert_eq!(task.status, TaskStatus::Failed);
        assert_eq!(task.error.as_ref().unwrap().code, ErrorCode::Internal);
    }
}

#[tokio::test]
async fn other_desktop_operations_stay_closed_with_clipboard_writes_enabled() {
    let (agent, launches, _) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.ready().await;
    for (id, tool, args) in [
        ("d1", "desktop.capture_window", json!({"target": 1})),
        ("d2", "desktop.read_clipboard_text", json!({})),
        (
            "d3",
            "desktop.type_text",
            json!({"target": 1, "text": "hi"}),
        ),
    ] {
        let outcome = h.request(id, tool, args).await;
        assert!(matches!(outcome, ToolOutcome::Denied { .. }), "{outcome:?}");
    }
    let payload = jarvis_protocol::PayloadId::new();
    let sha256 = "ab".repeat(32);
    for (id, args) in [
        ("x1", json!({"text": ""})),
        ("x2", json!({"text": "hello"})),
        ("x3", json!({"payload_id": payload})),
        ("x4", json!({"sha256": sha256})),
        (
            "x5",
            json!({"payload_id": payload, "sha256": sha256, "text": "hi"}),
        ),
        (
            "x6",
            json!({"payload_id": payload, "sha256": sha256, "target": 1}),
        ),
        ("x7", json!({"payload_id": "not-a-uuid", "sha256": sha256})),
        (
            "x8",
            json!({"payload_id": payload, "sha256": "AB".repeat(32)}),
        ),
        ("x9", json!({"payload_id": payload, "sha256": "ab"})),
    ] {
        let outcome = h.request(id, "desktop.write_clipboard_text", args).await;
        assert!(
            matches!(outcome, ToolOutcome::Rejected { .. }),
            "{outcome:?}"
        );
    }
    let (_, store, _) = h.finish().await;
    assert!(store.pending_approvals().unwrap().is_empty());
    assert_eq!(launches.load(Ordering::SeqCst), 0);
}

// --- clipboard payloads (ADR 0022) --------------------------------------------------------------

/// A text no other part of a test can contain.
const CANARY: &str = "canary-4e1b7a90-clipboard";

/// Every value of every table except `payloads`, read through a second
/// connection to the same file.
fn immutable_records(path: &std::path::Path) -> String {
    use rusqlite::types::ValueRef;
    let conn = rusqlite::Connection::open(path).unwrap();
    let tables: Vec<String> = {
        let mut statement = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name NOT LIKE 'sqlite_%' AND name <> 'payloads'",
            )
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let mut dump = String::new();
    for table in tables {
        let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for column in 0..columns {
                match row.get_ref(column).unwrap() {
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                        dump.push_str(&String::from_utf8_lossy(bytes));
                    }
                    ValueRef::Integer(value) => dump.push_str(&value.to_string()),
                    ValueRef::Real(value) => dump.push_str(&value.to_string()),
                    ValueRef::Null => {}
                }
                dump.push('|');
            }
            dump.push('\n');
        }
    }
    dump
}

/// Whether `needle` is anywhere in the database file or its log.
fn on_disk(dir: &std::path::Path, needle: &str) -> bool {
    ["jarvis.db", "jarvis.db-wal"].iter().any(|name| {
        std::fs::read(dir.join(name)).is_ok_and(|bytes| {
            bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
        })
    })
}

fn payload_rows(dir: &std::path::Path) -> i64 {
    rusqlite::Connection::open(dir.join("jarvis.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM payloads", [], |row| row.get(0))
        .unwrap()
}

/// Wait until the store shows the job as ended.
async fn job_ends(store: &Store, job: JobId) -> JobStatus {
    for _ in 0..500 {
        let status = store.job(job).unwrap().unwrap().status;
        if status.is_terminal() {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the job did not end");
}

#[tokio::test]
async fn an_approved_clipboard_text_never_enters_the_immutable_records() {
    let (agent, _, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let text = format!("hello {CANARY}");
    let args = h.clipboard_job(&text).await;
    let path = h.dir.path().join("jarvis.db");
    // Queued and running: the job and its goal name the text, never hold it.
    assert!(!immutable_records(&path).contains(CANARY));

    h.send_request("c1", "desktop.write_clipboard_text", args)
        .await;
    let approval = h.pending_approval().await;
    // While a person decides, the text is shown but is in no record.
    let shown = jarvis_core::approval::view(&approval, now_ms(), &h.store);
    assert_eq!(shown.arguments["text"], text);
    assert!(!immutable_records(&path).contains(CANARY));
    assert!(
        on_disk(h.dir.path(), CANARY),
        "the payload holds it meanwhile"
    );
    h.grant(&approval, &approval.fingerprint).unwrap();
    let outcome = h.response("c1").await;
    assert!(
        matches!(outcome, ToolOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(performs.load(Ordering::SeqCst), 1);

    // Executed, the text is still in no record; the payload goes when the
    // job does.
    assert!(!immutable_records(&path).contains(CANARY));
    let job = h.job_id();
    h.finish_job("completed", "copied").await;
    assert_eq!(job_ends(&h.store, job).await, JobStatus::Completed);
    assert_eq!(payload_rows(h.dir.path()), 0);
    assert!(!immutable_records(&path).contains(CANARY));
    assert!(
        !on_disk(h.dir.path(), CANARY),
        "the text is in neither the database file nor its log"
    );
    // After the job, the approval view says so.
    let later = h.store.approval(approval.approval_id).unwrap().unwrap();
    let shown = jarvis_core::approval::view(&later, now_ms(), &h.store);
    assert_eq!(shown.arguments["text"], "the text is no longer kept");
    assert_eq!(shown.arguments["sha256"].len(), 64);
    h.finish().await;
}

#[tokio::test]
async fn the_payload_goes_with_its_job_when_the_request_is_declined_or_fails() {
    // Declined by a person.
    let (agent, _, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let args = h.clipboard_job(&format!("declined {CANARY}")).await;
    h.send_request("c1", "desktop.write_clipboard_text", args)
        .await;
    let approval = h.pending_approval().await;
    h.deny(&approval, "no").unwrap();
    assert!(matches!(
        h.response("c1").await,
        ToolOutcome::Declined { .. }
    ));
    assert_eq!(payload_rows(h.dir.path()), 1, "kept until the job ends");
    let job = h.job_id();
    h.finish_job("failed", "declined").await;
    assert_eq!(job_ends(&h.store, job).await, JobStatus::Failed);
    assert_eq!(payload_rows(h.dir.path()), 0);
    assert!(!on_disk(h.dir.path(), CANARY));
    assert_eq!(performs.load(Ordering::SeqCst), 0);
    h.finish().await;

    // The approval expires.
    let (agent, _, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut options = clipboard_options(Some(agent));
    options.approval_ttl = Duration::from_millis(100);
    let mut h = Harness::start(options);
    h.hello().await;
    let args = h.clipboard_job(&format!("expired {CANARY}")).await;
    let outcome = h.request("c1", "desktop.write_clipboard_text", args).await;
    assert!(
        matches!(outcome, ToolOutcome::Expired { .. }),
        "{outcome:?}"
    );
    let job = h.job_id();
    h.finish_job("failed", "expired").await;
    assert_eq!(job_ends(&h.store, job).await, JobStatus::Failed);
    assert_eq!(payload_rows(h.dir.path()), 0);
    assert!(!on_disk(h.dir.path(), CANARY));
    assert_eq!(performs.load(Ordering::SeqCst), 0);
    h.finish().await;

    // The Session Agent reports a failure.
    let (agent, _, _) = fake_agent(Fake::ClipboardBusy, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let args = h.clipboard_job(&format!("busy {CANARY}")).await;
    let outcome = approved_clipboard_write(&mut h, "c1", args, &format!("busy {CANARY}")).await;
    assert!(matches!(outcome, ToolOutcome::Failed { .. }), "{outcome:?}");
    let job = h.job_id();
    h.finish_job("failed", "busy").await;
    assert_eq!(job_ends(&h.store, job).await, JobStatus::Failed);
    assert_eq!(payload_rows(h.dir.path()), 0);
    assert!(!on_disk(h.dir.path(), CANARY));
    h.finish().await;
}

#[tokio::test]
async fn a_job_ended_by_its_time_limit_loses_its_payload() {
    let (agent, _, _) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut options = clipboard_options(Some(agent));
    options.job_timeout = Duration::from_millis(300);
    let mut h = Harness::start(options);
    h.hello().await;
    let _args = h.clipboard_job(&format!("slow {CANARY}")).await;
    let job = h.job_id();
    let session = h.session;
    let report = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::JobTimedOut(job));
    assert_eq!(h.store.job(job).unwrap().unwrap().status, JobStatus::Failed);
    assert_eq!(payload_rows(h.dir.path()), 0);
    assert!(!on_disk(h.dir.path(), CANARY));
}

#[tokio::test]
async fn a_job_cut_short_keeps_its_payload_for_the_next_attempt() {
    let (agent, _, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let text = format!("again {CANARY}");
    let args = h.clipboard_job(&text).await;
    let job = h.job_id();
    let dir = h.dir.path().to_path_buf();
    // The worker goes away before asking for anything: the job goes back to
    // the queue with its text.
    let (report, store, _) = h.finish().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
    assert_eq!(store.job(job).unwrap().unwrap().status, JobStatus::Queued);
    let payload_id: jarvis_protocol::PayloadId =
        args["payload_id"].as_str().unwrap().parse().unwrap();
    let kept = store.payload(payload_id).unwrap().unwrap();
    assert_eq!(kept.text, text);
    assert_eq!(kept.job_id, job);
    assert_eq!(performs.load(Ordering::SeqCst), 0);
    let _ = dir;
}

#[tokio::test]
async fn a_changed_payload_is_refused_before_the_approval_is_used() {
    let (agent, launches, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let args = h.clipboard_job("the text the person approved").await;
    h.send_request("c1", "desktop.write_clipboard_text", args)
        .await;
    let approval = h.pending_approval().await;
    // A same-user process edits the stored text after the request was made.
    rusqlite::Connection::open(h.dir.path().join("jarvis.db"))
        .unwrap()
        .execute("UPDATE payloads SET text = 'a different text'", [])
        .unwrap();
    let shown = jarvis_core::approval::view(&approval, now_ms(), &h.store);
    assert!(shown.arguments["text"].contains("changed"), "{shown:?}");
    assert!(shown.arguments["text"].contains("refuse"), "{shown:?}");
    assert!(!shown.arguments.values().any(|v| v.contains("different")));
    h.grant(&approval, &approval.fingerprint).unwrap();
    let outcome = h.response("c1").await;
    assert!(
        matches!(outcome, ToolOutcome::Expired { .. }),
        "{outcome:?}"
    );

    // Nothing was consumed, started or sent.
    assert_eq!(h.approval_status(&approval), ApprovalStatus::Expired);
    assert_eq!(performs.load(Ordering::SeqCst), 0);
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let kinds = Harness::task_kinds(&store);
    assert!(!kinds.contains(&"approval_consumed"), "{kinds:?}");
    assert!(!kinds.contains(&"execution_started"), "{kinds:?}");
    assert!(!kinds.contains(&"session_agent_dispatched"), "{kinds:?}");
}

#[tokio::test]
async fn a_missing_payload_is_refused_before_the_approval_is_used() {
    let (agent, launches, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    let args = h.clipboard_job("gone before it was used").await;
    h.send_request("c1", "desktop.write_clipboard_text", args)
        .await;
    let approval = h.pending_approval().await;
    rusqlite::Connection::open(h.dir.path().join("jarvis.db"))
        .unwrap()
        .execute("DELETE FROM payloads", [])
        .unwrap();
    let shown = jarvis_core::approval::view(&approval, now_ms(), &h.store);
    assert_eq!(shown.arguments["text"], "the text is no longer kept");
    assert_eq!(shown.arguments["sha256"].len(), 64);
    h.grant(&approval, &approval.fingerprint).unwrap();
    let outcome = h.response("c1").await;
    assert!(
        matches!(outcome, ToolOutcome::Expired { .. }),
        "{outcome:?}"
    );
    assert_eq!(h.approval_status(&approval), ApprovalStatus::Expired);
    assert_eq!(performs.load(Ordering::SeqCst), 0);
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    let (_, store, _) = h.finish().await;
    assert!(!Harness::task_kinds(&store).contains(&"approval_consumed"));
}

#[tokio::test]
async fn a_worker_cannot_name_the_payload_of_another_job() {
    let (agent, launches, performs) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.hello().await;
    h.job("an unrelated job").await;
    // Another client's clipboard job waits in the queue.
    let other = h
        .store
        .submit_clipboard_job(
            &ClipboardText::try_from(format!("someone else's {CANARY}")).unwrap(),
            "other client",
        )
        .unwrap();
    let rest = other.goal.as_str().strip_prefix("copy payload:").unwrap();
    let (payload_id, sha256) = rest.split_once(':').unwrap();
    let stolen = json!({"payload_id": payload_id, "sha256": sha256});
    h.send_request("c1", "desktop.write_clipboard_text", stolen)
        .await;
    let approval = h.pending_approval().await;
    let shown = jarvis_core::approval::view(&approval, now_ms(), &h.store);
    assert_eq!(shown.arguments["text"], "the text is no longer kept");
    assert!(!shown.arguments.values().any(|value| value.contains(CANARY)));
    h.grant(&approval, &approval.fingerprint).unwrap();
    let outcome = h.response("c1").await;
    assert!(
        matches!(outcome, ToolOutcome::Expired { .. }),
        "{outcome:?}"
    );
    assert_eq!(performs.load(Ordering::SeqCst), 0);
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    h.finish().await;
}

#[tokio::test]
async fn the_old_argument_shape_with_text_is_rejected() {
    let (agent, launches, _) = fake_agent(Fake::Clipboard, Duration::from_secs(5), 4);
    let mut h = Harness::start(clipboard_options(Some(agent)));
    h.ready().await;
    let outcome = h
        .request(
            "c1",
            "desktop.write_clipboard_text",
            json!({"text": format!("old {CANARY}")}),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Rejected { .. }),
        "{outcome:?}"
    );
    let (_, store, _) = h.finish().await;
    assert!(store.pending_approvals().unwrap().is_empty());
    assert_eq!(launches.load(Ordering::SeqCst), 0);
}

/// The `session_agent_*` events and the report of the completion, if any.
fn agent_events(store: &Store) -> (Vec<&'static str>, Option<AgentReport>) {
    let events = store.audit_events(None, 1000).unwrap();
    let report = events.iter().find_map(|event| match &event.event {
        AuditEventKind::SessionAgentCompleted { report, .. } => Some(report.clone()),
        _ => None,
    });
    let kinds = events
        .into_iter()
        .map(|event| event.event.name())
        .filter(|kind| kind.starts_with("session_agent"))
        .collect();
    (kinds, report)
}

/// Request a health check and approve it as a person would, after checking
/// what that person is shown.
async fn approved_healthcheck(h: &mut Harness, id: &str, label: &str) -> ToolOutcome {
    h.send_request(id, "session_agent.healthcheck", healthcheck(label))
        .await;
    let approval = h.pending_approval().await;
    assert_eq!(approval.capabilities, [Capability::SessionAgentHealthcheck]);
    let shown = jarvis_core::approval::view(&approval, now_ms(), &h.store);
    assert!(
        shown.arguments["action"].contains("health check"),
        "{shown:?}"
    );
    assert_eq!(shown.arguments["label"], label);
    h.grant(&approval, &approval.fingerprint).unwrap();
    h.response(id).await
}

#[tokio::test]
async fn an_approved_healthcheck_runs_once_in_the_real_session_agent() {
    let mut h = Harness::start(agent_options(Some(real_agent())));
    h.ready().await;
    let outcome = approved_healthcheck(&mut h, "a1", "ping").await;
    let ToolOutcome::Completed {
        result: ToolResult::AgentReceipt(receipt),
    } = outcome
    else {
        panic!("expected a receipt, got {outcome:?}");
    };
    // The worker learns that it completed, nothing the agent reported.
    assert_eq!(receipt.agent_operation, "session_agent.healthcheck");

    // The same request again is a new request: it needs its own approval.
    let second = approved_healthcheck(&mut h, "a2", "ping").await;
    assert!(
        matches!(second, ToolOutcome::Completed { .. }),
        "{second:?}"
    );

    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing ran in the Core");
    let tasks = store.tasks(10).unwrap();
    assert!(tasks.iter().all(|t| t.status == TaskStatus::Completed));
    for task in &tasks {
        assert_eq!(
            task.result.as_deref(),
            Some(r#"{"agent_operation":"session_agent.healthcheck"}"#)
        );
    }
    let (kinds, report) = agent_events(&store);
    assert_eq!(
        kinds,
        [
            "session_agent_started",
            "session_agent_dispatched",
            "session_agent_completed",
            "session_agent_dispatched",
            "session_agent_completed",
        ]
    );
    let Some(AgentReport::Healthcheck(report)) = report else {
        panic!("expected a health report, got {report:?}");
    };
    assert_eq!(report.label.as_str(), "ping");
    // The executable that was started is recorded by its SHA-256.
    let recorded = store
        .audit_events(None, 1000)
        .unwrap()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::SessionAgentStarted { image_sha256, .. } => image_sha256,
            _ => None,
        })
        .expect("the agent's image hash was recorded");
    let image = std::fs::read(env!("CARGO_BIN_EXE_jarvis-session-agent")).unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(&image).into();
    assert_eq!(recorded, Fingerprint::from_digest(&digest));
    let first_task = tasks.last().unwrap().task_id;
    let task_events: Vec<_> = store
        .audit_events(Some(first_task), 100)
        .unwrap()
        .into_iter()
        .map(|event| event.event.name())
        .collect();
    assert_eq!(
        task_events,
        [
            "request_received",
            "policy_evaluated",
            "approval_requested",
            "approval_granted",
            "session_agent_started",
            "approval_consumed",
            "execution_started",
            "session_agent_dispatched",
            "session_agent_completed",
            "execution_finished",
        ]
    );
}

#[tokio::test]
async fn a_declined_healthcheck_never_reaches_the_agent() {
    let (agent, launches, _) = fake_agent(Fake::Refuse, Duration::from_secs(5), 4);
    let mut h = Harness::start(agent_options(Some(agent)));
    h.ready().await;
    h.send_request("a1", "session_agent.healthcheck", healthcheck("ping"))
        .await;
    let approval = h.pending_approval().await;
    h.deny(&approval, "no").unwrap();
    assert!(matches!(
        h.response("a1").await,
        ToolOutcome::Declined { .. }
    ));
    let (_, store, _) = h.finish().await;
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    assert!(agent_events(&store).0.is_empty());
}

#[tokio::test]
async fn desktop_operations_are_denied_and_never_reach_the_agent() {
    let (agent, launches, _) = fake_agent(Fake::Refuse, Duration::from_secs(5), 4);
    let mut h = Harness::start(agent_options(Some(agent)));
    h.ready().await;
    for (id, tool, args) in [
        ("d1", "desktop.capture_window", json!({"target": 1})),
        ("d2", "desktop.read_clipboard_text", json!({})),
        (
            "d3",
            "desktop.write_clipboard_text",
            json!({"payload_id": jarvis_protocol::PayloadId::new(), "sha256": "ab".repeat(32)}),
        ),
        (
            "d4",
            "desktop.type_text",
            json!({"target": 1, "text": "hi"}),
        ),
    ] {
        let outcome = h.request(id, tool, args).await;
        assert!(matches!(outcome, ToolOutcome::Denied { .. }), "{outcome:?}");
    }
    // Unknown operations and smuggled fields are rejected before policy.
    for (id, tool, args) in [
        ("x1", "desktop.capture_screen", json!({})),
        ("x2", "session_agent.run", json!({"command": "cmd.exe"})),
        (
            "x3",
            "session_agent.healthcheck",
            json!({"label": "ping", "grant": 1}),
        ),
        (
            "x4",
            "desktop.type_text",
            json!({"target": 1, "text": "a\nb"}),
        ),
    ] {
        let outcome = h.request(id, tool, args).await;
        assert!(
            matches!(outcome, ToolOutcome::Rejected { .. }),
            "{outcome:?}"
        );
    }
    let (_, store, _) = h.finish().await;
    assert!(store.pending_approvals().unwrap().is_empty());
    assert_eq!(launches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn without_a_session_agent_the_approval_expires_unused() {
    let mut h = Harness::start(agent_options(None));
    h.ready().await;
    h.send_request("a1", "session_agent.healthcheck", healthcheck("ping"))
        .await;
    let approval = h.pending_approval().await;
    h.grant(&approval, &approval.fingerprint).unwrap();
    assert!(matches!(
        h.response("a1").await,
        ToolOutcome::Expired { .. }
    ));
    assert_eq!(h.approval_status(&approval), ApprovalStatus::Expired);
    let (_, store, _) = h.finish().await;
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Expired);
    assert!(
        !Harness::task_kinds(&store).contains(&"approval_consumed"),
        "a refusal before consumption leaves the approval unused"
    );
}

/// After a `perform` was sent, no valid answer means: the agent is stopped,
/// the task fails with `internal`, and the operation is never sent again.
#[tokio::test]
async fn an_ambiguous_agent_outcome_fails_closed() {
    for behaviour in [
        Fake::ExitAfterPerform,
        Fake::WrongGrant,
        Fake::Hang,
        Fake::Garbage,
    ] {
        let (agent, launches, performs) = fake_agent(behaviour, Duration::from_millis(500), 4);
        let mut h = Harness::start(agent_options(Some(agent)));
        h.ready().await;
        let outcome = approved_healthcheck(&mut h, "a1", "ping").await;
        let ToolOutcome::Failed { error } = outcome else {
            panic!("{behaviour:?}: expected a failure, got {outcome:?}");
        };
        assert_eq!(error.code, ErrorCode::Internal, "{behaviour:?}");
        // The next operation starts a fresh agent; nothing is resent.
        let next = approved_healthcheck(&mut h, "a2", "ping").await;
        assert!(matches!(next, ToolOutcome::Failed { .. }), "{behaviour:?}");
        let (_, store, _) = h.finish().await;
        assert_eq!(launches.load(Ordering::SeqCst), 2, "{behaviour:?}");
        assert_eq!(
            performs.load(Ordering::SeqCst),
            2,
            "{behaviour:?}: one send each"
        );
        let (kinds, _) = agent_events(&store);
        assert_eq!(
            kinds,
            [
                "session_agent_started",
                "session_agent_dispatched",
                "session_agent_stopped",
                "session_agent_outcome_unknown",
                "session_agent_started",
                "session_agent_dispatched",
                "session_agent_stopped",
                "session_agent_outcome_unknown",
            ],
            "{behaviour:?}"
        );
        for task in store.tasks(10).unwrap() {
            assert_eq!(task.status, TaskStatus::Failed);
            assert_eq!(task.error.unwrap().code, ErrorCode::Internal);
        }
    }
}

#[tokio::test]
async fn an_agent_refusal_is_recorded_as_not_performed() {
    let (agent, _, performs) = fake_agent(Fake::Refuse, Duration::from_secs(5), 4);
    let mut h = Harness::start(agent_options(Some(agent)));
    h.ready().await;
    let outcome = approved_healthcheck(&mut h, "a1", "ping").await;
    let ToolOutcome::Failed { error } = outcome else {
        panic!("expected a failure, got {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::ToolFailed);
    let (_, store, _) = h.finish().await;
    assert_eq!(performs.load(Ordering::SeqCst), 1);
    assert_eq!(
        agent_events(&store).0,
        [
            "session_agent_started",
            "session_agent_dispatched",
            "session_agent_refused",
        ]
    );
}

#[tokio::test]
async fn an_agent_that_never_starts_leaves_the_approval_unused() {
    let (agent, launches, performs) = fake_agent(Fake::Silent, Duration::from_millis(300), 1);
    let mut h = Harness::start(agent_options(Some(agent)));
    h.ready().await;
    // The agent is started before the approval is used: a failed start
    // expires the approval, unconsumed.
    for id in ["a1", "a2"] {
        h.send_request(id, "session_agent.healthcheck", healthcheck("ping"))
            .await;
        let approval = h.pending_approval().await;
        h.grant(&approval, &approval.fingerprint).unwrap();
        assert!(matches!(h.response(id).await, ToolOutcome::Expired { .. }));
        assert_eq!(h.approval_status(&approval), ApprovalStatus::Expired);
    }
    let (_, store, _) = h.finish().await;
    // The second attempt found the start budget spent and started nothing.
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    assert_eq!(performs.load(Ordering::SeqCst), 0);
    assert_eq!(agent_events(&store).0, ["session_agent_stopped"]);
    assert!(!Harness::task_kinds(&store).contains(&"approval_consumed"));
}

/// An agent that exits while idle is noticed before the next operation is
/// sent: a new one is started, and nothing is recorded as unknown.
#[tokio::test]
async fn an_agent_that_exits_while_idle_is_replaced_before_anything_is_sent() {
    let (agent, launches, performs) = fake_agent(Fake::OnceThenExit, Duration::from_secs(5), 4);
    let mut h = Harness::start(agent_options(Some(agent)));
    h.ready().await;
    for id in ["a1", "a2"] {
        let outcome = approved_healthcheck(&mut h, id, "ping").await;
        assert!(
            matches!(outcome, ToolOutcome::Completed { .. }),
            "{outcome:?}"
        );
    }
    let (_, store, _) = h.finish().await;
    assert_eq!(launches.load(Ordering::SeqCst), 2);
    assert_eq!(performs.load(Ordering::SeqCst), 2);
    assert_eq!(
        agent_events(&store).0,
        [
            "session_agent_started",
            "session_agent_dispatched",
            "session_agent_completed",
            "session_agent_stopped",
            "session_agent_started",
            "session_agent_dispatched",
            "session_agent_completed",
        ]
    );
}

/// A job holding an operation whose outcome is unknown is never resumed:
/// the session that dispatched it ends, and the job is quarantined.
#[tokio::test]
async fn a_job_with_an_unknown_agent_outcome_is_not_resumed() {
    let (agent, _, _) = fake_agent(Fake::ExitAfterPerform, Duration::from_millis(500), 4);
    let mut h = Harness::start(agent_options(Some(agent)));
    h.ready().await;
    let job = h.job_id();
    approved_healthcheck(&mut h, "a1", "ping").await;
    // The worker goes away mid-job, as on a crash.
    let (_, store, _) = h.finish().await;
    let settled = store.job(job).unwrap().unwrap();
    assert_eq!(settled.status, JobStatus::Interrupted);
    assert!(Harness::kinds(&store).contains(&"job_quarantined"));
}

#[tokio::test]
async fn shutdown_while_the_agent_works_is_an_unknown_outcome() {
    let (agent, _, performs) = fake_agent(Fake::Hang, Duration::from_secs(30), 4);
    let mut h = Harness::start(agent_options(Some(agent)));
    h.ready().await;
    h.send_request("a1", "session_agent.healthcheck", healthcheck("ping"))
        .await;
    let approval = h.pending_approval().await;
    h.grant(&approval, &approval.fingerprint).unwrap();
    for _ in 0..500 {
        if performs.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.shutdown.cancel();
    let outcome = h.response("a1").await;
    let ToolOutcome::Failed { error } = outcome else {
        panic!("expected a failure, got {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::Internal);
    let store = h.store.clone();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.session).await;
    assert!(
        agent_events(&store)
            .0
            .contains(&"session_agent_outcome_unknown")
    );
}

/// The real agent, killed while idle, is replaced before the next operation
/// is sent: its end of the channel shows end of input, and nothing is
/// recorded as unknown.
#[tokio::test]
async fn a_real_agent_killed_while_idle_is_replaced() {
    let mut h = Harness::start(agent_options(Some(real_agent())));
    h.ready().await;
    let first = approved_healthcheck(&mut h, "a1", "ping").await;
    assert!(matches!(first, ToolOutcome::Completed { .. }), "{first:?}");
    let pid = h
        .store
        .audit_events(None, 1000)
        .unwrap()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::SessionAgentStarted { pid, .. } => pid,
            _ => None,
        })
        .expect("the agent's pid was recorded");
    let killed = if cfg!(windows) {
        std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output()
    } else {
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
    };
    assert!(killed.unwrap().status.success());
    for _ in 0..500 {
        if !jarvis_sandbox::process_exists(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = approved_healthcheck(&mut h, "a2", "ping").await;
    assert!(
        matches!(second, ToolOutcome::Completed { .. }),
        "{second:?}"
    );
    let (_, store, _) = h.finish().await;
    let (kinds, _) = agent_events(&store);
    assert_eq!(
        kinds,
        [
            "session_agent_started",
            "session_agent_dispatched",
            "session_agent_completed",
            "session_agent_stopped",
            "session_agent_started",
            "session_agent_dispatched",
            "session_agent_completed",
        ]
    );
}
