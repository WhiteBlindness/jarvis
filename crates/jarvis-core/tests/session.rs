//! Session behaviour over in-memory pipes: the worker side of each test
//! writes raw frames, exactly as an untrusted worker could. Decisions on
//! approvals are made through the store and the hub, the same calls the RPC
//! server makes for a local client.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jarvis_core::config::Limits;
use jarvis_core::gateway::Gateway;
use jarvis_core::hub::Hub;
use jarvis_core::policy::Policy;
use jarvis_core::session::{SessionContext, SessionEnd, SessionError, SessionReport, run_session};
use jarvis_core::store::{ApprovalError, ApprovalRecord, Store, now_ms};
use jarvis_protocol::{
    ApprovalStatus, AuditEventKind, Capability, CoreMessage, ErrorCode, Fingerprint, Goal, JobId,
    JobStatus, PolicyDecision, Summary, TaskStatus, ToolCall, ToolOutcome, ToolResult,
    decode_core_message,
};
use jarvis_tools::{FixtureRoot, ToolExecutor, ToolFuture, Toolbox, WorkspaceRoot};
use serde_json::{Value, json};
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
        self.send(json!({"protocol": 2, "type": "hello", "worker": "test", "worker_version": "1"}))
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

    fn job_id(&self) -> JobId {
        self.job.expect("no job")
    }

    async fn send_request(&mut self, id: &str, tool: &str, args: Value) {
        let job_id = self.job_id();
        self.send(json!({
            "protocol": 2, "type": "tool_request", "request_id": id, "job_id": job_id,
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
            "protocol": 2, "type": "job_result", "job_id": job_id,
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
        JobStatus::Interrupted,
        "the worker left in the middle of the second job"
    );
}

#[tokio::test]
async fn requests_and_results_must_belong_to_the_current_job() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    let stranger = JobId::new();
    // No job yet.
    h.send(
        json!({"protocol": 2, "type": "tool_request", "request_id": "r1",
        "job_id": stranger, "tool": "system.info", "args": {}}),
    )
    .await;
    h.expect_error(ErrorCode::UnexpectedMessage, false).await;
    h.job("test").await;
    h.send(
        json!({"protocol": 2, "type": "tool_request", "request_id": "r2",
        "job_id": stranger, "tool": "system.info", "args": {}}),
    )
    .await;
    h.expect_error(ErrorCode::UnexpectedMessage, false).await;
    h.send(
        json!({"protocol": 2, "type": "job_result", "job_id": stranger,
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
        br#"{"protocol":2,"type":"shell","command":"id"}"#,
        br#"{"protocol":2,"type":"tool_request","request_id":"r1","tool":"system.info","args":{}}"#,
        br#"{"protocol":2,"type":"job","job_id":"01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b","goal":"x"}"#,
        br#"{"protocol":2,"type":"job_result","job_id":"01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b","outcome":"approved","summary":""}"#,
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
    for version in [1, 3] {
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
        "protocol": 3, "type": "tool_request", "request_id": "r1", "job_id": job,
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
        JobStatus::Interrupted
    );
}

#[tokio::test]
async fn request_before_hello_is_fatal() {
    let mut h = Harness::start(Options::default());
    h.send(json!({
        "protocol": 2, "type": "tool_request", "request_id": "r1", "job_id": JobId::new(),
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
    h.send(json!({"protocol": 2, "type": "hello", "worker": "again", "worker_version": "1"}))
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
        "protocol": 2, "type": "tool_request", "request_id": "r1", "job_id": job,
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
        r#"{{"protocol":2,"type":"tool_request","request_id":"r1","job_id":"{}","tool":"system.info","args":{{"pad":"{}"}}}}"#,
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

    let mut frame = json!({"protocol": 2, "type": "tool_request", "request_id": "r2",
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
        JobStatus::Interrupted
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
    let recovered = store.recover().unwrap();
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
    store.recover().unwrap();
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
