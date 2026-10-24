//! Durable jobs over in-memory pipes: a job whose worker went away is handed
//! to a later session, which must replay what already completed, ask again
//! for what did not, and never repeat a step whose outcome is unknown.
//!
//! One `Env` is one database and one workspace; each `Env::session` is one
//! worker session on it, like successive workers under the supervisor.

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
    ApprovalStatus, AuditEventKind, Capability, ClipboardText, CoreMessage, ErrorCode, Goal, JobId,
    JobStatus, PolicyDecision, TaskId, TaskStatus, ToolCall, ToolOutcome, ToolResult,
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
        }
    }
}

struct Env {
    dir: tempfile::TempDir,
    store: Store,
    calls: Arc<AtomicUsize>,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("fixtures")).unwrap();
        std::fs::create_dir_all(dir.path().join("workspace")).unwrap();
        std::fs::write(dir.path().join("fixtures").join("welcome.txt"), "hello\n").unwrap();
        std::fs::write(dir.path().join("fixtures").join("other.txt"), "other\n").unwrap();
        let store = Store::open(&dir.path().join("jarvis.db")).unwrap();
        Self {
            dir,
            store,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn submit(&self, goal: &str) -> JobId {
        let goal = Goal::try_from(goal.to_owned()).unwrap();
        self.store.submit_job(&goal, "test client").unwrap().job_id
    }

    fn workspace_file(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.path().join("workspace").join(name)).ok()
    }

    fn executions(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn count(&self, kind: &str) -> usize {
        self.store
            .audit_events(None, 10_000)
            .unwrap()
            .into_iter()
            .filter(|event| event.event.name() == kind)
            .count()
    }

    fn job(&self, job: JobId) -> (JobStatus, String) {
        let record = self.store.job(job).unwrap().unwrap();
        let summary = record
            .summary
            .map_or_else(String::new, |s| s.as_str().into());
        (record.status, summary)
    }

    /// Start a session on this database and complete the handshake.
    async fn session(&self, options: Options) -> Harness {
        let probe = Probe {
            inner: Toolbox::new(
                "test",
                FixtureRoot::open(&self.dir.path().join("fixtures"), 1024).unwrap(),
                WorkspaceRoot::open(&self.dir.path().join("workspace"), 1024).unwrap(),
            ),
            calls: Arc::clone(&self.calls),
            hang: options.hang,
        };
        let policy: BTreeMap<_, _> = options.policy.into_iter().collect();
        let hub = Arc::new(Hub::default());
        let ctx = SessionContext {
            store: self.store.clone(),
            policy: Policy::new(policy),
            gateway: Gateway::new(
                Arc::new(probe),
                options.limits.tool_timeout,
                options.limits.max_result_bytes(),
            ),
            limits: options.limits,
            handshake_timeout: Duration::from_secs(10),
            approval_ttl: Duration::from_secs(60),
            job_timeout: Duration::from_secs(120),
            core_version: "test",
            hub: Arc::clone(&hub),
            session_agent: None,
        };
        let (to_core, core_reader) = tokio::io::duplex(1 << 20);
        let (core_writer, from_core) = tokio::io::duplex(1 << 20);
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let session =
            tokio::spawn(async move { run_session(&ctx, core_reader, core_writer, &token).await });
        let mut harness = Harness {
            store: self.store.clone(),
            hub,
            shutdown,
            to_core: Some(to_core),
            from_core: BufReader::new(from_core).lines(),
            session,
            job: None,
        };
        harness
            .send(json!({"protocol": 3, "type": "hello", "worker": "test", "worker_version": "1"}))
            .await;
        assert!(matches!(harness.recv().await, CoreMessage::Welcome(_)));
        harness
    }
}

struct Harness {
    store: Store,
    hub: Arc<Hub>,
    shutdown: CancellationToken,
    to_core: Option<DuplexStream>,
    from_core: Lines<BufReader<DuplexStream>>,
    session: JoinHandle<Result<SessionReport, SessionError>>,
    job: Option<JobId>,
}

impl Harness {
    async fn send(&mut self, value: Value) {
        let pipe = self.to_core.as_mut().unwrap();
        pipe.write_all(&serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();
        pipe.write_all(b"\n").await.unwrap();
    }

    async fn recv(&mut self) -> CoreMessage {
        let line = tokio::time::timeout(Duration::from_secs(10), self.from_core.next_line())
            .await
            .expect("no reply from the Core")
            .unwrap()
            .expect("the Core closed the stream");
        decode_core_message(line.as_bytes()).expect("the Core sent an invalid frame")
    }

    /// The Core hands over the job it queued.
    async fn takes(&mut self, job: JobId) {
        match self.recv().await {
            CoreMessage::Job(assigned) => assert_eq!(assigned.job_id, job),
            other => panic!("expected a job, got {other:?}"),
        }
        self.job = Some(job);
    }

    async fn send_request(&mut self, id: &str, tool: &str, args: Value) {
        let job_id = self.job.expect("no job");
        self.send(json!({
            "protocol": 3, "type": "tool_request", "request_id": id, "job_id": job_id,
            "tool": tool, "args": args
        }))
        .await;
    }

    async fn response(&mut self, id: &str) -> (TaskId, ToolOutcome) {
        match self.recv().await {
            CoreMessage::ToolResponse(response) => {
                assert_eq!(response.request_id.as_str(), id);
                (response.task_id, response.outcome)
            }
            other => panic!("expected a tool_response, got {other:?}"),
        }
    }

    async fn request(&mut self, id: &str, tool: &str, args: Value) -> (TaskId, ToolOutcome) {
        self.send_request(id, tool, args).await;
        self.response(id).await
    }

    async fn expect_fatal(&mut self, code: ErrorCode) {
        match self.recv().await {
            CoreMessage::Error(error) => {
                assert_eq!(error.error.code, code, "{}", error.error.message);
                assert!(error.fatal);
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    async fn expect_error(&mut self, code: ErrorCode) {
        match self.recv().await {
            CoreMessage::Error(error) => assert_eq!(error.error.code, code),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    async fn pending_approval(&self) -> ApprovalRecord {
        for _ in 0..1000 {
            if let Some(record) = self.store.pending_approvals().unwrap().pop() {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no approval was requested");
    }

    /// What the RPC server does for `approve`.
    fn approve(&self, record: &ApprovalRecord) {
        self.store
            .grant_approval(
                record.approval_id,
                &record.fingerprint,
                "test client",
                now_ms(),
            )
            .unwrap();
        self.hub.approvals.notify(record.approval_id);
        self.hub.changed();
    }

    /// The worker goes away; wait for the session to end.
    async fn worker_exits(mut self) -> SessionReport {
        self.to_core.take();
        self.ended().await
    }

    async fn ended(self) -> SessionReport {
        tokio::time::timeout(Duration::from_secs(10), self.session)
            .await
            .expect("session did not end")
            .unwrap()
            .unwrap()
    }
}

fn write_args(path: &str, content: &str) -> Value {
    json!({"path": path, "content": content})
}

fn completed(outcome: ToolOutcome) -> ToolResult {
    match outcome {
        ToolOutcome::Completed { result } => result,
        other => panic!("expected a completed call, got {other:?}"),
    }
}

/// Attempt 1 of a job that completes `system.info` and then loses its worker.
async fn first_attempt_completes_system_info(env: &Env) -> (JobId, TaskId, ToolResult) {
    let job = env.submit("system info");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    let (task, outcome) = h.request("r1", "system.info", json!({})).await;
    let result = completed(outcome);
    let report = h.worker_exits().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
    assert_eq!(env.job(job).0, JobStatus::Queued, "the job was requeued");
    (job, task, result)
}

// --- replay -------------------------------------------------------------------------------------

#[tokio::test]
async fn a_completed_step_is_replayed_and_the_next_one_runs_normally() {
    let env = Env::new();
    let (job, task, result) = first_attempt_completes_system_info(&env).await;
    assert_eq!(env.executions(), 1);

    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    let (replayed_task, outcome) = h.request("r1", "system.info", json!({})).await;
    assert_eq!(replayed_task, task, "the original task is named");
    assert_eq!(completed(outcome), result, "the stored result is returned");
    assert_eq!(env.executions(), 1, "nothing ran again");
    assert_eq!(env.store.tasks(10).unwrap().len(), 1, "no new task");
    assert_eq!(env.count("execution_started"), 1);
    assert_eq!(env.count("step_replayed"), 1);

    // The position after the replayed one is an ordinary new request.
    let (next, outcome) = h
        .request(
            "r2",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"}),
        )
        .await;
    assert_ne!(next, task);
    assert!(matches!(completed(outcome), ToolResult::Fixture(_)));
    assert_eq!(env.executions(), 2);

    let replayed = env
        .store
        .audit_events(Some(task), 100)
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.event {
            AuditEventKind::StepReplayed {
                job_id,
                seq,
                task_id,
            } => Some((job_id, seq, task_id)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(replayed, [(job, 1, task)]);

    let report = h.worker_exits().await;
    assert_eq!(report.requests, 2, "a replay counts as a request");
    assert_eq!(env.job(job).0, JobStatus::Queued);
}

#[tokio::test]
async fn a_replayed_step_counts_against_the_session_request_limit() {
    let env = Env::new();
    let (job, _, _) = first_attempt_completes_system_info(&env).await;
    let limits = Limits {
        max_requests_per_session: 1,
        tool_timeout: Duration::from_secs(10),
        ..Limits::default()
    };
    let mut h = env
        .session(Options {
            limits,
            ..Options::default()
        })
        .await;
    h.takes(job).await;
    h.request("r1", "system.info", json!({})).await;
    h.send_request("r2", "system.info", json!({})).await;
    h.expect_fatal(ErrorCode::LimitExceeded).await;
    let report = h.ended().await;
    assert!(matches!(report.end, SessionEnd::Terminated(_)));
    assert_eq!(env.executions(), 1);
}

#[tokio::test]
async fn a_replayed_request_id_cannot_be_reused_and_a_refusal_takes_no_position() {
    let env = Env::new();
    let job = env.submit("two steps");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    let (first, _) = h.request("r1", "system.info", json!({})).await;
    let fixture = json!({"path": "welcome.txt"});
    let (second, _) = h
        .request("r2", "filesystem.read_fixture", fixture.clone())
        .await;
    h.worker_exits().await;

    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    assert_eq!(h.request("r1", "system.info", json!({})).await.0, first);
    h.send_request("r1", "system.info", json!({})).await;
    h.expect_error(ErrorCode::DuplicateRequest).await;
    // The refused frame did not use up position 2.
    let (replayed, _) = h.request("r2", "filesystem.read_fixture", fixture).await;
    assert_eq!(replayed, second);
    assert_eq!(env.executions(), 2);
    h.worker_exits().await;
}

/// A replayed request has no task, so the store alone cannot tell that its
/// request_id was used; the id must not name a second position either.
#[tokio::test]
async fn a_replayed_request_id_cannot_name_a_new_task() {
    let env = Env::new();
    let (job, first, _) = first_attempt_completes_system_info(&env).await;
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    assert_eq!(h.request("r1", "system.info", json!({})).await.0, first);
    // Position 2 is open, and `r1` is taken.
    h.send_request(
        "r1",
        "filesystem.read_fixture",
        json!({"path": "welcome.txt"}),
    )
    .await;
    h.expect_error(ErrorCode::DuplicateRequest).await;
    assert_eq!(
        env.store.tasks(10).unwrap().len(),
        1,
        "no task for the reused id"
    );
    assert_eq!(env.executions(), 1);
    // The refusal took no position: the next request is position 2.
    let (task, outcome) = h
        .request(
            "r2",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"}),
        )
        .await;
    assert!(matches!(completed(outcome), ToolResult::Fixture(_)));
    assert_ne!(task, first);
    assert_eq!(env.store.tasks(10).unwrap().len(), 2);
    h.worker_exits().await;
}

/// A request_id already used for a task of this session is refused even where
/// the position it arrives at has a completed step to compare with.
#[tokio::test]
async fn a_reused_request_id_is_refused_before_the_replay_check() {
    let env = Env::new();
    let job = env.submit("read a file, then system info");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    // Step 1 fails (no such fixture), step 2 completes.
    let (_, outcome) = h
        .request(
            "r1",
            "filesystem.read_fixture",
            json!({"path": "missing.txt"}),
        )
        .await;
    assert!(matches!(outcome, ToolOutcome::Failed { .. }));
    h.request("r2", "system.info", json!({})).await;
    h.worker_exits().await;

    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    // Position 1 has no completed step: a new task is created for `r1`.
    let (_, outcome) = h
        .request(
            "r1",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"}),
        )
        .await;
    assert!(matches!(completed(outcome), ToolResult::Fixture(_)));
    // Position 2 completed before. `r1` again is a protocol error, not a
    // reason to fail the job.
    h.send_request(
        "r1",
        "filesystem.read_fixture",
        json!({"path": "other.txt"}),
    )
    .await;
    h.expect_error(ErrorCode::DuplicateRequest).await;
    let (_, outcome) = h.request("r2", "system.info", json!({})).await;
    assert!(matches!(completed(outcome), ToolResult::SystemInfo(_)));
    assert_eq!(env.count("step_replayed"), 1);
    h.worker_exits().await;
}

#[tokio::test]
async fn a_request_that_differs_from_the_completed_step_fails_the_job() {
    let cases = [
        (
            "another tool",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"}),
        ),
        ("an unknown tool", "shell.exec", json!({"command": "id"})),
        ("invalid arguments", "system.info", json!({"verbose": true})),
    ];
    for (name, tool, args) in cases {
        let env = Env::new();
        let (job, _, _) = first_attempt_completes_system_info(&env).await;
        let mut h = env.session(Options::default()).await;
        h.takes(job).await;
        h.send_request("r1", tool, args).await;
        h.expect_fatal(ErrorCode::UnexpectedMessage).await;
        let report = h.ended().await;
        assert!(matches!(report.end, SessionEnd::Terminated(_)), "{name}");
        let (status, summary) = env.job(job);
        assert_eq!(status, JobStatus::Failed, "{name}");
        assert!(summary.contains("step 1"), "{name}: {summary}");
        assert_eq!(env.executions(), 1, "{name}: nothing ran");
        assert_eq!(env.store.tasks(10).unwrap().len(), 1, "{name}: no task");
        assert_eq!(env.count("step_replayed"), 0, "{name}");
    }
}

#[tokio::test]
async fn different_arguments_at_a_completed_step_fail_the_job() {
    let env = Env::new();
    let job = env.submit("read");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.request(
        "r1",
        "filesystem.read_fixture",
        json!({"path": "welcome.txt"}),
    )
    .await;
    h.worker_exits().await;

    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.send_request(
        "r1",
        "filesystem.read_fixture",
        json!({"path": "other.txt"}),
    )
    .await;
    h.expect_fatal(ErrorCode::UnexpectedMessage).await;
    h.ended().await;
    assert_eq!(env.job(job).0, JobStatus::Failed);
    assert_eq!(env.executions(), 1);
}

#[tokio::test]
async fn a_step_that_policy_now_denies_is_not_replayed() {
    let env = Env::new();
    let (job, _, _) = first_attempt_completes_system_info(&env).await;
    let mut h = env
        .session(Options {
            policy: vec![(Capability::SystemInfo, PolicyDecision::Deny)],
            ..Options::default()
        })
        .await;
    h.takes(job).await;
    h.send_request("r1", "system.info", json!({})).await;
    h.expect_fatal(ErrorCode::UnexpectedMessage).await;
    h.ended().await;
    let (status, summary) = env.job(job);
    assert_eq!(status, JobStatus::Failed);
    assert!(summary.contains("step 1"), "{summary}");
    assert_eq!(env.executions(), 1);
    assert_eq!(env.count("step_replayed"), 0);
}

#[tokio::test]
async fn a_stored_result_that_does_not_decode_is_not_replayed() {
    // A row as a damaged database could hold it: completed, with a result
    // that is not what `system.info` returns.
    let env = Env::new();
    let session = jarvis_protocol::SessionId::new();
    let goal = Goal::try_from("system".to_owned()).unwrap();
    let job = env.store.submit_job(&goal, "test client").unwrap().job_id;
    env.store.claim_next_job(session).unwrap().unwrap();
    let task = jarvis_core::store::NewTask {
        task_id: TaskId::new(),
        session_id: session,
        job_id: Some(job),
        step: Some(jarvis_core::store::JobStep { attempt: 1, seq: 1 }),
        request_id: jarvis_protocol::RequestId::try_from("r1".to_owned()).unwrap(),
        tool: jarvis_protocol::ToolName::try_from("system.info".to_owned()).unwrap(),
        args: json!({}),
    };
    env.store.create_task(&task).unwrap();
    let started = AuditEventKind::ExecutionStarted {
        tool: "system.info".into(),
    };
    env.store
        .transition(
            task.task_id,
            &[TaskStatus::Received],
            &jarvis_core::store::TaskChange::to(TaskStatus::Executing),
            &[started],
        )
        .unwrap();
    let change = jarvis_core::store::TaskChange {
        result: Some(r#"{"unexpected":"shape"}"#.to_owned()),
        ..jarvis_core::store::TaskChange::to(TaskStatus::Completed)
    };
    env.store
        .transition(task.task_id, &[TaskStatus::Executing], &change, &[])
        .unwrap();
    env.store
        .requeue_or_close(job, 3, Some(session), "test")
        .unwrap();

    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.send_request("r1", "system.info", json!({})).await;
    h.expect_fatal(ErrorCode::UnexpectedMessage).await;
    h.ended().await;
    assert_eq!(env.job(job).0, JobStatus::Failed);
    assert_eq!(env.executions(), 0);
}

// --- approvals ----------------------------------------------------------------------------------

#[tokio::test]
async fn an_approval_from_an_earlier_attempt_cannot_be_used_in_the_next() {
    let env = Env::new();
    let job = env.submit("system info, then write");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.request("r1", "system.info", json!({})).await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let old = h.pending_approval().await;
    // The worker goes away while the write waits for a person. A grant sent
    // while the session still waits could be used by that session, which is
    // allowed, so the grant is only attempted once the session has ended.
    h.worker_exits().await;
    assert_eq!(env.job(job).0, JobStatus::Queued);
    assert_eq!(env.workspace_file("a.txt"), None);
    let status = env.store.approval(old.approval_id).unwrap().unwrap().status;
    assert_eq!(status, ApprovalStatus::Expired);
    assert!(
        matches!(
            env.store
                .grant_approval(old.approval_id, &old.fingerprint, "test client", now_ms()),
            Err(ApprovalError::NotPending(ApprovalStatus::Expired))
        ),
        "an approval from an ended session cannot be granted"
    );

    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.request("r1", "system.info", json!({})).await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let new = h.pending_approval().await;
    assert_ne!(new.approval_id, old.approval_id);
    assert_ne!(new.task_id, old.task_id, "a new task at the open position");
    assert_ne!(new.fingerprint, old.fingerprint);
    assert!(matches!(
        env.store
            .consume_approval(old.approval_id, &old.fingerprint, now_ms(), &[]),
        Err(ApprovalError::NotGranted(ApprovalStatus::Expired))
    ));
    assert_eq!(env.workspace_file("a.txt"), None, "still nothing written");

    h.approve(&new);
    let (_, outcome) = h.response("w1").await;
    assert!(matches!(completed(outcome), ToolResult::Written(_)));
    assert_eq!(env.workspace_file("a.txt").as_deref(), Some("x"));
    assert_eq!(env.executions(), 2, "system.info once, the write once");
    assert_eq!(env.count("execution_started"), 2);
}

#[tokio::test]
async fn a_completed_write_is_replayed_without_a_new_approval() {
    let env = Env::new();
    let job = env.submit("write a.txt: x");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.send_request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    let approval = h.pending_approval().await;
    h.approve(&approval);
    let (task, outcome) = h.response("w1").await;
    let written = completed(outcome);
    // The worker dies before reporting the job's result.
    h.worker_exits().await;
    assert_eq!(env.job(job).0, JobStatus::Queued);

    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    let (replayed, outcome) = h
        .request("w1", "workspace.write_file", write_args("a.txt", "x"))
        .await;
    assert_eq!(replayed, task);
    assert_eq!(completed(outcome), written);
    assert!(env.store.pending_approvals().unwrap().is_empty());
    assert_eq!(env.count("approval_requested"), 1, "no new approval");
    assert_eq!(env.executions(), 1, "the file was written exactly once");
    assert_eq!(env.workspace_file("a.txt").as_deref(), Some("x"));
    h.worker_exits().await;
}

#[tokio::test]
async fn a_requeued_clipboard_job_resumes_with_its_text() {
    let env = Env::new();
    let text = "resume me: \"quoted\" text";
    let submitted = env
        .store
        .submit_clipboard_job(&ClipboardText::try_from(text.to_owned()).unwrap(), "client")
        .unwrap();
    let job = submitted.job_id;
    let rest = submitted
        .goal
        .as_str()
        .strip_prefix("copy payload:")
        .unwrap();
    let (payload_id, sha256) = rest.split_once(':').unwrap();
    let args = json!({"payload_id": payload_id, "sha256": sha256});
    let payload = |env: &Env| env.store.payload(payload_id.parse().unwrap()).unwrap();

    // The first worker goes away before asking for anything.
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.worker_exits().await;
    assert_eq!(env.job(job).0, JobStatus::Queued);
    assert_eq!(
        payload(&env).unwrap().text,
        text,
        "kept for the next attempt"
    );

    // The next one is handed the same job, asks, and the person is shown
    // the text.
    let mut options = Options::default();
    options.policy.push((
        Capability::DesktopClipboardWrite,
        PolicyDecision::RequireConfirmation,
    ));
    let mut h = env.session(options).await;
    h.takes(job).await;
    h.send_request("c1", "desktop.write_clipboard_text", args)
        .await;
    let approval = h.pending_approval().await;
    let shown = jarvis_core::approval::view(&approval, now_ms(), &env.store);
    assert_eq!(
        shown.arguments["text"],
        jarvis_core::approval::display_safe(text, usize::MAX)
    );

    // It is lost again while the person decides: the approval lapses, the
    // job is requeued and still has its text.
    h.worker_exits().await;
    assert_eq!(env.job(job).0, JobStatus::Queued);
    assert_eq!(payload(&env).unwrap().text, text);
    assert_eq!(env.executions(), 0);

    // Once the job ends, so does the text.
    env.store
        .claim_next_job(jarvis_protocol::SessionId::new())
        .unwrap()
        .unwrap();
    env.store
        .finish_job(job, JobStatus::Failed, None, None)
        .unwrap();
    assert!(payload(&env).is_none());
}

// --- how a session ends -------------------------------------------------------------------------

#[tokio::test]
async fn a_job_whose_attempts_are_spent_ends_interrupted() {
    let env = Env::new();
    let job = env.submit("system info");
    let options = || Options {
        limits: Limits {
            max_job_attempts: 2,
            tool_timeout: Duration::from_secs(10),
            ..Limits::default()
        },
        ..Options::default()
    };
    let mut h = env.session(options()).await;
    h.takes(job).await;
    h.request("r1", "system.info", json!({})).await;
    h.worker_exits().await;
    assert_eq!(env.job(job).0, JobStatus::Queued);

    let mut h = env.session(options()).await;
    h.takes(job).await;
    h.request("r1", "system.info", json!({})).await;
    let report = h.worker_exits().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
    let (status, summary) = env.job(job);
    assert_eq!(status, JobStatus::Interrupted);
    assert!(summary.contains("attempt limit"), "{summary}");
    assert_eq!(env.executions(), 1, "the step ran in attempt 1 only");
    assert_eq!(env.count("job_requeued"), 1);
}

#[tokio::test]
async fn a_requeued_job_wakes_whoever_waits_for_work() {
    let env = Env::new();
    let job = env.submit("system info");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    let hub = Arc::clone(&h.hub);
    h.worker_exits().await;
    assert_eq!(env.job(job).0, JobStatus::Queued);
    let woken = tokio::time::timeout(Duration::from_millis(500), hub.jobs.notified()).await;
    assert!(woken.is_ok(), "an idle session must learn about the job");
}

#[tokio::test]
async fn a_worker_whose_stream_fails_leaves_its_job_in_the_queue() {
    let env = Env::new();
    let job = env.submit("system info");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    // The worker stops reading: the Core's reply cannot be delivered.
    h.from_core = BufReader::new(tokio::io::duplex(1).1).lines();
    h.send_request("r1", "system.info", json!({})).await;
    let report = h.ended().await;
    assert_eq!(report.end, SessionEnd::WorkerGone);
    assert_eq!(env.job(job).0, JobStatus::Queued);
    assert_eq!(env.count("job_requeued"), 1);
}

#[tokio::test]
async fn a_protocol_violation_fails_the_job_instead_of_retrying_it() {
    let env = Env::new();
    let job = env.submit("system info");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.send(json!({"protocol": 99, "type": "hello", "worker": "x", "worker_version": "1"}))
        .await;
    h.expect_fatal(ErrorCode::UnsupportedProtocolVersion).await;
    let report = h.ended().await;
    assert!(matches!(report.end, SessionEnd::Terminated(_)));
    assert_eq!(env.job(job).0, JobStatus::Failed);
    assert_eq!(env.count("job_requeued"), 0);
}

#[tokio::test]
async fn shutdown_puts_an_idle_job_back_in_the_queue() {
    let env = Env::new();
    let job = env.submit("system info");
    let mut h = env.session(Options::default()).await;
    h.takes(job).await;
    h.request("r1", "system.info", json!({})).await;
    h.shutdown.cancel();
    let report = h.ended().await;
    assert_eq!(report.end, SessionEnd::Shutdown);
    assert_eq!(env.job(job).0, JobStatus::Queued);
}

#[tokio::test]
async fn a_tool_cancelled_by_shutdown_quarantines_its_job() {
    let env = Env::new();
    let job = env.submit("system info");
    let mut h = env
        .session(Options {
            hang: true,
            ..Options::default()
        })
        .await;
    h.takes(job).await;
    h.send_request("r1", "system.info", json!({})).await;
    for _ in 0..1000 {
        if env.executions() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(env.executions(), 1);
    h.shutdown.cancel();
    h.expect_response_then_end().await;
    let (status, summary) = env.job(job);
    assert_eq!(status, JobStatus::Interrupted);
    assert!(summary.contains("not resumed"), "{summary}");
    let task = env.store.tasks(1).unwrap().remove(0);
    assert_eq!(task.status, TaskStatus::Cancelled);
    assert!(
        env.store
            .audit_events(None, 1000)
            .unwrap()
            .iter()
            .any(|event| event.event
                == AuditEventKind::JobQuarantined {
                    job_id: job,
                    task_id: task.task_id
                })
    );
    assert_eq!(env.count("job_requeued"), 0);
}

impl Harness {
    /// The cancelled call is answered, then the session ends.
    async fn expect_response_then_end(mut self) {
        match self.recv().await {
            CoreMessage::ToolResponse(response) => {
                assert!(matches!(response.outcome, ToolOutcome::Failed { .. }));
            }
            other => panic!("expected a tool_response, got {other:?}"),
        }
        let report = self.ended().await;
        assert_eq!(report.end, SessionEnd::Shutdown);
    }
}
