//! Session behaviour over in-memory pipes: the worker side of each test
//! writes raw frames, exactly as an untrusted worker could.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jarvis_core::config::Limits;
use jarvis_core::gateway::Gateway;
use jarvis_core::policy::Policy;
use jarvis_core::session::{SessionContext, SessionEnd, SessionError, SessionReport, run_session};
use jarvis_core::store::Store;
use jarvis_protocol::{
    AuditEventKind, Capability, CoreMessage, ErrorCode, PolicyDecision, TaskStatus, ToolCall,
    ToolOutcome, ToolResult, decode_core_message,
};
use jarvis_tools::{FixtureRoot, ToolExecutor, ToolFuture, Toolbox};
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
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy: vec![
                (Capability::SystemInfo, PolicyDecision::Allow),
                (Capability::FilesystemReadFixture, PolicyDecision::Allow),
            ],
            limits: Limits {
                tool_timeout: Duration::from_secs(10),
                ..Limits::default()
            },
            hang: false,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

struct Harness {
    dir: tempfile::TempDir,
    store: Store,
    calls: Arc<AtomicUsize>,
    shutdown: CancellationToken,
    to_core: Option<DuplexStream>,
    from_core: Lines<BufReader<DuplexStream>>,
    session: JoinHandle<Result<SessionReport, SessionError>>,
}

impl Harness {
    fn start(options: Options) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fixtures = dir.path().join("fixtures");
        std::fs::create_dir_all(&fixtures).unwrap();
        std::fs::write(fixtures.join("welcome.txt"), "hello\n").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "do not read").unwrap();

        let store = Store::open(&dir.path().join("jarvis.db")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = Probe {
            inner: Toolbox::new("test", FixtureRoot::open(&fixtures, 1024).unwrap()),
            calls: Arc::clone(&calls),
            hang: options.hang,
        };
        let policy: BTreeMap<_, _> = options.policy.into_iter().collect();
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
            core_version: "test",
        };

        let (to_core, core_reader) = tokio::io::duplex(1 << 20);
        let (core_writer, from_core) = tokio::io::duplex(1 << 20);
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let session =
            tokio::spawn(async move { run_session(&ctx, core_reader, core_writer, &token).await });
        Self {
            dir,
            store,
            calls,
            shutdown,
            to_core: Some(to_core),
            from_core: BufReader::new(from_core).lines(),
            session,
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
        self.send(json!({"protocol": 1, "type": "hello", "worker": "test", "worker_version": "1"}))
            .await;
        assert!(matches!(self.recv().await, CoreMessage::Welcome(_)));
    }

    async fn request(&mut self, id: &str, tool: &str, args: Value) -> ToolOutcome {
        self.send(json!({
            "protocol": 1, "type": "tool_request", "request_id": id, "tool": tool, "args": args
        }))
        .await;
        match self.recv().await {
            CoreMessage::ToolResponse(response) => {
                assert_eq!(response.request_id.as_str(), id);
                let task = self.store.task(response.task_id).unwrap().unwrap();
                assert_eq!(task.request_id.as_str(), id);
                response.outcome
            }
            other => panic!("expected a tool_response, got {other:?}"),
        }
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
}

#[tokio::test]
async fn valid_allowed_request_completes_and_is_recorded() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
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
        Harness::kinds(&store),
        [
            "session_opened",
            "request_received",
            "policy_evaluated",
            "execution_started",
            "execution_finished",
            "session_closed",
        ]
    );
}

#[tokio::test]
async fn denied_capability_never_executes() {
    let mut h = Harness::start(Options {
        policy: vec![(Capability::SystemInfo, PolicyDecision::Deny)],
        ..Options::default()
    });
    h.hello().await;
    let outcome = h.request("r1", "system.info", json!({})).await;
    assert!(
        matches!(&outcome, ToolOutcome::Denied { capabilities, .. } if capabilities == &[Capability::SystemInfo]),
        "{outcome:?}"
    );
    // Unlisted capabilities are denied as well.
    let outcome = h
        .request(
            "r2",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"}),
        )
        .await;
    assert!(matches!(outcome, ToolOutcome::Denied { .. }), "{outcome:?}");
    assert_eq!(h.statuses(), [TaskStatus::Denied, TaskStatus::Denied]);

    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!Harness::kinds(&store).contains(&"execution_started"));
}

#[tokio::test]
async fn confirmation_required_is_not_executed() {
    let mut h = Harness::start(Options {
        policy: vec![(
            Capability::FilesystemReadFixture,
            PolicyDecision::RequireConfirmation,
        )],
        ..Options::default()
    });
    h.hello().await;
    let outcome = h
        .request(
            "r1",
            "filesystem.read_fixture",
            json!({"path": "welcome.txt"}),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::ConfirmationRequired { .. }),
        "{outcome:?}"
    );
    assert_eq!(h.statuses(), [TaskStatus::AwaitingConfirmation]);

    let (_, store, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let task = store.tasks(1).unwrap().remove(0);
    assert_eq!(
        task.status,
        TaskStatus::Expired,
        "approval must not outlive the session"
    );
    assert!(Harness::kinds(&store).contains(&"task_expired"));
}

#[tokio::test]
async fn malformed_frames_are_answered_and_session_continues() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    for frame in [
        &b"not json"[..],
        b"[1, 2, 3]",
        b"{}",
        br#"{"protocol":1,"type":"shell","command":"id"}"#,
        br#"{"protocol":1,"type":"tool_request","request_id":"r1","tool":"system.info"}"#,
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
    h.hello().await;
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
    h.hello().await;
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
}

#[tokio::test]
async fn path_traversal_is_rejected() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    for (i, path) in [
        "../secret.txt",
        "notes/../../secret.txt",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "..\\secret.txt",
        ".ssh/id_rsa",
        "CON",
    ]
    .into_iter()
    .enumerate()
    {
        let outcome = h
            .request(
                &format!("r{i}"),
                "filesystem.read_fixture",
                json!({"path": path}),
            )
            .await;
        assert!(
            matches!(&outcome, ToolOutcome::Rejected { error } if error.code == ErrorCode::InvalidArguments),
            "{path}: {outcome:?}"
        );
    }
    let (_, _, calls) = h.finish().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tool_failure_is_recorded_without_corrupting_history() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
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
    h.hello().await;
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
    h.hello().await;
    h.send(json!({
        "protocol": 1, "type": "tool_request", "request_id": "r1",
        "tool": "system.info", "args": {}
    }))
    .await;
    // Wait until the decision is recorded and the tool is running.
    for _ in 0..200 {
        if h.statuses() == [TaskStatus::Executing] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(h.statuses(), [TaskStatus::Executing]);

    h.shutdown.cancel();
    match h.recv().await {
        CoreMessage::ToolResponse(response) => assert!(
            matches!(&response.outcome, ToolOutcome::Failed { error } if error.code == ErrorCode::Cancelled)
        ),
        other => panic!("expected a tool_response, got {other:?}"),
    }
    let (report, store, _) = h.finish().await;
    assert_eq!(report.end, SessionEnd::Shutdown);
    assert_eq!(store.tasks(1).unwrap()[0].status, TaskStatus::Cancelled);
}

#[tokio::test]
async fn duplicate_request_id_is_rejected() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    assert!(matches!(
        h.request("r1", "system.info", json!({})).await,
        ToolOutcome::Completed { .. }
    ));
    h.send(json!({
        "protocol": 1, "type": "tool_request", "request_id": "r1",
        "tool": "system.info", "args": {}
    }))
    .await;
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

#[tokio::test]
async fn protocol_version_mismatch_closes_session() {
    let mut h = Harness::start(Options::default());
    h.send(json!({"protocol": 2, "type": "hello", "worker": "future", "worker_version": "9"}))
        .await;
    h.expect_error(ErrorCode::UnsupportedProtocolVersion, true)
        .await;
    let (report, _, _) = h.finish().await;
    assert!(!report.opened);
    assert!(
        matches!(report.end, SessionEnd::Terminated(ref e) if e.code == ErrorCode::UnsupportedProtocolVersion)
    );
}

#[tokio::test]
async fn version_change_mid_session_closes_session() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    h.send(json!({
        "protocol": 2, "type": "tool_request", "request_id": "r1",
        "tool": "system.info", "args": {}
    }))
    .await;
    h.expect_error(ErrorCode::UnsupportedProtocolVersion, true)
        .await;
    let (report, _, calls) = h.finish().await;
    assert!(matches!(report.end, SessionEnd::Terminated(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn request_before_hello_is_fatal() {
    let mut h = Harness::start(Options::default());
    h.send(json!({
        "protocol": 1, "type": "tool_request", "request_id": "r1",
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
    h.send(json!({"protocol": 1, "type": "hello", "worker": "again", "worker_version": "1"}))
        .await;
    h.expect_error(ErrorCode::UnexpectedMessage, false).await;
    h.finish().await;
}

#[tokio::test]
async fn worker_cannot_smuggle_authority() {
    let mut h = Harness::start(Options {
        policy: vec![(Capability::SystemInfo, PolicyDecision::Deny)],
        ..Options::default()
    });
    h.hello().await;
    let base = json!({
        "protocol": 1, "type": "tool_request", "request_id": "r1",
        "tool": "system.info", "args": {}
    });
    for (key, value) in [
        ("capabilities", json!(["system.info"])),
        ("approved", json!(true)),
        ("decision", json!("allow")),
        ("task_id", json!("01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c")),
        ("session_id", json!("01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b")),
    ] {
        let mut frame = base.clone();
        frame[key] = value;
        h.send(frame).await;
        h.expect_error(ErrorCode::MalformedFrame, false).await;
    }
    // The plain request is still evaluated against policy, and denied.
    let outcome = h.request("r1", "system.info", json!({})).await;
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
    h.hello().await;
    h.request("r1", "system.info", json!({})).await;
    h.request("r2", "system.info", json!({})).await;
    h.send(json!({
        "protocol": 1, "type": "tool_request", "request_id": "r3",
        "tool": "system.info", "args": {}
    }))
    .await;
    h.expect_error(ErrorCode::LimitExceeded, true).await;
    let (report, store, calls) = h.finish().await;
    assert_eq!(report.requests, 2);
    assert_eq!(store.tasks(10).unwrap().len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn oversized_frame_is_rejected_and_session_continues() {
    let mut h = Harness::start(Options::default());
    h.hello().await;
    let huge = format!(
        r#"{{"protocol":1,"type":"tool_request","request_id":"r1","tool":"system.info","args":{{"pad":"{}"}}}}"#,
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
    h.hello().await;
    // Simulate a write failure for exactly the record that precedes execution.
    let path = h.dir.path().join("jarvis.db");
    rusqlite_fault(&path);

    h.send(json!({
        "protocol": 1, "type": "tool_request", "request_id": "r1",
        "tool": "system.info", "args": {}
    }))
    .await;
    h.to_core.take();
    let result = tokio::time::timeout(Duration::from_secs(10), h.session)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(SessionError::Store(_))));
    assert_eq!(h.calls.load(Ordering::SeqCst), 0, "the tool must not run");
    assert_eq!(h.store.tasks(1).unwrap()[0].status, TaskStatus::Received);
}

fn rusqlite_fault(path: &std::path::Path) {
    // A second connection adds a trigger that rejects `execution_started`.
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_execution_started BEFORE INSERT ON audit_events
         WHEN NEW.kind = 'execution_started'
         BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END;",
    )
    .unwrap();
}

#[tokio::test]
async fn every_task_reaches_exactly_one_terminal_state() {
    let mut h = Harness::start(Options {
        policy: vec![
            (Capability::SystemInfo, PolicyDecision::Allow),
            (
                Capability::FilesystemReadFixture,
                PolicyDecision::RequireConfirmation,
            ),
        ],
        ..Options::default()
    });
    h.hello().await;
    h.request("a", "system.info", json!({})).await;
    h.request(
        "b",
        "filesystem.read_fixture",
        json!({"path": "welcome.txt"}),
    )
    .await;
    h.request("c", "nope.tool", json!({})).await;
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
