//! End-to-end tests: the real `jarvis-core` binary supervising real worker
//! processes. They need a Python 3.11+ interpreter, named by
//! `JARVIS_TEST_PYTHON` or found as `python3` (`python` on Windows).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jarvis_core::store::{NewTask, Store, TaskChange};
use jarvis_protocol::{
    AuditEvent, AuditEventKind, RequestId, SessionId, TaskId, TaskStatus, ToolName,
};
use serde_json::Value;

const CORE: &str = env!("CARGO_BIN_EXE_jarvis-core");

/// Repository root, without `..` components: Windows child processes get it
/// as their working directory.
fn repo() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("crate lives two levels below the repository root")
        .to_path_buf()
}

fn python() -> String {
    std::env::var("JARVIS_TEST_PYTHON")
        .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned())
}

struct Setup {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Setup {
    /// Write a config for `worker` (`"real"` or a rogue mode).
    fn new(worker: &str, goal: &str, policy: &str, extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (cwd, args) = if worker == "real" {
            (
                repo().join("services/intelligence-python/src"),
                format!(r#"["-m", "jarvis_worker", "--goal", {goal:?}]"#),
            )
        } else {
            (
                repo().join("crates/jarvis-core/tests/workers"),
                format!(r#"["rogue_worker.py", {worker:?}]"#),
            )
        };
        let text = format!(
            r#"
database = {database:?}

[worker]
program = {python:?}
args = {args}
cwd = {cwd:?}
{extra}

[fixtures]
root = {fixtures:?}

[limits]
shutdown_grace_ms = 3000

[policy]
{policy}
"#,
            database = dir.path().join("jarvis.db"),
            python = python(),
            cwd = cwd,
            fixtures = repo().join("tests/fixtures/files"),
        );
        let config = dir.path().join("jarvis.toml");
        std::fs::write(&config, text).unwrap();
        Self { dir, config }
    }

    fn core(&self, args: &[&str]) -> Command {
        let mut command = Command::new(CORE);
        command.args(args).arg("--config").arg(&self.config);
        command
    }

    fn run(&self) -> Output {
        self.core(&["run"])
            .env("JARVIS_TEST_SECRET", "must-not-reach-the-worker")
            .output()
            .unwrap()
    }

    fn database(&self) -> PathBuf {
        self.dir.path().join("jarvis.db")
    }

    fn store(&self) -> Store {
        Store::open_read_only(&self.database()).unwrap()
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.store().audit_events(None, 10_000).unwrap()
    }

    fn kinds(&self) -> Vec<&'static str> {
        self.events().into_iter().map(|e| e.event.name()).collect()
    }

    fn statuses(&self) -> Vec<(String, TaskStatus)> {
        let mut tasks = self.store().tasks(100).unwrap();
        tasks.reverse();
        tasks.into_iter().map(|t| (t.tool, t.status)).collect()
    }

    fn json_lines(&self, args: &[&str]) -> Vec<Value> {
        let output = self.core(args).arg("--json").output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

const ALLOW_ALL: &str = r#""system.info" = "allow"
"filesystem.read.fixture" = "allow""#;

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn worker_exit(setup: &Setup) -> (Option<i32>, bool) {
    setup
        .events()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::WorkerExited { code, success } => Some((code, success)),
            _ => None,
        })
        .expect("worker_exited was not recorded")
}

#[test]
fn python_worker_end_to_end() {
    let setup = Setup::new(
        "real",
        "describe the runtime, then read welcome.txt, then read ../Cargo.toml",
        ALLOW_ALL,
        "",
    );
    let output = setup.run();
    assert!(output.status.success(), "{}", stderr(&output));

    assert_eq!(
        setup.statuses(),
        [
            ("system.info".to_owned(), TaskStatus::Completed),
            ("filesystem.read_fixture".to_owned(), TaskStatus::Completed),
            ("filesystem.read_fixture".to_owned(), TaskStatus::Rejected),
        ]
    );
    let kinds = setup.kinds();
    assert_eq!(kinds.first(), Some(&"core_started"));
    assert_eq!(kinds.last(), Some(&"core_stopped"));
    for expected in [
        "worker_spawned",
        "session_opened",
        "policy_evaluated",
        "execution_started",
        "execution_finished",
        "request_rejected",
        "session_closed",
        "worker_exited",
    ] {
        assert!(kinds.contains(&expected), "missing {expected} in {kinds:?}");
    }
    assert_eq!(worker_exit(&setup), (Some(0), true));

    // The inspection commands read the same durable state.
    let tasks = setup.json_lines(&["tasks"]);
    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0]["status"], "completed");
    assert_eq!(tasks[2]["error"]["code"], "invalid_arguments");
    let audit = setup.json_lines(&["audit"]);
    assert_eq!(audit.len(), kinds.len());

    // A second run reopens the same database and adds to it.
    let output = setup.run();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(setup.statuses().len(), 6);
    let starts = setup
        .kinds()
        .into_iter()
        .filter(|kind| *kind == "core_started")
        .count();
    assert_eq!(starts, 2);
}

#[test]
fn rogue_worker_cannot_bypass_policy() {
    let setup = Setup::new(
        "bypass",
        "",
        r#""system.info" = "deny"
"filesystem.read.fixture" = "allow""#,
        "",
    );
    let output = setup.run();
    // The rogue worker exits 0 only if every attempt was refused.
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        setup.statuses(),
        [
            ("filesystem.read_fixture".to_owned(), TaskStatus::Rejected),
            ("shell.exec".to_owned(), TaskStatus::Rejected),
            ("system.info".to_owned(), TaskStatus::Denied),
            ("filesystem.read_fixture".to_owned(), TaskStatus::Completed),
        ]
    );
    let started: Vec<_> = setup
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            AuditEventKind::ExecutionStarted { tool } => Some(tool),
            _ => None,
        })
        .collect();
    assert_eq!(
        started,
        ["filesystem.read_fixture"],
        "only the allowed call ran"
    );
}

#[test]
fn worker_environment_is_cleared() {
    let setup = Setup::new("env", "", ALLOW_ALL, "");
    let output = setup.run();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(worker_exit(&setup), (Some(0), true));
}

#[test]
fn worker_crash_is_recorded() {
    let setup = Setup::new("crash", "", ALLOW_ALL, "");
    let output = setup.run();
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(worker_exit(&setup), (Some(7), false));
    assert!(setup.kinds().contains(&"session_closed"));
}

#[test]
fn handshake_timeout_kills_worker() {
    let setup = Setup::new("silent", "", ALLOW_ALL, "handshake_timeout_ms = 300");
    let output = setup.run();
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let killed = setup
        .events()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::WorkerKilled { reason } => Some(reason),
            _ => None,
        });
    assert_eq!(killed.as_deref(), Some("handshake timeout"));
    assert!(setup.statuses().is_empty());
}

#[test]
fn missing_worker_program_fails_cleanly() {
    let setup = Setup::new("crash", "", ALLOW_ALL, "");
    let text = std::fs::read_to_string(&setup.config).unwrap().replace(
        &format!("program = {:?}", python()),
        "program = \"jarvis-no-such-interpreter\"",
    );
    std::fs::write(&setup.config, text).unwrap();
    let output = setup.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("cannot start worker"));
    let stopped = setup
        .events()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::CoreStopped { reason } => Some(reason),
            _ => None,
        });
    assert!(stopped.unwrap().contains("failed to start"));
}

#[test]
fn restart_recovers_interrupted_tasks() {
    let setup = Setup::new("crash", "", ALLOW_ALL, "");
    // Leave a task in `executing`, as a Core that died mid-tool would.
    let task_id = TaskId::new();
    {
        let store = Store::open(&setup.database()).unwrap();
        store
            .create_task(&NewTask {
                task_id,
                session_id: SessionId::new(),
                request_id: RequestId::try_from("r1".to_owned()).unwrap(),
                tool: ToolName::try_from("system.info".to_owned()).unwrap(),
                args: serde_json::json!({}),
            })
            .unwrap();
        store
            .transition(
                task_id,
                &[TaskStatus::Received],
                &TaskChange::to(TaskStatus::Executing),
                &[],
            )
            .unwrap();
    }
    setup.run();
    let task = setup.store().task(task_id).unwrap().unwrap();
    assert_eq!(task.status, TaskStatus::Interrupted);
    let recovered = setup
        .store()
        .audit_events(Some(task_id), 100)
        .unwrap()
        .into_iter()
        .any(|event| matches!(event.event, AuditEventKind::TaskRecovered { .. }));
    assert!(recovered);
}

#[cfg(unix)]
#[test]
fn signal_triggers_graceful_shutdown() {
    use std::time::{Duration, Instant};

    let setup = Setup::new("stubborn", "", ALLOW_ALL, "");
    let text = std::fs::read_to_string(&setup.config)
        .unwrap()
        .replace("shutdown_grace_ms = 3000", "shutdown_grace_ms = 300");
    std::fs::write(&setup.config, text).unwrap();

    let mut child = setup.core(&["run"]).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let opened = Store::open_read_only(&setup.database())
            .ok()
            .and_then(|store| store.audit_events(None, 100).ok())
            .is_some_and(|events| {
                events
                    .iter()
                    .any(|e| matches!(e.event, AuditEventKind::SessionOpened { .. }))
            });
        if opened {
            break;
        }
        assert!(Instant::now() < deadline, "session never opened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let exit = child.wait().unwrap();
    assert_eq!(exit.code(), Some(2));

    let events = setup.events();
    let reason = |wanted: fn(&AuditEventKind) -> Option<String>| {
        events.iter().find_map(|event| wanted(&event.event))
    };
    assert_eq!(
        reason(|e| match e {
            AuditEventKind::SessionClosed { reason, .. } => Some(reason.clone()),
            _ => None,
        })
        .as_deref(),
        Some("Core shutdown")
    );
    assert!(
        reason(|e| match e {
            AuditEventKind::WorkerKilled { reason } => Some(reason.clone()),
            _ => None,
        })
        .is_some(),
        "a worker that ignores end-of-input is killed after the grace period"
    );
    assert_eq!(
        reason(|e| match e {
            AuditEventKind::CoreStopped { reason } => Some(reason.clone()),
            _ => None,
        })
        .as_deref(),
        Some("shutdown requested")
    );
}
