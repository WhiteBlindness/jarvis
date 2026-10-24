//! End-to-end tests: the real `jarvis-core` binary running as a long-lived
//! Core, supervising real worker processes, driven by its own CLI and by raw
//! RPC connections. They need a Python 3.11+ interpreter, named by
//! `JARVIS_TEST_PYTHON` or found as `python3` (`python` on Windows).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use jarvis_core::config::Config;
use jarvis_core::rpc::Endpoint;
use jarvis_core::rpc::client::Client;
use jarvis_core::store::{NewTask, Store, TaskChange};
use jarvis_protocol::{
    ApprovalStatus, AuditEvent, AuditEventKind, JobStatus, RequestId, RpcErrorCode, RpcRequest,
    RpcResponse, SessionId, TaskId, TaskStatus, ToolName, WorkerState,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

const CORE: &str = env!("CARGO_BIN_EXE_jarvis-core");
const WAIT: Duration = Duration::from_secs(30);

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

const POLICY: &str = r#""system.info" = "allow"
"filesystem.read.fixture" = "allow"
"workspace.write" = "require_confirmation""#;

struct Setup {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Setup {
    /// Write a config for `worker` (`"real"` or a rogue mode).
    fn new(worker: &str, policy: &str, extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("rpc").join("jarvis.sock");
        let pipe = format!("jarvis-test-{}", TaskId::new());
        let endpoint = if cfg!(windows) {
            format!(r"\\.\pipe\{pipe}")
        } else {
            socket.display().to_string()
        };
        let (cwd, args) = if worker == "real" {
            (
                repo().join("services/intelligence-python/src"),
                r#"["-m", "jarvis_worker"]"#.to_owned(),
            )
        } else {
            (
                repo().join("crates/jarvis-core/tests/workers"),
                format!(r#"["rogue_worker.py", {worker:?}, {endpoint:?}]"#),
            )
        };
        let text = format!(
            r#"
database = {database:?}

[worker]
program = {python:?}
args = {args}
cwd = {cwd:?}

[fixtures]
root = {fixtures:?}

[workspace]
root = {workspace:?}

[limits]
shutdown_grace_ms = 3000

[supervisor]
restart_budget = 3
backoff_initial_ms = 50
backoff_max_ms = 200

[rpc]
socket = {socket:?}
pipe = {pipe:?}
allow_shutdown = true

[policy]
{policy}

{extra}
"#,
            database = dir.path().join("jarvis.db"),
            python = python(),
            fixtures = repo().join("tests/fixtures/files"),
            workspace = dir.path().join("workspace"),
        );
        let config = dir.path().join("jarvis.toml");
        std::fs::write(&config, text).unwrap();
        Self { dir, config }
    }

    /// Replace one line of the config.
    fn edit(&self, from: &str, to: &str) {
        let text = std::fs::read_to_string(&self.config).unwrap();
        assert!(text.contains(from), "{from} not in config");
        std::fs::write(&self.config, text.replace(from, to)).unwrap();
    }

    fn cli(&self, args: &[&str]) -> Command {
        let mut command = Command::new(CORE);
        command
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cli(args).output().unwrap()
    }

    /// Run a client command that prints JSON lines. Exit code 2 (a negative
    /// answer, such as a failed job) still prints the answer.
    fn json(&self, args: &[&str]) -> Vec<Value> {
        let output = self.cli(args).arg("--json").output().unwrap();
        assert!(
            matches!(output.status.code(), Some(0 | 2)),
            "{args:?}: {}",
            stderr(&output)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint::from_config(&Config::load(&self.config).unwrap().rpc)
    }

    fn database(&self) -> PathBuf {
        self.dir.path().join("jarvis.db")
    }

    fn workspace_file(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.path().join("workspace").join(name)).ok()
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

    fn count(&self, kind: &str) -> usize {
        self.kinds().into_iter().filter(|k| *k == kind).count()
    }

    fn statuses(&self) -> Vec<(String, TaskStatus)> {
        let mut tasks = self.store().tasks(100).unwrap();
        tasks.reverse();
        tasks.into_iter().map(|t| (t.tool, t.status)).collect()
    }

    /// Start `jarvis-core serve` and wait for its ready line.
    fn serve(&self) -> Daemon {
        let log =
            std::fs::File::create(self.dir.path().join(format!("core-{}.log", TaskId::new())))
                .unwrap();
        let mut child = self
            .cli(&["serve"])
            .env("JARVIS_TEST_SECRET", "must-not-reach-the-worker")
            .stdout(Stdio::piped())
            .stderr(log)
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (lines, ready) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if lines.send(line).is_err() {
                    return;
                }
            }
        });
        match ready.recv_timeout(WAIT) {
            Ok(line) => assert!(line.starts_with("ready "), "unexpected first line {line:?}"),
            Err(_) => {
                let _ = child.kill();
                panic!("the Core did not become ready: {}", self.log());
            }
        }
        Daemon { child }
    }

    fn log(&self) -> String {
        let mut text = String::new();
        for entry in std::fs::read_dir(self.dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "log") {
                text.push_str(&std::fs::read_to_string(path).unwrap_or_default());
            }
        }
        text
    }

    /// Wait until `ready` holds for the audit log.
    fn wait_for(&self, what: &str, ready: impl Fn(&[AuditEvent]) -> bool) {
        let deadline = Instant::now() + WAIT;
        loop {
            if Store::open_read_only(&self.database())
                .ok()
                .and_then(|store| store.audit_events(None, 10_000).ok())
                .is_some_and(|events| ready(&events))
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn wait_for_kind(&self, kind: &str, times: usize) {
        self.wait_for(kind, |events| {
            events.iter().filter(|e| e.event.name() == kind).count() >= times
        });
    }

    fn health(&self) -> Value {
        self.json(&["health"]).remove(0)
    }

    fn wait_for_worker(&self, state: &str) {
        let deadline = Instant::now() + WAIT;
        while self.health()["worker"]["state"] != state {
            assert!(
                Instant::now() < deadline,
                "worker never became {state}: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn submit(&self, goal: &str) -> String {
        let job = self.json(&["submit", goal]).remove(0);
        assert_eq!(job["status"], "queued");
        job["job_id"].as_str().unwrap().to_owned()
    }

    fn pending_approval(&self) -> Value {
        let approvals = self.json(&["approvals", "list", "--wait", "30s"]);
        assert_eq!(approvals.len(), 1, "{approvals:?}");
        approvals.into_iter().next().unwrap()
    }

    fn shutdown(&self, mut daemon: Daemon) -> ExitStatus {
        let output = self.run(&["shutdown"]);
        assert!(output.status.success(), "{}", stderr(&output));
        daemon.wait()
    }
}

struct Daemon {
    child: Child,
}

impl Daemon {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the Core did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Kill the Core without letting it clean up, as a crash or power loss
    /// would.
    fn crash(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn worker_exits(setup: &Setup) -> Vec<(Option<i32>, bool)> {
    setup
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            AuditEventKind::WorkerExited { code, success } => Some((code, success)),
            _ => None,
        })
        .collect()
}

#[test]
fn the_daemon_runs_jobs_from_clients_with_the_python_worker() {
    let setup = Setup::new("real", POLICY, "");
    let daemon = setup.serve();
    setup.wait_for_worker("idle");
    let health = setup.health();
    assert_eq!(health["ok"], true);
    assert_eq!(health["worker_protocol"], 3);
    assert_eq!(health["rpc_protocol"], 4);
    assert!(health["worker"]["pid"].is_u64());
    assert!(!health["worker"]["containment"].as_str().unwrap().is_empty());

    let job = setup
        .json(&[
            "submit",
            "describe the runtime, then read welcome.txt, then read ../Cargo.toml",
            "--wait",
        ])
        .remove(0);
    assert_eq!(job["status"], "failed", "one read is rejected: {job}");
    assert_eq!(
        job["summary"],
        "3 call(s): completed=2 denied=0 declined=0 expired=0 rejected=1 failed=0"
    );
    let job = setup
        .json(&["submit", "describe the runtime", "--wait"])
        .remove(0);
    assert_eq!(job["status"], "completed");
    assert_eq!(
        setup.statuses(),
        [
            ("system.info".to_owned(), TaskStatus::Completed),
            ("filesystem.read_fixture".to_owned(), TaskStatus::Completed),
            ("filesystem.read_fixture".to_owned(), TaskStatus::Rejected),
            ("system.info".to_owned(), TaskStatus::Completed),
        ]
    );
    let jobs = setup.json(&["jobs"]);
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0]["status"], "completed", "most recent first");

    let status = setup.shutdown(daemon);
    assert!(status.success(), "{}", setup.log());
    let kinds = setup.kinds();
    assert_eq!(kinds.first(), Some(&"core_started"));
    assert_eq!(kinds.last(), Some(&"core_stopped"));
    for expected in [
        "worker_spawned",
        "session_opened",
        "job_submitted",
        "job_started",
        "policy_evaluated",
        "execution_started",
        "execution_finished",
        "request_rejected",
        "job_finished",
        "session_closed",
        "worker_exited",
    ] {
        assert!(kinds.contains(&expected), "missing {expected} in {kinds:?}");
    }
    assert_eq!(worker_exits(&setup), [(Some(0), true)]);

    // The read-only commands see the same durable state after the Core stopped.
    let audit = setup.json(&["audit"]);
    assert_eq!(audit.len(), kinds.len());
    assert_eq!(setup.json(&["tasks"]).len(), 4);
    // Client commands fail cleanly when no Core is running.
    let output = setup.run(&["health"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("cannot reach the Core"));
}

#[test]
fn a_write_runs_only_after_a_person_approves_it_through_another_client() {
    let setup = Setup::new("real", POLICY, "");
    let daemon = setup.serve();
    let job = setup.submit("write notes.txt: hello from jarvis");
    let approval = setup.pending_approval();
    let id = approval["approval_id"].as_str().unwrap().to_owned();
    assert_eq!(approval["status"], "pending");
    assert_eq!(approval["tool"], "workspace.write_file");
    assert_eq!(
        approval["capabilities"],
        serde_json::json!(["workspace.write"])
    );
    assert_eq!(approval["job_id"], job.as_str());
    assert_eq!(approval["arguments"]["path"], "notes.txt");
    assert_eq!(approval["arguments"]["bytes"], "17");
    assert_eq!(approval["arguments"]["preview"], "hello from jarvis");
    assert!(approval["expires_in_ms"].as_u64().unwrap() > 0);
    assert_eq!(
        setup.workspace_file("notes.txt"),
        None,
        "nothing before approval"
    );

    // The human-readable listing shows what is being approved.
    let listing = stdout(&setup.run(&["approvals", "list"]));
    for expected in [
        "workspace.write_file",
        "notes.txt",
        "hello from jarvis",
        &id,
    ] {
        assert!(
            listing.contains(expected),
            "{expected} missing in:\n{listing}"
        );
    }
    // A fingerprint other than the reviewed one approves nothing.
    let output = setup.run(&[
        "approvals",
        "approve",
        &id,
        "--yes",
        "--fingerprint",
        &"0".repeat(64),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("nothing was approved"));
    // Without a terminal, approving needs an explicit --yes.
    let output = setup.run(&["approvals", "approve", &id]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("--yes"));
    assert_eq!(
        setup
            .store()
            .approval(id.parse().unwrap())
            .unwrap()
            .unwrap()
            .status,
        ApprovalStatus::Pending
    );

    let fingerprint = approval["fingerprint"].as_str().unwrap();
    let output = setup.run(&[
        "approvals",
        "approve",
        &id,
        "--yes",
        "--fingerprint",
        fingerprint,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let done = setup.json(&["job", &job, "--wait"]).remove(0);
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        setup.workspace_file("notes.txt").as_deref(),
        Some("hello from jarvis")
    );

    // The approval is spent.
    let output = setup.run(&["approvals", "approve", &id, "--yes"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("consumed"), "{}", stderr(&output));

    // A second write is declined: nothing changes on disk.
    let job = setup.submit("write notes.txt: overwritten");
    let id = setup.pending_approval()["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let output = setup.run(&[
        "approvals",
        "deny",
        &id,
        "--reason",
        "keep the first version",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let done = setup.json(&["job", &job, "--wait"]).remove(0);
    assert_eq!(done["status"], "failed");
    assert!(done["summary"].as_str().unwrap().contains("declined=1"));
    assert_eq!(
        setup.workspace_file("notes.txt").as_deref(),
        Some("hello from jarvis")
    );

    assert!(setup.shutdown(daemon).success());
    let kinds = setup.kinds();
    for expected in [
        "approval_requested",
        "approval_granted",
        "approval_consumed",
        "approval_denied",
    ] {
        assert!(kinds.contains(&expected), "missing {expected}");
    }
    let granted_by = setup
        .events()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::ApprovalGranted { client, .. } => Some(client),
            _ => None,
        });
    assert!(granted_by.unwrap().starts_with("local client pid "));
}

/// A clipboard text submitted through the CLI is shown to the person in full
/// while its job exists, is in no immutable record, and is gone from the
/// database file and its log once the job has ended (ADR 0022).
#[test]
fn a_clipboard_text_lives_only_as_long_as_its_job() {
    const TEXT: &str = "clipboard-canary-91c2d7";
    let policy = format!("{POLICY}\n\"desktop.clipboard.write\" = \"require_confirmation\"");
    let setup = Setup::new("real", &policy, "");
    let daemon = setup.serve();
    let grep = |needle: &str| {
        ["jarvis.db", "jarvis.db-wal"].iter().any(|name| {
            std::fs::read(setup.dir.path().join(name)).is_ok_and(|bytes| {
                bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            })
        })
    };

    // Text the Core would refuse as clipboard text never becomes a job.
    let output = setup.run(&["clipboard", "bad \u{1b}[2J text"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("invalid clipboard text"));

    let job = setup
        .json(&["clipboard", &format!("copy me {TEXT}")])
        .remove(0);
    let goal = job["goal"].as_str().unwrap();
    assert!(goal.starts_with("copy payload:"), "{goal}");
    assert!(!goal.contains(TEXT));
    let job = job["job_id"].as_str().unwrap().to_owned();

    // The person is shown the text in full.
    let approval = setup.pending_approval();
    assert_eq!(approval["tool"], "desktop.write_clipboard_text");
    assert_eq!(approval["arguments"]["text"], format!("copy me {TEXT}"));
    assert!(grep(TEXT), "the payload holds the text meanwhile");
    // No immutable record has it.
    let store = setup.store();
    for task in store.tasks(10).unwrap() {
        assert!(!task.args.contains(TEXT));
    }
    for job in store.jobs(10).unwrap() {
        assert!(!job.goal.as_str().contains(TEXT));
    }
    let events: Vec<_> = setup.events().into_iter().map(|e| e.event).collect();
    assert!(!serde_json::to_string(&events).unwrap().contains(TEXT));
    drop(store);

    let id = approval["approval_id"].as_str().unwrap().to_owned();
    let output = setup.run(&["approvals", "deny", &id, "--reason", "not now"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let done = setup.json(&["job", &job, "--wait"]).remove(0);
    assert_eq!(done["status"], "failed", "{done}");
    // The job has ended: the text is in neither file.
    assert!(!grep(TEXT), "the text outlived its job");

    let store = setup.store();
    let record = store
        .tasks(10)
        .unwrap()
        .into_iter()
        .find(|task| task.tool == "desktop.write_clipboard_text")
        .unwrap();
    assert!(!record.args.contains(TEXT));
    drop(store);
    assert!(setup.shutdown(daemon).success());
    assert!(!grep(TEXT));
}

/// Pending approvals do not survive a restart, and a consumed approval stays
/// consumed: neither can be used after the Core comes back. The job that was
/// waiting is queued again and asks again with a new approval.
#[test]
fn no_approval_can_be_used_after_the_core_restarts() {
    let setup = Setup::new("real", POLICY, "");
    let mut daemon = setup.serve();
    setup.submit("write a.txt: first");
    let first = setup.pending_approval();
    let first_id = first["approval_id"].as_str().unwrap().to_owned();
    assert!(
        setup
            .run(&["approvals", "approve", &first_id, "--yes"])
            .status
            .success()
    );
    setup.wait_for_kind("job_finished", 1);

    let job = setup.submit("write b.txt: second");
    let second = setup.pending_approval();
    let second_id = second["approval_id"].as_str().unwrap().to_owned();
    daemon.crash();

    let daemon = setup.serve();
    let renewed = setup.pending_approval();
    assert_ne!(renewed["approval_id"], second_id.as_str());
    assert_ne!(renewed["fingerprint"], second["fingerprint"]);
    let shown = setup.json(&["approvals", "show", &second_id]).remove(0);
    assert_eq!(shown["status"], "expired");
    let shown = setup.json(&["approvals", "show", &first_id]).remove(0);
    assert_eq!(shown["status"], "consumed");
    for id in [&first_id, &second_id] {
        let output = setup.run(&["approvals", "approve", id, "--yes"]);
        assert_eq!(output.status.code(), Some(1), "{id} was approved again");
    }
    let job = setup.json(&["job", &job]).remove(0);
    assert_eq!(job["status"], "running", "waiting for the new approval");
    assert_eq!(setup.workspace_file("a.txt").as_deref(), Some("first"));
    assert_eq!(setup.workspace_file("b.txt"), None);
    assert!(setup.shutdown(daemon).success());
    assert_eq!(setup.count("approval_consumed"), 1);
}

#[test]
fn a_rogue_worker_cannot_bypass_policy_or_approve_its_own_request() {
    let setup = Setup::new(
        "bypass",
        r#""system.info" = "deny"
"filesystem.read.fixture" = "allow"
"workspace.write" = "require_confirmation""#,
        "",
    );
    let daemon = setup.serve();
    setup.submit("anything");
    let approval = setup.pending_approval();
    // The rogue attacks the RPC endpoint before it reads the decision, so by
    // the time the job finishes the attack has happened.
    let id = approval["approval_id"].as_str().unwrap();
    assert!(setup.run(&["approvals", "deny", id]).status.success());
    setup.wait_for_kind("job_finished", 1);
    assert!(setup.shutdown(daemon).success());

    // The rogue exits 0 only if every attempt was refused.
    assert_eq!(worker_exits(&setup), [(Some(0), true)], "{}", setup.log());
    // Under confinement the worker cannot create a socket or open the pipe,
    // so the attack never reaches the Core's own peer check.
    if cfg!(any(target_os = "linux", windows)) {
        assert_eq!(setup.count("rpc_client_rejected"), 0, "{}", setup.log());
    }
    assert_eq!(
        setup.statuses(),
        [
            ("filesystem.read_fixture".to_owned(), TaskStatus::Rejected),
            ("workspace.write_file".to_owned(), TaskStatus::Rejected),
            ("shell.exec".to_owned(), TaskStatus::Rejected),
            ("system.info".to_owned(), TaskStatus::Denied),
            ("filesystem.read_fixture".to_owned(), TaskStatus::Completed),
            ("workspace.write_file".to_owned(), TaskStatus::Denied),
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
    assert_eq!(setup.workspace_file("rogue.txt"), None);
    assert!(setup.workspace_file("../escape.txt").is_none());
}

#[test]
fn the_worker_environment_is_cleared() {
    let setup = Setup::new("env", POLICY, "");
    let daemon = setup.serve();
    setup.wait_for_kind("session_opened", 1);
    assert!(setup.shutdown(daemon).success());
    assert_eq!(worker_exits(&setup), [(Some(0), true)], "{}", setup.log());
}

#[test]
fn a_crashing_worker_is_restarted_until_the_budget_is_spent() {
    let setup = Setup::new("crash", POLICY, "");
    let daemon = setup.serve();
    setup.wait_for_kind("worker_restart_abandoned", 1);
    let health = setup.health();
    assert_eq!(health["ok"], false);
    assert_eq!(health["worker"]["state"], "failed");
    assert_eq!(health["worker"]["restarts"], 3);
    // The health command reports the failure through its exit code too.
    assert_eq!(setup.run(&["health"]).status.code(), Some(2));
    let output = setup.run(&["submit", "system"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("unavailable"),
        "{}",
        stderr(&output)
    );

    let status = setup.shutdown(daemon);
    assert_eq!(status.code(), Some(2), "gave up on the worker");
    assert_eq!(setup.count("worker_spawned"), 4);
    assert_eq!(setup.count("worker_restart_scheduled"), 3);
    assert_eq!(worker_exits(&setup), [(Some(7), false); 4]);
}

#[test]
fn a_worker_that_dies_while_waiting_for_approval_leaves_nothing_usable() {
    let setup = Setup::new("crash-waiting", POLICY, "");
    let daemon = setup.serve();
    let job = setup.submit("anything");
    // Nothing the worker did completed or started, so the job is tried again
    // until its attempts are spent. Every attempt asks anew.
    setup.wait_for_kind("job_finished", 1);
    let approvals: Vec<_> = setup
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            AuditEventKind::ApprovalRequested { approval_id, .. } => Some(approval_id),
            _ => None,
        })
        .collect();
    assert_eq!(approvals.len(), 3);
    for approval in approvals {
        let record = setup.store().approval(approval).unwrap().unwrap();
        assert_eq!(record.status, ApprovalStatus::Expired);
        let output = setup.run(&["approvals", "approve", &approval.to_string(), "--yes"]);
        assert_eq!(output.status.code(), Some(1));
    }
    assert_eq!(setup.count("job_requeued"), 2);
    let job = setup.json(&["job", &job]).remove(0);
    assert_eq!(job["status"], "interrupted");
    assert!(job["summary"].as_str().unwrap().contains("attempt limit"));
    assert_eq!(setup.workspace_file("never.txt"), None);
    drop(daemon);
}

#[test]
fn a_silent_worker_is_killed_at_the_handshake_timeout() {
    let setup = Setup::new("silent", POLICY, "");
    setup.edit("[worker]", "[worker]\nhandshake_timeout_ms = 300");
    setup.edit("restart_budget = 3", "restart_budget = 0");
    let daemon = setup.serve();
    setup.wait_for_kind("worker_restart_abandoned", 1);
    let killed = setup
        .events()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::WorkerKilled { reason } => Some(reason),
            _ => None,
        });
    assert_eq!(killed.as_deref(), Some("handshake timeout"));
    assert_eq!(setup.shutdown(daemon).code(), Some(2));
}

#[test]
fn a_missing_worker_program_stops_the_core_before_any_worker() {
    // The worker's isolation is checked before the first start, and that
    // needs the program; a Core that cannot check it does not run.
    let setup = Setup::new("crash", POLICY, "");
    setup.edit(
        &format!("program = {:?}", python()),
        "program = \"jarvis-no-such-interpreter\"",
    );
    let output = setup.run(&["serve"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("was not found"),
        "{}",
        stderr(&output)
    );
    assert_eq!(setup.count("worker_spawned"), 0);
    let stopped = setup
        .events()
        .into_iter()
        .find_map(|event| match event.event {
            AuditEventKind::CoreStopped { reason } => Some(reason),
            _ => None,
        });
    assert!(stopped.is_some_and(|reason| reason.contains("was not found")));
}

#[test]
fn isolation_check_proves_the_boundary_without_a_running_core() {
    let setup = Setup::new("real", POLICY, "");
    let output = setup.run(&["isolation", "check"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{text}\n{}", stderr(&output));
    for check in [
        "no loopback TCP",
        "no loopback UDP",
        "no access to the Core's files",
        "no child processes",
    ] {
        assert!(text.contains(&format!("ok          {check}")), "{text}");
    }
    // It ran no Core: there is no database.
    assert!(!setup.database().exists());
}

#[test]
fn a_second_core_cannot_use_the_same_database() {
    let setup = Setup::new("real", POLICY, "");
    let daemon = setup.serve();
    let output = setup.run(&["serve"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("in use by another Core"),
        "{}",
        stderr(&output)
    );
    // The first Core is unaffected.
    assert_eq!(setup.health()["ok"], true);
    assert!(setup.shutdown(daemon).success());
}

#[test]
fn shutdown_over_rpc_can_be_disabled() {
    let setup = Setup::new("real", POLICY, "");
    setup.edit("allow_shutdown = true", "allow_shutdown = false");
    let mut daemon = setup.serve();
    let output = setup.run(&["shutdown"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("forbidden"), "{}", stderr(&output));
    assert_eq!(setup.health()["ok"], true);
    daemon.crash();
}

#[test]
fn start_up_recovers_what_a_previous_run_left_open() {
    let setup = Setup::new("real", POLICY, "");
    // Leave a task in `executing`, as a Core that died mid-tool would.
    let task_id = TaskId::new();
    {
        let store = Store::open(&setup.database()).unwrap();
        store
            .create_task(&NewTask {
                task_id,
                session_id: SessionId::new(),
                job_id: None,
                step: None,
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
        let goal = jarvis_protocol::Goal::try_from("left behind".to_owned()).unwrap();
        store.submit_job(&goal, "test").unwrap();
    }
    let daemon = setup.serve();
    // The queued job is carried over and run by the new worker.
    setup.wait_for_kind("job_finished", 1);
    assert!(setup.shutdown(daemon).success());
    let store = setup.store();
    assert_eq!(
        store.task(task_id).unwrap().unwrap().status,
        TaskStatus::Interrupted
    );
    let job = &store.jobs(1).unwrap()[0];
    // The worker ran it: the goal names nothing it knows how to do.
    assert_eq!(job.status, JobStatus::Failed);
    let summary = job.summary.as_ref().unwrap();
    assert!(summary.as_str().contains("known action"), "{summary:?}");
    assert_eq!(job.attempts, 1);
    assert_eq!(setup.count("job_started"), 1);
    assert_eq!(setup.count("job_requeued"), 0);
    assert!(
        store
            .audit_events(Some(task_id), 100)
            .unwrap()
            .into_iter()
            .any(|event| matches!(event.event, AuditEventKind::TaskRecovered { .. }))
    );
}

#[cfg(unix)]
#[test]
fn a_signal_shuts_down_gracefully_and_kills_a_stubborn_worker() {
    let setup = Setup::new("stubborn", POLICY, "");
    setup.edit("shutdown_grace_ms = 3000", "shutdown_grace_ms = 300");
    let mut daemon = setup.serve();
    setup.wait_for_kind("session_opened", 1);
    let worker = setup.health()["worker"]["pid"].as_u64().unwrap() as u32;

    let status = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(daemon.wait().success(), "{}", setup.log());
    assert!(
        !jarvis_sandbox::process_exists(worker),
        "the worker outlived the Core"
    );

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

/// If the Core dies without cleaning up, the worker does not outlive it.
#[test]
fn the_worker_dies_with_the_core() {
    let setup = Setup::new("stubborn", POLICY, "");
    let mut daemon = setup.serve();
    setup.wait_for_kind("session_opened", 1);
    let worker = setup.health()["worker"]["pid"].as_u64().unwrap() as u32;
    assert!(jarvis_sandbox::process_exists(worker));
    daemon.crash();
    let deadline = Instant::now() + WAIT;
    while jarvis_sandbox::process_exists(worker) {
        assert!(Instant::now() < deadline, "the worker outlived the Core");
        std::thread::sleep(Duration::from_millis(50));
    }
}

// --- the RPC interface --------------------------------------------------------------------------

async fn raw_exchange(endpoint: &Endpoint, frames: &[&[u8]]) -> Vec<Value> {
    let stream = jarvis_core::rpc::transport::connect(endpoint)
        .await
        .unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = tokio::io::BufReader::new(reader).lines();
    let mut replies = Vec::new();
    for frame in frames {
        if writer.write_all(frame).await.is_err() || writer.write_all(b"\n").await.is_err() {
            break;
        }
        match tokio::time::timeout(WAIT, lines.next_line()).await.unwrap() {
            Ok(Some(line)) => replies.push(serde_json::from_str(&line).unwrap()),
            _ => break,
        }
    }
    replies
}

#[test]
fn the_rpc_interface_is_strict_and_bounded() {
    let setup = Setup::new("real", POLICY, "");
    let daemon = setup.serve();
    let endpoint = setup.endpoint();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let health = br#"{"rpc":4,"type":"health"}"#;
        let replies = raw_exchange(
            &endpoint,
            &[
                b"not json",
                br#"{"rpc":4,"type":"health","extra":1}"#,
                br#"{"rpc":4,"type":"run_command","command":"id"}"#,
                br#"{"rpc":5,"type":"health"}"#,
                br#"{"rpc":3,"type":"health"}"#,
                br#"{"protocol":3,"type":"hello","worker":"w","worker_version":"1"}"#,
                br#"{"rpc":4,"type":"approve","approval_id":"01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c","fingerprint":"aa","approved":true}"#,
                br#"{"rpc":4,"type":"approve","approval_id":"01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                health,
            ],
        )
        .await;
        let codes: Vec<_> = replies
            .iter()
            .map(|reply| reply["code"].as_str().unwrap_or("-"))
            .collect();
        assert_eq!(
            codes,
            [
                "malformed_request",
                "malformed_request",
                "malformed_request",
                "unsupported_version",
                "unsupported_version",
                "malformed_request",
                "malformed_request",
                "not_found",
                "-",
            ]
        );
        // A client of the previous version is refused, and the answer is
        // encoded at this version: an older client cannot decode it either.
        assert_eq!(replies[4]["rpc"], 4);
        assert!(replies[4]["message"].as_str().unwrap().contains("version 3"));
        assert_eq!(replies[8]["type"], "health", "the connection survives bad requests");

        // An oversized request is answered once, then the connection closes.
        let huge = format!(
            r#"{{"rpc":4,"type":"submit_job","goal":"{}"}}"#,
            "x".repeat(20 * 1024)
        );
        let replies = raw_exchange(&endpoint, &[huge.as_bytes(), health]).await;
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["code"], "request_too_large");

        // A client that disconnects in the middle of a long poll does not
        // disturb the Core.
        let stream = jarvis_core::rpc::transport::connect(&endpoint).await.unwrap();
        let (_, mut writer) = tokio::io::split(stream);
        writer
            .write_all(b"{\"rpc\":2,\"type\":\"list_approvals\",\"wait_ms\":30000}\n")
            .await
            .unwrap();
        drop(writer);

        let mut client = Client::connect(&endpoint).await.unwrap();
        let RpcResponse::Health(report) = client.call(&RpcRequest::Health {}).await.unwrap()
        else {
            panic!("expected health");
        };
        assert!(report.ok);
        assert_ne!(report.worker.state, WorkerState::Failed);
        match client
            .call(&RpcRequest::GetJob {
                job_id: jarvis_protocol::JobId::new(),
                wait_ms: 0,
            })
            .await
            .unwrap()
        {
            RpcResponse::Error(error) => assert_eq!(error.code, RpcErrorCode::NotFound),
            other => panic!("expected an error, got {other:?}"),
        }
    });
    assert!(setup.shutdown(daemon).success());
    assert!(
        setup.count("rpc_client_rejected") == 0,
        "the CLI is a legitimate client"
    );
}

#[cfg(unix)]
#[test]
fn the_rpc_socket_is_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;

    let setup = Setup::new("real", POLICY, "");
    let daemon = setup.serve();
    let Endpoint::Socket(socket) = setup.endpoint();
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&socket), 0o600);
    assert_eq!(mode(socket.parent().unwrap()), 0o700);
    assert!(setup.shutdown(daemon).success());
    assert!(!socket.exists(), "the socket is removed on shutdown");

    // A socket directory that others can enter is refused, not repaired.
    std::fs::set_permissions(
        socket.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let output = setup.run(&["serve"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("mode 0700"), "{}", stderr(&output));
}

/// The Core is killed while step 2, a write, waits for a person. After the
/// restart the job comes back, step 1 is answered from its stored result, and
/// step 2 asks again with a new approval.
#[test]
fn a_job_resumes_after_a_core_crash_without_repeating_a_completed_step() {
    let setup = Setup::new("real", POLICY, "");
    let mut daemon = setup.serve();
    let job = setup.submit("system info, then write b.txt: hello");
    let first = setup.pending_approval();
    let first_id = first["approval_id"].as_str().unwrap().to_owned();
    assert_eq!(setup.count("execution_started"), 1, "system.info ran");
    let completed = setup
        .store()
        .tasks(10)
        .unwrap()
        .into_iter()
        .find(|task| task.tool == "system.info")
        .unwrap();
    daemon.crash();

    let daemon = setup.serve();
    let second = setup.pending_approval();
    let second_id = second["approval_id"].as_str().unwrap().to_owned();
    assert_ne!(second_id, first_id, "a new approval, not the old one");
    assert_ne!(second["fingerprint"], first["fingerprint"]);
    assert_eq!(second["arguments"]["path"], "b.txt");
    assert_eq!(setup.count("job_requeued"), 1);
    assert_eq!(setup.count("step_replayed"), 1);
    assert_eq!(
        setup.count("execution_started"),
        1,
        "system.info did not run again"
    );
    let shown = setup.json(&["approvals", "show", &first_id]).remove(0);
    assert_eq!(shown["status"], "expired");
    let output = setup.run(&["approvals", "approve", &first_id, "--yes"]);
    assert_eq!(output.status.code(), Some(1), "the old approval is dead");
    assert_eq!(setup.workspace_file("b.txt"), None);

    let fingerprint = second["fingerprint"].as_str().unwrap();
    let output = setup.run(&[
        "approvals",
        "approve",
        &second_id,
        "--yes",
        "--fingerprint",
        fingerprint,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let done = setup.json(&["job", &job, "--wait"]).remove(0);
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(setup.workspace_file("b.txt").as_deref(), Some("hello"));
    assert!(setup.shutdown(daemon).success());

    assert_eq!(setup.count("execution_started"), 2, "one per tool, no more");
    assert_eq!(setup.count("approval_consumed"), 1);
    let replayed: Vec<_> = setup
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            AuditEventKind::StepReplayed { seq, task_id, .. } => Some((seq, task_id)),
            _ => None,
        })
        .collect();
    assert_eq!(replayed, [(1, completed.task_id)]);
    let old = setup
        .store()
        .approval(first_id.parse().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(old.status, ApprovalStatus::Expired);
}

/// A worker that dies right after step 1 is answered, on every attempt. Each
/// attempt replays step 1, so the tool ran once, and the job ends when its
/// attempts are spent.
#[test]
fn a_job_whose_worker_keeps_dying_replays_its_first_step_until_the_attempts_are_spent() {
    let setup = Setup::new("die-after-first-response", POLICY, "");
    let daemon = setup.serve();
    let job = setup.submit("anything");
    setup.wait_for_kind("job_finished", 1);
    let job = setup.json(&["job", &job]).remove(0);
    assert_eq!(job["status"], "interrupted");
    assert!(job["summary"].as_str().unwrap().contains("attempt limit"));
    assert_eq!(setup.count("job_started"), 3);
    assert_eq!(setup.count("job_requeued"), 2);
    assert_eq!(setup.count("execution_started"), 1, "the tool ran once");
    assert_eq!(setup.count("step_replayed"), 2, "attempts 2 and 3 replayed");
    assert_eq!(setup.store().tasks(10).unwrap().len(), 1);
    drop(daemon);
}

// --- gaming governor (ADR 0016) -----------------------------------------------------------------

/// A name no other process uses, short enough for a Linux `comm`.
fn unique_game_name() -> String {
    let id = TaskId::new().to_string().replace('-', "");
    let stem = format!("jv{}", &id[id.len() - 12..]);
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem
    }
}

/// A stand-in process that is killed and reaped when it goes out of scope,
/// so that a failing assertion does not leave it running.
struct StandIn(Child);

impl StandIn {
    fn kill(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_stand_in_does_not_outlive_its_guard() {
    let dir = tempfile::tempdir().unwrap();
    let stand_in = start_stand_in(dir.path(), &unique_game_name());
    let pid = stand_in.0.id();
    assert!(jarvis_sandbox::process_exists(pid));
    drop(stand_in);
    assert!(!jarvis_sandbox::process_exists(pid));
}

/// Copy a harmless system binary to `dir/name` and run it for two minutes.
/// It is a stand-in for a game, found by its file name like one.
fn start_stand_in(dir: &Path, name: &str) -> StandIn {
    let target = dir.join(name);
    let (source, args): (&str, &[&str]) = if cfg!(windows) {
        (r"C:\Windows\System32\PING.EXE", &["-n", "120", "127.0.0.1"])
    } else {
        ("/bin/sleep", &["120"])
    };
    std::fs::copy(source, &target).unwrap();
    let child = Command::new(&target)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    StandIn(child)
}

impl Setup {
    fn wait_for_governor(&self, state: &str) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let governor = self.health()["governor"].clone();
            if governor["state"] == state {
                return governor;
            }
            assert!(
                Instant::now() < deadline,
                "the governor never became {state}, last {governor}: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
fn the_governor_is_off_unless_the_config_turns_it_on() {
    let setup = Setup::new("real", POLICY, "");
    let daemon = setup.serve();
    setup.wait_for_worker("idle");
    let governor = setup.health()["governor"].clone();
    assert_eq!(
        governor,
        serde_json::json!({"state": "off", "reason": null, "process": null,
                           "held_ms": null, "overdue": false})
    );
    let job = setup.json(&["submit", "describe the runtime", "--wait"]);
    assert_eq!(job[0]["status"], "completed");
    assert!(setup.shutdown(daemon).success());
    assert_eq!(setup.count("governor_hold"), 0);
}

#[test]
fn queued_jobs_wait_while_a_game_runs_and_start_after_it_exits() {
    let game = unique_game_name();
    let setup = Setup::new(
        "real",
        POLICY,
        &format!(
            "[governor]\nenabled = true\nprocesses = [{game:?}]\npoll_ms = 250\n\
             resume_delay_ms = 500\nalert_after_ms = 600000\n"
        ),
    );
    let daemon = setup.serve();
    setup.wait_for_worker("idle");
    setup.wait_for_governor("open");

    let mut stand_in = start_stand_in(setup.dir.path(), &game);
    let held = setup.wait_for_governor("held");
    assert_eq!(held["reason"], "game");
    assert_eq!(held["process"], game.as_str());
    setup.wait_for_kind("governor_hold", 1);

    let job = setup.submit("describe the runtime");
    std::thread::sleep(Duration::from_millis(1500));
    let status = setup.json(&["job", &job]).remove(0);
    assert_eq!(status["status"], "queued", "held while the game runs");
    assert_eq!(setup.count("job_started"), 0);
    assert_eq!(setup.health()["queued_jobs"], 1);

    stand_in.kill();
    let done = setup
        .json(&["job", &job, "--wait", "--timeout", "30s"])
        .remove(0);
    assert_eq!(done["status"], "completed", "{}", setup.log());
    assert_eq!(setup.health()["governor"]["state"], "open");

    let events = setup.events();
    let seq = |kind: &str| {
        events
            .iter()
            .find(|event| event.event.name() == kind)
            .map(|event| event.seq)
            .unwrap_or_else(|| panic!("no {kind} in the audit log"))
    };
    assert!(seq("governor_hold") < seq("governor_released"));
    assert!(
        seq("governor_released") < seq("job_started"),
        "the release is recorded before the job starts"
    );
    let process = events.iter().find_map(|event| match &event.event {
        AuditEventKind::GovernorHold { process, .. } => process.clone(),
        _ => None,
    });
    assert_eq!(process.as_deref(), Some(game.as_str()));
    assert!(setup.shutdown(daemon).success(), "{}", setup.log());
}

/// A stand-in for the desktop app: any process the test can end.
fn start_parent() -> Child {
    let (program, args): (&str, &[&str]) = if cfg!(windows) {
        (r"C:\Windows\System32\PING.EXE", &["-n", "60", "127.0.0.1"])
    } else {
        ("/bin/sleep", &["60"])
    };
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn a_core_started_with_exit_with_stops_when_that_process_exits() {
    let setup = Setup::new("real", POLICY, "");
    let mut parent = start_parent();
    let pid = parent.id().to_string();
    let log = std::fs::File::create(setup.dir.path().join("core-exit-with.log")).unwrap();
    let mut core = setup
        .cli(&["serve", "--exit-with", &pid])
        .stdout(Stdio::piped())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(core.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    assert!(first.starts_with("ready "), "{first:?}: {}", setup.log());
    setup.wait_for_worker("idle");

    parent.kill().unwrap();
    parent.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = core.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the Core outlived the process it follows: {}",
            setup.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success(), "{status:?}: {}", setup.log());
    let events = Store::open_read_only(&setup.database())
        .unwrap()
        .audit_events(None, 10_000)
        .unwrap();
    assert_eq!(
        events.last().map(|e| e.event.name()),
        Some("core_stopped"),
        "the Core stopped cleanly"
    );
    assert!(setup.log().contains("--exit-with"), "{}", setup.log());
}

#[test]
fn a_core_told_to_follow_a_missing_process_does_not_start() {
    let setup = Setup::new("real", POLICY, "");
    let mut gone = start_parent();
    let pid = gone.id();
    gone.kill().unwrap();
    gone.wait().unwrap();
    let output = setup
        .cli(&["serve", "--exit-with", &pid.to_string()])
        .output()
        .unwrap();
    // On Windows a reaped ID may already belong to another process; then
    // the Core would follow that one, which this test cannot rule out.
    if cfg!(unix) || !jarvis_sandbox::process_exists(pid) {
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).is_empty(),
            "never ready"
        );
    }
}
