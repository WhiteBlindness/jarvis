//! Containment probes: a real Python child tries to do what containment
//! should stop, and reports through its exit code.
//!
//! Needs a Python 3 interpreter, named by `JARVIS_TEST_PYTHON` or found as
//! `python3` (`python` on Windows).

use std::process::Stdio;
use std::time::Duration;

use jarvis_sandbox::{Limits, contain, prepare, process_exists};
use tokio::process::{Child, Command};

const LIMITS: Limits = Limits {
    memory_bytes: 256 * 1024 * 1024,
};

fn python() -> String {
    std::env::var("JARVIS_TEST_PYTHON")
        .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned())
}

fn spawn(code: &str) -> (Child, jarvis_sandbox::Contained) {
    let mut command = Command::new(python());
    command
        .args(["-I", "-B", "-c", code])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    prepare(&mut command, &LIMITS);
    let child = command.spawn().expect("cannot start python");
    let contained = contain(&child, &LIMITS).expect("containment failed");
    (child, contained)
}

async fn exit_code(mut child: Child) -> Option<i32> {
    tokio::time::timeout(Duration::from_secs(60), child.wait())
        .await
        .expect("child did not exit")
        .unwrap()
        .code()
}

#[tokio::test]
async fn memory_limit_applies() {
    let (child, contained) = spawn(
        "import sys\ntry:\n    b = bytearray(1024 * 1024 * 1024)\nexcept MemoryError:\n    sys.exit(44)\nsys.exit(0)",
    );
    assert!(!contained.describe().is_empty());
    assert_eq!(exit_code(child).await, Some(44), "{}", contained.describe());
}

#[tokio::test]
async fn kill_all_stops_the_worker() {
    let (child, contained) = spawn("import time\ntime.sleep(60)");
    let pid = child.id().unwrap();
    assert!(contained.contains(pid));
    assert!(process_exists(pid));
    contained.kill_all().unwrap();
    let code = exit_code(child).await;
    assert_ne!(code, Some(0));
    assert!(!process_exists(pid));
}

#[tokio::test]
async fn unrelated_processes_are_not_contained() {
    let (child, contained) = spawn("import time\ntime.sleep(60)");
    assert!(!contained.contains(std::process::id()));
    contained.kill_all().unwrap();
    let _ = exit_code(child).await;
}

#[cfg(unix)]
#[tokio::test]
async fn descendants_are_in_the_process_group_and_killed_with_it() {
    let (child, contained) = spawn(
        "import subprocess, sys, time\n\
         p = subprocess.Popen(['sleep', '60'])\n\
         print(p.pid, file=sys.stderr, flush=True)\n\
         time.sleep(60)",
    );
    let mut child = child;
    let stderr = child.stderr.take().unwrap();
    let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(stderr));
    let grandchild: u32 = lines
        .next_line()
        .await
        .unwrap()
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(contained.contains(grandchild));
    contained.kill_all().unwrap();
    let _ = exit_code(child).await;
    for _ in 0..100 {
        if !process_exists(grandchild) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("grandchild survived kill_all");
}

#[cfg(windows)]
#[tokio::test]
async fn child_processes_are_refused() {
    let (child, contained) = spawn(
        "import subprocess, sys\ntry:\n    subprocess.run(['cmd', '/c', 'exit 0'], check=True)\nexcept OSError:\n    sys.exit(42)\nsys.exit(0)",
    );
    assert_eq!(exit_code(child).await, Some(42), "{}", contained.describe());
}

#[cfg(windows)]
#[tokio::test]
async fn low_integrity_cannot_write_user_files() {
    let dir = std::env::temp_dir().join(format!("jarvis-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("probe.txt");
    let code = format!(
        "import sys\ntry:\n    open(r'{}', 'w').write('x')\nexcept PermissionError:\n    sys.exit(43)\nsys.exit(0)",
        target.display()
    );
    let (child, contained) = spawn(&code);
    assert!(contained.describe().contains("low integrity"));
    assert_eq!(exit_code(child).await, Some(43), "{}", contained.describe());
    assert!(!target.exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
#[tokio::test]
async fn dropping_the_guard_kills_the_worker() {
    let (child, contained) = spawn("import time\ntime.sleep(60)");
    let pid = child.id().unwrap();
    drop(contained);
    let code = exit_code(child).await;
    assert_ne!(code, Some(0));
    assert!(!process_exists(pid));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_descendant_that_leaves_the_process_group_is_still_recognised() {
    let (child, contained) = spawn(
        "import os, subprocess, sys, time\n\
         p = subprocess.Popen(['sleep', '60'], start_new_session=True)\n\
         print(p.pid, file=sys.stderr, flush=True)\n\
         time.sleep(60)",
    );
    let mut child = child;
    let stderr = child.stderr.take().unwrap();
    let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(stderr));
    let escaped: u32 = lines
        .next_line()
        .await
        .unwrap()
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        contained.contains(escaped),
        "a new session does not hide a descendant"
    );
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &escaped.to_string()])
        .status();
    contained.kill_all().unwrap();
    let _ = exit_code(child).await;
}

#[cfg(windows)]
#[tokio::test]
async fn the_worker_cannot_open_an_owner_only_pipe() {
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    let name = format!(r"\\.\pipe\jarvis-probe-{}", std::process::id());
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true);
    let server = jarvis_sandbox::create_owner_only_pipe(&options, &name).unwrap();
    // The user who created it can connect.
    let client = ClientOptions::new().open(&name).unwrap();
    server.connect().await.unwrap();
    drop(client);
    drop(server);

    let _server = jarvis_sandbox::create_owner_only_pipe(&options, &name).unwrap();
    let code = format!(
        "import sys\ntry:\n    open(r'{name}', 'r+b')\nexcept PermissionError:\n    sys.exit(45)\nsys.exit(0)"
    );
    let (child, contained) = spawn(&code);
    assert_eq!(exit_code(child).await, Some(45), "{}", contained.describe());
}
