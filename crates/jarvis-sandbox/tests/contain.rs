//! Containment probes: a real Python child tries to do what the confinement
//! should stop, and reports through its exit code. The child runs under the
//! same [`Confinement`] the Core builds for the worker, so these tests
//! exercise the real boundary, not a static scan.
//!
//! Needs a Python 3 interpreter, named by `JARVIS_TEST_PYTHON` or found as
//! `python3` (`python` on Windows).
//!
//! Exit-code convention for the probe snippets: `44` means the forbidden
//! operation was denied as expected, `0` means it unexpectedly succeeded
//! (the boundary failed), any other code is an unexpected error.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use jarvis_sandbox::{Confinement, Grant, contain, prepare, process_exists};
use tokio::process::{Child, Command};

const MEMORY: u64 = 256 * 1024 * 1024;

fn python() -> String {
    std::env::var("JARVIS_TEST_PYTHON")
        .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned())
}

/// The directory trees the worker is allowed to read and execute from, the
/// same set the Core grants: the interpreter's own location and the standard
/// runtime roots.
fn runtime_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(program) = which_python()
        && let Some(bin) = program.parent()
    {
        roots.push(bin.to_path_buf());
        if let Some(prefix) = bin.parent() {
            roots.push(prefix.to_path_buf());
        }
    }
    for root in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt"] {
        roots.push(PathBuf::from(root));
    }
    roots.retain(|r| r.exists());
    roots
}

fn which_python() -> std::io::Result<PathBuf> {
    let program = python();
    let direct = std::path::Path::new(&program);
    if direct.components().count() > 1 {
        return direct.canonicalize();
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(&program))
        .find_map(|c| c.canonicalize().ok())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
}

/// The worker's confinement: no network, no child processes, and (on Linux)
/// a Landlock filesystem boundary granting only the runtime roots.
fn confinement() -> Confinement {
    let mut c = Confinement::locked_down(MEMORY);
    for root in runtime_roots() {
        c = c.grant(Grant::read_execute(root));
    }
    c
}

fn spawn_with(code: &str, confinement: &Confinement) -> (Child, jarvis_sandbox::Contained) {
    let mut command = Command::new(python());
    command
        .args(["-I", "-S", "-B", "-c", code])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    prepare(&mut command, confinement).expect("prepare");
    let child = command.spawn().expect("cannot start python");
    let contained = contain(&child, confinement).expect("containment failed");
    (child, contained)
}

fn spawn(code: &str) -> (Child, jarvis_sandbox::Contained) {
    spawn_with(code, &confinement())
}

async fn exit_code(mut child: Child) -> Option<i32> {
    tokio::time::timeout(Duration::from_secs(60), child.wait())
        .await
        .expect("child did not exit")
        .unwrap()
        .code()
}

/// Run a probe that must report denial (exit 44).
#[cfg(target_os = "linux")]
async fn assert_denied(code: &str) {
    let (child, contained) = spawn(code);
    assert_eq!(
        exit_code(child).await,
        Some(44),
        "operation was not denied; confinement = {}",
        contained.describe()
    );
}

// --- lifecycle (all platforms) ------------------------------------------------------------------

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

// --- Linux: Landlock + seccomp ------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_runtime_is_readable_so_the_worker_runs() {
    // A granted read of the interpreter's own file succeeds: the boundary
    // does not break the worker.
    let program = which_python().unwrap();
    let code = format!(
        "import sys\nopen(r'{}', 'rb').read(16)\nsys.exit(0)",
        program.display()
    );
    let (child, contained) = spawn(&code);
    assert_eq!(exit_code(child).await, Some(0), "{}", contained.describe());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reading_outside_the_grants_is_denied() {
    for path in ["/etc/passwd", "/etc/hostname"] {
        assert_denied(&format!(
            "import sys\ntry:\n    open('{path}', 'rb').read()\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)"
        ))
        .await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reading_the_home_directory_is_denied() {
    // A canary the test can read but the worker must not: it is under the
    // home directory, outside every grant.
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let Some(home) = home.filter(|h| h.exists()) else {
        return;
    };
    let canary = home.join(format!(".jarvis-probe-{}", std::process::id()));
    std::fs::write(&canary, b"secret").unwrap();
    let code = format!(
        "import sys\ntry:\n    open(r'{}', 'rb').read()\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)",
        canary.display()
    );
    let (child, contained) = spawn(&code);
    let code = exit_code(child).await;
    let _ = std::fs::remove_file(&canary);
    assert_eq!(
        code,
        Some(44),
        "home read not denied: {}",
        contained.describe()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn listing_the_root_directory_is_denied() {
    assert_denied(
        "import os, sys\ntry:\n    os.listdir('/')\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)",
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn writing_anywhere_is_denied() {
    for path in ["/tmp/jarvis-probe", "/dev/shm/jarvis-probe"] {
        assert_denied(&format!(
            "import sys\ntry:\n    open('{path}', 'wb').write(b'x')\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)"
        ))
        .await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reading_another_process_is_denied() {
    assert_denied(
        "import sys\ntry:\n    open('/proc/1/environ', 'rb').read()\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)",
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn every_kind_of_socket_is_denied() {
    for family in ["AF_INET", "AF_INET6", "AF_UNIX"] {
        for kind in ["SOCK_STREAM", "SOCK_DGRAM"] {
            assert_denied(&format!(
                "import socket, sys\ntry:\n    socket.socket(socket.{family}, socket.{kind})\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)"
            ))
            .await;
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn connecting_to_a_loopback_listener_is_denied() {
    // Bind a real listener in the test; the confined worker must not reach it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    assert_denied(&format!(
        "import socket, sys\ntry:\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    s.connect(('127.0.0.1', {port}))\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)"
    ))
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn starting_a_child_process_is_denied() {
    assert_denied(
        "import os, sys\ntry:\n    os.fork()\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)",
    )
    .await;
    assert_denied(
        "import subprocess, sys\ntry:\n    subprocess.run(['/bin/true'])\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)",
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn changing_file_metadata_is_denied() {
    // chmod on the interpreter (readable, so the call reaches the metadata
    // syscall) is refused by seccomp.
    let program = which_python().unwrap();
    assert_denied(&format!(
        "import os, sys\ntry:\n    os.chmod(r'{}', 0o755)\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)",
        program.display()
    ))
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn unavailable_landlock_fails_closed() {
    // A grant for a path that cannot be opened must not silently drop the
    // boundary; here we assert the normal path builds. (A kernel without
    // Landlock makes prepare error, which the supervisor turns into a failed
    // spawn; that is covered by the process tests.)
    let (child, contained) = spawn("import sys\nsys.exit(0)");
    assert!(contained.describe().contains("landlock filesystem"));
    assert_eq!(exit_code(child).await, Some(0));
}

// --- Windows: AppContainer / job object ---------------------------------------------------------

#[cfg(windows)]
#[tokio::test]
async fn child_processes_are_refused() {
    let (child, contained) = spawn(
        "import subprocess, sys\ntry:\n    subprocess.run(['cmd', '/c', 'exit 0'], check=True)\nexcept OSError:\n    sys.exit(44)\nsys.exit(0)",
    );
    assert_eq!(exit_code(child).await, Some(44), "{}", contained.describe());
}

#[cfg(windows)]
#[tokio::test]
async fn writing_user_files_is_denied() {
    let dir = std::env::temp_dir().join(format!("jarvis-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("probe.txt");
    let code = format!(
        "import sys\ntry:\n    open(r'{}', 'w').write('x')\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)",
        target.display()
    );
    let (child, contained) = spawn(&code);
    let got = exit_code(child).await;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(got, Some(44), "{}", contained.describe());
}

#[cfg(windows)]
#[tokio::test]
async fn dropping_the_guard_kills_the_worker() {
    let (mut child, _contained) = spawn("import time\ntime.sleep(60)");
    let pid = child.id().unwrap();
    drop(_contained);
    tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("the worker outlived its job")
        .unwrap();
    assert!(!process_exists(pid));
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
    let client = ClientOptions::new().open(&name).unwrap();
    server.connect().await.unwrap();
    drop(client);
    drop(server);

    let name = format!("{name}-low");
    let _server = jarvis_sandbox::create_owner_only_pipe(&options, &name).unwrap();
    let code = format!(
        "import sys\ntry:\n    open(r'{name}', 'r+b')\n    sys.exit(0)\nexcept OSError:\n    sys.exit(44)"
    );
    let (child, contained) = spawn(&code);
    assert_eq!(exit_code(child).await, Some(44), "{}", contained.describe());
}
