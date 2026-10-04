//! Isolation probes: a real Python child, started through
//! [`jarvis_sandbox::spawn`] under the same kind of [`Confinement`] the Core
//! builds for the worker, tries to do what the boundary must stop, and
//! reports through its exit code. These exercise the real OS boundary, not a
//! static scan.
//!
//! Needs a Python 3 interpreter, named by `JARVIS_TEST_PYTHON` or found as
//! `python3` (`python` on Windows). On Windows it must be a real
//! `python.exe`, not the `py` launcher or a virtual-environment shim, because
//! the worker may not start child processes.
//!
//! Exit-code convention: `44` means the forbidden operation was refused by
//! the OS, `0` means it succeeded (the boundary failed), anything else is an
//! unexpected error. Every probe prints the error it got to stderr, which the
//! assertion shows.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jarvis_sandbox::{Confinement, Grant, Spawned, WorkerCommand, process_exists, spawn};
use tokio::io::AsyncReadExt;

const MEMORY: u64 = 256 * 1024 * 1024;
const DENIED: i32 = 44;

fn python() -> String {
    std::env::var("JARVIS_TEST_PYTHON")
        .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned())
}

/// The interpreter as an absolute path (the sandbox never searches `PATH`).
fn which_python() -> PathBuf {
    let program = python();
    let direct = Path::new(&program);
    let found = if direct.components().count() > 1 {
        Some(direct.to_path_buf())
    } else {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path).find_map(|dir| {
            [program.clone(), format!("{program}.exe")]
                .into_iter()
                .map(|name| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
    };
    let found = found.unwrap_or_else(|| panic!("{program} not found"));
    if cfg!(windows) {
        std::path::absolute(found).unwrap()
    } else {
        found.canonicalize().unwrap()
    }
}

/// The directory trees the Core lets the worker read and execute: the
/// interpreter's own install, plus (Linux) the standard runtime roots.
fn runtime_roots() -> Vec<PathBuf> {
    let program = which_python();
    let mut roots = Vec::new();
    if let Some(bin) = program.parent() {
        roots.push(bin.to_path_buf());
        if cfg!(target_os = "linux")
            && let Some(prefix) = bin.parent()
        {
            roots.push(prefix.to_path_buf());
        }
    }
    if cfg!(target_os = "linux") {
        for root in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt"] {
            roots.push(PathBuf::from(root));
        }
    }
    roots.retain(|root| root.exists());
    roots
}

/// The worker's confinement: no network, no child processes, and a
/// filesystem boundary granting only the runtime.
fn confinement() -> Confinement {
    let mut confinement = Confinement::locked_down(MEMORY);
    for root in runtime_roots() {
        confinement = confinement.grant(Grant::read_execute(root));
    }
    confinement
}

/// The variables the Core passes to the worker; nothing else.
fn environment() -> Vec<(OsString, OsString)> {
    ["PATH", "SYSTEMROOT"]
        .into_iter()
        .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect()
}

fn command(code: &str) -> WorkerCommand {
    WorkerCommand {
        program: which_python(),
        args: ["-I", "-S", "-B", "-c", code]
            .into_iter()
            .map(OsString::from)
            .collect(),
        env: environment(),
        cwd: None,
    }
}

fn start(code: &str) -> Spawned {
    spawn(&command(code), &confinement()).expect("the confined worker did not start")
}

#[derive(Debug)]
struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    controls: String,
}

/// Run `code` confined, with stdin closed, and collect what it reports.
async fn run(code: &str) -> Outcome {
    let Spawned {
        mut process,
        contained,
        stdin,
        mut stdout,
        mut stderr,
    } = start(code);
    drop(stdin);
    let mut out = String::new();
    let mut err = String::new();
    let (read_out, read_err, status) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            stdout.read_to_string(&mut out),
            stderr.read_to_string(&mut err),
            process.wait()
        )
    })
    .await
    .expect("the probe did not finish");
    read_out.unwrap();
    read_err.unwrap();
    Outcome {
        code: status.unwrap().code(),
        stdout: out,
        stderr: err,
        controls: contained.describe().to_owned(),
    }
}

/// Wrap `attempt` (Python statements performing one forbidden operation) so
/// the probe exits 44 if the OS refused it and 0 if it succeeded.
fn denial_probe(attempt: &str) -> String {
    let body: Vec<String> = attempt.lines().map(|line| format!("    {line}")).collect();
    format!(
        "import sys\ntry:\n{}\nexcept OSError as error:\n    print(repr(error), file=sys.stderr)\n    sys.exit({DENIED})\nprint('the operation succeeded', file=sys.stderr)\nsys.exit(0)",
        body.join("\n")
    )
}

async fn assert_denied(what: &str, attempt: &str) {
    let outcome = run(&denial_probe(attempt)).await;
    assert_eq!(
        outcome.code,
        Some(DENIED),
        "{what} was not refused\nstderr: {}\ncontrols: {}",
        outcome.stderr,
        outcome.controls
    );
}

fn py_str(path: &Path) -> String {
    format!("r'{}'", path.display())
}

/// A file the test can read and the worker must not: it lives outside every
/// grant (under the user's profile on Windows, the temp directory on Linux).
struct Canary {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Canary {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jarvis-canary.txt");
        std::fs::write(&path, "canary-secret").unwrap();
        Self { _dir: dir, path }
    }
}

// --- every platform: the worker still works, and dies with the Core -------------------------

#[tokio::test]
async fn the_confined_interpreter_runs_and_reads_its_runtime() {
    let program = which_python();
    let outcome = run(&format!(
        "import sys\nopen({}, 'rb').read(16)\nprint('ready')",
        py_str(&program)
    ))
    .await;
    assert_eq!(outcome.code, Some(0), "{outcome:?}");
    assert_eq!(outcome.stdout.trim(), "ready");
}

#[tokio::test]
async fn only_the_given_environment_reaches_the_worker() {
    let outcome = run(
        "import os, sys\nallowed = {'PATH', 'SYSTEMROOT', 'LC_CTYPE', '__CF_USER_TEXT_ENCODING'}\nextra = sorted(k for k in os.environ if k.upper() not in allowed and not k.startswith('='))\nprint(extra)\nsys.exit(1 if extra else 0)",
    )
    .await;
    assert_eq!(outcome.code, Some(0), "{outcome:?}");
}

#[tokio::test]
async fn the_memory_limit_applies() {
    let outcome = run(
        "import sys\ntry:\n    b = bytearray(1024 * 1024 * 1024)\nexcept MemoryError:\n    sys.exit(44)\nsys.exit(0)",
    )
    .await;
    assert_eq!(outcome.code, Some(DENIED), "{outcome:?}");
}

#[tokio::test]
async fn kill_all_stops_the_worker() {
    let Spawned {
        mut process,
        contained,
        ..
    } = start("import time\ntime.sleep(60)");
    let pid = process.id();
    assert!(contained.contains(pid));
    assert!(!contained.contains(std::process::id()));
    assert!(process_exists(pid));
    contained.kill_all().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), process.wait())
        .await
        .expect("the worker survived kill_all")
        .unwrap();
    assert!(!status.success());
    assert!(!process_exists(pid));
}

#[tokio::test]
async fn dropping_the_process_kills_the_worker() {
    let spawned = start("import time\ntime.sleep(60)");
    let pid = spawned.process.id();
    drop(spawned.process);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while is_running(pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "the worker outlived its handle"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_relative_program_is_refused() {
    let mut command = command("pass");
    command.program = PathBuf::from("python");
    let error = spawn(&command, &confinement()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

/// Whether `pid` is alive. A Linux zombie (killed, not yet reaped by the
/// runtime) counts as gone.
#[cfg(target_os = "linux")]
fn is_running(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let state = stat
        .rfind(')')
        .and_then(|end| stat[end + 1..].split_whitespace().next());
    matches!(state, Some(s) if s != "Z" && s != "X")
}

#[cfg(not(target_os = "linux"))]
fn is_running(pid: u32) -> bool {
    process_exists(pid)
}

// --- hostile probes: filesystem -------------------------------------------------------------

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn reading_a_user_file_is_denied() {
    let canary = Canary::new();
    assert_denied(
        "reading a file outside the grants",
        &format!("open({}, 'rb').read()", py_str(&canary.path)),
    )
    .await;
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn listing_the_home_directory_is_denied() {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .filter(|home| home.is_dir());
    let Some(home) = home else {
        return;
    };
    assert_denied(
        "listing the home directory",
        &format!("import os\nos.listdir({})", py_str(&home)),
    )
    .await;
    // The usual places personal files live, where they exist. Read-only
    // attempts: the test never writes there.
    for name in ["Documents", "Desktop", "Downloads", ".ssh"] {
        let dir = home.join(name);
        if dir.is_dir() {
            assert_denied(
                &format!("listing {name}"),
                &format!("import os\nos.listdir({})", py_str(&dir)),
            )
            .await;
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn writing_outside_the_grants_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("written-by-worker.txt");
    assert_denied(
        "writing to the temp directory",
        &format!("open({}, 'w').write('x')", py_str(&target)),
    )
    .await;
    assert!(!target.exists());
    // Writing into the granted runtime is refused too: the grant is read-only.
    let runtime = runtime_roots().remove(0).join("jarvis-probe.txt");
    assert_denied(
        "writing into the runtime",
        &format!("open({}, 'w').write('x')", py_str(&runtime)),
    )
    .await;
    let leaked = runtime.exists();
    let _ = std::fs::remove_file(&runtime);
    assert!(!leaked);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_files_outside_the_grants_are_denied() {
    for path in ["/etc/passwd", "/etc/hostname", "/proc/1/environ"] {
        assert_denied(
            &format!("reading {path}"),
            &format!("open('{path}', 'rb').read()"),
        )
        .await;
    }
    assert_denied("listing /", "import os\nos.listdir('/')").await;
    assert_denied(
        "writing to /dev/shm",
        "open('/dev/shm/jarvis-probe', 'wb').write(b'x')",
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn changing_file_metadata_is_denied() {
    // chmod on the interpreter (readable, so the call reaches the metadata
    // syscall) is refused by seccomp.
    assert_denied(
        "chmod",
        &format!("import os\nos.chmod({}, 0o755)", py_str(&which_python())),
    )
    .await;
}

// --- hostile probes: network ----------------------------------------------------------------

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn connecting_to_a_loopback_listener_is_denied() {
    use std::net::{TcpListener, UdpSocket};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let tcp = listener.local_addr().unwrap().port();
    let udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp_socket.set_nonblocking(true).unwrap();
    let udp = udp_socket.local_addr().unwrap().port();

    assert_denied(
        "a loopback TCP connection",
        &format!(
            "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout(5)\ns.connect(('127.0.0.1', {tcp}))"
        ),
    )
    .await;
    assert_denied(
        "a loopback UDP datagram",
        &format!(
            "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.sendto(b'x', ('127.0.0.1', {udp}))\ns.settimeout(2)\ns.recv(1)"
        ),
    )
    .await;
    // The test's own end confirms nothing arrived.
    assert!(listener.accept().is_err(), "the listener saw a connection");
    let mut buffer = [0u8; 8];
    assert!(udp_socket.recv(&mut buffer).is_err(), "a datagram arrived");
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn reaching_the_internet_is_denied() {
    // A public address and a public name. If the machine is offline these
    // also fail, which is the same answer; on CI they are reachable for any
    // unconfined process.
    assert_denied(
        "a TCP connection to a public address",
        "import socket\nsocket.create_connection(('1.1.1.1', 443), timeout=5)",
    )
    .await;
    assert_denied(
        "a DNS lookup",
        "import socket\nsocket.getaddrinfo('example.com', 443)",
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn every_kind_of_socket_is_denied() {
    for family in ["AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"] {
        for kind in ["SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW"] {
            assert_denied(
                &format!("socket({family}, {kind})"),
                &format!("import socket\nsocket.socket(socket.{family}, socket.{kind})"),
            )
            .await;
        }
    }
}

// --- hostile probes: processes and handles --------------------------------------------------

#[cfg(target_os = "linux")]
#[tokio::test]
async fn starting_a_child_process_is_denied() {
    assert_denied("fork", "import os\nos.fork()").await;
    assert_denied(
        "subprocess",
        "import subprocess\nsubprocess.run(['/bin/true'])",
    )
    .await;
    assert_denied(
        "a new user namespace",
        "import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\nif libc.unshare(0x10000000) != 0:\n    raise OSError(ctypes.get_errno(), 'unshare')",
    )
    .await;
}

#[cfg(windows)]
#[tokio::test]
async fn starting_a_child_process_is_denied() {
    assert_denied(
        "subprocess",
        "import subprocess\nsubprocess.run(['cmd', '/c', 'exit 0'], check=True)",
    )
    .await;
    // CREATE_BREAKAWAY_FROM_JOB: an attempt to escape the job object.
    assert_denied(
        "a process that breaks away from the job",
        "import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'pass'], creationflags=0x01000000, check=True)",
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reading_another_process_is_denied() {
    let parent = std::process::id();
    assert_denied(
        "reading the Core's memory",
        &format!("open('/proc/{parent}/mem', 'rb').read(1)"),
    )
    .await;
}

#[cfg(windows)]
#[tokio::test]
async fn reading_another_process_is_denied() {
    let parent = std::process::id();
    assert_denied(
        "opening the Core's process for reading",
        &format!(
            "import ctypes\nfrom ctypes import wintypes\nk = ctypes.WinDLL('kernel32', use_last_error=True)\nk.OpenProcess.restype = wintypes.HANDLE\nh = k.OpenProcess(0x0010 | 0x0400, False, {parent})\nif not h:\n    raise ctypes.WinError(ctypes.get_last_error())"
        ),
    )
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_inheritable_descriptor_does_not_reach_the_worker() {
    use std::os::fd::AsRawFd;

    let canary = Canary::new();
    let file = std::fs::File::open(&canary.path).unwrap();
    let fd = file.as_raw_fd();
    // Make it inheritable, as a careless parent might.
    // SAFETY: clearing FD_CLOEXEC on a descriptor this test owns.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    assert_denied(
        "using an inherited descriptor",
        &format!("import os\nos.fstat({fd})"),
    )
    .await;
}

#[cfg(windows)]
#[tokio::test]
async fn an_inheritable_handle_does_not_reach_the_worker() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

    let canary = Canary::new();
    let file = std::fs::File::open(&canary.path).unwrap();
    let handle = file.as_raw_handle();
    // SAFETY: marking a handle this test owns as inheritable.
    let ok = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
    assert_ne!(ok, 0);
    let value = handle as usize;
    assert_denied(
        "using an inherited handle",
        &format!(
            "import ctypes\nfrom ctypes import wintypes\nk = ctypes.WinDLL('kernel32', use_last_error=True)\nk.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]\nbuf = ctypes.create_unicode_buffer(1024)\nn = k.GetFinalPathNameByHandleW(wintypes.HANDLE({value}), buf, 1024, 0)\nif n == 0 or 'jarvis-canary' not in buf.value:\n    raise OSError('the handle was not inherited')"
        ),
    )
    .await;
}

// --- Windows: identity and the Core's pipe --------------------------------------------------

#[cfg(windows)]
#[tokio::test]
async fn the_worker_runs_in_an_app_container_at_low_integrity() {
    // TokenIsAppContainer = 29, TokenIntegrityLevel = 25; low = 0x1000.
    let outcome = run(
        "import ctypes, sys\nfrom ctypes import wintypes\na = ctypes.WinDLL('advapi32', use_last_error=True)\nk = ctypes.WinDLL('kernel32', use_last_error=True)\nk.GetCurrentProcess.restype = wintypes.HANDLE\ntoken = wintypes.HANDLE()\nif not a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, ctypes.byref(token)):\n    raise ctypes.WinError(ctypes.get_last_error())\nvalue = wintypes.DWORD()\nn = wintypes.DWORD()\na.GetTokenInformation(token, 29, ctypes.byref(value), 4, ctypes.byref(n))\nbuf = ctypes.create_string_buffer(64)\na.GetTokenInformation(token, 25, buf, 64, ctypes.byref(n))\na.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)\na.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)\nsid = ctypes.c_void_p.from_buffer(buf).value\ncount = a.GetSidSubAuthorityCount(ctypes.c_void_p(sid)).contents.value\nlevel = a.GetSidSubAuthority(ctypes.c_void_p(sid), count - 1).contents.value\nprint(value.value, hex(level))\nsys.exit(0 if value.value == 1 and level <= 0x1000 else 1)",
    )
    .await;
    assert_eq!(outcome.code, Some(0), "{outcome:?}");
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
    // The owner (this test) can connect.
    let server = jarvis_sandbox::create_owner_only_pipe(&options, &name).unwrap();
    let client = ClientOptions::new().open(&name).unwrap();
    server.connect().await.unwrap();
    drop(client);
    drop(server);

    let name = format!("{name}-worker");
    let _server = jarvis_sandbox::create_owner_only_pipe(&options, &name).unwrap();
    assert_denied(
        "opening the Core's pipe",
        &format!("open(r'{name}', 'r+b')"),
    )
    .await;
}

#[cfg(windows)]
#[tokio::test]
async fn the_rpc_check_recognises_the_worker_as_restricted() {
    let Spawned {
        process, contained, ..
    } = start("import time\ntime.sleep(60)");
    assert!(jarvis_sandbox::is_restricted_process(process.id()).unwrap());
    assert!(!jarvis_sandbox::is_restricted_process(std::process::id()).unwrap());
    contained.kill_all().unwrap();
}

// --- measurements ---------------------------------------------------------------------------

/// Not a pass/fail test: prints the cost of isolation on this machine.
/// CI runs it with `--ignored --nocapture` and the numbers appear in the log.
#[tokio::test]
#[ignore = "measurement; run explicitly"]
async fn measure_isolation_overhead() {
    const RUNS: usize = 7;
    let program = which_python();
    let mut plain = Vec::new();
    let mut confined = Vec::new();
    for _ in 0..RUNS {
        let started = std::time::Instant::now();
        let status = tokio::process::Command::new(&program)
            .args(["-I", "-S", "-B", "-c", "pass"])
            .env_clear()
            .envs(environment())
            .status()
            .await
            .unwrap();
        assert!(status.success());
        plain.push(started.elapsed());

        let started = std::time::Instant::now();
        let outcome = run("pass").await;
        assert_eq!(outcome.code, Some(0), "{outcome:?}");
        confined.push(started.elapsed());
    }
    plain.sort();
    confined.sort();
    println!(
        "interpreter start to exit, median of {RUNS}: unconfined {:?}, confined {:?}",
        plain[RUNS / 2],
        confined[RUNS / 2]
    );

    // Resident memory of an idle confined interpreter that has imported the
    // modules the worker uses.
    let Spawned {
        process,
        contained,
        mut stdout,
        ..
    } = start(
        "import json, sys, uuid, dataclasses\nprint('ready', flush=True)\nimport time\ntime.sleep(30)",
    );
    let mut ready = [0u8; 6];
    stdout.read_exact(&mut ready).await.unwrap();
    println!(
        "idle confined interpreter resident memory: {} KiB",
        resident_kib(process.id())
    );
    contained.kill_all().unwrap();
}

#[cfg(target_os = "linux")]
fn resident_kib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

#[cfg(windows)]
fn resident_kib(pid: u32) -> u64 {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: opens the process for a query; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    assert!(!process.is_null());
    // SAFETY: an all-zero PROCESS_MEMORY_COUNTERS is valid.
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: a valid process handle and a correctly sized structure.
    let ok = unsafe { K32GetProcessMemoryInfo(process, &mut counters, size) };
    // SAFETY: the handle opened above.
    unsafe { CloseHandle(process) };
    assert_ne!(ok, 0);
    counters.WorkingSetSize as u64 / 1024
}

#[cfg(not(any(target_os = "linux", windows)))]
fn resident_kib(_pid: u32) -> u64 {
    0
}
