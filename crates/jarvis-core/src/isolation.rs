//! What the worker may reach, and proof that the OS enforces it.
//!
//! [`launch`] decides what the worker legitimately needs (read and execute
//! on its interpreter and the libraries that load it, read on its own
//! source) and nothing else: no network, no child processes, no access to
//! the user's files or the Core's data. [`jarvis_sandbox`] enforces that per
//! OS (ADRs 0013 and 0014).
//!
//! [`verify`] does not take the enforcement on trust. Before the first
//! worker starts, the Core runs a short probe under the identical isolation
//! and checks, from its own side, that the probe could not connect to a
//! loopback listener the Core holds, could not send it a datagram, could not
//! read a file the Core just wrote next to its database, and could not start
//! a process. If any check fails, or the probe cannot run at all, the Core
//! refuses to start the worker.

use std::collections::hash_map::RandomState;
use std::ffi::OsString;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use jarvis_sandbox::{Confinement, Grant, Spawned, WorkerCommand};
use tokio::io::AsyncReadExt;

use crate::config::WorkerConfig;

/// Variables the worker keeps from the Core's environment: enough to find
/// and start an interpreter, nothing else. `SYSTEMROOT` is required by
/// Windows system libraries.
pub const PASSTHROUGH_ENV: &[&str] = &["PATH", "SYSTEMROOT"];

/// Standard directories that hold an interpreter, its dynamic loader and the
/// C library across common Linux layouts. Granted read and execute only if
/// they exist; the user's home is never among them.
#[cfg(target_os = "linux")]
const RUNTIME_ROOTS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt"];

/// The longest the start-up probe may take, including a first start on
/// Windows that grants the runtime directory to the worker's identity.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest probe output read; a valid report is far smaller.
const PROBE_OUTPUT_LIMIT: u64 = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    #[error("worker program {0:?} was not found (as a path, or on PATH)")]
    ProgramNotFound(String),
    #[error("the worker cannot be started in isolation: {0}")]
    Spawn(io::Error),
    #[error("the isolation probe did not run correctly: {0}")]
    Probe(String),
    #[error("worker isolation is not enforced on this machine: {}", failed(.0))]
    NotEnforced(Vec<Check>),
}

fn failed(checks: &[Check]) -> String {
    checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| format!("{} ({})", check.name, check.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Everything needed to start the worker: the exact command (absolute
/// program, arguments, complete environment, working directory) and the
/// isolation it runs under.
#[derive(Debug, Clone)]
pub struct WorkerLaunch {
    pub command: WorkerCommand,
    pub confinement: Confinement,
}

/// Resolve the worker program and build its command and confinement.
pub fn launch(config: &WorkerConfig) -> Result<WorkerLaunch, IsolationError> {
    let program = resolve_program(&config.program)
        .ok_or_else(|| IsolationError::ProgramNotFound(config.program.clone()))?;
    let env = PASSTHROUGH_ENV
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect();
    let mut confinement = Confinement::locked_down(config.memory_limit_bytes);
    // The interpreter and the directories that hold it and its libraries.
    for root in runtime_roots(&program) {
        confinement = confinement.grant(Grant::read_execute(root));
    }
    // The worker's own source tree (code, not user data), as an absolute
    // path so the grant and the working directory name the same place.
    let cwd = match &config.cwd {
        Some(cwd) => Some(absolute_dir(cwd).map_err(IsolationError::Spawn)?),
        None => None,
    };
    if let Some(cwd) = &cwd {
        confinement = confinement.grant(Grant::read(cwd.clone()));
    }
    Ok(WorkerLaunch {
        command: WorkerCommand {
            program,
            args: config.args.iter().map(OsString::from).collect(),
            env,
            cwd,
        },
        confinement,
    })
}

/// The directory trees the worker may read and execute from.
fn runtime_roots(program: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(bin) = program.parent() {
        // The interpreter's own directory. On Windows that is the whole
        // CPython install (`python.exe`, `DLLs`, `Lib`); system libraries
        // are readable by every AppContainer already.
        roots.push(bin.to_path_buf());
        // On Linux the install prefix one level up (`/usr`, a toolcache or
        // a per-user build) holds the standard library.
        #[cfg(target_os = "linux")]
        if let Some(prefix) = bin.parent() {
            roots.push(prefix.to_path_buf());
        }
    }
    #[cfg(target_os = "linux")]
    for root in RUNTIME_ROOTS {
        roots.push(PathBuf::from(root));
    }
    roots.retain(|root| root.exists());
    roots.sort();
    // A root inside another root adds nothing.
    let mut kept: Vec<PathBuf> = Vec::new();
    for root in roots {
        if !kept.iter().any(|outer| root.starts_with(outer)) {
            kept.push(root);
        }
    }
    kept
}

/// An existing directory as an absolute path (canonical on Unix; on Windows
/// without the `\\?\` prefix that canonicalisation adds).
fn absolute_dir(dir: &Path) -> io::Result<PathBuf> {
    let absolute = if cfg!(windows) {
        std::path::absolute(dir)?
    } else {
        dir.canonicalize()?
    };
    if !absolute.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("worker directory {} does not exist", dir.display()),
        ));
    }
    Ok(absolute)
}

/// Resolve the worker program to an absolute path: a path with a separator
/// is taken as given, a bare name is looked up on `PATH` (with `.exe` on
/// Windows). On Linux the result is canonical, so the Landlock rules name
/// the real directories.
pub fn resolve_program(program: &str) -> Option<PathBuf> {
    let direct = Path::new(program);
    let found = if direct.components().count() > 1 || direct.is_absolute() {
        direct.is_file().then(|| direct.to_path_buf())
    } else {
        let path = std::env::var_os("PATH")?;
        let names: Vec<String> = if cfg!(windows) && Path::new(program).extension().is_none() {
            vec![format!("{program}.exe"), program.to_owned()]
        } else {
            vec![program.to_owned()]
        };
        std::env::split_paths(&path).find_map(|dir| {
            names
                .iter()
                .map(|name| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
    }?;
    if cfg!(windows) {
        // Not canonicalize: on Windows it yields `\\?\` paths, which the
        // interpreter would then report as its own location.
        std::path::absolute(found).ok()
    } else {
        found.canonicalize().ok()
    }
}

/// One isolation check run by [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The result of a successful [`verify`].
#[derive(Debug, Clone)]
pub struct Verification {
    pub checks: Vec<Check>,
    pub elapsed: Duration,
    /// The controls the probe ran under, as the sandbox describes them.
    pub controls: String,
}

/// The probe. It reports what happened; the Core trusts only what it can
/// observe itself (its listener, its datagram socket, its canary's content)
/// plus the probe's report of refusals, and treats anything unexpected as a
/// failure.
const PROBE: &str = r#"
import json, socket, subprocess, sys
tcp, udp, canary = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
report = {}
def attempt(name, action):
    try:
        action()
    except OSError as error:
        report[name] = "denied: " + type(error).__name__
    else:
        report[name] = "allowed"
def connect_tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", tcp))
    s.sendall(b"probe")
def send_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"probe", ("127.0.0.1", udp))
def read_canary():
    with open(canary, "rb") as f:
        report["canary"] = f.read(128).decode("ascii", "replace")
def start_process():
    subprocess.run([sys.executable, "-c", "pass"], check=True, timeout=10)
attempt("loopback_tcp", connect_tcp)
attempt("loopback_udp", send_udp)
attempt("core_file", read_canary)
attempt("child_process", start_process)
print(json.dumps(report), flush=True)
"#;

/// Run the probe under `launch`'s isolation and check the result. `scratch`
/// is a directory the worker is not granted (the database's directory):
/// the canary file is written there and removed afterwards.
pub async fn verify(launch: &WorkerLaunch, scratch: &Path) -> Result<Verification, IsolationError> {
    let started = Instant::now();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(probe_io)?;
    listener.set_nonblocking(true).map_err(probe_io)?;
    let datagrams = std::net::UdpSocket::bind("127.0.0.1:0").map_err(probe_io)?;
    datagrams.set_nonblocking(true).map_err(probe_io)?;
    let tcp = listener.local_addr().map_err(probe_io)?.port();
    let udp = datagrams.local_addr().map_err(probe_io)?.port();

    let secret = nonce();
    // Absolute: the probe runs in the worker's working directory.
    let scratch = std::path::absolute(scratch).map_err(probe_io)?;
    let canary = scratch.join(format!(".jarvis-isolation-probe-{}", std::process::id()));
    std::fs::write(&canary, &secret).map_err(probe_io)?;
    let outcome = run_probe(launch, tcp, udp, &canary).await;
    let _ = std::fs::remove_file(&canary);
    let (report, stdout, controls) = outcome?;

    let probe_said = |name: &str| {
        report
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing")
            .to_owned()
    };
    let refused = |said: &str| said.starts_with("denied");
    let mut checks = Vec::new();

    let said = probe_said("loopback_tcp");
    let connected = listener.accept().is_ok();
    checks.push(Check {
        name: "no loopback TCP",
        passed: !connected && refused(&said),
        detail: if connected {
            "the Core's listener accepted a connection".to_owned()
        } else {
            said
        },
    });

    let mut buffer = [0u8; 16];
    let received = datagrams.recv(&mut buffer).is_ok();
    checks.push(Check {
        name: "no loopback UDP",
        passed: !received,
        detail: if received {
            "the Core's socket received a datagram".to_owned()
        } else {
            probe_said("loopback_udp")
        },
    });

    // The canary exists, so only a permission error counts: "not found"
    // would mean the probe looked in the wrong place.
    let said = probe_said("core_file");
    let leaked = stdout.contains(&secret);
    checks.push(Check {
        name: "no access to the Core's files",
        passed: !leaked && said == "denied: PermissionError",
        detail: if leaked {
            "the probe read a file next to the database".to_owned()
        } else {
            said
        },
    });

    if launch.confinement.deny_child_processes {
        let said = probe_said("child_process");
        checks.push(Check {
            name: "no child processes",
            passed: refused(&said),
            detail: said,
        });
    }

    if checks.iter().all(|check| check.passed) {
        Ok(Verification {
            checks,
            elapsed: started.elapsed(),
            controls,
        })
    } else {
        Err(IsolationError::NotEnforced(checks))
    }
}

/// Start the probe with the worker's program, environment, working
/// directory and confinement, and collect its one-line report.
async fn run_probe(
    launch: &WorkerLaunch,
    tcp: u16,
    udp: u16,
    canary: &Path,
) -> Result<(serde_json::Map<String, serde_json::Value>, String, String), IsolationError> {
    let mut command = launch.command.clone();
    command.args = ["-I", "-S", "-B", "-c", PROBE]
        .into_iter()
        .map(OsString::from)
        .chain([
            OsString::from(tcp.to_string()),
            OsString::from(udp.to_string()),
            canary.as_os_str().to_owned(),
        ])
        .collect();
    let Spawned {
        mut process,
        contained,
        stdin,
        stdout,
        stderr,
    } = jarvis_sandbox::spawn(&command, &launch.confinement).map_err(IsolationError::Spawn)?;
    drop(stdin);
    let mut out = String::new();
    let mut err = String::new();
    let mut stdout = stdout.take(PROBE_OUTPUT_LIMIT);
    let mut stderr = stderr.take(PROBE_OUTPUT_LIMIT);
    let finished = tokio::time::timeout(PROBE_TIMEOUT, async {
        tokio::join!(
            stdout.read_to_string(&mut out),
            stderr.read_to_string(&mut err),
            process.wait()
        )
    })
    .await;
    let Ok((read_out, _, status)) = finished else {
        let _ = contained.kill_all();
        return Err(IsolationError::Probe(format!(
            "it did not finish within {} s",
            PROBE_TIMEOUT.as_secs()
        )));
    };
    let _ = contained.kill_all();
    let status = status.map_err(probe_io)?;
    read_out.map_err(probe_io)?;
    let stderr_tail = tail(&err, 400);
    if !status.success() {
        return Err(IsolationError::Probe(format!(
            "it exited with {status}; stderr: {}",
            stderr_tail.trim()
        )));
    }
    let line = out.lines().last().unwrap_or_default();
    let report = serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| {
            IsolationError::Probe(format!(
                "it printed no report; stderr: {}",
                stderr_tail.trim()
            ))
        })?;
    Ok((report, out, contained.describe().to_owned()))
}

/// The last `max` characters of `text`, for error messages.
fn tail(text: &str, max: usize) -> String {
    let skip = text.chars().count().saturating_sub(max);
    text.chars().skip(skip).collect()
}

fn probe_io(error: io::Error) -> IsolationError {
    IsolationError::Probe(error.to_string())
}

/// 128 random bits as hex, from the standard library's OS-seeded hasher keys.
fn nonce() -> String {
    let mut text = String::new();
    for salt in 0..2u8 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u8(salt);
        text.push_str(&format!("{:016x}", hasher.finish()));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_program_is_reported() {
        assert!(resolve_program("jarvis-no-such-interpreter").is_none());
        let config = WorkerConfig {
            program: "jarvis-no-such-interpreter".to_owned(),
            args: Vec::new(),
            cwd: None,
            handshake_timeout: Duration::from_secs(1),
            memory_limit_bytes: 1 << 28,
        };
        assert!(matches!(
            launch(&config),
            Err(IsolationError::ProgramNotFound(_))
        ));
    }

    #[test]
    fn the_worker_gets_its_runtime_and_source_and_nothing_writable() {
        let program = std::env::current_exe().unwrap();
        let source = std::env::temp_dir();
        let config = WorkerConfig {
            program: program.display().to_string(),
            args: vec!["-m".to_owned(), "jarvis_worker".to_owned()],
            cwd: Some(source.clone()),
            handshake_timeout: Duration::from_secs(1),
            memory_limit_bytes: 1 << 28,
        };
        let launch = launch(&config).unwrap();
        assert!(launch.command.program.is_absolute());
        assert!(launch.confinement.deny_network);
        assert!(launch.confinement.deny_child_processes);
        let grants = &launch.confinement.filesystem;
        assert!(
            grants
                .iter()
                .all(|g| g.access != jarvis_sandbox::Access::ReadWrite)
        );
        assert!(grants.contains(&Grant::read(source)));
        assert!(grants.iter().any(
            |g| program.starts_with(&g.path) && g.access == jarvis_sandbox::Access::ReadExecute
        ));
        let keys: Vec<_> = launch.command.env.iter().map(|(k, _)| k.clone()).collect();
        assert!(keys.iter().all(|k| PASSTHROUGH_ENV.iter().any(|p| k == p)));
    }

    #[test]
    fn nonces_differ() {
        assert_ne!(nonce(), nonce());
        assert_eq!(nonce().len(), 32);
    }
}
