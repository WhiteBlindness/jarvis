//! OS-level isolation of the worker process.
//!
//! The protocol already stops a worker from bypassing policy through the
//! Core. This crate stops a compromised worker from going *around* the Core,
//! by calling the operating system directly. It is the only crate in the
//! workspace that contains `unsafe` code; every block states why it is sound.
//!
//! The Core describes what the worker legitimately needs as a [`Confinement`]
//! (which directories, whether it may use the network or start child
//! processes) and [`spawn`] starts the worker under it, with the strongest
//! mechanism each OS offers without administrator rights:
//!
//! | Control | Windows | Linux |
//! | --- | --- | --- |
//! | Cannot read the user's files | AppContainer (dual access check) | Landlock (default-deny filesystem) |
//! | Cannot use the network | AppContainer with no capabilities | seccomp denies all socket creation |
//! | Cannot start child processes | Child-process policy + job limit | seccomp denies fork and process clones |
//! | Cannot read other processes | AppContainer, low integrity | seccomp denies ptrace/process_vm_readv |
//! | Dies with the Core | Job object, kill on close | `PR_SET_PDEATHSIG` |
//! | Memory limit | Job commit limit | `RLIMIT_AS` |
//! | Only stdio reaches the worker | Explicit handle list | descriptors marked close-on-exec |
//!
//! Every control is applied before the worker runs its first instruction,
//! and any failure aborts the start: the worker never runs less isolated than
//! the Core asked for. A kernel or OS-API escape is outside the scope of this
//! crate (see the threat model). On Windows the boundary is an AppContainer
//! (ADR 0013); on Linux it is Landlock plus seccomp (ADR 0014). Platforms
//! reach the same goals by different mechanisms; exact symmetry is not a goal.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

/// Resource limits for the worker process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Address-space (Linux) or committed-memory (Windows) limit in bytes.
    pub memory_bytes: u64,
}

/// What the worker may do with one directory tree. The Core grants the least
/// each path needs; everything not granted is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read, list and execute files beneath the path (the interpreter, its
    /// loader and its libraries).
    ReadExecute,
    /// Read and list files beneath the path (the worker's own source).
    Read,
    /// Read, list, create, write, truncate and remove files beneath the path
    /// (a scratch area). No execute, no special files.
    ReadWrite,
}

/// One directory tree the worker is allowed to reach, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub path: PathBuf,
    pub access: Access,
}

impl Grant {
    pub fn read_execute(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: Access::ReadExecute,
        }
    }

    pub fn read(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: Access::Read,
        }
    }

    pub fn read_write(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: Access::ReadWrite,
        }
    }
}

/// The complete description of what the worker may do outside the protocol.
/// Built by the Core and enforced by this crate before the worker runs any
/// code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confinement {
    pub limits: Limits,
    /// Directory trees the worker may reach. A listed path that does not
    /// exist is skipped, so the set can name optional runtime roots.
    pub filesystem: Vec<Grant>,
    /// Deny the worker every network operation. Windows supports only
    /// `true`: an AppContainer without capabilities has no network.
    pub deny_network: bool,
    /// Deny the worker starting child processes.
    pub deny_child_processes: bool,
}

impl Confinement {
    /// A confinement with no filesystem grants that denies the network and
    /// child processes. The Core adds the grants the worker needs.
    pub fn locked_down(memory_bytes: u64) -> Self {
        Self {
            limits: Limits { memory_bytes },
            filesystem: Vec::new(),
            deny_network: true,
            deny_child_processes: true,
        }
    }

    /// Add a filesystem grant.
    #[must_use]
    pub fn grant(mut self, grant: Grant) -> Self {
        self.filesystem.push(grant);
        self
    }
}

/// What to start: an absolute program path (never resolved through a shell
/// or a search path here), its arguments, its complete environment and its
/// working directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCommand {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// The whole environment of the worker; nothing is inherited.
    pub env: Vec<(OsString, OsString)>,
    pub cwd: Option<PathBuf>,
}

/// The worker's standard input, written by the Core.
pub type WorkerStdin = platform::Stdin;
/// The worker's standard output, read by the Core.
pub type WorkerStdout = platform::Stdout;
/// The worker's standard error, read by the Core.
pub type WorkerStderr = platform::Stderr;

/// A worker started under its confinement, with its three pipes.
#[derive(Debug)]
pub struct Spawned {
    pub process: Process,
    pub contained: Contained,
    pub stdin: WorkerStdin,
    pub stdout: WorkerStdout,
    pub stderr: WorkerStderr,
}

/// Start `command` under `confinement`.
///
/// Every control is in force before the worker's first instruction runs. If
/// any of them cannot be applied (for example, Landlock is unavailable, or
/// the AppContainer cannot be created), no worker is left running and an
/// error is returned: the caller must not fall back to a less isolated
/// start.
pub fn spawn(command: &WorkerCommand, confinement: &Confinement) -> io::Result<Spawned> {
    if !command.program.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the worker program must be an absolute path",
        ));
    }
    platform::spawn(command, confinement)
}

/// A running worker process. Dropping it kills the process if it is still
/// running.
#[derive(Debug)]
pub struct Process {
    inner: platform::Process,
}

impl Process {
    /// The process ID.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Wait for the process to exit.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.wait().await
    }

    /// The exit status, if the process has exited.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    /// Ask the OS to kill the process now; [`Process::wait`] reaps it.
    pub fn start_kill(&mut self) -> io::Result<()> {
        self.inner.start_kill()
    }
}

/// The OS objects that keep a worker isolated. Dropping it releases them; on
/// Windows that kills every process left in the job.
#[derive(Debug)]
pub struct Contained {
    inner: platform::Guard,
    description: String,
}

impl Contained {
    /// Human-readable list of the controls in force.
    pub fn describe(&self) -> &str {
        &self.description
    }

    /// Kill the worker and every process it may have started.
    pub fn kill_all(&self) -> io::Result<()> {
        self.inner.kill_all()
    }

    /// Whether `pid` is the worker or one of its processes. Used to refuse
    /// RPC connections from the worker.
    pub fn contains(&self, pid: u32) -> bool {
        self.inner.contains(pid)
    }
}

/// Whether a process with this ID is running. For tests and diagnostics.
pub fn process_exists(pid: u32) -> bool {
    platform::process_exists(pid)
}

/// What [`spawn`] would use on this machine, for `isolation status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The isolation mechanism, for example `"landlock (ABI 7) + seccomp"`.
    pub mechanism: String,
    /// Identity details: the AppContainer name and package SID on Windows.
    pub identity: Vec<(String, String)>,
}

/// Describe the isolation available here without starting anything. Fails if
/// the mechanism [`spawn`] needs is not available.
pub fn report(confinement: &Confinement) -> io::Result<Report> {
    platform::report(confinement)
}

/// Undo the persistent changes [`spawn`] made for `confinement`: on Windows,
/// the access entries for the worker's package SID on each granted path and
/// the AppContainer profile. Nothing to undo on Linux.
pub fn remove(confinement: &Confinement) -> io::Result<Vec<String>> {
    platform::remove(confinement)
}

/// The real user ID of this process.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    unix::current_uid()
}

/// Create a named pipe server instance that only the current user can open.
/// An AppContainer process cannot open it: its package SID is not granted.
#[cfg(windows)]
pub fn create_owner_only_pipe(
    options: &tokio::net::windows::named_pipe::ServerOptions,
    name: &str,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    windows::create_owner_only_pipe(options, name)
}

/// The process ID of the client connected to a named pipe server handle.
#[cfg(windows)]
pub fn named_pipe_client_pid(pipe: std::os::windows::io::RawHandle) -> io::Result<u32> {
    windows::named_pipe_client_pid(pipe)
}

/// Whether the process `pid` runs with a restricted token: an AppContainer,
/// or an integrity level below medium. Errors (for example, the process has
/// already exited) are returned, so the caller can fail closed.
#[cfg(windows)]
pub fn is_restricted_process(pid: u32) -> io::Result<bool> {
    windows::is_restricted_process(pid)
}
