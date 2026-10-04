//! OS-level containment of the worker process.
//!
//! The protocol already stops a worker from bypassing policy through the
//! Core. This crate reduces what a compromised worker can do *outside* the
//! protocol, by calling the operating system directly. It is the only crate
//! in the workspace that contains `unsafe` code; every block states why it is
//! sound.
//!
//! The Core describes what the worker legitimately needs as a [`Confinement`]
//! (which directories, whether it may use the network or start child
//! processes) and this crate enforces it with the strongest mechanism each OS
//! offers without administrator rights:
//!
//! | Control | Windows | Linux |
//! | --- | --- | --- |
//! | Cannot read the user's files | AppContainer (dual access check) | Landlock (default-deny filesystem) |
//! | Cannot use the network | AppContainer, no capabilities | seccomp denies all socket creation |
//! | Cannot start child processes | Child-process policy + job limit | seccomp denies fork/clone-of-process |
//! | Cannot read other processes | AppContainer, low integrity | seccomp denies ptrace/process_vm_readv |
//! | Dies with the Core | Job object, kill on close | `PR_SET_PDEATHSIG` |
//! | Memory limit | Job commit limit | `RLIMIT_AS` |
//! | Only stdio reaches the worker | Handle list / non-inheritable handles | descriptors marked close-on-exec |
//!
//! This is containment, not a sandbox: a kernel or OS-API escape is outside
//! its scope (see the threat model). On Windows the boundary is an
//! AppContainer (ADR 0013); on Linux it is Landlock plus seccomp (ADR 0014).
//! Platforms reach the same goals by different mechanisms; exact symmetry is
//! not a goal.

use std::io;
use std::path::PathBuf;

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
    /// loader, its libraries and the worker's own source).
    ReadExecute,
    /// Read and list files beneath the path.
    Read,
    /// Read, list, create, write, truncate and remove files beneath the path
    /// (a scratch/temp area). No executes, no special files.
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
    /// Directory trees the worker may reach. Only existing paths are applied;
    /// a listed path that does not exist is skipped (so the set can name
    /// optional runtime roots).
    pub filesystem: Vec<Grant>,
    /// Deny the worker every network operation.
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

/// Prepare the command before it is spawned. On Linux this builds the
/// Landlock ruleset and the seccomp filter in the parent and installs a
/// pre-exec step that applies them in the child. On Windows the process is
/// created suspended, so nothing runs before [`contain`] has applied every
/// control.
///
/// Returns an error if the confinement cannot be built (for example, Landlock
/// is unavailable): the caller must not spawn a worker that would be less
/// contained than configured.
pub fn prepare(command: &mut tokio::process::Command, confinement: &Confinement) -> io::Result<()> {
    platform::prepare(command, confinement)
}

/// Apply containment to a child spawned from a [`prepare`]d command, then let
/// it run. On error the caller must kill the child (on Windows it is still
/// suspended and has run no code).
pub fn contain(child: &tokio::process::Child, confinement: &Confinement) -> io::Result<Contained> {
    platform::contain(child, confinement)
}

/// A contained worker process. Dropping it releases the OS objects; on
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

/// The real user ID of this process.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    unix::current_uid()
}

/// Create a named pipe server instance that only the current user can open.
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
