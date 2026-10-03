//! OS-level containment of the worker process.
//!
//! The protocol already stops a worker from bypassing policy through the
//! Core. This crate reduces what a compromised worker can do *outside* the
//! protocol, by calling the operating system directly. It is the only crate in
//! the workspace that contains `unsafe` code; every block states why it is
//! sound.
//!
//! What is applied (see `docs/decisions/0012-worker-containment.md`):
//!
//! | Control | Windows | Linux |
//! | --- | --- | --- |
//! | Worker and its descendants die with the Core | Job object, kill on close | `PR_SET_PDEATHSIG` |
//! | Whole process tree can be killed at once | `TerminateJobObject` | own process group, `killpg` |
//! | No child processes | Job active-process limit of 1 | not enforced |
//! | Memory limit | Job per-process commit limit | `RLIMIT_AS` |
//! | Cannot write to the user's files or the Core's IPC endpoint | Low integrity level | not enforced |
//! | Privileges | All removed except change-notify | `no_new_privs` |
//! | Clipboard, desktop and other UI access | Job UI restrictions, unless the worker is already in a job | not applicable |
//!
//! This is not a full sandbox. In particular, nothing here stops the worker
//! from reading files the user can read or from opening network connections.

use std::io;

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

/// Prepare the command before it is spawned. On Windows the process is
/// created suspended, so nothing runs before [`contain`] has applied every
/// control.
pub fn prepare(command: &mut tokio::process::Command, limits: &Limits) {
    platform::prepare(command, limits);
}

/// Apply containment to a child spawned from a [`prepare`]d command, then let
/// it run. On error the caller must kill the child (on Windows it is still
/// suspended and has run no code).
pub fn contain(child: &tokio::process::Child, limits: &Limits) -> io::Result<Contained> {
    platform::contain(child, limits)
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
