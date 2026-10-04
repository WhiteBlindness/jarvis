//! Starting, containing, watching and stopping the worker process.
//!
//! The worker is started directly (no shell) with a cleared environment, so
//! secrets in the Core's environment are not inherited, and there is no way
//! to add variables back from the config. OS containment
//! ([`jarvis_sandbox`]) is applied before the worker runs any code; if it
//! cannot be applied, the worker is killed and the start fails. Its stdin and
//! stdout carry the protocol; its stderr is forwarded to the Core's log, one
//! escaped and length-limited line at a time.

use std::io;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use jarvis_sandbox::{Confinement, Contained};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;

use crate::config::WorkerConfig;
use crate::framing::{Frame, FrameReader};

/// Variables the worker keeps from the Core's environment: enough to find
/// and start an interpreter, nothing else. `SYSTEMROOT` is required by
/// Windows system libraries.
pub const PASSTHROUGH_ENV: &[&str] = &["PATH", "SYSTEMROOT"];

const MAX_LOG_LINE: usize = 4096;

#[derive(Debug)]
pub struct Worker {
    child: Child,
    contained: Arc<Contained>,
    stderr: Option<JoinHandle<()>>,
}

/// How the worker process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerExit {
    pub status: ExitStatus,
    /// The Core had to kill it.
    pub killed: bool,
}

/// Start and contain the worker; return it with its protocol pipes.
pub fn spawn(
    config: &WorkerConfig,
    confinement: &Confinement,
) -> io::Result<(Worker, ChildStdin, ChildStdout)> {
    let mut command = Command::new(&config.program);
    command
        .args(&config.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for key in PASSTHROUGH_ENV {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(cwd) = &config.cwd {
        command.current_dir(cwd);
    }
    jarvis_sandbox::prepare(&mut command, confinement)?;

    let mut child = command.spawn()?;
    let contained = match jarvis_sandbox::contain(&child, confinement) {
        Ok(contained) => Arc::new(contained),
        Err(error) => {
            // Still suspended on Windows: it has run no code.
            let _ = child.start_kill();
            return Err(io::Error::new(
                error.kind(),
                format!("cannot contain the worker: {error}"),
            ));
        }
    };
    let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(stdin), Some(stdout), Some(stderr)) = pipes else {
        let _ = contained.kill_all();
        return Err(io::Error::other("worker pipes were not created"));
    };
    let worker = Worker {
        child,
        contained,
        stderr: Some(tokio::spawn(forward_stderr(stderr))),
    };
    Ok((worker, stdin, stdout))
}

impl Worker {
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn contained(&self) -> Arc<Contained> {
        Arc::clone(&self.contained)
    }

    /// Wait up to `grace` for the worker to exit on its own (its stdin
    /// should already be closed), then kill it and anything it started.
    pub async fn stop(mut self, grace: Duration) -> io::Result<WorkerExit> {
        let exit = match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(status) => WorkerExit {
                status: status?,
                killed: false,
            },
            Err(_) => self.kill_now().await?,
        };
        // Nothing the worker started may outlive it.
        let _ = self.contained.kill_all();
        self.drain_stderr().await;
        Ok(exit)
    }

    /// Kill the worker immediately.
    pub async fn kill(mut self) -> io::Result<WorkerExit> {
        let exit = self.kill_now().await?;
        self.drain_stderr().await;
        Ok(exit)
    }

    async fn kill_now(&mut self) -> io::Result<WorkerExit> {
        // The process may exit between the timeout and the kill.
        if let Some(status) = self.child.try_wait()? {
            let _ = self.contained.kill_all();
            return Ok(WorkerExit {
                status,
                killed: false,
            });
        }
        self.contained.kill_all()?;
        let status = match tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.child.kill().await?;
                self.child.wait().await?
            }
        };
        Ok(WorkerExit {
            status,
            killed: true,
        })
    }

    async fn drain_stderr(&mut self) {
        if let Some(task) = self.stderr.take() {
            // A process that escaped could hold stderr open; do not wait for
            // it forever.
            if tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .is_err()
            {
                tracing::warn!("worker stderr did not close; no longer forwarding it");
            }
        }
    }
}

async fn forward_stderr(stderr: ChildStderr) {
    let mut reader = FrameReader::new(stderr, MAX_LOG_LINE);
    loop {
        match reader.next_frame().await {
            Ok(Some(Frame::Line(line))) => {
                let text = String::from_utf8_lossy(&line);
                tracing::info!(target: "jarvis::worker", "{}", text.escape_debug());
            }
            Ok(Some(Frame::TooLarge)) => {
                tracing::warn!(target: "jarvis::worker", "stderr line over {MAX_LOG_LINE} bytes discarded");
            }
            Ok(None) | Err(_) => return,
        }
    }
}
