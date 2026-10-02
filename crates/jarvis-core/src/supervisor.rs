//! Starting, watching and stopping the worker process.
//!
//! The worker is started directly (no shell) with a cleared environment, so
//! secrets in the Core's environment are not inherited. Its stdin and stdout
//! carry the protocol; its stderr is forwarded to the Core's log, one escaped
//! and length-limited line at a time.

use std::io;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

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
    stderr: Option<JoinHandle<()>>,
}

/// How the worker process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerExit {
    pub status: ExitStatus,
    /// The Core had to kill it.
    pub killed: bool,
}

/// Start the worker and return it with its protocol pipes.
pub fn spawn(config: &WorkerConfig) -> io::Result<(Worker, ChildStdin, ChildStdout)> {
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
    command.envs(&config.env);
    if let Some(cwd) = &config.cwd {
        command.current_dir(cwd);
    }

    let mut child = command.spawn()?;
    let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(stdin), Some(stdout), Some(stderr)) = pipes else {
        return Err(io::Error::other("worker pipes were not created"));
    };
    let worker = Worker {
        child,
        stderr: Some(tokio::spawn(forward_stderr(stderr))),
    };
    Ok((worker, stdin, stdout))
}

impl Worker {
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Wait up to `grace` for the worker to exit on its own (its stdin
    /// should already be closed), then kill it.
    pub async fn stop(mut self, grace: Duration) -> io::Result<WorkerExit> {
        let exit = match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(status) => WorkerExit {
                status: status?,
                killed: false,
            },
            Err(_) => self.kill_now().await?,
        };
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
            return Ok(WorkerExit {
                status,
                killed: false,
            });
        }
        self.child.kill().await?;
        Ok(WorkerExit {
            status: self.child.wait().await?,
            killed: true,
        })
    }

    async fn drain_stderr(&mut self) {
        if let Some(task) = self.stderr.take() {
            // A grandchild could hold stderr open; do not wait for it forever.
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
