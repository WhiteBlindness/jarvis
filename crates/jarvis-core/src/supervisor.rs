//! Starting, watching and stopping the worker process.
//!
//! The worker is started directly (no shell) with a cleared environment, so
//! secrets in the Core's environment are not inherited, and there is no way
//! to add variables back from the config. It starts inside its OS isolation
//! ([`jarvis_sandbox::spawn`], configured by [`crate::isolation`]); if any
//! part of that cannot be applied, no worker runs and the start fails. Its
//! stdin and stdout carry the protocol; its stderr is forwarded to the
//! Core's log, one escaped and length-limited line at a time.

use std::io;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

use jarvis_sandbox::{Contained, Process, Spawned, WorkerStderr, WorkerStdin, WorkerStdout};
use tokio::task::JoinHandle;

use crate::framing::{Frame, FrameReader};
use crate::isolation::WorkerLaunch;

const MAX_LOG_LINE: usize = 4096;

#[derive(Debug)]
pub struct Worker {
    process: Process,
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

/// Start the worker in isolation; return it with its protocol pipes.
pub fn spawn(launch: &WorkerLaunch) -> io::Result<(Worker, WorkerStdin, WorkerStdout)> {
    let Spawned {
        process,
        contained,
        stdin,
        stdout,
        stderr,
    } = jarvis_sandbox::spawn(&launch.command, &launch.confinement).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot start the worker in isolation: {error}"),
        )
    })?;
    let worker = Worker {
        process,
        contained: Arc::new(contained),
        stderr: Some(tokio::spawn(forward_stderr(stderr))),
    };
    Ok((worker, stdin, stdout))
}

impl Worker {
    pub fn pid(&self) -> Option<u32> {
        Some(self.process.id())
    }

    pub fn contained(&self) -> Arc<Contained> {
        Arc::clone(&self.contained)
    }

    /// Wait up to `grace` for the worker to exit on its own (its stdin
    /// should already be closed), then kill it and anything it started.
    pub async fn stop(mut self, grace: Duration) -> io::Result<WorkerExit> {
        let exit = match tokio::time::timeout(grace, self.process.wait()).await {
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
        if let Some(status) = self.process.try_wait()? {
            let _ = self.contained.kill_all();
            return Ok(WorkerExit {
                status,
                killed: false,
            });
        }
        self.contained.kill_all()?;
        let status = match tokio::time::timeout(Duration::from_secs(5), self.process.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.process.start_kill()?;
                self.process.wait().await?
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

async fn forward_stderr(stderr: WorkerStderr) {
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
