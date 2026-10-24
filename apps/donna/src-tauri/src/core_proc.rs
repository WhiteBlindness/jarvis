//! Starting and stopping the Core when it is not already running.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};

use crate::error::DonnaError;
use crate::{log, paths};

/// Windows `CREATE_NO_WINDOW`.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// The Core prints one short line before `ready`; read no more than this.
const READY_MAX_BYTES: u64 = 64 * 1024;

fn launch_error(message: impl Into<String>) -> DonnaError {
    DonnaError::Launch {
        message: message.into(),
    }
}

/// Start `jarvis-core serve --config <config>` directly (no shell). The
/// caller keeps the child at once and then waits with [`wait_ready`], so a
/// shutdown during start-up can still stop it.
pub fn spawn(exe: &Path, config: &Path) -> Result<(Child, ChildStdout), DonnaError> {
    let log_path = paths::data_dir().join("core.log");
    let stderr = std::fs::create_dir_all(paths::data_dir())
        .and_then(|()| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
        })
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null());
    let mut child = Command::new(exe)
        .arg("serve")
        .arg("--config")
        .arg(config)
        // The Core stops by itself if this app is killed.
        .arg("--exit-with")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| launch_error(format!("cannot start {}: {error}", exe.display())))?;
    match child.stdout.take() {
        Some(stdout) => Ok((child, stdout)),
        None => {
            let _ = child.start_kill();
            Err(launch_error("the Core has no output to read"))
        }
    }
}

/// Wait for the `ready <endpoint>` line, reading at most [`READY_MAX_BYTES`]
/// and for at most [`READY_TIMEOUT`]. Afterwards the output is drained so the
/// Core can never block on a full pipe.
pub async fn wait_ready(stdout: ChildStdout) -> Result<(), DonnaError> {
    let mut reader = BufReader::new(stdout.take(READY_MAX_BYTES));
    let ready = tokio::time::timeout(READY_TIMEOUT, async {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => return Err("the Core exited before it was ready".to_owned()),
                Ok(_) if line.starts_with("ready ") => return Ok(()),
                Ok(_) => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    })
    .await;
    match ready {
        Ok(Ok(())) => {
            let mut rest = reader.into_inner().into_inner();
            tauri::async_runtime::spawn(async move {
                let _ = tokio::io::copy(&mut rest, &mut tokio::io::sink()).await;
            });
            Ok(())
        }
        Ok(Err(message)) => Err(launch_error(format!(
            "{message} (log: {})",
            paths::data_dir().join("core.log").display()
        ))),
        Err(_) => Err(launch_error(
            "the Core did not become ready within 30 seconds",
        )),
    }
}

/// Wait for the child to exit; kill it after `grace`.
pub async fn stop(mut child: Child, grace: Duration) {
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        log::line("the Core did not stop in time; killing it");
        let _ = child.kill().await;
    }
}
