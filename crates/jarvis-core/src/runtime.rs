//! Core lifecycle: start, run one supervised worker session, stop.
//!
//! Startup opens the store (lock, migrations), closes tasks left open by a
//! previous run and records `core_started`. Shutdown cancels the running
//! tool, closes the worker's stdin, waits a grace period, kills the worker
//! if needed, and records how everything ended.

use std::path::PathBuf;
use std::sync::Arc;

use jarvis_protocol::{AuditEventKind, ProtocolVersion};
use jarvis_tools::{FixtureRoot, ToolExecutor, Toolbox};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::gateway::Gateway;
use crate::session::{SessionContext, SessionEnd, SessionError, SessionReport, run_session};
use crate::store::{Store, StoreError};
use crate::supervisor::{self, WorkerExit};

pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("cannot open fixture directory {path}: {source}")]
    Fixtures {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot start worker `{program}`: {source}")]
    WorkerSpawn {
        program: String,
        source: std::io::Error,
    },
    #[error("cannot supervise worker: {0}")]
    Worker(std::io::Error),
}

#[derive(Debug)]
pub struct RunReport {
    pub session: SessionReport,
    pub worker: WorkerExit,
}

impl RunReport {
    /// The worker finished its work and closed the session cleanly.
    pub fn succeeded(&self) -> bool {
        self.session.end == SessionEnd::WorkerClosed
            && self.worker.status.success()
            && !self.worker.killed
    }
}

/// Run the Core with the first-party tool set.
pub async fn run(config: &Config, shutdown: CancellationToken) -> Result<RunReport, CoreError> {
    let fixtures =
        FixtureRoot::open(&config.fixtures.root, config.fixtures.max_bytes).map_err(|source| {
            CoreError::Fixtures {
                path: config.fixtures.root.clone(),
                source,
            }
        })?;
    run_with_executor(
        config,
        Arc::new(Toolbox::new(CORE_VERSION, fixtures)),
        shutdown,
    )
    .await
}

/// Run the Core with a given executor. Tests use this to substitute tools
/// that fail or hang.
pub async fn run_with_executor(
    config: &Config,
    executor: Arc<dyn ToolExecutor>,
    shutdown: CancellationToken,
) -> Result<RunReport, CoreError> {
    let store = Store::open(&config.database)?;
    let recovered = store.call(Store::recover).await?;
    if recovered > 0 {
        tracing::warn!(recovered, "closed tasks left open by a previous run");
    }
    record(
        &store,
        AuditEventKind::CoreStarted {
            core_version: CORE_VERSION.to_owned(),
            protocol_version: ProtocolVersion::CURRENT,
        },
    )
    .await?;
    tracing::info!(version = CORE_VERSION, database = %config.database.display(), "core started");

    let ctx = SessionContext {
        store: store.clone(),
        policy: config.policy.clone(),
        gateway: Gateway::new(
            executor,
            config.limits.tool_timeout,
            config.limits.max_result_bytes(),
        ),
        limits: config.limits,
        handshake_timeout: config.worker.handshake_timeout,
        core_version: CORE_VERSION,
    };

    let (worker, stdin, stdout) = match supervisor::spawn(&config.worker) {
        Ok(spawned) => spawned,
        Err(source) => {
            let reason = format!("worker failed to start: {source}");
            record(&store, AuditEventKind::CoreStopped { reason }).await?;
            return Err(CoreError::WorkerSpawn {
                program: config.worker.program.clone(),
                source,
            });
        }
    };
    record(&store, AuditEventKind::WorkerSpawned { pid: worker.pid() }).await?;

    // The session owns the worker's stdin and drops it when it ends, which
    // tells the worker to exit.
    let session = match run_session(&ctx, stdout, stdin, &shutdown).await {
        Ok(report) => report,
        Err(error) => {
            // The store may be what failed, so every write below is best
            // effort, and the original error is what the caller sees.
            if let Err(kill) = worker.kill().await {
                tracing::error!(error = %kill, "could not kill the worker");
            }
            let reason = format!("stopped after an internal error: {error}");
            if let Err(audit) = record(&store, AuditEventKind::CoreStopped { reason }).await {
                tracing::error!(error = %audit, "could not record core_stopped");
            }
            return Err(error.into());
        }
    };

    let (exit, kill_reason) = if session.end == SessionEnd::HandshakeTimeout {
        (worker.kill().await, "handshake timeout".to_owned())
    } else {
        let reason = format!(
            "did not exit within {} ms after the session closed",
            config.limits.shutdown_grace.as_millis()
        );
        (worker.stop(config.limits.shutdown_grace).await, reason)
    };
    let exit = exit.map_err(CoreError::Worker)?;

    if exit.killed {
        tracing::warn!(reason = kill_reason, "worker killed");
        record(
            &store,
            AuditEventKind::WorkerKilled {
                reason: kill_reason,
            },
        )
        .await?;
    }
    record(
        &store,
        AuditEventKind::WorkerExited {
            code: exit.status.code(),
            success: exit.status.success(),
        },
    )
    .await?;
    tracing::info!(code = ?exit.status.code(), "worker exited");

    let reason = match &session.end {
        SessionEnd::Shutdown => "shutdown requested".to_owned(),
        _ => "worker session ended".to_owned(),
    };
    record(&store, AuditEventKind::CoreStopped { reason }).await?;
    tracing::info!("core stopped");

    Ok(RunReport {
        session,
        worker: exit,
    })
}

async fn record(store: &Store, event: AuditEventKind) -> Result<(), StoreError> {
    store
        .call(move |s| s.append(None, None, &event).map(|_| ()))
        .await
}
