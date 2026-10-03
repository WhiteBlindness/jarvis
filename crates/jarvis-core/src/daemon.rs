//! The long-lived Core.
//!
//! Start-up opens the store (lock, migrations), closes everything a previous
//! run left open, records `core_started`, and starts the local RPC server.
//! The Core then supervises the worker: it starts and contains it, runs one
//! session with it, and when the worker stops, restarts it with exponential
//! backoff as long as the restart budget allows. Shutdown (signal or an
//! authorised RPC request) cancels the running tool, expires pending
//! approvals, closes the worker's stdin, kills it after the grace period, and
//! records how everything ended.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jarvis_protocol::{AuditEventKind, ProtocolVersion, WorkerState};
use jarvis_tools::{FixtureRoot, ToolExecutor, Toolbox, WorkspaceRoot};
use tokio_util::sync::CancellationToken;

use crate::config::{Config, SupervisorConfig};
use crate::gateway::Gateway;
use crate::hub::Hub;
use crate::rpc::{self, Endpoint, Listener, RpcState};
use crate::session::{SessionContext, SessionEnd, SessionError, run_session};
use crate::store::{Store, StoreError};
use crate::supervisor;

pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("cannot open {what} {path}: {source}")]
    Root {
        what: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot listen on {endpoint}: {source}")]
    Listen {
        endpoint: String,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeReport {
    pub sessions: u32,
    pub restarts: u32,
    /// The worker exhausted its restart budget before shutdown.
    pub gave_up: bool,
}

/// What to do after the worker stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    After { delay: Duration, attempt: u32 },
    GiveUp { restarts: u32 },
}

/// Bounded restarts with exponential backoff. At most `restart_budget`
/// restarts within `restart_window`; the delay doubles after each quick
/// failure and resets after a worker ran for longer than `backoff_max`.
#[derive(Debug)]
pub struct RestartPolicy {
    config: SupervisorConfig,
    history: VecDeque<Instant>,
    consecutive: u32,
    total: u32,
}

impl RestartPolicy {
    pub fn new(config: SupervisorConfig) -> Self {
        Self {
            config,
            history: VecDeque::new(),
            consecutive: 0,
            total: 0,
        }
    }

    pub fn on_exit(&mut self, now: Instant, ran_for: Duration) -> Restart {
        while self
            .history
            .front()
            .is_some_and(|at| now.duration_since(*at) > self.config.restart_window)
        {
            self.history.pop_front();
        }
        if self.history.len() >= self.config.restart_budget as usize {
            return Restart::GiveUp {
                restarts: self.total,
            };
        }
        if ran_for > self.config.backoff_max {
            self.consecutive = 0;
        }
        let factor = 1u32
            .checked_shl(self.consecutive.min(20))
            .unwrap_or(u32::MAX);
        let delay = self
            .config
            .backoff_initial
            .saturating_mul(factor)
            .min(self.config.backoff_max);
        self.consecutive += 1;
        self.total += 1;
        self.history.push_back(now);
        Restart::After {
            delay,
            attempt: self.total,
        }
    }
}

/// Run the long-lived Core with the first-party tool set until `shutdown`.
pub async fn serve(
    config: &Config,
    shutdown: CancellationToken,
    ready: impl FnOnce(&Endpoint),
) -> Result<ServeReport, CoreError> {
    let fixtures =
        FixtureRoot::open(&config.fixtures.root, config.fixtures.max_bytes).map_err(|source| {
            CoreError::Root {
                what: "fixture directory",
                path: config.fixtures.root.clone(),
                source,
            }
        })?;
    std::fs::create_dir_all(&config.workspace.root).map_err(|source| CoreError::Root {
        what: "workspace",
        path: config.workspace.root.clone(),
        source,
    })?;
    let workspace = WorkspaceRoot::open(&config.workspace.root, config.workspace.max_bytes)
        .map_err(|source| CoreError::Root {
            what: "workspace",
            path: config.workspace.root.clone(),
            source,
        })?;
    let toolbox = Toolbox::new(CORE_VERSION, fixtures, workspace);
    serve_with_executor(config, Arc::new(toolbox), shutdown, ready).await
}

/// Run the Core with a given executor. Tests use this to substitute tools.
pub async fn serve_with_executor(
    config: &Config,
    executor: Arc<dyn ToolExecutor>,
    shutdown: CancellationToken,
    ready: impl FnOnce(&Endpoint),
) -> Result<ServeReport, CoreError> {
    let store = Store::open(&config.database)?;
    let recovered = store.call(Store::recover).await?;
    if !recovered.is_empty() {
        tracing::warn!(
            tasks = recovered.tasks,
            approvals = recovered.approvals,
            jobs = recovered.jobs,
            "closed what a previous run left open"
        );
    }
    record(
        &store,
        AuditEventKind::CoreStarted {
            core_version: CORE_VERSION.to_owned(),
            protocol_version: ProtocolVersion::CURRENT,
        },
    )
    .await?;

    let hub = Arc::new(Hub::default());
    let endpoint = Endpoint::from_config(&config.rpc);
    let listener = match Listener::bind(&endpoint) {
        Ok(listener) => listener,
        Err(source) => {
            let reason = format!("cannot listen on {endpoint}: {source}");
            record(&store, AuditEventKind::CoreStopped { reason }).await?;
            return Err(CoreError::Listen {
                endpoint: endpoint.to_string(),
                source,
            });
        }
    };
    let rpc_state = Arc::new(RpcState {
        store: store.clone(),
        hub: Arc::clone(&hub),
        config: config.rpc.clone(),
        shutdown: shutdown.clone(),
        started: Instant::now(),
        core_version: CORE_VERSION,
    });
    let rpc_stop = CancellationToken::new();
    let rpc_task = tokio::spawn(rpc::serve(rpc_state, listener, rpc_stop.clone()));
    tracing::info!(version = CORE_VERSION, %endpoint, "core started");
    ready(&endpoint);

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
        approval_ttl: config.approvals.ttl,
        job_timeout: config.supervisor.job_timeout,
        core_version: CORE_VERSION,
        hub: Arc::clone(&hub),
    };
    let supervised = supervise(config, &ctx, &shutdown).await;

    rpc_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), rpc_task).await;
    let report = match supervised {
        Ok(report) => report,
        Err(error) => {
            let reason = format!("stopped after an internal error: {error}");
            if let Err(audit) = record(&store, AuditEventKind::CoreStopped { reason }).await {
                tracing::error!(error = %audit, "could not record core_stopped");
            }
            return Err(error);
        }
    };
    let reason = hub
        .stop_reason()
        .unwrap_or_else(|| "shutdown requested".to_owned());
    record(&store, AuditEventKind::CoreStopped { reason }).await?;
    tracing::info!("core stopped");
    Ok(report)
}

async fn supervise(
    config: &Config,
    ctx: &SessionContext,
    shutdown: &CancellationToken,
) -> Result<ServeReport, CoreError> {
    let hub = &ctx.hub;
    let mut policy = RestartPolicy::new(config.supervisor);
    let mut report = ServeReport {
        sessions: 0,
        restarts: 0,
        gave_up: false,
    };
    while !shutdown.is_cancelled() {
        hub.update_worker(|worker| {
            worker.state = WorkerState::Starting;
            worker.pid = None;
        });
        let started = Instant::now();
        match supervisor::spawn(&config.worker) {
            Err(error) => {
                tracing::error!(%error, program = %config.worker.program, "worker failed to start");
                record(
                    &ctx.store,
                    AuditEventKind::WorkerExited {
                        code: None,
                        success: false,
                    },
                )
                .await?;
            }
            Ok((worker, stdin, stdout)) => {
                let contained = worker.contained();
                hub.update_worker(|view| {
                    view.pid = worker.pid();
                    view.containment = contained.describe().to_owned();
                });
                hub.set_contained(Some(contained));
                record(
                    &ctx.store,
                    AuditEventKind::WorkerSpawned { pid: worker.pid() },
                )
                .await?;
                tracing::info!(pid = ?worker.pid(), containment = %hub.worker().containment, "worker started");

                // The session owns the worker's stdin and drops it when it
                // ends, which tells the worker to exit.
                let session = run_session(ctx, stdout, stdin, shutdown).await;
                report.sessions += 1;
                hub.set_worker_state(WorkerState::Stopping);
                let kill_reason;
                let exit = match &session {
                    Ok(done) if done.end == SessionEnd::HandshakeTimeout => {
                        kill_reason = "handshake timeout".to_owned();
                        worker.kill().await
                    }
                    Ok(done) if matches!(done.end, SessionEnd::JobTimedOut(_)) => {
                        kill_reason = "job timeout".to_owned();
                        worker.kill().await
                    }
                    Ok(_) => {
                        kill_reason = format!(
                            "did not exit within {} ms after the session closed",
                            config.limits.shutdown_grace.as_millis()
                        );
                        worker.stop(config.limits.shutdown_grace).await
                    }
                    Err(_) => {
                        kill_reason = "Core error".to_owned();
                        worker.kill().await
                    }
                };
                hub.set_contained(None);
                let session = session?;
                match exit {
                    Ok(exit) => {
                        if exit.killed {
                            tracing::warn!(reason = %kill_reason, "worker killed");
                            record(
                                &ctx.store,
                                AuditEventKind::WorkerKilled {
                                    reason: kill_reason,
                                },
                            )
                            .await?;
                        }
                        record(
                            &ctx.store,
                            AuditEventKind::WorkerExited {
                                code: exit.status.code(),
                                success: exit.status.success(),
                            },
                        )
                        .await?;
                        tracing::info!(code = ?exit.status.code(), "worker exited: {}", session.end.describe());
                    }
                    Err(error) => tracing::error!(%error, "could not stop the worker cleanly"),
                }
            }
        }
        if shutdown.is_cancelled() {
            break;
        }

        match policy.on_exit(Instant::now(), started.elapsed()) {
            Restart::After { delay, attempt } => {
                report.restarts = attempt;
                hub.update_worker(|worker| {
                    worker.state = WorkerState::Restarting;
                    worker.restarts = attempt;
                    worker.pid = None;
                });
                record(
                    &ctx.store,
                    AuditEventKind::WorkerRestartScheduled {
                        attempt,
                        delay_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    },
                )
                .await?;
                tracing::warn!(
                    attempt,
                    delay_ms = delay.as_millis(),
                    "restarting the worker"
                );
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(delay) => {}
                }
            }
            Restart::GiveUp { restarts } => {
                report.gave_up = true;
                hub.update_worker(|worker| {
                    worker.state = WorkerState::Failed;
                    worker.pid = None;
                });
                hub.changed();
                record(
                    &ctx.store,
                    AuditEventKind::WorkerRestartAbandoned {
                        restarts,
                        window_ms: u64::try_from(config.supervisor.restart_window.as_millis())
                            .unwrap_or(u64::MAX),
                    },
                )
                .await?;
                tracing::error!(
                    restarts,
                    "worker restart budget exhausted; waiting for shutdown"
                );
                shutdown.cancelled().await;
                break;
            }
        }
    }
    hub.set_worker_state(WorkerState::Stopping);
    Ok(report)
}

async fn record(store: &Store, event: AuditEventKind) -> Result<(), StoreError> {
    store
        .call(move |s| s.append(None, None, &event).map(|_| ()))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(budget: u32) -> RestartPolicy {
        RestartPolicy::new(SupervisorConfig {
            restart_budget: budget,
            restart_window: Duration::from_secs(60),
            backoff_initial: Duration::from_millis(100),
            backoff_max: Duration::from_secs(1),
            job_timeout: Duration::from_secs(600),
        })
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let mut policy = policy(10);
        let start = Instant::now();
        let delays: Vec<_> = (0..6)
            .map(
                |i| match policy.on_exit(start + Duration::from_millis(i), Duration::ZERO) {
                    Restart::After { delay, .. } => delay.as_millis(),
                    Restart::GiveUp { .. } => panic!("gave up too early"),
                },
            )
            .collect();
        assert_eq!(delays, [100, 200, 400, 800, 1000, 1000]);
    }

    #[test]
    fn budget_is_enforced_within_the_window() {
        let mut policy = policy(3);
        let start = Instant::now();
        for _ in 0..3 {
            assert!(matches!(
                policy.on_exit(start, Duration::ZERO),
                Restart::After { .. }
            ));
        }
        assert_eq!(
            policy.on_exit(start, Duration::ZERO),
            Restart::GiveUp { restarts: 3 }
        );
    }

    #[test]
    fn old_restarts_leave_the_window() {
        let mut policy = policy(2);
        let start = Instant::now();
        policy.on_exit(start, Duration::ZERO);
        policy.on_exit(start, Duration::ZERO);
        let later = start + Duration::from_secs(61);
        assert!(matches!(
            policy.on_exit(later, Duration::ZERO),
            Restart::After { .. }
        ));
    }

    #[test]
    fn a_long_healthy_run_resets_the_backoff() {
        let mut policy = policy(10);
        let start = Instant::now();
        policy.on_exit(start, Duration::ZERO);
        policy.on_exit(start, Duration::ZERO);
        match policy.on_exit(start, Duration::from_secs(5)) {
            Restart::After { delay, .. } => assert_eq!(delay, Duration::from_millis(100)),
            Restart::GiveUp { .. } => panic!(),
        }
    }

    #[test]
    fn zero_budget_never_restarts() {
        assert_eq!(
            policy(0).on_exit(Instant::now(), Duration::ZERO),
            Restart::GiveUp { restarts: 0 }
        );
    }
}
