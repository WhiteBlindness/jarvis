use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use jarvis_core::config::Config;
use jarvis_core::runtime;
use jarvis_core::store::Store;
use jarvis_protocol::TaskId;
use tokio_util::sync::CancellationToken;

/// JARVIS Core: executes typed tool requests from a supervised worker under a
/// capability policy, and records every decision in SQLite.
#[derive(Debug, Parser)]
#[command(name = "jarvis-core", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the Core and run one supervised worker session.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, value_enum, default_value_t = LogFormat::Text)]
        log_format: LogFormat,
    },
    /// List recent tasks (read-only; safe while the Core runs).
    Tasks {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Print one JSON object per line.
        #[arg(long)]
        json: bool,
    },
    /// Print the audit log in sequence order (read-only).
    Audit {
        #[arg(long)]
        config: PathBuf,
        /// Only events for this task.
        #[arg(long)]
        task: Option<TaskId>,
        #[arg(long, default_value_t = 1000)]
        limit: u32,
        /// Print one JSON object per line.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

/// Exit codes: 0 the worker finished cleanly; 1 the Core failed; 2 the
/// session did not end cleanly (worker error, protocol violation, shutdown).
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { config, log_format } => {
            init_logging(log_format);
            match run(&config) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::from(2),
                Err(error) => {
                    tracing::error!("{error:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Tasks {
            config,
            limit,
            json,
        } => report(print_tasks(&config, limit, json)),
        Command::Audit {
            config,
            task,
            limit,
            json,
        } => report(print_audit(&config, task, limit, json)),
    }
}

fn report(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("JARVIS_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

fn run(config_path: &std::path::Path) -> anyhow::Result<bool> {
    let config = Config::load(config_path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(async {
        let shutdown = CancellationToken::new();
        let signal = tokio::spawn(cancel_on_signal(shutdown.clone()));
        let result = runtime::run(&config, shutdown).await;
        signal.abort();
        let report = result?;
        Ok(report.succeeded())
    })
}

/// The first signal starts a graceful shutdown. Every step of it is bounded,
/// but a second signal exits at once for an operator who will not wait.
async fn cancel_on_signal(shutdown: CancellationToken) {
    wait_for_signal().await;
    tracing::info!("shutdown requested; send the signal again to exit immediately");
    shutdown.cancel();
    wait_for_signal().await;
    tracing::warn!("second signal: exiting without a clean shutdown");
    std::process::exit(130);
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn open_store(config_path: &std::path::Path) -> anyhow::Result<Store> {
    let config = Config::load(config_path)?;
    Store::open_read_only(&config.database)
        .with_context(|| format!("cannot open {}", config.database.display()))
}

fn print_tasks(config_path: &std::path::Path, limit: u32, json: bool) -> anyhow::Result<()> {
    let store = open_store(config_path)?;
    for task in store.tasks(limit)?.into_iter().rev() {
        if json {
            let value = serde_json::json!({
                "task_id": task.task_id,
                "session_id": task.session_id,
                "request_id": task.request_id,
                "tool": task.tool,
                "status": task.status,
                "decision": task.decision,
                "capabilities": task.capabilities,
                "error": task.error,
                "created_at": task.created_at,
                "updated_at": task.updated_at,
            });
            println!("{value}");
        } else {
            let decision = task.decision.map_or("-", |d| d.as_str());
            let error = task
                .error
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_default();
            let line = format!(
                "{}  {}  {:<21} {:<23} {:<20} {}",
                task.created_at,
                task.task_id,
                task.status.as_str(),
                task.tool,
                decision,
                error
            );
            println!("{}", line.trim_end());
        }
    }
    Ok(())
}

fn print_audit(
    config_path: &std::path::Path,
    task: Option<TaskId>,
    limit: u32,
    json: bool,
) -> anyhow::Result<()> {
    let store = open_store(config_path)?;
    for event in store.audit_events(task, limit)? {
        if json {
            println!("{}", serde_json::to_string(&event)?);
        } else {
            let mut detail = serde_json::to_value(&event.event)?;
            if let Some(object) = detail.as_object_mut() {
                object.remove("kind");
            }
            let task = event
                .task_id
                .map_or_else(|| "-".to_owned(), |id| id.to_string());
            println!(
                "{:>5}  {}  {:<20} {:<36}  {}",
                event.seq,
                event.at,
                event.event.name(),
                task,
                detail
            );
        }
    }
    Ok(())
}
