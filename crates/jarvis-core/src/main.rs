use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use jarvis_core::config::Config;
use jarvis_core::rpc::Endpoint;
use jarvis_core::rpc::client::Client;
use jarvis_core::store::Store;
use jarvis_core::{daemon, isolation};
use jarvis_protocol::{
    ApprovalId, ApprovalStatus, ApprovalView, ChatLanguage, ChatText, ClipboardText,
    ConversationId, Fingerprint, Goal, GovernorPhase, GovernorReason, GovernorView, HealthReport,
    JobId, JobStatus, JobView, MessageStatus, RpcError, RpcRequest, RpcResponse, Summary, TaskId,
};
use tokio_util::sync::CancellationToken;

/// JARVIS Core: executes typed tool requests from a supervised worker under a
/// capability policy, asks a person before anything that changes state, and
/// records every decision in SQLite.
///
/// `serve` runs the long-lived Core. The other commands are local clients:
/// they talk to a running Core over its local RPC endpoint (`tasks` and
/// `audit` read the database directly, read-only).
///
/// Exit codes: 0 success; 1 error (including a Core that cannot be reached
/// or refuses the request); 2 a negative answer: the worker failed for good
/// (`serve`, `health`), a job did not complete (`submit --wait`, `job`), or
/// an approval was not given (`approvals approve`).
#[derive(Debug, Parser)]
#[command(name = "jarvis-core", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct ConfigArg {
    /// Path to the Core configuration file.
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the long-lived Core: supervise the worker and serve local clients
    /// until interrupted (or until an authorised `shutdown`). Prints
    /// `ready <endpoint>` on stdout once clients can connect; logs go to
    /// stderr.
    Serve {
        #[command(flatten)]
        config: ConfigArg,
        #[arg(long, value_enum, default_value_t = LogFormat::Text)]
        log_format: LogFormat,
        /// Stop, as on Ctrl+C, when the process with this ID exits. The
        /// desktop app passes its own ID when it starts the Core, so that a
        /// Core it started never outlives it; a Core started any other way
        /// is not affected.
        #[arg(long, value_name = "PID")]
        exit_with: Option<u32>,
    },
    /// Show the health of the running Core and its worker.
    Health {
        #[command(flatten)]
        config: ConfigArg,
        #[arg(long)]
        json: bool,
    },
    /// Queue a goal for the worker.
    Submit {
        #[command(flatten)]
        config: ConfigArg,
        /// What the worker should do, in one line.
        goal: String,
        /// Wait until the job has finished.
        #[arg(long)]
        wait: bool,
        /// Longest time to wait with `--wait`.
        #[arg(long, default_value = "10m")]
        timeout: humantime::Duration,
        #[arg(long)]
        json: bool,
    },
    /// Queue a job that copies this text to the clipboard once you approve
    /// it (ADR 0022). The text is held by the Core only until the job ends
    /// and is never written into the job.
    Clipboard {
        #[command(flatten)]
        config: ConfigArg,
        /// The text to copy: up to 1024 characters of plain text.
        text: String,
        /// Wait until the job has finished.
        #[arg(long)]
        wait: bool,
        /// Longest time to wait with `--wait`.
        #[arg(long, default_value = "10m")]
        timeout: humantime::Duration,
        #[arg(long)]
        json: bool,
    },
    /// Show one job.
    Job {
        #[command(flatten)]
        config: ConfigArg,
        job_id: JobId,
        /// Wait until the job has finished.
        #[arg(long)]
        wait: bool,
        /// Longest time to wait with `--wait`.
        #[arg(long, default_value = "10m")]
        timeout: humantime::Duration,
        #[arg(long)]
        json: bool,
    },
    /// List recent jobs, most recent first.
    Jobs {
        #[command(flatten)]
        config: ConfigArg,
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Send one message to the local model and print the reply as it is
    /// written (ADR 0021).
    Chat {
        #[command(flatten)]
        config: ConfigArg,
        message: String,
        /// Continue this conversation instead of starting one.
        #[arg(long)]
        conversation: Option<ConversationId>,
        #[arg(long, value_enum, default_value_t = Language::PtPt)]
        language: Language,
        /// Print the final reply and its measurements as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Review and decide on requests that wait for a person.
    #[command(subcommand)]
    Approvals(ApprovalCommand),
    /// Ask the running Core to stop. Refused unless `rpc.allow_shutdown` is
    /// set in its configuration.
    Shutdown {
        #[command(flatten)]
        config: ConfigArg,
    },
    /// List recent tasks (read-only; safe while the Core runs).
    Tasks {
        #[command(flatten)]
        config: ConfigArg,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Print one JSON object per line.
        #[arg(long)]
        json: bool,
    },
    /// Inspect or undo the worker's OS isolation on this machine.
    #[command(subcommand)]
    Isolation(IsolationCommand),
    /// Print the audit log in sequence order (read-only).
    Audit {
        #[command(flatten)]
        config: ConfigArg,
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

#[derive(Debug, Subcommand)]
enum IsolationCommand {
    /// Show how the worker is isolated here, then prove it: run the same
    /// probe the Core runs before its first worker (no network, no access to
    /// the Core's files, no child processes). Needs no running Core and no
    /// administrator rights. Exits 2 if isolation is not enforced.
    Check {
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Undo what starting the worker changed on this machine: on Windows,
    /// the access entries for the worker's AppContainer on the granted
    /// directories, and the AppContainer profile itself. Nothing to undo on
    /// Linux. Stop the Core first.
    Remove {
        #[command(flatten)]
        config: ConfigArg,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// List pending approvals, oldest first.
    List {
        #[command(flatten)]
        config: ConfigArg,
        /// Wait up to this long for at least one approval to be pending.
        #[arg(long)]
        wait: Option<humantime::Duration>,
        #[arg(long)]
        json: bool,
    },
    /// Show one approval in full.
    Show {
        #[command(flatten)]
        config: ConfigArg,
        approval_id: ApprovalId,
        #[arg(long)]
        json: bool,
    },
    /// Approve one pending request after reviewing it.
    ///
    /// The request is shown first, and the approval is bound to the
    /// fingerprint of exactly what was shown. Without `--yes`, a person must
    /// confirm at the terminal.
    Approve {
        #[command(flatten)]
        config: ConfigArg,
        approval_id: ApprovalId,
        /// Approve only if the request still has this fingerprint (as shown
        /// by `approvals list` or `approvals show`).
        #[arg(long)]
        fingerprint: Option<Fingerprint>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Refuse one pending request. The tool will not run.
    Deny {
        #[command(flatten)]
        config: ConfigArg,
        approval_id: ApprovalId,
        #[arg(long, default_value = "declined by the operator")]
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

/// The negative-answer exit code.
const NEGATIVE: u8 = 2;
/// Longest single long-poll; the Core caps waits at 60 s.
const POLL: Duration = Duration::from_secs(55);

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Serve {
            config,
            log_format,
            exit_with,
        } => {
            init_logging(log_format);
            let result = serve(&config.config, exit_with);
            if let Err(error) = &result {
                // The log is where an operator of the Core looks.
                tracing::error!("{error:#}");
                return ExitCode::FAILURE;
            }
            result
        }
        Command::Tasks {
            config,
            limit,
            json,
        } => print_tasks(&config.config, limit, json).map(|()| true),
        Command::Audit {
            config,
            task,
            limit,
            json,
        } => print_audit(&config.config, task, limit, json).map(|()| true),
        Command::Isolation(command) => isolation(command),
        command => client_command(command),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(NEGATIVE),
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

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")
}

/// Returns false if the worker exhausted its restart budget.
fn serve(config_path: &Path, exit_with: Option<u32>) -> anyhow::Result<bool> {
    let config = Config::load(config_path)?;
    // Opened before anything starts: a parent that is already gone means
    // nobody is waiting for this Core.
    let parent = exit_with
        .map(|pid| {
            let watched = jarvis_sandbox::WatchedProcess::new(pid)
                .with_context(|| format!("process {pid} (--exit-with) cannot be watched"))?;
            if watched.has_exited() {
                bail!("process {pid} (--exit-with) has already exited");
            }
            Ok(watched)
        })
        .transpose()?;
    let runtime = runtime()?;
    let outcome = runtime.block_on(async {
        let shutdown = CancellationToken::new();
        let signal = tokio::spawn(cancel_on_signal(shutdown.clone()));
        if let Some(parent) = parent {
            tokio::spawn(cancel_when_exited(parent, shutdown.clone()));
        }
        let result = daemon::serve(&config, shutdown, |endpoint| {
            // The line tests and scripts wait for. Clients can connect now.
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "ready {endpoint}");
            let _ = stdout.flush();
        })
        .await;
        signal.abort();
        let report = result?;
        Ok(!report.gave_up)
    });
    // A read of the process list that never returns would otherwise keep the
    // process alive: dropping a runtime waits for blocking threads.
    runtime.shutdown_timeout(Duration::from_secs(5));
    outcome
}

/// Stop the Core once the process it was told to follow has exited.
async fn cancel_when_exited(parent: jarvis_sandbox::WatchedProcess, shutdown: CancellationToken) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = tick.tick() => {}
        }
        if parent.has_exited() {
            tracing::info!("the process this Core follows (--exit-with) has exited; stopping");
            shutdown.cancel();
            return;
        }
    }
}

fn isolation(command: IsolationCommand) -> anyhow::Result<bool> {
    match command {
        IsolationCommand::Check { config } => {
            let config = Config::load(&config.config)?;
            let launch = isolation::launch(&config.worker, &isolation::protected_paths(&config))?;
            let report = jarvis_sandbox::report(&launch.confinement)?;
            println!("mechanism   {}", report.mechanism);
            for (key, value) in &report.identity {
                println!("{:<11} {value}", key.replace('_', " "));
            }
            println!("program     {}", launch.command.program.display());
            for grant in &launch.confinement.filesystem {
                let access = match grant.access {
                    jarvis_sandbox::Access::ReadExecute => "read+execute",
                    jarvis_sandbox::Access::Read => "read",
                    jarvis_sandbox::Access::ReadWrite => "read+write",
                };
                println!("grant       {access:<12} {}", grant.path.display());
            }
            let scratch = config
                .database
                .parent()
                .filter(|dir| !dir.as_os_str().is_empty())
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            std::fs::create_dir_all(&scratch)
                .with_context(|| format!("cannot create {}", scratch.display()))?;
            let verified = runtime()?.block_on(isolation::verify(&launch, &scratch));
            match verified {
                Ok(verification) => {
                    for check in &verification.checks {
                        println!("ok          {} ({})", check.name, check.detail);
                    }
                    println!(
                        "verified in {} ms under: {}",
                        verification.elapsed.as_millis(),
                        verification.controls
                    );
                    Ok(true)
                }
                Err(isolation::IsolationError::NotEnforced(checks)) => {
                    for check in &checks {
                        let mark = if check.passed { "ok" } else { "FAILED" };
                        println!("{mark:<11} {} ({})", check.name, check.detail);
                    }
                    println!("worker isolation is NOT enforced; the Core will not start a worker");
                    Ok(false)
                }
                Err(error) => Err(error.into()),
            }
        }
        IsolationCommand::Remove { config } => {
            let config = Config::load(&config.config)?;
            let launch = isolation::launch(&config.worker, &isolation::protected_paths(&config))?;
            let done = jarvis_sandbox::remove(&launch.confinement)?;
            if done.is_empty() {
                println!("nothing to remove");
            }
            for line in done {
                println!("{line}");
            }
            Ok(true)
        }
    }
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

#[cfg(windows)]
async fn wait_for_signal() {
    use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_shutdown};
    let (Ok(mut brk), Ok(mut close), Ok(mut shut)) = (ctrl_break(), ctrl_close(), ctrl_shutdown())
    else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = brk.recv() => {}
        _ = close.recv() => {}
        _ = shut.recv() => {}
    }
}

fn client_command(command: Command) -> anyhow::Result<bool> {
    runtime()?.block_on(async move {
        match command {
            Command::Health { config, json } => health(&config.config, json).await,
            Command::Submit {
                config,
                goal,
                wait,
                timeout,
                json,
            } => submit(&config.config, goal, wait.then_some(*timeout), json).await,
            Command::Clipboard {
                config,
                text,
                wait,
                timeout,
                json,
            } => clipboard(&config.config, text, wait.then_some(*timeout), json).await,
            Command::Chat {
                config,
                message,
                conversation,
                language,
                json,
            } => chat(&config.config, &message, conversation, language, json).await,
            Command::Job {
                config,
                job_id,
                wait,
                timeout,
                json,
            } => {
                let mut client = connect(&config.config).await?;
                let job = if wait {
                    wait_for_job(&mut client, job_id, *timeout).await?
                } else {
                    expect_job(
                        client
                            .call(&RpcRequest::GetJob { job_id, wait_ms: 0 })
                            .await?,
                    )?
                };
                print_job(&job, json)?;
                if !json {
                    print_job_outcomes(&config.config, job_id);
                }
                Ok(!job.status.is_terminal() || job.status == JobStatus::Completed)
            }
            Command::Jobs {
                config,
                limit,
                json,
            } => {
                let mut client = connect(&config.config).await?;
                let jobs = match client.call(&RpcRequest::ListJobs { limit }).await? {
                    RpcResponse::Jobs { jobs } => jobs,
                    other => return Err(unexpected(other)),
                };
                for job in &jobs {
                    if json {
                        println!("{}", serde_json::to_string(job)?);
                    } else {
                        println!("{}", job_line(job));
                    }
                }
                Ok(true)
            }
            Command::Approvals(command) => approvals(command).await,
            Command::Shutdown { config } => {
                let mut client = connect(&config.config).await?;
                match client.call(&RpcRequest::Shutdown {}).await? {
                    RpcResponse::ShuttingDown {} => {
                        println!("the Core is shutting down");
                        Ok(true)
                    }
                    other => Err(unexpected(other)),
                }
            }
            Command::Serve { .. }
            | Command::Tasks { .. }
            | Command::Audit { .. }
            | Command::Isolation(_) => {
                bail!("internal error: not a client command")
            }
        }
    })
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Language {
    PtPt,
    En,
    Auto,
}

async fn chat(
    config_path: &Path,
    message: &str,
    conversation: Option<ConversationId>,
    language: Language,
    json: bool,
) -> anyhow::Result<bool> {
    let text = ChatText::try_from(message.to_owned()).map_err(anyhow::Error::msg)?;
    let language = match language {
        Language::PtPt => ChatLanguage::PtPt,
        Language::En => ChatLanguage::En,
        Language::Auto => ChatLanguage::Auto,
    };
    let mut client = connect(config_path).await?;
    let turn = match client
        .call(&RpcRequest::ChatSend {
            conversation_id: conversation,
            text,
            language,
        })
        .await?
    {
        RpcResponse::ChatTurn(turn) => turn,
        other => return Err(unexpected(other)),
    };
    let mut cursor = 0;
    let mut stdout = std::io::stdout();
    loop {
        let delta = match client
            .call(&RpcRequest::ChatPoll {
                turn_id: turn.turn_id,
                cursor,
                wait_ms: 30_000,
            })
            .await?
        {
            RpcResponse::ChatDelta(delta) => delta,
            other => return Err(unexpected(other)),
        };
        cursor = delta.next_cursor;
        if !json {
            write!(stdout, "{}", delta.text)?;
            stdout.flush()?;
        }
        if delta.status.is_final() {
            if json {
                let view = match client
                    .call(&RpcRequest::GetConversation {
                        conversation_id: turn.conversation_id,
                    })
                    .await?
                {
                    RpcResponse::Conversation(view) => view,
                    other => return Err(unexpected(other)),
                };
                let reply = view.messages.iter().find(|m| m.message_id == turn.turn_id);
                println!(
                    "{}",
                    serde_json::json!({
                        "conversation_id": turn.conversation_id,
                        "turn_id": turn.turn_id,
                        "status": delta.status,
                        "error": delta.error,
                        "reply": reply,
                    })
                );
            } else {
                writeln!(stdout)?;
                if let Some(error) = &delta.error {
                    eprintln!("error: {error}");
                }
                if let Some(stats) = &delta.stats {
                    eprintln!(
                        "[{} prompt tokens, {} reply tokens, first token {} ms, {:.1} tokens/s; conversation {}]",
                        stats.prompt_tokens,
                        stats.completion_tokens,
                        stats.first_token_ms,
                        f64::from(stats.tokens_per_second_x10) / 10.0,
                        turn.conversation_id
                    );
                }
                if let Some(proposal) = &delta.proposal {
                    eprintln!("[clipboard proposal: {:?}]", proposal.as_str());
                }
            }
            return Ok(delta.status == MessageStatus::Complete);
        }
    }
}

async fn connect(config_path: &Path) -> anyhow::Result<Client> {
    let config = Config::load(config_path)?;
    let endpoint = Endpoint::from_config(&config.rpc);
    Ok(Client::connect(&endpoint).await?)
}

/// Turn an RPC error reply into an error, and anything else unexpected too.
fn unexpected(response: RpcResponse) -> anyhow::Error {
    match response {
        RpcResponse::Error(error) => rpc_error(&error),
        other => anyhow::anyhow!("unexpected response from the Core: {other:?}"),
    }
}

fn rpc_error(error: &RpcError) -> anyhow::Error {
    anyhow::anyhow!(
        "the Core refused the request ({}): {}",
        error.code,
        error.message
    )
}

async fn health(config_path: &Path, json: bool) -> anyhow::Result<bool> {
    let mut client = connect(config_path).await?;
    let report = match client.call(&RpcRequest::Health {}).await? {
        RpcResponse::Health(report) => report,
        other => return Err(unexpected(other)),
    };
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        print_health(&report);
    }
    Ok(report.ok)
}

fn print_health(report: &HealthReport) {
    let worker = &report.worker;
    println!(
        "status             {}",
        if report.ok { "ok" } else { "worker failed" }
    );
    println!("core               {}", report.core_version);
    println!(
        "protocols          worker {}, rpc {}",
        report.worker_protocol, report.rpc_protocol
    );
    println!(
        "uptime             {}",
        humantime::format_duration(Duration::from_secs(report.uptime_ms / 1000))
    );
    let state = serde_json::to_value(worker.state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    println!(
        "worker             {state}{}",
        worker
            .pid
            .map(|pid| format!(" (pid {pid})"))
            .unwrap_or_default()
    );
    println!("restarts           {}", worker.restarts);
    println!(
        "containment        {}",
        if worker.containment.is_empty() {
            "-"
        } else {
            &worker.containment
        }
    );
    println!("governor           {}", governor_line(&report.governor));
    println!("queued jobs        {}", report.queued_jobs);
    println!("pending approvals  {}", report.pending_approvals);
}

/// One line for `health`: whether queued jobs may start, and if not, why.
fn governor_line(governor: &GovernorView) -> String {
    let held_for = || {
        governor
            .held_ms
            .map(|ms| humantime::format_duration(Duration::from_secs(ms / 1000)).to_string())
            .unwrap_or_default()
    };
    let line = match governor.state {
        GovernorPhase::Off => return "off".to_owned(),
        GovernorPhase::Open => return "open".to_owned(),
        GovernorPhase::Releasing => format!("releasing, held for {}", held_for()),
        GovernorPhase::Held => {
            let why = match (governor.reason, governor.process.as_deref()) {
                (Some(GovernorReason::Game), Some(name)) => format!("{name} is running"),
                (Some(GovernorReason::DetectionFailed), _) => {
                    "cannot read the process list".to_owned()
                }
                (Some(GovernorReason::Starting), _) => "waiting for the first check".to_owned(),
                _ => "queued jobs are held".to_owned(),
            };
            format!("held, {why}, for {}", held_for())
        }
    };
    if governor.overdue {
        format!("{line} (longer than the alert time)")
    } else {
        line
    }
}

async fn submit(
    config_path: &Path,
    goal: String,
    wait: Option<Duration>,
    json: bool,
) -> anyhow::Result<bool> {
    let goal = Goal::try_from(goal).map_err(|error| anyhow::anyhow!("invalid goal: {error}"))?;
    queue(config_path, &RpcRequest::SubmitJob { goal }, wait, json).await
}

async fn clipboard(
    config_path: &Path,
    text: String,
    wait: Option<Duration>,
    json: bool,
) -> anyhow::Result<bool> {
    let text = ClipboardText::try_from(text)
        .map_err(|error| anyhow::anyhow!("invalid clipboard text: {error}"))?;
    queue(
        config_path,
        &RpcRequest::SubmitClipboardJob { text },
        wait,
        json,
    )
    .await
}

/// Send a request that queues a job, and optionally wait for it to finish.
async fn queue(
    config_path: &Path,
    request: &RpcRequest,
    wait: Option<Duration>,
    json: bool,
) -> anyhow::Result<bool> {
    let mut client = connect(config_path).await?;
    let job = expect_job(client.call(request).await?)?;
    let Some(timeout) = wait else {
        print_job(&job, json)?;
        return Ok(true);
    };
    if !json {
        eprintln!("submitted job {}; waiting for it to finish", job.job_id);
    }
    let job = wait_for_job(&mut client, job.job_id, timeout).await?;
    print_job(&job, json)?;
    Ok(job.status == JobStatus::Completed)
}

fn expect_job(response: RpcResponse) -> anyhow::Result<JobView> {
    match response {
        RpcResponse::Job(job) => Ok(job),
        other => Err(unexpected(other)),
    }
}

async fn wait_for_job(
    client: &mut Client,
    job_id: JobId,
    timeout: Duration,
) -> anyhow::Result<JobView> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let wait_ms = u32::try_from(left.min(POLL).as_millis()).unwrap_or(0);
        let job = expect_job(client.call(&RpcRequest::GetJob { job_id, wait_ms }).await?)?;
        if job.status.is_terminal() {
            return Ok(job);
        }
        if left.is_zero() {
            bail!(
                "job {job_id} is still {} after {}",
                job.status,
                humantime::format_duration(timeout)
            );
        }
    }
}

fn print_job(job: &JobView, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string(job)?);
    } else {
        println!("job        {}", job.job_id);
        println!("status     {}", job.status);
        println!("goal       {}", job.goal);
        println!(
            "summary    {}",
            job.summary.as_ref().map_or("-", Summary::as_str)
        );
        println!("submitted  {}", job.submitted_at);
        println!("updated    {}", job.updated_at);
    }
    Ok(())
}

fn job_line(job: &JobView) -> String {
    let line = format!(
        "{}  {}  {:<11}  {}  {}",
        job.submitted_at,
        job.job_id,
        job.status.as_str(),
        job.goal,
        job.summary.as_ref().map_or("", Summary::as_str)
    );
    line.trim_end().to_owned()
}

async fn approvals(command: ApprovalCommand) -> anyhow::Result<bool> {
    match command {
        ApprovalCommand::List { config, wait, json } => {
            let mut client = connect(&config.config).await?;
            let wait = wait.map_or(Duration::ZERO, |wait| *wait);
            let deadline = tokio::time::Instant::now() + wait;
            let approvals = loop {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                let wait_ms = u32::try_from(left.min(POLL).as_millis()).unwrap_or(0);
                let approvals = match client.call(&RpcRequest::ListApprovals { wait_ms }).await? {
                    RpcResponse::Approvals { approvals } => approvals,
                    other => return Err(unexpected(other)),
                };
                if !approvals.is_empty() || left.is_zero() {
                    break approvals;
                }
            };
            if json {
                for approval in &approvals {
                    println!("{}", serde_json::to_string(approval)?);
                }
            } else if approvals.is_empty() {
                println!("no pending approvals");
            } else {
                for (i, approval) in approvals.iter().enumerate() {
                    if i > 0 {
                        println!();
                    }
                    print_approval(approval);
                }
            }
            Ok(true)
        }
        ApprovalCommand::Show {
            config,
            approval_id,
            json,
        } => {
            let mut client = connect(&config.config).await?;
            let approval = get_approval(&mut client, approval_id).await?;
            if json {
                println!("{}", serde_json::to_string(&approval)?);
            } else {
                print_approval(&approval);
            }
            Ok(true)
        }
        ApprovalCommand::Approve {
            config,
            approval_id,
            fingerprint,
            yes,
        } => {
            let mut client = connect(&config.config).await?;
            let approval = get_approval(&mut client, approval_id).await?;
            print_approval(&approval);
            if approval.status != ApprovalStatus::Pending {
                bail!("approval {approval_id} is {}, not pending", approval.status);
            }
            // Bind the decision to what the person reviewed: the fingerprint
            // they pass, or else the one of the request shown above.
            let fingerprint = match fingerprint {
                Some(expected) if expected != approval.fingerprint => bail!(
                    "the request's fingerprint is {}, not the one given; nothing was approved",
                    approval.fingerprint
                ),
                Some(expected) => expected,
                None => approval.fingerprint.clone(),
            };
            if !yes {
                match confirm()? {
                    Answer::Approve => {}
                    Answer::Deny => {
                        let reason = Summary::try_from("denied at the terminal".to_owned())
                            .map_err(|error| anyhow::anyhow!("invalid reason: {error}"))?;
                        return match client
                            .call(&RpcRequest::Deny {
                                approval_id,
                                reason,
                            })
                            .await?
                        {
                            RpcResponse::Approval(_) => {
                                println!("denied");
                                Ok(false)
                            }
                            other => Err(unexpected(other)),
                        };
                    }
                    Answer::Cancel => {
                        println!("cancelled; the request is still pending");
                        return Ok(false);
                    }
                }
            }
            match client
                .call(&RpcRequest::Approve {
                    approval_id,
                    fingerprint,
                })
                .await?
            {
                RpcResponse::Approval(approval) => {
                    println!(
                        "approval {} is now {}",
                        approval.approval_id, approval.status
                    );
                    Ok(true)
                }
                other => Err(unexpected(other)),
            }
        }
        ApprovalCommand::Deny {
            config,
            approval_id,
            reason,
        } => {
            let reason = Summary::try_from(reason)
                .map_err(|error| anyhow::anyhow!("invalid reason: {error}"))?;
            let mut client = connect(&config.config).await?;
            match client
                .call(&RpcRequest::Deny {
                    approval_id,
                    reason,
                })
                .await?
            {
                RpcResponse::Approval(approval) => {
                    println!(
                        "approval {} is now {}",
                        approval.approval_id, approval.status
                    );
                    Ok(true)
                }
                other => Err(unexpected(other)),
            }
        }
    }
}

async fn get_approval(
    client: &mut Client,
    approval_id: ApprovalId,
) -> anyhow::Result<ApprovalView> {
    match client
        .call(&RpcRequest::GetApproval { approval_id })
        .await?
    {
        RpcResponse::Approval(approval) => Ok(approval),
        other => Err(unexpected(other)),
    }
}

/// What the person typed at the terminal.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Approve,
    Deny,
    Cancel,
}

fn parse_answer(text: &str) -> Answer {
    match text.trim() {
        "yes" => Answer::Approve,
        "no" => Answer::Deny,
        _ => Answer::Cancel,
    }
}

/// Ask at the terminal. Refuses to guess when there is no terminal.
fn confirm() -> anyhow::Result<Answer> {
    if !std::io::stdin().is_terminal() {
        bail!("no terminal to confirm on; review the request and pass --yes to approve it");
    }
    eprint!("Approve this request? Type yes to approve, no to deny, or press Enter to cancel: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(parse_answer(&answer))
}

/// Everything a person needs to decide. Every value comes from the Core
/// already made safe to print (control characters escaped, long text cut).
fn print_approval(approval: &ApprovalView) {
    let capabilities: Vec<&str> = approval
        .capabilities
        .iter()
        .map(|capability| capability.as_str())
        .collect();
    println!("approval      {}", approval.approval_id);
    println!("status        {}", approval.status);
    println!("tool          {}", approval.tool);
    println!("capabilities  {}", capabilities.join(", "));
    if approval.arguments.is_empty() {
        println!("arguments     (none)");
    }
    for (i, (key, value)) in approval.arguments.iter().enumerate() {
        let label = if i == 0 { "arguments" } else { "" };
        println!("{label:<12}  {key} = {value}");
    }
    println!("task          {}", approval.task_id);
    println!("request       {}", approval.request_id);
    println!(
        "job           {}",
        approval
            .job_id
            .map_or_else(|| "-".to_owned(), |id| id.to_string())
    );
    println!(
        "requested     {} ({} ago)",
        approval.requested_at,
        age(&approval.requested_at)
    );
    let left = if approval.expires_in_ms == 0 {
        "expired".to_owned()
    } else {
        format!(
            "in {}",
            humantime::format_duration(Duration::from_secs(approval.expires_in_ms.div_ceil(1000)))
        )
    };
    println!("expires       {} ({left})", approval.expires_at);
    println!("fingerprint   {}", approval.fingerprint);
}

fn age(at: &str) -> String {
    humantime::parse_rfc3339(at)
        .ok()
        .and_then(|at| SystemTime::now().duration_since(at).ok())
        .map_or_else(
            || "?".to_owned(),
            |age| humantime::format_duration(Duration::from_secs(age.as_secs())).to_string(),
        )
}

fn open_store(config_path: &Path) -> anyhow::Result<Store> {
    let config = Config::load(config_path)?;
    Store::open_read_only(&config.database)
        .with_context(|| format!("cannot open {}", config.database.display()))
}

/// Audit events that settle an agent operation, with how each is shown.
/// In order of precedence: if a task ever had more than one outcome, the
/// least reassuring one is shown.
const OUTCOME_EVENTS: [(&str, &str); 3] = [
    (
        "session_agent_outcome_unknown",
        "OUTCOME UNKNOWN (may have happened; not retried)",
    ),
    ("session_agent_refused", "REFUSED (not performed)"),
    ("session_agent_completed", "COMPLETED"),
];

fn is_agent_tool(tool: &str) -> bool {
    tool.starts_with("session_agent.") || tool.starts_with("desktop.")
}

/// How an agent operation ended, from the names of its task's audit events.
/// `-` while no outcome has been recorded.
fn agent_outcome(events: &[&str]) -> &'static str {
    OUTCOME_EVENTS
        .iter()
        .find(|(name, _)| events.contains(name))
        .map_or("-", |(_, text)| text)
}

/// The outcome of a task, or `None` if it does not go through the Session
/// Agent.
fn task_outcome(
    store: &Store,
    task_id: TaskId,
    tool: &str,
) -> anyhow::Result<Option<&'static str>> {
    if !is_agent_tool(tool) {
        return Ok(None);
    }
    let events = store.audit_events(Some(task_id), 500)?;
    let names: Vec<&str> = events.iter().map(|event| event.event.name()).collect();
    Ok(Some(agent_outcome(&names)))
}

/// One `outcome` line per agent task of a job, when there are any. A failure
/// to read the audit log is reported but does not change the exit status.
fn print_job_outcomes(config_path: &Path, job_id: JobId) {
    let lines = (|| -> anyhow::Result<Vec<String>> {
        let store = open_store(config_path)?;
        let mut lines = Vec::new();
        for task in store.tasks(500)?.into_iter().rev() {
            if task.job_id != Some(job_id) {
                continue;
            }
            if let Some(outcome) = task_outcome(&store, task.task_id, &task.tool)? {
                lines.push(format!("outcome    {outcome}"));
            }
        }
        Ok(lines)
    })();
    match lines {
        Ok(lines) => lines.iter().for_each(|line| println!("{line}")),
        Err(error) => eprintln!("cannot read the outcome: {error:#}"),
    }
}

fn print_tasks(config_path: &Path, limit: u32, json: bool) -> anyhow::Result<()> {
    let store = open_store(config_path)?;
    for task in store.tasks(limit)?.into_iter().rev() {
        let outcome = task_outcome(&store, task.task_id, &task.tool)?;
        if json {
            let mut value = serde_json::json!({
                "task_id": task.task_id,
                "session_id": task.session_id,
                "job_id": task.job_id,
                "request_id": task.request_id,
                "tool": task.tool,
                "status": task.status,
                "decision": task.decision,
                "capabilities": task.capabilities,
                "error": task.error,
                "created_at": task.created_at,
                "updated_at": task.updated_at,
            });
            if let (Some(outcome), Some(object)) = (outcome, value.as_object_mut()) {
                object.insert("outcome".to_owned(), outcome.into());
            }
            println!("{value}");
        } else {
            let decision = task.decision.map_or("-", |d| d.as_str());
            let error = task
                .error
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_default();
            let outcome = outcome.map_or_else(String::new, |o| format!("  outcome: {o}"));
            let line = format!(
                "{}  {}  {:<21} {:<23} {:<20} {}{}",
                task.created_at,
                task.task_id,
                task.status.as_str(),
                task.tool,
                decision,
                error,
                outcome
            );
            println!("{}", line.trim_end());
        }
    }
    Ok(())
}

fn print_audit(
    config_path: &Path,
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
                "{:>5}  {}  {:<26} {:<36}  {}",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn view(
        state: GovernorPhase,
        reason: Option<GovernorReason>,
        held_ms: Option<u64>,
    ) -> GovernorView {
        GovernorView {
            state,
            reason,
            process: (reason == Some(GovernorReason::Game)).then(|| "cs2.exe".to_owned()),
            held_ms,
            overdue: false,
        }
    }

    #[test]
    fn terminal_answers_are_exact() {
        assert_eq!(parse_answer("yes\n"), Answer::Approve);
        assert_eq!(parse_answer(" no \r\n"), Answer::Deny);
        for other in ["", "\n", "y", "Yes", "NO", "yes please", "n"] {
            assert_eq!(parse_answer(other), Answer::Cancel, "{other:?}");
        }
    }

    #[test]
    fn agent_outcomes_are_unambiguous() {
        assert_eq!(
            agent_outcome(&["execution_started", "session_agent_dispatched"]),
            "-"
        );
        assert_eq!(
            agent_outcome(&["session_agent_dispatched", "session_agent_completed"]),
            "COMPLETED"
        );
        assert_eq!(
            agent_outcome(&["session_agent_refused"]),
            "REFUSED (not performed)"
        );
        assert_eq!(
            agent_outcome(&["session_agent_outcome_unknown"]),
            "OUTCOME UNKNOWN (may have happened; not retried)"
        );
        assert!(is_agent_tool("desktop.write_clipboard_text"));
        assert!(is_agent_tool("session_agent.healthcheck"));
        assert!(!is_agent_tool("system.info"));
    }

    #[test]
    fn health_says_why_jobs_are_held() {
        assert_eq!(governor_line(&GovernorView::OFF), "off");
        assert_eq!(
            governor_line(&view(GovernorPhase::Open, None, None)),
            "open"
        );
        let game = view(
            GovernorPhase::Held,
            Some(GovernorReason::Game),
            Some(61_000),
        );
        assert_eq!(governor_line(&game), "held, cs2.exe is running, for 1m 1s");
        let failed = view(
            GovernorPhase::Held,
            Some(GovernorReason::DetectionFailed),
            Some(5_000),
        );
        assert_eq!(
            governor_line(&failed),
            "held, cannot read the process list, for 5s"
        );
        let releasing = view(GovernorPhase::Releasing, None, Some(90_000));
        assert_eq!(governor_line(&releasing), "releasing, held for 1m 30s");
        let overdue = GovernorView {
            overdue: true,
            ..game
        };
        assert!(governor_line(&overdue).ends_with("(longer than the alert time)"));
    }
}
