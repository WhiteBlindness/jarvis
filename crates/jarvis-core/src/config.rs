//! Configuration loading and validation.
//!
//! The config file is TOML. Unknown keys are errors, relative paths are
//! resolved against the directory that contains the file, and every limit is
//! checked against a sane range before the Core starts. The policy cannot
//! grant a capability more than its action class allows.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jarvis_protocol::{Capability, PolicyDecision};
use serde::Deserialize;

use crate::policy::Policy;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub database: PathBuf,
    pub worker: WorkerConfig,
    pub fixtures: RootConfig,
    pub workspace: RootConfig,
    pub limits: Limits,
    pub approvals: ApprovalConfig,
    pub supervisor: SupervisorConfig,
    pub rpc: RpcConfig,
    pub governor: GovernorConfig,
    pub session_agent: SessionAgentConfig,
    /// The local model (ADR 0021). `None` when the section is absent.
    pub inference: Option<InferenceConfig>,
    pub policy: Policy,
}

/// The local model server the Core starts and talks to on loopback
/// (ADR 0021).
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    /// The `llama-server` executable.
    pub server: PathBuf,
    /// Conversations, in their own database (not the audit database).
    pub chat_database: PathBuf,
    /// The system prompt that gives the assistant its voice.
    pub persona: PathBuf,
    pub primary: ModelConfig,
    /// A model used while a game runs, when `on_game` is `fallback`.
    pub fallback: Option<ModelConfig>,
    pub on_game: OnGame,
    pub context_size: u32,
    pub max_reply_tokens: u32,
    /// Penalty on tokens already used in the reply (0.0 to 2.0).
    pub presence_penalty: f64,
    pub threads: u32,
    pub load_timeout: Duration,
    pub reply_timeout: Duration,
    /// Conversations not updated for this many days are deleted; 0 keeps
    /// them until a person deletes them.
    pub retention_days: u32,
    pub load_on_start: bool,
    /// A warm-up after each load measures generation speed; a GPU model
    /// below this many tokens per second is reported as slow (0: never).
    pub slow_below_tokens_per_second: u32,
}

/// One model file and how to run it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelConfig {
    /// Shown to people.
    pub name: String,
    pub path: PathBuf,
    /// Expected SHA-256, 64 lowercase hexadecimal characters. A file that
    /// does not match is never loaded.
    pub sha256: String,
    /// Layers on the GPU; 0 runs on the CPU only.
    pub gpu_layers: u32,
}

/// What the model does while the governor reports a game.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnGame {
    /// Stop the server so the game has the GPU; chat waits.
    Unload,
    /// Switch to the fallback model (normally CPU only).
    Fallback,
}

/// The Session Agent (ADR 0019): a trusted helper the Core starts on first
/// use and talks to over pipes only it holds.
#[derive(Debug, Clone)]
pub struct SessionAgentConfig {
    /// The agent executable. `None` means `jarvis-session-agent` next to the
    /// Core's own executable.
    pub program: Option<PathBuf>,
    /// How long the agent has to start or to answer one operation.
    pub timeout: Duration,
    /// Lifetime of a grant from its issue to its use.
    pub grant_ttl: Duration,
    /// Agent starts allowed per Core run, the first included.
    pub max_starts: u32,
}

impl Default for SessionAgentConfig {
    fn default() -> Self {
        Self {
            program: None,
            timeout: Duration::from_secs(5),
            grant_ttl: Duration::from_secs(10),
            max_starts: 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Program to run. Started directly, never through a shell, with an
    /// empty environment apart from `PATH` and `SYSTEMROOT`.
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub handshake_timeout: Duration,
    /// Memory limit applied by the OS containment.
    pub memory_limit_bytes: u64,
}

/// A directory a tool is confined to.
#[derive(Debug, Clone)]
pub struct RootConfig {
    pub root: PathBuf,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub tool_timeout: Duration,
    /// How long a write to the worker may block. A worker that stops
    /// reading its input must not stall the Core.
    pub write_timeout: Duration,
    pub max_requests_per_session: u32,
    pub max_protocol_errors: u32,
    /// How many times a job may be claimed before it is no longer put back in
    /// the queue after its worker or the Core stops.
    pub max_job_attempts: u32,
    pub shutdown_grace: Duration,
}

impl Limits {
    /// Bytes reserved for the response envelope around a tool result, so a
    /// verified result always fits in one frame.
    pub const RESPONSE_OVERHEAD: usize = 1024;

    pub fn max_result_bytes(&self) -> usize {
        self.max_frame_bytes - Self::RESPONSE_OVERHEAD
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 64 * 1024,
            tool_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            max_requests_per_session: 1000,
            max_protocol_errors: 16,
            max_job_attempts: 3,
            shutdown_grace: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ApprovalConfig {
    /// How long a person has to decide before the approval expires.
    pub ttl: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct SupervisorConfig {
    /// Restarts allowed within `restart_window` before the Core gives up on
    /// the worker.
    pub restart_budget: u32,
    pub restart_window: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// Longest a job may run, including time spent waiting for approvals.
    pub job_timeout: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            restart_budget: 5,
            restart_window: Duration::from_secs(300),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            job_timeout: Duration::from_secs(600),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Unix domain socket path. Its directory is created with mode 0700.
    pub socket: PathBuf,
    /// Windows named pipe name, without the `\\.\pipe\` prefix.
    pub pipe: String,
    /// Whether a local client may stop the Core.
    pub allow_shutdown: bool,
    pub max_connections: usize,
    pub idle_timeout: Duration,
}

/// The gaming governor (ADR 0016): while a listed process runs, queued jobs
/// wait. Off by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernorConfig {
    pub enabled: bool,
    /// Executable names that count as a game, compared ASCII
    /// case-insensitively. Validated even when the governor is off.
    pub processes: Vec<String>,
    /// How often the process list is read.
    pub poll: Duration,
    /// How long the list must stay clear before queued jobs start again.
    pub resume_delay: Duration,
    /// After this long a hold raises an alert. It never ends the hold.
    pub alert_after: Duration,
}

impl GovernorConfig {
    pub const MAX_PROCESSES: usize = 16;
    pub const MAX_NAME_BYTES: usize = 64;
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            processes: vec!["cs2.exe".to_owned()],
            poll: Duration::from_millis(5_000),
            resume_delay: Duration::from_millis(30_000),
            alert_after: Duration::from_millis(4 * 60 * 60 * 1_000),
        }
    }
}

impl RpcConfig {
    /// Largest request frame a client may send.
    pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
    /// Longest a long-polling request may wait.
    pub const MAX_WAIT: Duration = Duration::from_secs(60);
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    database: PathBuf,
    worker: RawWorker,
    fixtures: RawRoot,
    workspace: RawRoot,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    approvals: RawApprovals,
    #[serde(default)]
    supervisor: RawSupervisor,
    #[serde(default)]
    rpc: RawRpc,
    #[serde(default)]
    governor: RawGovernor,
    #[serde(default)]
    session_agent: RawSessionAgent,
    inference: Option<RawInference>,
    policy: BTreeMap<Capability, PolicyDecision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInference {
    server: PathBuf,
    chat_database: Option<PathBuf>,
    persona: PathBuf,
    primary: RawModel,
    fallback: Option<RawModel>,
    on_game: Option<OnGame>,
    context_size: Option<u32>,
    max_reply_tokens: Option<u32>,
    presence_penalty: Option<f64>,
    threads: Option<u32>,
    load_timeout_ms: Option<u64>,
    reply_timeout_ms: Option<u64>,
    retention_days: Option<u32>,
    load_on_start: Option<bool>,
    slow_below_tokens_per_second: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModel {
    name: String,
    path: PathBuf,
    sha256: String,
    gpu_layers: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSessionAgent {
    program: Option<PathBuf>,
    timeout_ms: Option<u64>,
    grant_ttl_ms: Option<u64>,
    max_starts: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorker {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<PathBuf>,
    handshake_timeout_ms: Option<u64>,
    memory_limit_mb: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoot {
    root: PathBuf,
    max_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_frame_bytes: Option<usize>,
    tool_timeout_ms: Option<u64>,
    write_timeout_ms: Option<u64>,
    max_requests_per_session: Option<u32>,
    max_protocol_errors: Option<u32>,
    max_job_attempts: Option<u32>,
    shutdown_grace_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApprovals {
    ttl_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSupervisor {
    restart_budget: Option<u32>,
    restart_window_ms: Option<u64>,
    backoff_initial_ms: Option<u64>,
    backoff_max_ms: Option<u64>,
    job_timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRpc {
    socket: Option<PathBuf>,
    pipe: Option<String>,
    allow_shutdown: Option<bool>,
    max_connections: Option<usize>,
    idle_timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGovernor {
    enabled: Option<bool>,
    processes: Option<Vec<String>>,
    poll_ms: Option<u64>,
    resume_delay_ms: Option<u64>,
    alert_after_ms: Option<u64>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::from_toml(&text, base)
    }

    /// Parse config text; relative paths are resolved against `base`.
    pub fn from_toml(text: &str, base: &Path) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text)?;
        let resolve = |path: PathBuf| {
            if path.is_absolute() {
                path
            } else {
                base.join(path)
            }
        };

        let defaults = Limits::default();
        let limits = Limits {
            max_frame_bytes: within(
                "limits.max_frame_bytes",
                raw.limits
                    .max_frame_bytes
                    .unwrap_or(defaults.max_frame_bytes),
                4 * 1024,
                1024 * 1024,
            )?,
            tool_timeout: ms(
                "limits.tool_timeout_ms",
                raw.limits.tool_timeout_ms,
                defaults.tool_timeout,
                1,
                600_000,
            )?,
            write_timeout: ms(
                "limits.write_timeout_ms",
                raw.limits.write_timeout_ms,
                defaults.write_timeout,
                1,
                60_000,
            )?,
            max_requests_per_session: within(
                "limits.max_requests_per_session",
                raw.limits
                    .max_requests_per_session
                    .unwrap_or(defaults.max_requests_per_session),
                1,
                100_000,
            )?,
            max_protocol_errors: within(
                "limits.max_protocol_errors",
                raw.limits
                    .max_protocol_errors
                    .unwrap_or(defaults.max_protocol_errors),
                1,
                1_000,
            )?,
            max_job_attempts: within(
                "limits.max_job_attempts",
                raw.limits
                    .max_job_attempts
                    .unwrap_or(defaults.max_job_attempts),
                1,
                10,
            )?,
            shutdown_grace: ms(
                "limits.shutdown_grace_ms",
                raw.limits.shutdown_grace_ms,
                defaults.shutdown_grace,
                1,
                60_000,
            )?,
        };

        if raw.worker.program.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "worker.program must not be empty".into(),
            ));
        }
        let worker = WorkerConfig {
            program: raw.worker.program,
            args: raw.worker.args,
            cwd: raw.worker.cwd.map(resolve),
            handshake_timeout: ms(
                "worker.handshake_timeout_ms",
                raw.worker.handshake_timeout_ms,
                Duration::from_secs(5),
                1,
                60_000,
            )?,
            memory_limit_bytes: within(
                "worker.memory_limit_mb",
                raw.worker.memory_limit_mb.unwrap_or(512),
                64,
                16 * 1024,
            )? * 1024
                * 1024,
        };

        // Leave room for JSON escaping; the Gateway still checks the real size.
        let max_root_bytes = (limits.max_result_bytes() as u64) / 2;
        let fixtures = RootConfig {
            root: resolve(raw.fixtures.root),
            max_bytes: within(
                "fixtures.max_bytes",
                raw.fixtures.max_bytes.unwrap_or(16 * 1024),
                1,
                max_root_bytes,
            )?,
        };
        let workspace = RootConfig {
            root: resolve(raw.workspace.root),
            max_bytes: within(
                "workspace.max_bytes",
                raw.workspace.max_bytes.unwrap_or(16 * 1024),
                1,
                max_root_bytes,
            )?,
        };

        let approvals = ApprovalConfig {
            ttl: ms(
                "approvals.ttl_ms",
                raw.approvals.ttl_ms,
                Duration::from_secs(300),
                1_000,
                3_600_000,
            )?,
        };

        let supervisor_defaults = SupervisorConfig::default();
        let supervisor = SupervisorConfig {
            restart_budget: within(
                "supervisor.restart_budget",
                raw.supervisor
                    .restart_budget
                    .unwrap_or(supervisor_defaults.restart_budget),
                0,
                100,
            )?,
            restart_window: ms(
                "supervisor.restart_window_ms",
                raw.supervisor.restart_window_ms,
                supervisor_defaults.restart_window,
                1_000,
                86_400_000,
            )?,
            backoff_initial: ms(
                "supervisor.backoff_initial_ms",
                raw.supervisor.backoff_initial_ms,
                supervisor_defaults.backoff_initial,
                1,
                600_000,
            )?,
            backoff_max: ms(
                "supervisor.backoff_max_ms",
                raw.supervisor.backoff_max_ms,
                supervisor_defaults.backoff_max,
                1,
                3_600_000,
            )?,
            job_timeout: ms(
                "supervisor.job_timeout_ms",
                raw.supervisor.job_timeout_ms,
                supervisor_defaults.job_timeout,
                1_000,
                86_400_000,
            )?,
        };
        if supervisor.backoff_max < supervisor.backoff_initial {
            return Err(ConfigError::Invalid(
                "supervisor.backoff_max_ms must not be below backoff_initial_ms".into(),
            ));
        }
        if supervisor.job_timeout <= approvals.ttl + limits.tool_timeout {
            return Err(ConfigError::Invalid(
                "supervisor.job_timeout_ms must exceed approvals.ttl_ms plus limits.tool_timeout_ms"
                    .into(),
            ));
        }

        let database = resolve(raw.database);
        let socket = match raw.rpc.socket {
            Some(socket) => resolve(socket),
            None => database
                .parent()
                .unwrap_or(Path::new("."))
                .join("rpc")
                .join("jarvis.sock"),
        };
        let pipe = raw.rpc.pipe.unwrap_or_else(|| "jarvis".to_owned());
        if pipe.is_empty()
            || pipe.len() > 200
            || !pipe
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ConfigError::Invalid(
                "rpc.pipe must be 1 to 200 characters from [A-Za-z0-9._-]".into(),
            ));
        }
        let rpc = RpcConfig {
            socket,
            pipe,
            allow_shutdown: raw.rpc.allow_shutdown.unwrap_or(false),
            max_connections: within(
                "rpc.max_connections",
                raw.rpc.max_connections.unwrap_or(16),
                1,
                256,
            )?,
            idle_timeout: ms(
                "rpc.idle_timeout_ms",
                raw.rpc.idle_timeout_ms,
                Duration::from_secs(30),
                100,
                3_600_000,
            )?,
        };

        let governor_defaults = GovernorConfig::default();
        let governor = GovernorConfig {
            enabled: raw.governor.enabled.unwrap_or(governor_defaults.enabled),
            processes: process_names(
                raw.governor
                    .processes
                    .unwrap_or(governor_defaults.processes),
            )?,
            poll: ms(
                "governor.poll_ms",
                raw.governor.poll_ms,
                governor_defaults.poll,
                250,
                60_000,
            )?,
            resume_delay: ms(
                "governor.resume_delay_ms",
                raw.governor.resume_delay_ms,
                governor_defaults.resume_delay,
                0,
                600_000,
            )?,
            alert_after: ms(
                "governor.alert_after_ms",
                raw.governor.alert_after_ms,
                governor_defaults.alert_after,
                60_000,
                86_400_000,
            )?,
        };

        let agent_defaults = SessionAgentConfig::default();
        let session_agent = SessionAgentConfig {
            program: raw.session_agent.program.map(resolve),
            timeout: ms(
                "session_agent.timeout_ms",
                raw.session_agent.timeout_ms,
                agent_defaults.timeout,
                100,
                60_000,
            )?,
            grant_ttl: ms(
                "session_agent.grant_ttl_ms",
                raw.session_agent.grant_ttl_ms,
                agent_defaults.grant_ttl,
                100,
                jarvis_protocol::MAX_GRANT_TTL_MS,
            )?,
            max_starts: within(
                "session_agent.max_starts",
                raw.session_agent
                    .max_starts
                    .unwrap_or(agent_defaults.max_starts),
                1,
                100,
            )?,
        };

        let inference = match raw.inference {
            None => None,
            Some(raw_inference) => Some(inference_config(raw_inference, &database, &resolve)?),
        };

        for (&capability, &decision) in &raw.policy {
            // Writing the clipboard is the one desktop operation (ADR 0020).
            // The owner opts in here; each write still needs an approval.
            if capability.is_desktop()
                && capability != Capability::DesktopClipboardWrite
                && decision != PolicyDecision::Deny
            {
                return Err(ConfigError::Invalid(format!(
                    "policy cannot set `{capability}` to `{decision}`: that desktop operation \
                     is not available, so it can only be `deny`"
                )));
            }
            let ceiling = capability.class().ceiling();
            if decision < ceiling {
                return Err(ConfigError::Invalid(format!(
                    "policy cannot set `{capability}` to `{decision}`: it is a class {:?} \
                     capability, so the most it allows is `{ceiling}`",
                    capability.class()
                )));
            }
        }

        Ok(Self {
            database,
            worker,
            fixtures,
            workspace,
            limits,
            approvals,
            supervisor,
            rpc,
            governor,
            session_agent,
            inference,
            policy: Policy::new(raw.policy),
        })
    }
}

fn inference_config(
    raw: RawInference,
    database: &Path,
    resolve: &impl Fn(PathBuf) -> PathBuf,
) -> Result<InferenceConfig, ConfigError> {
    let model = |name: &str, raw: RawModel| -> Result<ModelConfig, ConfigError> {
        if raw.name.trim().is_empty() || raw.name.chars().count() > 120 {
            return Err(ConfigError::Invalid(format!(
                "inference.{name}.name must be 1 to 120 characters"
            )));
        }
        if raw.sha256.len() != 64
            || !raw
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ConfigError::Invalid(format!(
                "inference.{name}.sha256 must be 64 lowercase hexadecimal characters"
            )));
        }
        Ok(ModelConfig {
            name: raw.name,
            path: resolve(raw.path),
            sha256: raw.sha256,
            gpu_layers: within(
                &format!("inference.{name}.gpu_layers"),
                raw.gpu_layers.unwrap_or(999),
                0,
                999,
            )?,
        })
    };
    let primary = model("primary", raw.primary)?;
    let fallback = raw
        .fallback
        .map(|fallback| model("fallback", fallback))
        .transpose()?;
    let on_game = raw.on_game.unwrap_or(OnGame::Unload);
    if on_game == OnGame::Fallback && fallback.is_none() {
        return Err(ConfigError::Invalid(
            "inference.on_game = \"fallback\" needs an [inference.fallback] model".into(),
        ));
    }
    let context_size = raw.context_size.unwrap_or(16_384);
    if !jarvis_protocol::CONTEXT_SIZES.contains(&context_size) {
        return Err(ConfigError::Invalid(format!(
            "inference.context_size must be one of {:?}",
            jarvis_protocol::CONTEXT_SIZES
        )));
    }
    let chat_database = match raw.chat_database {
        Some(path) => resolve(path),
        None => database
            .parent()
            .unwrap_or(Path::new("."))
            .join("donna-chat.db"),
    };
    if chat_database == database {
        return Err(ConfigError::Invalid(
            "inference.chat_database must not be the audit database".into(),
        ));
    }
    let server = resolve(raw.server);
    if !server.is_absolute() {
        return Err(ConfigError::Invalid(
            "inference.server must resolve to an absolute path".into(),
        ));
    }
    let load_timeout = ms(
        "inference.load_timeout_ms",
        raw.load_timeout_ms,
        Duration::from_secs(180),
        1_000,
        900_000,
    )?;
    let reply_timeout = ms(
        "inference.reply_timeout_ms",
        raw.reply_timeout_ms,
        Duration::from_secs(300),
        1_000,
        3_600_000,
    )?;
    // A reply's time includes loading the model when it is not loaded.
    if reply_timeout <= load_timeout {
        return Err(ConfigError::Invalid(
            "inference.reply_timeout_ms must exceed inference.load_timeout_ms".into(),
        ));
    }
    Ok(InferenceConfig {
        server,
        chat_database,
        persona: resolve(raw.persona),
        primary,
        fallback,
        on_game,
        context_size,
        max_reply_tokens: within(
            "inference.max_reply_tokens",
            raw.max_reply_tokens.unwrap_or(1024),
            64,
            8192,
        )?,
        presence_penalty: within(
            "inference.presence_penalty",
            raw.presence_penalty.unwrap_or(0.3),
            0.0,
            2.0,
        )?,
        threads: within("inference.threads", raw.threads.unwrap_or(8), 1, 64)?,
        load_timeout,
        reply_timeout,
        retention_days: within(
            "inference.retention_days",
            raw.retention_days.unwrap_or(0),
            0,
            36_500,
        )?,
        load_on_start: raw.load_on_start.unwrap_or(true),
        slow_below_tokens_per_second: within(
            "inference.slow_below_tokens_per_second",
            raw.slow_below_tokens_per_second.unwrap_or(30),
            0,
            1000,
        )?,
    })
}

fn process_names(names: Vec<String>) -> Result<Vec<String>, ConfigError> {
    if names.is_empty() || names.len() > GovernorConfig::MAX_PROCESSES {
        return Err(ConfigError::Invalid(format!(
            "governor.processes must list 1 to {} names, got {}",
            GovernorConfig::MAX_PROCESSES,
            names.len()
        )));
    }
    for name in &names {
        let printable = name.bytes().all(|b| (0x20..=0x7e).contains(&b));
        let separator = name
            .bytes()
            .any(|b| matches!(b, b'/' | 0x5c /* backslash */));
        if name.is_empty() || name.len() > GovernorConfig::MAX_NAME_BYTES || !printable || separator
        {
            return Err(ConfigError::Invalid(format!(
                "governor.processes names must be 1 to {} printable ASCII characters without \
                 a slash or backslash, got {name:?}",
                GovernorConfig::MAX_NAME_BYTES
            )));
        }
    }
    Ok(names)
}

fn ms(
    name: &str,
    value: Option<u64>,
    default: Duration,
    min: u64,
    max: u64,
) -> Result<Duration, ConfigError> {
    let default = u64::try_from(default.as_millis()).unwrap_or(u64::MAX);
    within(name, value.unwrap_or(default), min, max).map(Duration::from_millis)
}

fn within<T: PartialOrd + std::fmt::Display + Copy>(
    name: &str,
    value: T,
    min: T,
    max: T,
) -> Result<T, ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::Invalid(format!(
            "{name} must be between {min} and {max}, got {value}"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        database = "state/jarvis.db"

        [worker]
        program = "python3"
        args = ["-m", "jarvis_worker"]
        cwd = "worker"

        [fixtures]
        root = "fixtures"

        [workspace]
        root = "workspace"

        [policy]
        "system.info" = "allow"
        "filesystem.read.fixture" = "require_confirmation"
        "workspace.write" = "require_confirmation"
    "#;

    #[test]
    fn resolves_relative_paths_against_the_config_directory() {
        let config = Config::from_toml(MINIMAL, Path::new("/etc/jarvis")).unwrap();
        assert_eq!(config.database, Path::new("/etc/jarvis/state/jarvis.db"));
        assert_eq!(config.fixtures.root, Path::new("/etc/jarvis/fixtures"));
        assert_eq!(config.workspace.root, Path::new("/etc/jarvis/workspace"));
        assert_eq!(
            config.worker.cwd.as_deref(),
            Some(Path::new("/etc/jarvis/worker"))
        );
        assert_eq!(
            config.rpc.socket,
            Path::new("/etc/jarvis/state/rpc/jarvis.sock")
        );
        assert!(!config.rpc.allow_shutdown, "shutdown over RPC is opt-in");
        assert_eq!(
            config
                .policy
                .decision_for(Capability::FilesystemReadFixture),
            PolicyDecision::RequireConfirmation
        );
    }

    #[test]
    fn class_b_capability_cannot_be_allowed_automatically() {
        let text = MINIMAL.replace(
            "\"workspace.write\" = \"require_confirmation\"",
            "\"workspace.write\" = \"allow\"",
        );
        let error = Config::from_toml(&text, Path::new(".")).unwrap_err();
        assert!(error.to_string().contains("workspace.write"), "{error}");
        let text = MINIMAL.replace(
            "\"workspace.write\" = \"require_confirmation\"",
            "\"workspace.write\" = \"deny\"",
        );
        assert!(Config::from_toml(&text, Path::new(".")).is_ok());
    }

    #[test]
    fn desktop_capabilities_can_only_be_denied() {
        let clipboard = Capability::DesktopClipboardWrite;
        for decision in ["deny", "require_confirmation"] {
            let text = format!("{MINIMAL}\"{clipboard}\" = \"{decision}\"\n");
            assert!(
                Config::from_toml(&text, Path::new(".")).is_ok(),
                "{decision}"
            );
        }
        let text = format!("{MINIMAL}\"{clipboard}\" = \"allow\"\n");
        let error = Config::from_toml(&text, Path::new(".")).unwrap_err();
        assert!(error.to_string().contains("class"), "{error}");
        for capability in Capability::ALL
            .iter()
            .filter(|c| c.is_desktop() && **c != clipboard)
        {
            for decision in ["allow", "require_confirmation"] {
                let text = format!(
                    "{MINIMAL}\"{capability}\" = \"{decision}\"
"
                );
                let error = Config::from_toml(&text, Path::new(".")).unwrap_err();
                assert!(error.to_string().contains("desktop"), "{error}");
            }
            let text = format!(
                "{MINIMAL}\"{capability}\" = \"deny\"
"
            );
            assert!(Config::from_toml(&text, Path::new(".")).is_ok());
        }
        let text = format!(
            "{MINIMAL}\"session_agent.healthcheck\" = \"allow\"
"
        );
        assert!(Config::from_toml(&text, Path::new(".")).is_err(), "class B");
        let text = format!(
            "{MINIMAL}\"session_agent.healthcheck\" = \"require_confirmation\"
"
        );
        assert!(Config::from_toml(&text, Path::new(".")).is_ok());
    }

    #[test]
    fn session_agent_settings_are_bounded() {
        let config = Config::from_toml(MINIMAL, Path::new("/etc/jarvis")).unwrap();
        assert!(config.session_agent.program.is_none());
        let text = MINIMAL.replace(
            "[policy]",
            "[session_agent]
program = \"bin/agent\"
grant_ttl_ms = 2000

[policy]",
        );
        let config = Config::from_toml(&text, Path::new("/etc/jarvis")).unwrap();
        assert_eq!(
            config.session_agent.program.as_deref(),
            Some(Path::new("/etc/jarvis/bin/agent"))
        );
        assert_eq!(config.session_agent.grant_ttl, Duration::from_secs(2));
        for bad in [
            "grant_ttl_ms = 60001",
            "timeout_ms = 0",
            "max_starts = 0",
            "shell = true",
        ] {
            let text = MINIMAL.replace(
                "[policy]",
                &format!(
                    "[session_agent]
{bad}

[policy]"
                ),
            );
            assert!(Config::from_toml(&text, Path::new(".")).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_capability_in_policy_is_rejected() {
        let text = MINIMAL.replace("\"system.info\"", "\"shell.exec\"");
        let error = Config::from_toml(&text, Path::new(".")).unwrap_err();
        assert!(error.to_string().contains("shell.exec"), "{error}");
    }

    #[test]
    fn unknown_decision_is_rejected() {
        let text = MINIMAL.replace("= \"allow\"", "= \"always\"");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = format!("{MINIMAL}\n[extras]\nshell = true\n");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
        let text = MINIMAL.replace("[worker]", "[worker]\nshell = true");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
        let text = MINIMAL.replace("[worker]", "[worker]\nenv = { SECRET = \"x\" }");
        assert!(
            Config::from_toml(&text, Path::new(".")).is_err(),
            "no way to pass variables to the worker"
        );
    }

    #[test]
    fn limits_are_range_checked() {
        let text = format!("{MINIMAL}\n[limits]\ntool_timeout_ms = 0\n");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
        let text = format!("{MINIMAL}\n[limits]\nmax_frame_bytes = 10\n");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
        let text = format!("{MINIMAL}\n[approvals]\nttl_ms = 10\n");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
    }

    #[test]
    fn a_job_gets_a_few_attempts_by_default_and_the_number_is_bounded() {
        let config = Config::from_toml(MINIMAL, Path::new(".")).unwrap();
        assert_eq!(config.limits.max_job_attempts, 3);
        let text = format!("{MINIMAL}\n[limits]\nmax_job_attempts = 10\n");
        let config = Config::from_toml(&text, Path::new(".")).unwrap();
        assert_eq!(config.limits.max_job_attempts, 10);
        for bad in ["0", "11"] {
            let text = format!("{MINIMAL}\n[limits]\nmax_job_attempts = {bad}\n");
            let error = Config::from_toml(&text, Path::new(".")).unwrap_err();
            assert!(error.to_string().contains("max_job_attempts"), "{error}");
        }
    }

    #[test]
    fn job_timeout_must_outlast_an_approval() {
        let text = format!(
            "{MINIMAL}\n[approvals]\nttl_ms = 60000\n[supervisor]\njob_timeout_ms = 30000\n"
        );
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
    }

    #[test]
    fn root_limits_must_fit_in_a_frame() {
        let text = MINIMAL.replace(
            "root = \"workspace\"",
            "root = \"workspace\"\nmax_bytes = 1048576",
        );
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
    }

    #[test]
    fn pipe_name_is_validated() {
        let text = format!("{MINIMAL}\n[rpc]\npipe = \"..\\\\evil\"\n");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
    }

    fn governor(section: &str) -> Result<GovernorConfig, ConfigError> {
        let text = format!("{MINIMAL}\n[governor]\n{section}\n");
        Config::from_toml(&text, Path::new(".")).map(|config| config.governor)
    }

    #[test]
    fn the_governor_is_off_unless_asked_for() {
        let config = Config::from_toml(MINIMAL, Path::new(".")).unwrap();
        let governor = config.governor;
        assert!(!governor.enabled);
        assert_eq!(governor.processes, ["cs2.exe"]);
        assert_eq!(governor.poll, Duration::from_millis(5_000));
        assert_eq!(governor.resume_delay, Duration::from_millis(30_000));
        assert_eq!(governor.alert_after, Duration::from_millis(14_400_000));
        let governor = self::governor("enabled = true").unwrap();
        assert!(governor.enabled);
        assert_eq!(governor.processes, ["cs2.exe"]);
    }

    #[test]
    fn governor_settings_are_read() {
        let governor = governor(
            "enabled = true\nprocesses = [\"Game.exe\", \"other\"]\npoll_ms = 500\n\
             resume_delay_ms = 0\nalert_after_ms = 120000",
        )
        .unwrap();
        assert_eq!(governor.processes, ["Game.exe", "other"]);
        assert_eq!(governor.poll, Duration::from_millis(500));
        assert_eq!(governor.resume_delay, Duration::ZERO);
        assert_eq!(governor.alert_after, Duration::from_millis(120_000));
    }

    #[test]
    fn governor_times_are_range_checked_at_each_bound() {
        for (key, low, high) in [
            ("poll_ms", 250, 60_000),
            ("resume_delay_ms", 0, 600_000),
            ("alert_after_ms", 60_000, 86_400_000),
        ] {
            for ok in [low, high] {
                assert!(governor(&format!("{key} = {ok}")).is_ok(), "{key} = {ok}");
            }
            let mut bad = vec![high + 1];
            if low > 0 {
                bad.push(low - 1);
            }
            for value in bad {
                let error = governor(&format!("{key} = {value}")).unwrap_err();
                assert!(error.to_string().contains(key), "{key} = {value}: {error}");
            }
        }
        assert!(governor("poll_ms = -1").is_err());
    }

    #[test]
    fn governor_process_names_are_validated() {
        let names = |list: &str| governor(&format!("processes = {list}"));
        assert!(names("[\"a\"]").is_ok());
        assert!(
            names("[\"Counter Strike 2.exe\"]").is_ok(),
            "spaces are printable"
        );
        let sixteen = vec!["\"p\""; 16].join(",");
        assert!(names(&format!("[{sixteen}]")).is_ok());
        let seventeen = vec!["\"p\""; 17].join(",");
        assert!(names(&format!("[{seventeen}]")).is_err());
        assert!(
            names("[]").is_err(),
            "an enabled governor needs something to look for"
        );
        assert!(names("[\"\"]").is_err());
        assert!(names(&format!("[\"{}\"]", "a".repeat(64))).is_ok());
        assert!(names(&format!("[\"{}\"]", "a".repeat(65))).is_err());
        for bad in [
            r#""dir/game.exe""#,
            r#""nul\u0000byte""#,
            r#""tab\there""#,
            r#""new\nline""#,
            r#""del\u007f""#,
            r#""sp\u00e4ter.exe""#,
        ] {
            let error = names(&format!("[{bad}]")).unwrap_err();
            assert!(
                error.to_string().contains("governor.processes"),
                "{bad}: {error}"
            );
        }
        // A literal TOML string, so that the backslash reaches the check.
        for bad in ["dir{}game.exe", "C:{}game.exe"] {
            let bad = bad.replace("{}", "\u{5c}");
            let error = names(&format!("['{bad}']")).unwrap_err();
            assert!(
                error.to_string().contains("governor.processes"),
                "{bad}: {error}"
            );
        }
    }

    #[test]
    fn the_example_config_documents_the_governor_defaults_and_leaves_it_off() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/jarvis.example.toml");
        let config = Config::load(&path).unwrap();
        assert_eq!(config.governor, GovernorConfig::default());
        assert!(!config.governor.enabled);
    }

    #[test]
    fn governor_rejects_unknown_keys() {
        assert!(governor("unknown_key_ms = 1000").is_err());
        assert!(governor("enabled = \"yes\"").is_err());
        assert!(governor("processes = \"cs2.exe\"").is_err());
    }
    #[test]
    fn missing_policy_entries_default_to_deny() {
        let text = MINIMAL.replace("\"filesystem.read.fixture\" = \"require_confirmation\"", "");
        let config = Config::from_toml(&text, Path::new(".")).unwrap();
        assert_eq!(
            config
                .policy
                .decision_for(Capability::FilesystemReadFixture),
            PolicyDecision::Deny
        );
    }
}
