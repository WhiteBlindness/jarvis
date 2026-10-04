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
    pub policy: Policy,
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
    policy: BTreeMap<Capability, PolicyDecision>,
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

        for (&capability, &decision) in &raw.policy {
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
            policy: Policy::new(raw.policy),
        })
    }
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
