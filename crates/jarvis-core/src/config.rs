//! Configuration loading and validation.
//!
//! The config file is TOML. Unknown keys are errors, relative paths are
//! resolved against the directory that contains the file, and every limit is
//! checked against a sane range before the Core starts.

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
    pub fixtures: FixturesConfig,
    pub limits: Limits,
    pub policy: Policy,
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Program to run. Started directly, never through a shell.
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// Extra environment variables. The worker otherwise starts with an
    /// empty environment apart from `PATH` and `SYSTEMROOT`.
    pub env: BTreeMap<String, String>,
    pub handshake_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct FixturesConfig {
    pub root: PathBuf,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub tool_timeout: Duration,
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
            max_requests_per_session: 1000,
            max_protocol_errors: 16,
            shutdown_grace: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    database: PathBuf,
    worker: RawWorker,
    fixtures: RawFixtures,
    #[serde(default)]
    limits: RawLimits,
    policy: BTreeMap<Capability, PolicyDecision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorker {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<PathBuf>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default = "default_handshake_timeout_ms")]
    handshake_timeout_ms: u64,
}

fn default_handshake_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFixtures {
    root: PathBuf,
    #[serde(default = "default_fixture_max_bytes")]
    max_bytes: u64,
}

fn default_fixture_max_bytes() -> u64 {
    16 * 1024
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_frame_bytes: Option<usize>,
    tool_timeout_ms: Option<u64>,
    max_requests_per_session: Option<u32>,
    max_protocol_errors: Option<u32>,
    shutdown_grace_ms: Option<u64>,
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
            tool_timeout: Duration::from_millis(within(
                "limits.tool_timeout_ms",
                raw.limits
                    .tool_timeout_ms
                    .unwrap_or(millis(defaults.tool_timeout)),
                1,
                600_000,
            )?),
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
            shutdown_grace: Duration::from_millis(within(
                "limits.shutdown_grace_ms",
                raw.limits
                    .shutdown_grace_ms
                    .unwrap_or(millis(defaults.shutdown_grace)),
                1,
                60_000,
            )?),
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
            env: raw.worker.env,
            handshake_timeout: Duration::from_millis(within(
                "worker.handshake_timeout_ms",
                raw.worker.handshake_timeout_ms,
                1,
                60_000,
            )?),
        };

        let fixtures = FixturesConfig {
            root: resolve(raw.fixtures.root),
            max_bytes: within(
                "fixtures.max_bytes",
                raw.fixtures.max_bytes,
                1,
                (limits.max_result_bytes() as u64) / 2,
            )?,
        };

        Ok(Self {
            database: resolve(raw.database),
            worker,
            fixtures,
            limits,
            policy: Policy::new(raw.policy),
        })
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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

        [policy]
        "system.info" = "allow"
        "filesystem.read.fixture" = "require_confirmation"
    "#;

    #[test]
    fn resolves_relative_paths_against_the_config_directory() {
        let config = Config::from_toml(MINIMAL, Path::new("/etc/jarvis")).unwrap();
        assert_eq!(config.database, Path::new("/etc/jarvis/state/jarvis.db"));
        assert_eq!(config.fixtures.root, Path::new("/etc/jarvis/fixtures"));
        assert_eq!(
            config.worker.cwd.as_deref(),
            Some(Path::new("/etc/jarvis/worker"))
        );
        assert_eq!(
            config
                .policy
                .decision_for(Capability::FilesystemReadFixture),
            PolicyDecision::RequireConfirmation
        );
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
    }

    #[test]
    fn limits_are_range_checked() {
        let text = format!("{MINIMAL}\n[limits]\ntool_timeout_ms = 0\n");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
        let text = format!("{MINIMAL}\n[limits]\nmax_frame_bytes = 10\n");
        assert!(Config::from_toml(&text, Path::new(".")).is_err());
    }

    #[test]
    fn fixture_limit_must_fit_in_a_frame() {
        let text = MINIMAL.replace(
            "root = \"fixtures\"",
            "root = \"fixtures\"\nmax_bytes = 1048576",
        );
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
