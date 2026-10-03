//! Typed tools: their names, argument schemas and result schemas.
//!
//! There is deliberately no generic variant. A tool that accepted a command
//! line, a script or an arbitrary path would make every policy decision
//! meaningless, so each ability is its own typed call.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ProtocolVersion, ToolName};

/// Arguments of `system.info`. The tool takes none; any field is an error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemInfoArgs {}

/// Arguments of `filesystem.read_fixture`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFixtureArgs {
    pub path: FixturePath,
}

/// A validated, typed tool invocation. Produced only by
/// [`ToolCall::from_request`], so holding one means the tool exists and its
/// arguments passed schema and syntax checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCall {
    SystemInfo(SystemInfoArgs),
    ReadFixture(ReadFixtureArgs),
}

/// Why a well-formed request could not become a [`ToolCall`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    #[error("unknown tool `{0}`")]
    UnknownTool(String),
    #[error("invalid arguments for `{tool}`: {reason}")]
    InvalidArguments { tool: &'static str, reason: String },
}

impl ToolCall {
    pub const SYSTEM_INFO: &'static str = "system.info";
    pub const READ_FIXTURE: &'static str = "filesystem.read_fixture";

    /// Every tool the protocol defines, in a stable order.
    pub const NAMES: &'static [&'static str] = &[Self::READ_FIXTURE, Self::SYSTEM_INFO];

    /// Resolve a tool name and decode its arguments into the tool's schema.
    pub fn from_request(tool: &ToolName, args: &serde_json::Value) -> Result<Self, CallError> {
        match tool.as_str() {
            Self::SYSTEM_INFO => decode_args(Self::SYSTEM_INFO, args).map(Self::SystemInfo),
            Self::READ_FIXTURE => decode_args(Self::READ_FIXTURE, args).map(Self::ReadFixture),
            other => Err(CallError::UnknownTool(other.to_owned())),
        }
    }

    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::SystemInfo(_) => Self::SYSTEM_INFO,
            Self::ReadFixture(_) => Self::READ_FIXTURE,
        }
    }
}

fn decode_args<T: serde::de::DeserializeOwned>(
    tool: &'static str,
    args: &serde_json::Value,
) -> Result<T, CallError> {
    if !args.is_object() {
        return Err(CallError::InvalidArguments {
            tool,
            reason: "arguments must be a JSON object".to_owned(),
        });
    }
    T::deserialize(args).map_err(|error| CallError::InvalidArguments {
        tool,
        reason: error.to_string(),
    })
}

/// A path relative to the fixture directory, checked for syntax before it
/// reaches the filesystem.
///
/// The rules are an allowlist: forward-slash separated components, each made
/// of ASCII letters, digits, `.`, `_` and `-`, starting with a letter or digit
/// and not ending with `.`. That excludes `..`, `.`, hidden files, absolute
/// paths, drive prefixes, backslashes, alternate data streams and Windows
/// device names. The fixture tool still checks the resolved path against the
/// canonical fixture root, which catches symlinks that point outside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FixturePath(String);

impl FixturePath {
    pub const MAX_LEN: usize = 255;
    pub const MAX_COMPONENTS: usize = 16;

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

impl TryFrom<String> for FixturePath {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err("path must not be empty".to_owned());
        }
        if value.len() > Self::MAX_LEN {
            return Err(format!("path must be at most {} bytes", Self::MAX_LEN));
        }
        let mut count = 0;
        for component in value.split('/') {
            count += 1;
            check_component(component)?;
        }
        if count > Self::MAX_COMPONENTS {
            return Err(format!(
                "path must have at most {} components",
                Self::MAX_COMPONENTS
            ));
        }
        Ok(Self(value))
    }
}

fn check_component(component: &str) -> Result<(), String> {
    let bytes = component.as_bytes();
    let Some(&first) = bytes.first() else {
        return Err("path must be relative and must not contain empty components".to_owned());
    };
    if !first.is_ascii_alphanumeric() {
        return Err(format!(
            "component `{component}` must start with a letter or digit"
        ));
    }
    if bytes.last() == Some(&b'.') {
        return Err(format!("component `{component}` must not end with '.'"));
    }
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "component `{component}` may contain only letters, digits, '.', '_' and '-'"
        ));
    }
    let stem = component.split('.').next().unwrap_or(component);
    if WINDOWS_DEVICE_NAMES
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
    {
        return Err(format!("component `{component}` is a reserved device name"));
    }
    Ok(())
}

impl From<FixturePath> for String {
    fn from(value: FixturePath) -> Self {
        value.0
    }
}

impl fmt::Display for FixturePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result of `system.info`. Deliberately excludes hostname, username,
/// environment variables and filesystem paths: those identify the user and
/// are not needed to describe the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemInfo {
    /// Operating system, as reported by the Rust standard library (`linux`, `windows`).
    pub os: String,
    /// OS family (`unix`, `windows`).
    pub os_family: String,
    /// CPU architecture (`x86_64`, `aarch64`).
    pub arch: String,
    /// Logical CPUs available to the Core process.
    pub logical_cpus: u32,
    pub core_version: String,
    pub protocol_version: ProtocolVersion,
    /// Milliseconds since the Core started.
    pub core_uptime_ms: u64,
}

/// Result of `filesystem.read_fixture`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureContent {
    pub path: FixturePath,
    /// Size of `content` in bytes.
    pub bytes: u64,
    pub content: String,
}

/// Typed output of a tool. Serialised without a tag: the worker already
/// knows which tool it called, and the Core checks that the variant matches
/// the call before the result leaves the Gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolResult {
    SystemInfo(SystemInfo),
    Fixture(FixtureContent),
}

impl ToolResult {
    /// Whether this result is the kind of output `call` must produce.
    pub fn answers(&self, call: &ToolCall) -> bool {
        matches!(
            (self, call),
            (Self::SystemInfo(_), ToolCall::SystemInfo(_))
                | (Self::Fixture(_), ToolCall::ReadFixture(_))
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn tool(name: &str) -> ToolName {
        ToolName::try_from(name.to_owned()).unwrap()
    }

    #[test]
    fn decodes_known_tools() {
        assert_eq!(
            ToolCall::from_request(&tool("system.info"), &json!({})).unwrap(),
            ToolCall::SystemInfo(SystemInfoArgs {})
        );
        let call = ToolCall::from_request(
            &tool("filesystem.read_fixture"),
            &json!({"path": "a/b.txt"}),
        )
        .unwrap();
        assert_eq!(call.tool_name(), "filesystem.read_fixture");
    }

    #[test]
    fn unknown_tool_is_distinct_from_invalid_arguments() {
        assert_eq!(
            ToolCall::from_request(&tool("shell.exec"), &json!({"command": "id"})),
            Err(CallError::UnknownTool("shell.exec".to_owned()))
        );
        assert!(matches!(
            ToolCall::from_request(&tool("system.info"), &json!({"verbose": true})),
            Err(CallError::InvalidArguments { .. })
        ));
    }

    #[test]
    fn arguments_must_be_an_object() {
        for args in [json!(null), json!([]), json!("x"), json!(1)] {
            assert!(matches!(
                ToolCall::from_request(&tool("system.info"), &args),
                Err(CallError::InvalidArguments { .. })
            ));
        }
    }

    #[test]
    fn fixture_path_accepts_plain_relative_paths() {
        for ok in ["welcome.txt", "notes/today.md", "a/b/c-d_e.1.txt", "2026"] {
            assert!(FixturePath::try_from(ok.to_owned()).is_ok(), "{ok}");
        }
    }

    #[test]
    fn fixture_path_rejects_escapes_and_ambiguous_forms() {
        for bad in [
            "",
            "..",
            ".",
            "../secret",
            "a/../../b",
            "a/./b",
            "/etc/passwd",
            "a//b",
            "a/",
            "C:/Windows/win.ini",
            "C:secret",
            "a\\..\\b",
            "\\\\server\\share",
            ".hidden",
            "a/.ssh/id_rsa",
            "file.txt.",
            "file.txt:stream",
            "CON",
            "nul.txt",
            "dir/com1.log",
            "white space.txt",
            "caf\u{e9}.txt",
            "a\0b",
        ] {
            assert!(FixturePath::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fixture_path_enforces_length_and_depth() {
        assert!(FixturePath::try_from("a".repeat(256)).is_err());
        assert!(FixturePath::try_from(vec!["a"; 17].join("/")).is_err());
        assert!(FixturePath::try_from(vec!["a"; 16].join("/")).is_ok());
    }

    #[test]
    fn result_must_answer_its_call() {
        let info = ToolResult::SystemInfo(SystemInfo {
            os: "linux".into(),
            os_family: "unix".into(),
            arch: "x86_64".into(),
            logical_cpus: 4,
            core_version: "0.1.0".into(),
            protocol_version: ProtocolVersion::CURRENT,
            core_uptime_ms: 1,
        });
        assert!(info.answers(&ToolCall::SystemInfo(SystemInfoArgs {})));
        let read = ToolCall::ReadFixture(ReadFixtureArgs {
            path: FixturePath::try_from("a.txt".to_owned()).unwrap(),
        });
        assert!(!info.answers(&read));
    }
}
