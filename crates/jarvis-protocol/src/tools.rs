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
    pub path: RelativePath,
}

/// Arguments of `workspace.write_file`: create or replace one UTF-8 text
/// file inside the configured workspace. The Core enforces the size limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteFileArgs {
    pub path: RelativePath,
    pub content: String,
}

/// A validated, typed tool invocation. Produced only by
/// [`ToolCall::from_request`], so holding one means the tool exists and its
/// arguments passed schema and syntax checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCall {
    SystemInfo(SystemInfoArgs),
    ReadFixture(ReadFixtureArgs),
    WriteFile(WriteFileArgs),
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
    pub const WRITE_FILE: &'static str = "workspace.write_file";

    /// Every tool the protocol defines, in a stable order.
    pub const NAMES: &'static [&'static str] =
        &[Self::READ_FIXTURE, Self::SYSTEM_INFO, Self::WRITE_FILE];

    /// Resolve a tool name and decode its arguments into the tool's schema.
    pub fn from_request(tool: &ToolName, args: &serde_json::Value) -> Result<Self, CallError> {
        match tool.as_str() {
            Self::SYSTEM_INFO => decode_args(Self::SYSTEM_INFO, args).map(Self::SystemInfo),
            Self::READ_FIXTURE => decode_args(Self::READ_FIXTURE, args).map(Self::ReadFixture),
            Self::WRITE_FILE => decode_args(Self::WRITE_FILE, args).map(Self::WriteFile),
            other => Err(CallError::UnknownTool(other.to_owned())),
        }
    }

    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::SystemInfo(_) => Self::SYSTEM_INFO,
            Self::ReadFixture(_) => Self::READ_FIXTURE,
            Self::WriteFile(_) => Self::WRITE_FILE,
        }
    }

    /// The validated arguments in normalised form: re-serialised from the
    /// typed value, with keys in a fixed order. This is what approval
    /// fingerprints are computed over.
    pub fn arguments(&self) -> serde_json::Value {
        let encoded = match self {
            Self::SystemInfo(args) => serde_json::to_value(args),
            Self::ReadFixture(args) => serde_json::to_value(args),
            Self::WriteFile(args) => serde_json::to_value(args),
        };
        // Plain structs of strings always serialise.
        encoded.unwrap_or(serde_json::Value::Null)
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

/// A path relative to a tool's root directory (the fixture directory or the
/// workspace), checked for syntax before it reaches the filesystem.
///
/// The rules are an allowlist: forward-slash separated components, each made
/// of ASCII letters, digits, `.`, `_` and `-`, starting with a letter or digit
/// and not ending with `.`. That excludes `..`, `.`, hidden files, absolute
/// paths, drive prefixes, backslashes, alternate data streams and Windows
/// device names. The tools still resolve the path beneath their root directory
/// handle, which catches symlinks and junctions that point outside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelativePath(String);

impl RelativePath {
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

impl TryFrom<String> for RelativePath {
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

impl From<RelativePath> for String {
    fn from(value: RelativePath) -> Self {
        value.0
    }
}

impl fmt::Display for RelativePath {
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
    pub path: RelativePath,
    /// Size of `content` in bytes.
    pub bytes: u64,
    pub content: String,
}

/// Result of `workspace.write_file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteOutcome {
    pub path: RelativePath,
    /// Bytes written.
    pub bytes: u64,
    /// The file did not exist before.
    pub created: bool,
}

/// Typed output of a tool. Serialised without a tag: the worker already
/// knows which tool it called, and the Core checks that the variant matches
/// the call before the result leaves the Gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolResult {
    SystemInfo(SystemInfo),
    Fixture(FixtureContent),
    Written(WriteOutcome),
}

impl ToolResult {
    /// Whether this result is the kind of output `call` must produce.
    pub fn answers(&self, call: &ToolCall) -> bool {
        matches!(
            (self, call),
            (Self::SystemInfo(_), ToolCall::SystemInfo(_))
                | (Self::Fixture(_), ToolCall::ReadFixture(_))
                | (Self::Written(_), ToolCall::WriteFile(_))
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
    fn write_file_arguments_are_strict_and_normalised() {
        let call = ToolCall::from_request(
            &tool("workspace.write_file"),
            &json!({"content": "hi", "path": "notes/a.txt"}),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&call.arguments()).unwrap(),
            r#"{"content":"hi","path":"notes/a.txt"}"#
        );
        for args in [
            json!({"path": "a.txt"}),
            json!({"path": "../a.txt", "content": ""}),
            json!({"path": "a.txt", "content": "x", "append": true}),
            json!({"path": "a.txt", "content": 5}),
        ] {
            assert!(matches!(
                ToolCall::from_request(&tool("workspace.write_file"), &args),
                Err(CallError::InvalidArguments { .. })
            ));
        }
    }

    #[test]
    fn untagged_results_decode_to_the_right_variant() {
        let written: ToolResult =
            serde_json::from_value(json!({"path": "a.txt", "bytes": 2, "created": true})).unwrap();
        assert!(matches!(written, ToolResult::Written(_)));
        let fixture: ToolResult =
            serde_json::from_value(json!({"path": "a.txt", "bytes": 2, "content": "hi"})).unwrap();
        assert!(matches!(fixture, ToolResult::Fixture(_)));
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
            assert!(RelativePath::try_from(ok.to_owned()).is_ok(), "{ok}");
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
            assert!(RelativePath::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fixture_path_enforces_length_and_depth() {
        assert!(RelativePath::try_from("a".repeat(256)).is_err());
        assert!(RelativePath::try_from(vec!["a"; 17].join("/")).is_err());
        assert!(RelativePath::try_from(vec!["a"; 16].join("/")).is_ok());
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
            path: RelativePath::try_from("a.txt".to_owned()).unwrap(),
        });
        assert!(!info.answers(&read));
    }
}
