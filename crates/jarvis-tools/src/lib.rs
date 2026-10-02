//! First-party tools executed by the Core's Tool Gateway.
//!
//! Tools know nothing about policy. By the time a [`ToolCall`] reaches them,
//! the Core has validated it and policy has allowed it. Tools return typed
//! results; the Gateway verifies them before they are stored or returned.

mod fixtures;
mod system_info;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use jarvis_protocol::{ToolCall, ToolResult};

pub use fixtures::FixtureRoot;
pub use system_info::collect as system_info;

/// Why a tool could not produce a result. Messages never contain absolute
/// paths or other details of the host beyond what the caller sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind}: {message}")]
pub struct ToolError {
    pub kind: ToolErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolErrorKind {
    NotFound,
    AccessDenied,
    TooLarge,
    NotText,
    Io,
}

impl fmt::Display for ToolErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "not found",
            Self::AccessDenied => "access denied",
            Self::TooLarge => "too large",
            Self::NotText => "not UTF-8 text",
            Self::Io => "I/O error",
        })
    }
}

impl ToolError {
    pub fn new(kind: ToolErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

pub type ToolFuture<'a> = Pin<Box<dyn Future<Output = Result<ToolResult, ToolError>> + Send + 'a>>;

/// Executes validated tool calls. The production implementation is
/// [`Toolbox`]; tests substitute executors that fail, hang or misbehave to
/// exercise the Gateway's boundaries.
pub trait ToolExecutor: Send + Sync + fmt::Debug {
    fn execute(&self, call: ToolCall) -> ToolFuture<'_>;
}

/// The first-party tool set.
#[derive(Debug)]
pub struct Toolbox {
    core_version: &'static str,
    started: Instant,
    fixtures: FixtureRoot,
}

impl Toolbox {
    pub fn new(core_version: &'static str, fixtures: FixtureRoot) -> Self {
        Self {
            core_version,
            started: Instant::now(),
            fixtures,
        }
    }
}

impl ToolExecutor for Toolbox {
    fn execute(&self, call: ToolCall) -> ToolFuture<'_> {
        Box::pin(async move {
            match call {
                ToolCall::SystemInfo(_) => Ok(ToolResult::SystemInfo(system_info::collect(
                    self.core_version,
                    self.started,
                ))),
                ToolCall::ReadFixture(args) => self
                    .fixtures
                    .read(&args.path)
                    .await
                    .map(ToolResult::Fixture),
            }
        })
    }
}
