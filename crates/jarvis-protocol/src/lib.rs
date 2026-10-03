//! Wire protocol between the JARVIS Core and its workers.
//!
//! The protocol is vendor-neutral and transport-agnostic: it defines typed
//! messages, their JSON encoding and the rules for validating them. Framing
//! (one JSON object per line) and I/O live in the Core.
//!
//! Decoding is strict. Unknown message types, unknown fields and other
//! protocol versions are errors, never silently ignored. A worker names a
//! tool and its arguments; it never names capabilities. Capabilities are
//! derived by the Core from the typed [`ToolCall`].

mod audit;
mod capability;
mod error;
mod ids;
mod message;
mod rpc;
mod task;
mod text;
mod tools;

pub use audit::{AuditEvent, AuditEventKind};
pub use capability::{ActionClass, Capability, UnknownCapability};
pub use error::{ErrorCode, WireError};
pub use ids::{ApprovalId, Fingerprint, InvalidId, JobId, RequestId, SessionId, TaskId, ToolName};
pub use message::{
    CoreMessage, DecodeError, ErrorMessage, Hello, JobAssignment, JobOutcome, JobResult, Label,
    SessionLimits, ToolOutcome, ToolRequest, ToolResponse, Welcome, WorkerMessage,
    decode_core_message, decode_worker_message, encode_core_message, encode_worker_message,
};
pub use rpc::{
    ApprovalView, HealthReport, JobView, RpcError, RpcErrorCode, RpcRequest, RpcResponse,
    RpcVersion, WorkerState, WorkerView, decode_rpc_request, decode_rpc_response,
    encode_rpc_request, encode_rpc_response,
};
pub use task::{ApprovalStatus, JobStatus, PolicyDecision, TaskStatus};
pub use text::{Goal, Summary};
pub use tools::{
    CallError, FixtureContent, ReadFixtureArgs, RelativePath, SystemInfo, SystemInfoArgs, ToolCall,
    ToolResult, WriteFileArgs, WriteOutcome,
};

/// Version of the wire protocol. Every frame carries it, and the Core accepts
/// only its own version: both sides ship from this repository, so any change
/// to the wire format bumps this number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
    pub const CURRENT: Self = Self(2);
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
