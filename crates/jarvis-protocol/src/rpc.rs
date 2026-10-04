//! Local RPC between clients (the CLI today, a dashboard later) and the
//! long-lived Core.
//!
//! This is a separate protocol from the worker protocol, with its own
//! version key (`"rpc"`): a client is a person's tool, a worker is untrusted.
//! The operations are deliberately few and typed. There is no operation that
//! runs a command, and approving requires the fingerprint of the exact
//! request being approved.
//!
//! ```json
//! {"rpc":1,"type":"approve","approval_id":"…","fingerprint":"…"}
//! ```

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::message::decode_versioned;
use crate::{
    ApprovalId, ApprovalStatus, Capability, DecodeError, Fingerprint, Goal, JobId, JobStatus,
    ProtocolVersion, RequestId, Summary, TaskId, ToolName, error::sanitize_message,
};

/// Version of the RPC protocol. Like the worker protocol, the Core accepts
/// only its own version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpcVersion(pub u32);

impl RpcVersion {
    pub const CURRENT: Self = Self(1);
}

impl fmt::Display for RpcVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Requests a local client may send. Every field is required; long-polling
/// operations take `wait_ms` (0 for an immediate answer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RpcRequest {
    Health {},
    /// Queue a goal for the worker.
    SubmitJob {
        goal: Goal,
    },
    /// One job. With `wait_ms > 0`, waits until the job has finished or the
    /// time is up.
    GetJob {
        job_id: JobId,
        wait_ms: u32,
    },
    /// Most recent jobs first.
    ListJobs {
        limit: u32,
    },
    /// Pending approvals. With `wait_ms > 0`, waits until at least one is
    /// pending or the time is up.
    ListApprovals {
        wait_ms: u32,
    },
    GetApproval {
        approval_id: ApprovalId,
    },
    /// Approve one pending request. `fingerprint` must be the fingerprint the
    /// person reviewed; if the request is not exactly that, nothing happens.
    Approve {
        approval_id: ApprovalId,
        fingerprint: Fingerprint,
    },
    Deny {
        approval_id: ApprovalId,
        reason: Summary,
    },
    /// Stop the Core. Refused unless the configuration allows it.
    Shutdown {},
}

/// Replies from the Core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RpcResponse {
    Health(HealthReport),
    Job(JobView),
    Jobs { jobs: Vec<JobView> },
    Approval(ApprovalView),
    Approvals { approvals: Vec<ApprovalView> },
    ShuttingDown {},
    Error(RpcError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    /// Started; waiting for its `hello`.
    Starting,
    Idle,
    Busy,
    /// Stopped; a restart is scheduled.
    Restarting,
    /// Stopped after exhausting its restart budget. Jobs are refused.
    Failed,
    Stopping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerView {
    pub state: WorkerState,
    pub pid: Option<u32>,
    /// Restarts since the Core started.
    pub restarts: u32,
    /// Which OS controls apply to the worker process.
    pub containment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReport {
    /// False when the worker has failed for good.
    pub ok: bool,
    pub core_version: String,
    pub worker_protocol: ProtocolVersion,
    pub rpc_protocol: RpcVersion,
    pub uptime_ms: u64,
    pub worker: WorkerView,
    pub queued_jobs: u32,
    pub pending_approvals: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobView {
    pub job_id: JobId,
    pub status: JobStatus,
    pub goal: Goal,
    #[serde(deserialize_with = "Option::deserialize")]
    pub summary: Option<Summary>,
    pub submitted_at: String,
    pub updated_at: String,
}

/// What a person needs to decide on an approval. `arguments` is a
/// display-safe description computed by the Core (control characters
/// escaped, long values shortened); the exact arguments are bound by
/// `fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalView {
    pub approval_id: ApprovalId,
    pub status: ApprovalStatus,
    pub task_id: TaskId,
    #[serde(deserialize_with = "Option::deserialize")]
    pub job_id: Option<JobId>,
    pub request_id: RequestId,
    pub tool: ToolName,
    pub capabilities: Vec<Capability>,
    pub arguments: BTreeMap<String, String>,
    pub fingerprint: Fingerprint,
    pub requested_at: String,
    pub expires_at: String,
    /// Milliseconds left before expiry; 0 once expired.
    pub expires_in_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    MalformedRequest,
    UnsupportedVersion,
    RequestTooLarge,
    NotFound,
    /// The object is not in a state that allows the operation, such as
    /// approving something that was already decided.
    Conflict,
    Expired,
    /// The approval does not match the request the person reviewed.
    FingerprintMismatch,
    Forbidden,
    /// The worker is not available, for example after exhausting its
    /// restart budget.
    Unavailable,
    Internal,
}

impl RpcErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::UnsupportedVersion => "unsupported_version",
            Self::RequestTooLarge => "request_too_large",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Expired => "expired",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::Forbidden => "forbidden",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for RpcErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
}

impl RpcError {
    /// Like [`crate::WireError::new`]: control characters are escaped and the
    /// message is shortened.
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_message(message.into()),
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

const VERSION_KEY: &str = "rpc";

#[derive(Serialize)]
struct Envelope<'a, T> {
    rpc: RpcVersion,
    #[serde(flatten)]
    message: &'a T,
}

fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&Envelope {
        rpc: RpcVersion::CURRENT,
        message,
    })
}

pub fn encode_rpc_request(request: &RpcRequest) -> Result<Vec<u8>, serde_json::Error> {
    encode(request)
}

pub fn encode_rpc_response(response: &RpcResponse) -> Result<Vec<u8>, serde_json::Error> {
    encode(response)
}

pub fn decode_rpc_request(frame: &[u8]) -> Result<RpcRequest, DecodeError> {
    decode_versioned(frame, VERSION_KEY, RpcVersion::CURRENT.0)
}

pub fn decode_rpc_response(frame: &[u8]) -> Result<RpcResponse, DecodeError> {
    decode_versioned(frame, VERSION_KEY, RpcVersion::CURRENT.0)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn frame(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn requests_round_trip_with_the_version_first() {
        let request = RpcRequest::Approve {
            approval_id: ApprovalId::new(),
            fingerprint: Fingerprint::from_digest(&[7; 32]),
        };
        let bytes = encode_rpc_request(&request).unwrap();
        assert!(bytes.starts_with(br#"{"rpc":1,"type":"approve""#));
        assert_eq!(decode_rpc_request(&bytes).unwrap(), request);
        let health = encode_rpc_request(&RpcRequest::Health {}).unwrap();
        assert_eq!(health, br#"{"rpc":1,"type":"health"}"#);
    }

    #[test]
    fn requests_are_strict() {
        for value in [
            json!({"rpc": 1, "type": "health", "extra": true}),
            json!({"rpc": 1, "type": "run_command", "command": "id"}),
            json!({"rpc": 1, "type": "submit_job"}),
            json!({"rpc": 1, "type": "submit_job", "goal": ""}),
            json!({"rpc": 1, "type": "submit_job", "goal": "a\nb"}),
            json!({"rpc": 1, "type": "get_job", "job_id": JobId::new()}),
            json!({"rpc": 1, "type": "approve", "approval_id": ApprovalId::new()}),
            json!({"rpc": 1, "type": "approve", "approval_id": ApprovalId::new(),
                   "fingerprint": "abc"}),
            json!({"rpc": 1, "type": "approve", "approval_id": ApprovalId::new(),
                   "fingerprint": "a".repeat(64), "approved": true}),
            json!({"protocol": 2, "type": "health"}),
        ] {
            let error = decode_rpc_request(&frame(value.clone())).unwrap_err();
            assert_eq!(error.code(), crate::ErrorCode::MalformedFrame, "{value}");
        }
        let error = decode_rpc_request(&frame(json!({"rpc": 2, "type": "health"}))).unwrap_err();
        assert!(matches!(
            error,
            DecodeError::UnsupportedVersion {
                found: 2,
                expected: 1,
                ..
            }
        ));
    }

    #[test]
    fn worker_frames_are_not_rpc_requests() {
        let worker = br#"{"protocol":2,"type":"hello","worker":"w","worker_version":"1"}"#;
        assert!(decode_rpc_request(worker).is_err());
    }

    #[test]
    fn error_messages_are_sanitised() {
        let error = RpcError::new(RpcErrorCode::NotFound, "no \u{1b}[2J such\napproval");
        assert!(!error.message.chars().any(char::is_control));
    }
}
