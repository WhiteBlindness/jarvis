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
//! {"rpc":4,"type":"approve","approval_id":"…","fingerprint":"…"}
//! ```

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::agent::ClipboardText;
use crate::chat::{
    ChatDelta, ChatLanguage, ChatText, ChatTurn, ConversationSummary, ConversationView,
    InferenceView, SearchQuery,
};
use crate::message::decode_versioned;
use crate::{
    ApprovalId, ApprovalStatus, Capability, ConversationId, DecodeError, Fingerprint, Goal, JobId,
    JobStatus, MessageId, ProtocolVersion, RequestId, Summary, TaskId, ToolName,
    error::sanitize_message,
};

/// Version of the RPC protocol. Like the worker protocol, the Core accepts
/// only its own version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpcVersion(pub u32);

impl RpcVersion {
    pub const CURRENT: Self = Self(4);
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
    /// Send a message to the assistant, in a new conversation when
    /// `conversation_id` is null. The reply is generated under the returned
    /// turn; poll it with `chat_poll`. One reply is generated at a time.
    ChatSend {
        #[serde(deserialize_with = "Option::deserialize")]
        conversation_id: Option<ConversationId>,
        text: ChatText,
        language: ChatLanguage,
    },
    /// Replace the last reply of a conversation with a new one.
    ChatRegenerate {
        conversation_id: ConversationId,
        language: ChatLanguage,
    },
    /// The reply text after `cursor`. With `wait_ms > 0`, waits until there
    /// is new text, the reply is final, or the time is up.
    ChatPoll {
        turn_id: MessageId,
        cursor: u32,
        wait_ms: u32,
    },
    /// Stop generating a reply. The text so far is kept.
    ChatCancel {
        turn_id: MessageId,
    },
    /// Conversations, most recently updated first; with `query`, only those
    /// with a message containing it.
    ListConversations {
        #[serde(deserialize_with = "Option::deserialize")]
        query: Option<SearchQuery>,
        limit: u32,
    },
    GetConversation {
        conversation_id: ConversationId,
    },
    /// Delete one conversation and its messages for good.
    DeleteConversation {
        conversation_id: ConversationId,
    },
    /// Delete every stored conversation for good.
    DeleteAllConversations {},
    InferenceStatus {},
    /// Load the model now instead of on the next message.
    LoadModel {},
    /// Stop the model server and free its memory. A reply being generated
    /// is cancelled.
    UnloadModel {},
    /// Use another context size (one of `CONTEXT_SIZES`). A loaded model is
    /// reloaded.
    SetContextSize {
        context_size: u32,
    },
    /// Delete conversations not updated for this many days (one of
    /// `RETENTION_DAYS`; 0 keeps them until a person deletes them). Applies
    /// at once and is remembered across restarts.
    SetRetention {
        days: u32,
    },
    /// Queue a job that copies this text to the clipboard once a person
    /// approves it (ADR 0022). The text is held by the Core as a temporary
    /// payload and never written into the job's goal; the reply is the job.
    SubmitClipboardJob {
        text: ClipboardText,
    },
}

/// Replies from the Core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RpcResponse {
    Health(HealthReport),
    Job(JobView),
    Jobs {
        jobs: Vec<JobView>,
    },
    Approval(ApprovalView),
    Approvals {
        approvals: Vec<ApprovalView>,
    },
    ShuttingDown {},
    ChatTurn(ChatTurn),
    ChatDelta(ChatDelta),
    Conversations {
        conversations: Vec<ConversationSummary>,
    },
    Conversation(ConversationView),
    Deleted {
        conversations: u32,
    },
    Inference(InferenceView),
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

/// Where the gaming governor stands. `Off` is a Core that was started with
/// the governor disabled: jobs start whenever a worker is free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernorPhase {
    Off,
    /// No game is running; queued jobs may start.
    Open,
    /// Queued jobs wait. Running jobs are not affected.
    Held,
    /// The game has gone; queued jobs keep waiting out the resume delay.
    Releasing,
}

/// Why the governor holds queued jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernorReason {
    /// The first check since the Core started has not finished.
    Starting,
    /// A configured process is running.
    Game,
    /// The process list could not be read, so the governor cannot say
    /// whether a game runs.
    DetectionFailed,
}

/// The governor as `health` reports it. `reason` and `process` are set while
/// held; `held_ms` while held or releasing; `overdue` once a hold has lasted
/// longer than the configured alert time. `process` is the configured name
/// that matched, never anything read from the process list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorView {
    pub state: GovernorPhase,
    #[serde(deserialize_with = "Option::deserialize")]
    pub reason: Option<GovernorReason>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub process: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub held_ms: Option<u64>,
    pub overdue: bool,
}

impl GovernorView {
    /// The view of a Core whose governor is disabled.
    pub const OFF: Self = Self {
        state: GovernorPhase::Off,
        reason: None,
        process: None,
        held_ms: None,
        overdue: false,
    };
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
    pub governor: GovernorView,
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
        assert!(bytes.starts_with(br#"{"rpc":4,"type":"approve""#));
        assert_eq!(decode_rpc_request(&bytes).unwrap(), request);
        let health = encode_rpc_request(&RpcRequest::Health {}).unwrap();
        assert_eq!(health, br#"{"rpc":4,"type":"health"}"#);
    }

    #[test]
    fn requests_are_strict() {
        for value in [
            json!({"rpc": 4, "type": "health", "extra": true}),
            json!({"rpc": 4, "type": "run_command", "command": "id"}),
            json!({"rpc": 4, "type": "submit_job"}),
            json!({"rpc": 4, "type": "submit_job", "goal": ""}),
            json!({"rpc": 4, "type": "submit_job", "goal": "a\nb"}),
            json!({"rpc": 4, "type": "get_job", "job_id": JobId::new()}),
            json!({"rpc": 4, "type": "approve", "approval_id": ApprovalId::new()}),
            json!({"rpc": 4, "type": "approve", "approval_id": ApprovalId::new(),
                   "fingerprint": "abc"}),
            json!({"rpc": 4, "type": "approve", "approval_id": ApprovalId::new(),
                   "fingerprint": "a".repeat(64), "approved": true}),
            json!({"protocol": 2, "type": "health"}),
        ] {
            let error = decode_rpc_request(&frame(value.clone())).unwrap_err();
            assert_eq!(error.code(), crate::ErrorCode::MalformedFrame, "{value}");
        }
        for old in [1, 2, 3, 5] {
            let error =
                decode_rpc_request(&frame(json!({"rpc": old, "type": "health"}))).unwrap_err();
            assert!(matches!(
                error,
                DecodeError::UnsupportedVersion { found, expected: 4, .. } if found == old
            ));
        }
    }

    #[test]
    fn worker_frames_are_not_rpc_requests() {
        let worker = br#"{"protocol":2,"type":"hello","worker":"w","worker_version":"1"}"#;
        assert!(decode_rpc_request(worker).is_err());
    }

    #[test]
    fn the_governor_view_is_strict() {
        let valid = json!({"state": "held", "reason": "game", "process": "cs2.exe",
                           "held_ms": 5, "overdue": false});
        let view: GovernorView = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(view.state, GovernorPhase::Held);
        assert_eq!(view.reason, Some(GovernorReason::Game));
        assert_eq!(serde_json::to_value(&view).unwrap(), valid);
        assert_eq!(
            serde_json::to_value(GovernorView::OFF).unwrap(),
            json!({"state": "off", "reason": null, "process": null,
                   "held_ms": null, "overdue": false})
        );
        for bad in [
            json!({"state": "held", "reason": "game", "process": null, "held_ms": 5}),
            json!({"state": "held", "reason": "game", "held_ms": 5, "overdue": false}),
            json!({"state": "paused", "reason": null, "process": null,
                   "held_ms": null, "overdue": false}),
            json!({"state": "held", "reason": "gaming", "process": null,
                   "held_ms": null, "overdue": false}),
            json!({"state": "off", "reason": null, "process": null,
                   "held_ms": null, "overdue": false, "extra": 1}),
        ] {
            assert!(
                serde_json::from_value::<GovernorView>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn error_messages_are_sanitised() {
        let error = RpcError::new(RpcErrorCode::NotFound, "no \u{1b}[2J such\napproval");
        assert!(!error.message.chars().any(char::is_control));
    }
}
