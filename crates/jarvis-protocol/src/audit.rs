use serde::{Deserialize, Serialize};

use crate::message::Label;
use crate::{
    Capability, PolicyDecision, ProtocolVersion, RequestId, SessionId, TaskId, TaskStatus,
    ToolName, WireError,
};

/// One entry of the append-only audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    /// Monotonic sequence number assigned by the store.
    pub seq: i64,
    /// RFC 3339 timestamp in UTC.
    pub at: String,
    pub session_id: Option<SessionId>,
    pub task_id: Option<TaskId>,
    pub event: AuditEventKind,
}

/// What happened. Stored as JSON with a `kind` tag, so the audit log can be
/// read back into these types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditEventKind {
    CoreStarted {
        core_version: String,
        protocol_version: ProtocolVersion,
    },
    CoreStopped {
        reason: String,
    },
    /// A task left open by a previous run was closed during startup.
    TaskRecovered {
        from: TaskStatus,
        to: TaskStatus,
    },
    WorkerSpawned {
        pid: Option<u32>,
    },
    WorkerExited {
        code: Option<i32>,
        success: bool,
    },
    WorkerKilled {
        reason: String,
    },
    SessionOpened {
        worker: Label,
        worker_version: Label,
    },
    SessionClosed {
        reason: String,
        requests: u32,
    },
    /// A frame that did not create a task.
    FrameRejected {
        request_id: Option<RequestId>,
        error: WireError,
    },
    RequestReceived {
        request_id: RequestId,
        tool: ToolName,
    },
    /// The request named an unknown tool or had invalid arguments.
    RequestRejected {
        error: WireError,
    },
    PolicyEvaluated {
        capabilities: Vec<Capability>,
        decision: PolicyDecision,
    },
    /// Committed before the tool runs. If this event cannot be written, the
    /// tool does not run.
    ExecutionStarted {
        tool: String,
    },
    ExecutionFinished {
        status: TaskStatus,
        duration_ms: u64,
        error: Option<WireError>,
    },
    TaskExpired {
        reason: String,
    },
}

impl AuditEventKind {
    /// Value of the `kind` column, identical to the serialised tag.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CoreStarted { .. } => "core_started",
            Self::CoreStopped { .. } => "core_stopped",
            Self::TaskRecovered { .. } => "task_recovered",
            Self::WorkerSpawned { .. } => "worker_spawned",
            Self::WorkerExited { .. } => "worker_exited",
            Self::WorkerKilled { .. } => "worker_killed",
            Self::SessionOpened { .. } => "session_opened",
            Self::SessionClosed { .. } => "session_closed",
            Self::FrameRejected { .. } => "frame_rejected",
            Self::RequestReceived { .. } => "request_received",
            Self::RequestRejected { .. } => "request_rejected",
            Self::PolicyEvaluated { .. } => "policy_evaluated",
            Self::ExecutionStarted { .. } => "execution_started",
            Self::ExecutionFinished { .. } => "execution_finished",
            Self::TaskExpired { .. } => "task_expired",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matches_serialised_tag() {
        let events = [
            AuditEventKind::CoreStopped {
                reason: "test".into(),
            },
            AuditEventKind::PolicyEvaluated {
                capabilities: vec![Capability::SystemInfo],
                decision: PolicyDecision::Allow,
            },
            AuditEventKind::ExecutionStarted {
                tool: "system.info".into(),
            },
        ];
        for event in events {
            let value = serde_json::to_value(&event).unwrap();
            assert_eq!(value["kind"], event.name());
            let back: AuditEventKind = serde_json::from_value(value).unwrap();
            assert_eq!(back, event);
        }
    }
}
