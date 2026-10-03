use serde::{Deserialize, Serialize};

use crate::message::Label;
use crate::{
    ApprovalId, Capability, Fingerprint, JobId, JobStatus, PolicyDecision, ProtocolVersion,
    RequestId, SessionId, TaskId, TaskStatus, ToolName, WireError,
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
    /// The worker exited unexpectedly and will be started again.
    WorkerRestartScheduled {
        attempt: u32,
        delay_ms: u64,
    },
    /// The worker failed too often; the Core stops restarting it.
    WorkerRestartAbandoned {
        restarts: u32,
        window_ms: u64,
    },
    /// A local client asked for a job. The goal itself is kept in the jobs
    /// table, not repeated here.
    JobSubmitted {
        job_id: JobId,
        client: String,
    },
    JobStarted {
        job_id: JobId,
    },
    JobFinished {
        job_id: JobId,
        status: JobStatus,
    },
    ApprovalRequested {
        approval_id: ApprovalId,
        tool: ToolName,
        capabilities: Vec<Capability>,
        fingerprint: Fingerprint,
        expires_at: String,
    },
    /// A person approved the request through the local RPC interface.
    ApprovalGranted {
        approval_id: ApprovalId,
        client: String,
    },
    ApprovalDenied {
        approval_id: ApprovalId,
        client: String,
    },
    ApprovalExpired {
        approval_id: ApprovalId,
        reason: String,
    },
    /// Committed together with `execution_started`: the approval has been
    /// used and can never be used again.
    ApprovalConsumed {
        approval_id: ApprovalId,
    },
    /// A connection to the RPC interface was refused, for example because
    /// it came from the worker process.
    RpcClientRejected {
        client: String,
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
            Self::WorkerRestartScheduled { .. } => "worker_restart_scheduled",
            Self::WorkerRestartAbandoned { .. } => "worker_restart_abandoned",
            Self::JobSubmitted { .. } => "job_submitted",
            Self::JobStarted { .. } => "job_started",
            Self::JobFinished { .. } => "job_finished",
            Self::ApprovalRequested { .. } => "approval_requested",
            Self::ApprovalGranted { .. } => "approval_granted",
            Self::ApprovalDenied { .. } => "approval_denied",
            Self::ApprovalExpired { .. } => "approval_expired",
            Self::ApprovalConsumed { .. } => "approval_consumed",
            Self::RpcClientRejected { .. } => "rpc_client_rejected",
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
            AuditEventKind::ApprovalConsumed {
                approval_id: ApprovalId::new(),
            },
            AuditEventKind::WorkerRestartScheduled {
                attempt: 1,
                delay_ms: 500,
            },
            AuditEventKind::JobFinished {
                job_id: JobId::new(),
                status: JobStatus::Completed,
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
