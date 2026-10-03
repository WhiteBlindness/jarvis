use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Outcome of evaluating policy for a set of capabilities. Ordered from least
/// to most restrictive, so combining decisions is `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    RequireConfirmation,
    Deny,
}

impl PolicyDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::RequireConfirmation => "require_confirmation",
            Self::Deny => "deny",
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle of a durable task. Every tool request that passes decoding, the
/// handshake, the request cap and the replay check creates one task, and
/// every task ends in exactly one terminal state.
///
/// ```text
/// received ──► rejected | denied
///     │
///     ├──► awaiting_confirmation ──► denied | expired     (person declined / no decision)
///     │            │
///     │            └── approval consumed ──┐
///     ▼                                    ▼
///     └──────────────────────────────► executing ──► completed | failed | timed_out | cancelled
///
/// received | executing ──► interrupted     (found open at start-up)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Received,
    Executing,
    AwaitingConfirmation,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Denied,
    Rejected,
    Expired,
    Interrupted,
}

impl TaskStatus {
    pub const ALL: &'static [TaskStatus] = &[
        Self::Received,
        Self::Executing,
        Self::AwaitingConfirmation,
        Self::Completed,
        Self::Failed,
        Self::TimedOut,
        Self::Cancelled,
        Self::Denied,
        Self::Rejected,
        Self::Expired,
        Self::Interrupted,
    ];

    pub fn is_terminal(self) -> bool {
        !matches!(
            self,
            Self::Received | Self::Executing | Self::AwaitingConfirmation
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Executing => "executing",
            Self::AwaitingConfirmation => "awaiting_confirmation",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Denied => "denied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Interrupted => "interrupted",
        }
    }
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TaskStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|status| status.as_str() == value)
            .ok_or_else(|| format!("unknown task status `{value}`"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_restrictive_decision_is_max() {
        use PolicyDecision::*;
        assert_eq!(
            [Allow, RequireConfirmation].into_iter().max(),
            Some(RequireConfirmation)
        );
        assert_eq!(
            [RequireConfirmation, Deny, Allow].into_iter().max(),
            Some(Deny)
        );
    }

    #[test]
    fn status_strings_round_trip() {
        for status in TaskStatus::ALL {
            assert_eq!(status.as_str().parse::<TaskStatus>().unwrap(), *status);
            assert_eq!(
                serde_json::to_string(status).unwrap(),
                format!("\"{}\"", status.as_str())
            );
        }
    }

    #[test]
    fn only_three_states_are_open() {
        let open: Vec<_> = TaskStatus::ALL
            .iter()
            .filter(|status| !status.is_terminal())
            .collect();
        assert_eq!(
            open,
            [
                &TaskStatus::Received,
                &TaskStatus::Executing,
                &TaskStatus::AwaitingConfirmation
            ]
        );
    }
}

/// Lifecycle of a job: one goal submitted by a local client and worked on by
/// the worker.
///
/// ```text
/// queued ──► running ──► completed | failed | interrupted
///    │
///    └──► cancelled      (the Core stopped before the job started)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

impl JobStatus {
    pub const ALL: &'static [JobStatus] = &[
        Self::Queued,
        Self::Running,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::Interrupted,
    ];

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        }
    }
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|status| status.as_str() == value)
            .ok_or_else(|| format!("unknown job status `{value}`"))
    }
}

/// Lifecycle of an approval request. Only `granted` can become `consumed`,
/// exactly once, and only by the Core immediately before execution.
///
/// ```text
/// pending ──► granted ──► consumed
///    │           │
///    │           └──► expired
///    └──► denied | expired
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Granted,
    Denied,
    Expired,
    Consumed,
}

impl ApprovalStatus {
    pub const ALL: &'static [ApprovalStatus] = &[
        Self::Pending,
        Self::Granted,
        Self::Denied,
        Self::Expired,
        Self::Consumed,
    ];

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Denied | Self::Expired | Self::Consumed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Consumed => "consumed",
        }
    }
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ApprovalStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|status| status.as_str() == value)
            .ok_or_else(|| format!("unknown approval status `{value}`"))
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn job_and_approval_statuses_round_trip() {
        for status in JobStatus::ALL {
            assert_eq!(status.as_str().parse::<JobStatus>().unwrap(), *status);
            assert_eq!(
                serde_json::to_string(status).unwrap(),
                format!("\"{}\"", status.as_str())
            );
        }
        for status in ApprovalStatus::ALL {
            assert_eq!(status.as_str().parse::<ApprovalStatus>().unwrap(), *status);
            assert_eq!(
                serde_json::to_string(status).unwrap(),
                format!("\"{}\"", status.as_str())
            );
        }
        assert!(!ApprovalStatus::Granted.is_terminal());
        assert!(ApprovalStatus::Consumed.is_terminal());
        assert!(!JobStatus::Running.is_terminal());
    }
}
