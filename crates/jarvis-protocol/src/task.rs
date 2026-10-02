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

/// Lifecycle of a durable task. Every well-formed tool request creates one
/// task, and every task ends in exactly one terminal state.
///
/// ```text
/// received ──► rejected | denied | awaiting_confirmation ──► expired
///     │
///     └──► executing ──► completed | failed | timed_out | cancelled
///
/// any non-terminal state ──► interrupted   (Core restarted mid-task)
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
