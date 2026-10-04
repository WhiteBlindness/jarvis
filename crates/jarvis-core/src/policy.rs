//! Capability extraction and policy evaluation.
//!
//! Both are pure functions. The worker never names capabilities: they are
//! derived here from the typed call, through an exhaustive match, so adding a
//! tool without declaring its capabilities does not compile.

use std::collections::BTreeMap;

use jarvis_protocol::{Capability, PolicyDecision, ToolCall};

/// Capabilities a call needs. Never empty.
pub fn required_capabilities(call: &ToolCall) -> Vec<Capability> {
    match call {
        ToolCall::SystemInfo(_) => vec![Capability::SystemInfo],
        ToolCall::ReadFixture(_) => vec![Capability::FilesystemReadFixture],
        ToolCall::WriteFile(_) => vec![Capability::WorkspaceWrite],
    }
}

/// Maps each capability to a decision. Capabilities that are not listed are
/// denied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    rules: BTreeMap<Capability, PolicyDecision>,
}

/// Result of evaluating a call's capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: PolicyDecision,
    pub reason: String,
}

impl Policy {
    pub fn new(rules: BTreeMap<Capability, PolicyDecision>) -> Self {
        Self { rules }
    }

    pub fn decision_for(&self, capability: Capability) -> PolicyDecision {
        self.rules
            .get(&capability)
            .copied()
            .unwrap_or(PolicyDecision::Deny)
    }

    /// The most restrictive decision across all capabilities wins. An empty
    /// set is denied: a call that claims to need nothing is a bug, not a
    /// free pass.
    pub fn evaluate(&self, capabilities: &[Capability]) -> Evaluation {
        let deciding = capabilities
            .iter()
            .map(|&capability| (self.decision_for(capability), capability))
            .max_by_key(|&(decision, _)| decision);

        let (decision, reason) = match deciding {
            None => (
                PolicyDecision::Deny,
                "call requires no capability; refusing by default".to_owned(),
            ),
            Some((PolicyDecision::Allow, _)) => (
                PolicyDecision::Allow,
                "all required capabilities are allowed".to_owned(),
            ),
            Some((PolicyDecision::RequireConfirmation, capability)) => (
                PolicyDecision::RequireConfirmation,
                format!("policy requires confirmation for capability {capability}"),
            ),
            Some((PolicyDecision::Deny, capability)) => (
                PolicyDecision::Deny,
                format!("policy denies capability {capability}"),
            ),
        };
        Evaluation { decision, reason }
    }
}

#[cfg(test)]
mod tests {
    use jarvis_protocol::{ReadFixtureArgs, RelativePath, SystemInfoArgs, WriteFileArgs};
    use proptest::prelude::*;

    use super::*;

    fn policy(rules: &[(Capability, PolicyDecision)]) -> Policy {
        Policy::new(rules.iter().copied().collect())
    }

    #[test]
    fn every_tool_requires_at_least_one_capability() {
        let calls = [
            ToolCall::SystemInfo(SystemInfoArgs {}),
            ToolCall::ReadFixture(ReadFixtureArgs {
                path: RelativePath::try_from("a.txt".to_owned()).unwrap(),
            }),
            ToolCall::WriteFile(WriteFileArgs {
                path: RelativePath::try_from("a.txt".to_owned()).unwrap(),
                content: String::new(),
            }),
        ];
        assert_eq!(calls.len(), ToolCall::NAMES.len());
        for call in calls {
            assert!(!required_capabilities(&call).is_empty(), "{call:?}");
        }
    }

    #[test]
    fn default_is_deny() {
        let evaluation = Policy::default().evaluate(&[Capability::SystemInfo]);
        assert_eq!(evaluation.decision, PolicyDecision::Deny);
        assert_eq!(evaluation.reason, "policy denies capability system.info");
    }

    #[test]
    fn empty_capability_set_is_denied() {
        let open = policy(&[(Capability::SystemInfo, PolicyDecision::Allow)]);
        assert_eq!(open.evaluate(&[]).decision, PolicyDecision::Deny);
    }

    #[test]
    fn most_restrictive_wins_and_names_the_deciding_capability() {
        let rules = policy(&[
            (Capability::SystemInfo, PolicyDecision::Allow),
            (
                Capability::FilesystemReadFixture,
                PolicyDecision::RequireConfirmation,
            ),
        ]);
        let evaluation =
            rules.evaluate(&[Capability::SystemInfo, Capability::FilesystemReadFixture]);
        assert_eq!(evaluation.decision, PolicyDecision::RequireConfirmation);
        assert!(evaluation.reason.contains("filesystem.read.fixture"));
    }

    fn any_capability() -> impl Strategy<Value = Capability> {
        proptest::sample::select(Capability::ALL)
    }

    fn any_decision() -> impl Strategy<Value = PolicyDecision> {
        proptest::sample::select(
            &[
                PolicyDecision::Allow,
                PolicyDecision::RequireConfirmation,
                PolicyDecision::Deny,
            ][..],
        )
    }

    proptest! {
        /// Allow only if every capability is explicitly allowed; otherwise the
        /// strictest per-capability decision, with unlisted meaning deny.
        #[test]
        fn evaluation_is_the_strictest_rule(
            rules in proptest::collection::btree_map(any_capability(), any_decision(), 0..3),
            capabilities in proptest::collection::vec(any_capability(), 1..4),
        ) {
            let policy = Policy::new(rules.clone());
            let expected = capabilities
                .iter()
                .map(|c| rules.get(c).copied().unwrap_or(PolicyDecision::Deny))
                .max()
                .unwrap();
            let evaluation = policy.evaluate(&capabilities);
            prop_assert_eq!(evaluation.decision, expected);
            let all_allowed = capabilities
                .iter()
                .all(|c| rules.get(c) == Some(&PolicyDecision::Allow));
            prop_assert_eq!(evaluation.decision == PolicyDecision::Allow, all_allowed);
        }
    }
}
