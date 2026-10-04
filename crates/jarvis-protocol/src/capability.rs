use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::PolicyDecision;

/// A permission that policy can grant. Capabilities describe intent ("read a
/// fixture"), not syntax, and are a closed set: the policy file cannot name a
/// capability that is not listed here.
///
/// Workers never send capabilities. The Core derives them from the typed
/// tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Capability {
    /// Read non-identifying runtime information about the Core's environment.
    #[serde(rename = "system.info")]
    SystemInfo,
    /// Read a text file inside the configured fixture directory.
    #[serde(rename = "filesystem.read.fixture")]
    FilesystemReadFixture,
    /// Create or replace a text file inside the configured workspace.
    #[serde(rename = "workspace.write")]
    WorkspaceWrite,
}

/// How much authority a capability carries. See `docs/threat-model.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    /// A. Read-only, bounded, no personal data: may run without a person.
    Automatic,
    /// B. Has side effects or touches personal data: a person must confirm
    /// each use.
    Confirm,
}

impl ActionClass {
    /// The most permissive decision a policy may grant for this class.
    pub fn ceiling(self) -> PolicyDecision {
        match self {
            Self::Automatic => PolicyDecision::Allow,
            Self::Confirm => PolicyDecision::RequireConfirmation,
        }
    }
}

impl Capability {
    pub const ALL: &'static [Capability] = &[
        Self::SystemInfo,
        Self::FilesystemReadFixture,
        Self::WorkspaceWrite,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SystemInfo => "system.info",
            Self::FilesystemReadFixture => "filesystem.read.fixture",
            Self::WorkspaceWrite => "workspace.write",
        }
    }

    pub fn class(self) -> ActionClass {
        match self {
            Self::SystemInfo | Self::FilesystemReadFixture => ActionClass::Automatic,
            Self::WorkspaceWrite => ActionClass::Confirm,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown capability `{0}`")]
pub struct UnknownCapability(pub String);

impl FromStr for Capability {
    type Err = UnknownCapability;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|capability| capability.as_str() == value)
            .ok_or_else(|| UnknownCapability(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_form_matches_serde_form() {
        for capability in Capability::ALL {
            let json = serde_json::to_string(capability).unwrap();
            assert_eq!(json, format!("\"{}\"", capability.as_str()));
            assert_eq!(
                capability.as_str().parse::<Capability>().unwrap(),
                *capability
            );
        }
    }

    #[test]
    fn writing_needs_confirmation_at_most() {
        assert_eq!(Capability::WorkspaceWrite.class(), ActionClass::Confirm);
        assert_eq!(
            ActionClass::Confirm.ceiling(),
            PolicyDecision::RequireConfirmation
        );
        assert_eq!(
            Capability::SystemInfo.class().ceiling(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn unknown_capability_is_an_error() {
        assert!("shell.exec".parse::<Capability>().is_err());
        assert!(serde_json::from_str::<Capability>("\"shell.exec\"").is_err());
    }
}
