use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

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
}

impl Capability {
    pub const ALL: &'static [Capability] = &[Self::SystemInfo, Self::FilesystemReadFixture];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SystemInfo => "system.info",
            Self::FilesystemReadFixture => "filesystem.read.fixture",
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
    fn unknown_capability_is_an_error() {
        assert!("shell.exec".parse::<Capability>().is_err());
        assert!(serde_json::from_str::<Capability>("\"shell.exec\"").is_err());
    }
}
