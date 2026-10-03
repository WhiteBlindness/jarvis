//! Bounded, single-line text supplied by people or workers.
//!
//! Text that crosses a trust boundary and may later be shown in a terminal
//! must not carry control characters: they could forge log lines or move
//! the cursor. These types reject them at decode time instead of escaping
//! them on every display path.

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! bounded_text {
    ($(#[$doc:meta])* $name:ident, $kind:literal, min = $min:expr, max = $max:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Maximum length in characters.
            pub const MAX_CHARS: usize = $max;

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let chars = value.chars().count();
                if !($min..=$max).contains(&chars) {
                    return Err(format!(
                        "{} must be {} to {} characters",
                        $kind, $min, $max
                    ));
                }
                if value.chars().any(char::is_control) {
                    return Err(format!("{} must not contain control characters", $kind));
                }
                Ok(Self(value))
            }
        }

        impl std::str::FromStr for $name {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

bounded_text!(
    /// What a person asks JARVIS to do. Submitted over the local RPC
    /// interface and passed to the worker unchanged.
    Goal,
    "goal",
    min = 1,
    max = 2000
);

bounded_text!(
    /// A short single-line report, such as a worker's job summary or the
    /// reason a person gives for declining an approval.
    Summary,
    "summary",
    min = 0,
    max = 1000
);

impl Summary {
    /// A valid summary built from any text: control characters are escaped
    /// and the result is cut to [`Summary::MAX_CHARS`] characters.
    pub fn lossy(text: &str) -> Self {
        let mut out = String::new();
        let mut count = 0;
        for c in text.chars() {
            let piece: String = if c.is_control() {
                c.escape_default().collect()
            } else {
                c.to_string()
            };
            let len = piece.chars().count();
            if count + len > Self::MAX_CHARS {
                break;
            }
            count += len;
            out.push_str(&piece);
        }
        Self(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_control_characters_and_bounds_length() {
        assert!(Goal::try_from("describe the runtime".to_owned()).is_ok());
        assert!(Goal::try_from(String::new()).is_err());
        assert!(Goal::try_from("x".repeat(2001)).is_err());
        assert!(
            Goal::try_from("é".repeat(2000)).is_ok(),
            "limit counts characters"
        );
        for bad in ["a\nb", "a\u{1b}[31m", "a\rb", "a\u{7}"] {
            assert!(Goal::try_from(bad.to_owned()).is_err(), "{bad:?}");
            assert!(Summary::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
        assert!(Summary::try_from(String::new()).is_ok());
    }

    #[test]
    fn lossy_summary_is_always_valid() {
        let summary = Summary::lossy("a\nb\u{1b}c");
        assert_eq!(summary.as_str(), "a\\nb\\u{1b}c");
        let long = Summary::lossy(&"x".repeat(5000));
        assert_eq!(long.as_str().chars().count(), Summary::MAX_CHARS);
        assert!(Summary::try_from(long.as_str().to_owned()).is_ok());
    }
}
