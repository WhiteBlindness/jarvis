//! Operations performed by the Session Agent, and the messages between the
//! Core and the agent.
//!
//! The Session Agent is a trusted process of the user that the Core starts
//! and talks to over pipes it creates (ADR 0017). A worker can ask for an
//! agent operation only as a typed tool call, which goes through policy and,
//! because every agent capability is class B, a person's approval. What
//! crosses the agent channel is a single-use grant for one exact operation.
//!
//! Desktop operations are defined here so that a person can be shown exactly
//! what one would do. Only `desktop.write_clipboard_text` can be performed
//! (ADR 0020). The Core refuses the others before they reach the agent, and
//! the agent's operation set has no variant for them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::text::{check_plain, check_visible};

/// Visible text on one line: no control characters at all.
fn visible_line(kind: &str, value: &str, min: usize, max: usize) -> Result<(), String> {
    check_visible(kind, value, min, max, false)
}
use crate::{ApprovalId, Fingerprint, Label, PayloadId};

macro_rules! visible_text {
    ($(#[$doc:meta])* $name:ident, $kind:literal, min = $min:expr, max = $max:expr, check = $check:expr) => {
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
                $check($kind, &value, $min, $max)?;
                Ok(Self(value))
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

visible_text!(
    /// A short label a health check echoes back. Short enough to be shown to
    /// a person in full.
    AgentLabel,
    "label",
    min = 1,
    max = 64,
    check = visible_line
);

visible_text!(
    /// Clipboard text: bounded, and made only of characters that read the
    /// same to the person approving it as to the program it is pasted into
    /// (`text::is_plain`): letters, digits, common punctuation, spaces, tabs
    /// and newlines. Short enough to be shown to a person in full before
    /// they approve it, and for the largest value to fit in one agent frame.
    ClipboardText,
    "clipboard text",
    min = 1,
    max = 1024,
    check = check_plain
);

visible_text!(
    /// Text to type: bounded, visible, and no control characters at all.
    /// Typed, a newline or a tab would be Enter or Tab, which can submit a
    /// form or move focus; nor can an escape sequence or a key chord be
    /// expressed.
    TypedText,
    "typed text",
    min = 1,
    max = 4096,
    check = visible_line
);

/// A window the person would pick through the Session Agent's own picker.
/// There is no picker yet, so no value is valid for any operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WindowTarget(pub u64);

impl fmt::Display for WindowTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "window #{}", self.0)
    }
}

/// Arguments of `session_agent.healthcheck`: run the Session Agent's
/// synthetic operation, which touches no desktop or personal data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthcheckArgs {
    pub label: AgentLabel,
}

/// Arguments of `desktop.capture_window`: one image of one window, never the
/// whole screen. Not performable yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureWindowArgs {
    pub target: WindowTarget,
}

/// Arguments of `desktop.read_clipboard_text`. Not performable yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadClipboardTextArgs {}

/// Arguments of `desktop.write_clipboard_text`: replace the clipboard's
/// content with the text held under `payload_id`, exactly as stored: a line
/// end stays `\n`. The request names the text and binds it by its SHA-256;
/// it never carries the text, so neither the worker nor the task record
/// holds it (ADR 0022). The Core resolves the payload, checks that its
/// SHA-256 is `sha256`, and refuses otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteClipboardTextArgs {
    pub payload_id: PayloadId,
    pub sha256: Fingerprint,
}

/// Arguments of `desktop.type_text`: type text into one picked window. No
/// key chords, no other window. Not performable yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeTextArgs {
    pub target: WindowTarget,
    pub text: TypedText,
}

/// What the worker learns when an agent operation completed. The agent's own
/// report goes to the Core only and is kept in the audit log: results of
/// agent operations may one day be personal data, so none is ever sent to
/// the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReceipt {
    /// The tool that completed, for example `session_agent.healthcheck`.
    pub agent_operation: String,
}

/// Version of the Core-to-agent channel. Both ends ship together, so each
/// accepts only its own version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentVersion(pub u32);

impl AgentVersion {
    pub const CURRENT: Self = Self(1);
}

/// The longest a grant may live, in milliseconds.
pub const MAX_GRANT_TTL_MS: u64 = 60_000;

/// The largest frame either side of the agent channel accepts, in bytes.
pub const MAX_AGENT_FRAME_BYTES: usize = 16 * 1024;

/// An operation the Session Agent can perform: the synthetic health check
/// and writing the clipboard. There is deliberately no variant for any
/// other desktop operation, so none can be sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentOperation {
    Healthcheck { label: AgentLabel },
    WriteClipboardText { text: ClipboardText },
}

/// The one message the Core sends: perform this operation once, under the
/// grant named by the approval it came from, within `ttl_ms` of receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoreToAgent {
    Perform {
        v: AgentVersion,
        grant_id: ApprovalId,
        operation: AgentOperation,
        ttl_ms: u64,
    },
}

/// What the agent reports for a health check. Nothing about the desktop,
/// the user or the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealth {
    /// The label from the request, unchanged.
    pub label: AgentLabel,
    /// Operations this agent process has performed, this one included.
    pub performed: u64,
}

/// What the agent reports for a clipboard write. Never the text: the Core
/// checks the length against the approved text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardWritten {
    /// UTF-16 code units placed on the clipboard, without the terminator.
    pub utf16_units: u32,
}

/// The agent's report of a performed operation, one variant per operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentReport {
    Healthcheck(AgentHealth),
    WriteClipboardText(ClipboardWritten),
}

/// Why the agent did not perform an operation. Each one means it did
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRefusal {
    /// This agent has already seen the grant.
    ReplayedGrant,
    /// The grant's remaining lifetime was zero or out of range.
    Expired,
    /// Another program held the clipboard open. The agent tries once and
    /// never waits or retries.
    ClipboardBusy,
    /// The clipboard could not be prepared, or this platform has none.
    ClipboardUnavailable,
}

impl AgentRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayedGrant => "replayed_grant",
            Self::Expired => "expired",
            Self::ClipboardBusy => "clipboard_busy",
            Self::ClipboardUnavailable => "clipboard_unavailable",
        }
    }
}

/// Why the agent cannot say whether an operation took effect. The Core
/// records the outcome as unknown and never sends the operation again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentFault {
    /// The clipboard was emptied, but setting or closing it failed.
    ClipboardIncomplete,
}

impl AgentFault {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClipboardIncomplete => "clipboard_incomplete",
        }
    }
}

/// `done`: performed. `refused`: nothing was done. `faulted`: started and
/// may or may not have taken effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentOutcome {
    Done { report: AgentReport },
    Refused { reason: AgentRefusal },
    Faulted { reason: AgentFault },
}

/// Messages the agent sends: `ready` once at start, then one `result` per
/// `perform`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentToCore {
    Ready {
        v: AgentVersion,
        agent_version: Label,
    },
    Result {
        v: AgentVersion,
        grant_id: ApprovalId,
        outcome: AgentOutcome,
    },
}

/// Why an agent-channel frame was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentDecodeError {
    #[error("frame is larger than {MAX_AGENT_FRAME_BYTES} bytes")]
    TooLarge,
    #[error("malformed frame: {0}")]
    Malformed(String),
    #[error("unsupported agent channel version {0}")]
    UnsupportedVersion(u32),
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, AgentDecodeError> {
    if bytes.len() > MAX_AGENT_FRAME_BYTES {
        return Err(AgentDecodeError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|error| AgentDecodeError::Malformed(error.to_string()))
}

fn check_version(v: AgentVersion) -> Result<(), AgentDecodeError> {
    if v == AgentVersion::CURRENT {
        Ok(())
    } else {
        Err(AgentDecodeError::UnsupportedVersion(v.0))
    }
}

/// Decode a frame the agent received. Strict: unknown fields, unknown
/// operations and other versions are errors.
pub fn decode_core_to_agent(bytes: &[u8]) -> Result<CoreToAgent, AgentDecodeError> {
    let message: CoreToAgent = decode(bytes)?;
    match &message {
        CoreToAgent::Perform { v, .. } => check_version(*v)?,
    }
    Ok(message)
}

/// Decode a frame the Core received from the agent. Strict, as above.
pub fn decode_agent_to_core(bytes: &[u8]) -> Result<AgentToCore, AgentDecodeError> {
    let message: AgentToCore = decode(bytes)?;
    match &message {
        AgentToCore::Ready { v, .. } | AgentToCore::Result { v, .. } => check_version(*v)?,
    }
    Ok(message)
}

/// Encode one frame for the agent channel, without the trailing newline.
pub fn encode_agent_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn approved_text_is_visible_and_bounded() {
        assert!(AgentLabel::try_from("ping 1".to_owned()).is_ok());
        let long = "x".repeat(65);
        for bad in ["", "a\nb", "pay\u{202E}evil", "a\u{200B}b", long.as_str()] {
            assert!(AgentLabel::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
        for bad in [
            "\u{1b}[A",
            "a\u{8}",
            "\r",
            "send\n",
            "a\tb",
            "\u{FEFF}x",
            "",
        ] {
            assert!(TypedText::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
        assert!(ClipboardText::try_from("line\n\tindented".to_owned()).is_ok());
        for bad in [
            "\r",
            "",
            "a\u{202E}b",
            "\u{1b}[2J",
            "line\u{2028}separator",
            "para\u{2029}graph",
            "tag\u{E0041}\u{E0042}",
            "vs\u{FE0F}",
            "\u{206A}deprecated",
            "hangul\u{3164}filler",
            "braille\u{2800}blank",
            "cgj\u{034F}",
            "object\u{FFFC}",
            "nb\u{00A0}space",
            "ideo\u{3000}space",
            "private\u{E000}",
            "unassigned\u{0378}",
            "e\u{0301}",
            "emoji \u{1F600}",
        ] {
            assert!(ClipboardText::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
        for good in [
            "Ol\u{e1}, s\u{e3}o 10\u{20ac} \u{2014} \u{201c}ok\u{201d}\u{2026}",
            "\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442} \u{4e16}\u{754c} \u{645}\u{631}\u{62d}\u{628}\u{627}",
            "a\\nb\ttab\nnext line",
        ] {
            assert!(ClipboardText::try_from(good.to_owned()).is_ok(), "{good:?}");
        }
        assert!(ClipboardText::try_from("x".repeat(1025)).is_err());
        assert!(TypedText::try_from("x".repeat(4097)).is_err());
    }

    #[test]
    fn perform_round_trips_and_is_strict() {
        let grant_id = ApprovalId::new();
        let perform = CoreToAgent::Perform {
            v: AgentVersion::CURRENT,
            grant_id,
            operation: AgentOperation::Healthcheck {
                label: AgentLabel::try_from("ping".to_owned()).unwrap(),
            },
            ttl_ms: 5_000,
        };
        let bytes = encode_agent_frame(&perform).unwrap();
        assert_eq!(decode_core_to_agent(&bytes).unwrap(), perform);

        let base = json!({"type": "perform", "v": 1, "grant_id": grant_id,
            "operation": {"op": "healthcheck", "label": "ping"}, "ttl_ms": 5000});
        let mut extra = base.clone();
        extra["caller"] = json!("core");
        let mut desktop = base.clone();
        desktop["operation"] = json!({"op": "capture_window", "target": 1});
        let mut typing = base.clone();
        typing["operation"] = json!({"op": "type_text", "target": 1, "text": "x"});
        let mut read = base.clone();
        read["operation"] = json!({"op": "read_clipboard_text"});
        let mut control = base.clone();
        control["operation"] = json!({"op": "write_clipboard_text", "text": "a\rb"});
        let mut empty = base.clone();
        empty["operation"] = json!({"op": "write_clipboard_text", "text": ""});
        let mut smuggled = base.clone();
        smuggled["operation"]["command"] = json!("cmd.exe");
        let mut version = base.clone();
        version["v"] = json!(2);
        for (frame, case) in [
            (extra, "unknown field"),
            (desktop, "desktop operation"),
            (typing, "typing"),
            (read, "clipboard read"),
            (control, "control character in clipboard text"),
            (empty, "empty clipboard text"),
            (smuggled, "field inside the operation"),
        ] {
            let bytes = serde_json::to_vec(&frame).unwrap();
            assert!(
                matches!(
                    decode_core_to_agent(&bytes),
                    Err(AgentDecodeError::Malformed(_))
                ),
                "{case}"
            );
        }
        let bytes = serde_json::to_vec(&version).unwrap();
        assert_eq!(
            decode_core_to_agent(&bytes),
            Err(AgentDecodeError::UnsupportedVersion(2))
        );
        let huge = vec![b' '; MAX_AGENT_FRAME_BYTES + 1];
        assert_eq!(decode_core_to_agent(&huge), Err(AgentDecodeError::TooLarge));
    }

    #[test]
    fn agent_replies_are_strict() {
        let grant_id = ApprovalId::new();
        let done = AgentToCore::Result {
            v: AgentVersion::CURRENT,
            grant_id,
            outcome: AgentOutcome::Done {
                report: AgentReport::Healthcheck(AgentHealth {
                    label: AgentLabel::try_from("ping".to_owned()).unwrap(),
                    performed: 1,
                }),
            },
        };
        let bytes = encode_agent_frame(&done).unwrap();
        assert_eq!(decode_agent_to_core(&bytes).unwrap(), done);
        let refused = json!({"type": "result", "v": 1, "grant_id": grant_id,
            "outcome": {"status": "refused", "reason": "replayed_grant"}});
        assert!(decode_agent_to_core(&serde_json::to_vec(&refused).unwrap()).is_ok());
        let screenshot = json!({"type": "result", "v": 1, "grant_id": grant_id,
            "outcome": {"status": "done", "report": {"op": "healthcheck", "label": "x", "performed": 1, "image": "AAAA"}}});
        assert!(decode_agent_to_core(&serde_json::to_vec(&screenshot).unwrap()).is_err());
        let written = json!({"type": "result", "v": 1, "grant_id": grant_id,
            "outcome": {"status": "done", "report": {"op": "write_clipboard_text", "utf16_units": 5}}});
        assert!(decode_agent_to_core(&serde_json::to_vec(&written).unwrap()).is_ok());
        for leak in [
            json!({"op": "write_clipboard_text", "utf16_units": 5, "text": "hello"}),
            json!({"op": "read_clipboard_text", "text": "hello"}),
            json!({"label": "x", "performed": 1}),
        ] {
            let frame = json!({"type": "result", "v": 1, "grant_id": grant_id,
                "outcome": {"status": "done", "report": leak}});
            assert!(
                decode_agent_to_core(&serde_json::to_vec(&frame).unwrap()).is_err(),
                "{frame}"
            );
        }
        let faulted = json!({"type": "result", "v": 1, "grant_id": grant_id,
            "outcome": {"status": "faulted", "reason": "clipboard_incomplete"}});
        assert!(decode_agent_to_core(&serde_json::to_vec(&faulted).unwrap()).is_ok());
    }

    #[test]
    fn the_largest_clipboard_write_fits_in_one_frame() {
        // Every character at its widest: four UTF-8 bytes, or one that JSON
        // escapes to two.
        // The widest allowed letter takes four UTF-8 bytes.
        for widest in ["\u{20000}", "\n", "\"", "\\"] {
            let text = widest.repeat(ClipboardText::MAX_CHARS);
            let perform = CoreToAgent::Perform {
                v: AgentVersion::CURRENT,
                grant_id: ApprovalId::new(),
                operation: AgentOperation::WriteClipboardText {
                    text: ClipboardText::try_from(text).unwrap(),
                },
                ttl_ms: MAX_GRANT_TTL_MS,
            };
            let bytes = encode_agent_frame(&perform).unwrap();
            assert!(bytes.len() <= MAX_AGENT_FRAME_BYTES, "{}", bytes.len());
            assert_eq!(decode_core_to_agent(&bytes).unwrap(), perform);
        }
    }
}
