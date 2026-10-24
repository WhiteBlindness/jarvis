//! Conversation and local-model types for the RPC interface (ADR 0021).
//!
//! A person's text goes in as [`ChatText`]; the model's text comes back as a
//! plain `String`. Model output is untrusted data: it is never decoded as a
//! command, and the only structured thing the Core extracts from it is a
//! [`ClipboardProposal`], which a person must still submit and approve
//! through the ordinary job and approval path.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::text::{check_plain, check_visible};
use crate::{ConversationId, MessageId};

/// What a person types to the assistant: 1 to 6000 characters, newlines and
/// tabs allowed, no other control characters and no invisible formatting
/// characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ChatText(String);

impl ChatText {
    pub const MAX_CHARS: usize = 6000;
    /// Also bounded in UTF-8 bytes, so that a request always fits the RPC
    /// frame with room for the envelope.
    pub const MAX_BYTES: usize = 12 * 1024;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ChatText {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        check_visible("chat text", &value, 1, Self::MAX_CHARS, true)?;
        if value.len() > Self::MAX_BYTES {
            return Err(format!(
                "chat text must be at most {} bytes in UTF-8",
                Self::MAX_BYTES
            ));
        }
        if value.trim().is_empty() {
            return Err("chat text must not be blank".to_owned());
        }
        Ok(Self(value))
    }
}

impl From<ChatText> for String {
    fn from(value: ChatText) -> Self {
        value.0
    }
}

impl fmt::Display for ChatText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A search over stored conversations: 1 to 200 characters on one line.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SearchQuery(String);

impl SearchQuery {
    pub const MAX_CHARS: usize = 200;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SearchQuery {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        check_visible("search query", &value, 1, Self::MAX_CHARS, false)?;
        Ok(Self(value))
    }
}

impl From<SearchQuery> for String {
    fn from(value: SearchQuery) -> Self {
        value.0
    }
}

/// Text the model proposed for the clipboard, already checked by the Core:
/// one line of 1 to 1024 characters from the clipboard allowlist, so it can
/// be submitted unchanged with `submit_clipboard_job` (ADR 0022). A proposal is only a
/// suggestion shown to a person; it carries no authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClipboardProposal(String);

impl ClipboardProposal {
    pub const MAX_CHARS: usize = 1024;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClipboardProposal {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        check_plain("clipboard proposal", &value, 1, Self::MAX_CHARS)?;
        if value.contains('\n') || value.contains('\t') {
            return Err("clipboard proposal must be one line without tabs".to_owned());
        }
        if value.trim().is_empty() {
            return Err("clipboard proposal must not be blank".to_owned());
        }
        Ok(Self(value))
    }
}

impl From<ClipboardProposal> for String {
    fn from(value: ClipboardProposal) -> Self {
        value.0
    }
}

/// Which language the assistant answers in. `Auto` follows the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatLanguage {
    PtPt,
    En,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    /// The model is still writing it.
    Streaming,
    Complete,
    /// A person stopped it, or the model was unloaded while it ran.
    Cancelled,
    Failed,
    /// Found unfinished at start-up.
    Interrupted,
}

impl MessageStatus {
    pub fn is_final(self) -> bool {
        !matches!(self, Self::Streaming)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }
}

/// Measurements of one generated reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnStats {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    /// From sending the request to the first token.
    pub first_token_ms: u32,
    /// Generation speed in tenths of a token per second.
    pub tokens_per_second_x10: u32,
}

/// A new turn: the person's message is stored (unless the turn regenerates
/// a reply) and the reply is being generated under `turn_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatTurn {
    pub conversation_id: ConversationId,
    #[serde(deserialize_with = "Option::deserialize")]
    pub user_message_id: Option<MessageId>,
    pub turn_id: MessageId,
}

/// The reply text after `cursor`, a UTF-8 byte offset into the reply. The
/// next poll passes `next_cursor`. `proposal`, `stats` and `error` are set
/// once the reply is final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatDelta {
    pub turn_id: MessageId,
    pub text: String,
    pub next_cursor: u32,
    pub status: MessageStatus,
    #[serde(deserialize_with = "Option::deserialize")]
    pub error: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub stats: Option<TurnStats>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub proposal: Option<ClipboardProposal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationSummary {
    pub conversation_id: ConversationId,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub message_count: u32,
    /// For a search: an excerpt around the first match.
    #[serde(deserialize_with = "Option::deserialize")]
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageView {
    pub message_id: MessageId,
    pub role: ChatRole,
    pub content: String,
    pub status: MessageStatus,
    pub created_at: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub stats: Option<TurnStats>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub proposal: Option<ClipboardProposal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationView {
    pub conversation_id: ConversationId,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub messages: Vec<MessageView>,
}

/// Where the local model stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceState {
    /// No `[inference]` section in the configuration.
    Disabled,
    /// Not loaded; the next message loads it.
    Unloaded,
    Loading,
    Ready,
    Generating,
    /// Unloaded because a configured game is running (ADR 0016).
    PausedForGame,
    /// The server could not be started or stopped answering.
    Failed,
}

/// Which configured model file is in use: the primary one, or the smaller
/// fallback used while a game runs (when configured).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelProfile {
    Primary,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceView {
    pub state: InferenceState,
    pub profile: ModelProfile,
    /// The model's display name from the configuration.
    pub model: String,
    /// SHA-256 of the model file, as recorded in its manifest.
    pub model_sha256: String,
    pub context_size: u32,
    /// Layers placed on the GPU (0 = CPU only).
    pub gpu_layers: u32,
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_error: Option<String>,
    /// Time the last load took, from start to ready.
    #[serde(deserialize_with = "Option::deserialize")]
    pub load_ms: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_stats: Option<TurnStats>,
    /// Conversations not updated for this many days are deleted; 0 keeps
    /// them until a person deletes them.
    pub retention_days: u32,
    /// Generation speed measured by a short warm-up after the last load, in
    /// tenths of a token per second.
    #[serde(deserialize_with = "Option::deserialize")]
    pub warmup_tokens_per_second_x10: Option<u32>,
    /// The warm-up ran clearly slower than a GPU should (for example because
    /// the system moved part of the model out of video memory).
    pub slow: bool,
}

/// Context sizes a client may choose.
pub const CONTEXT_SIZES: [u32; 4] = [4096, 8192, 16384, 32768];

/// Retention periods a client may choose, in days; 0 keeps conversations
/// until a person deletes them.
pub const RETENTION_DAYS: [u32; 5] = [0, 7, 30, 90, 365];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_text_allows_layout_but_not_control_or_invisible_characters() {
        assert!(ChatText::try_from("Olá\nDonna\t!".to_owned()).is_ok());
        for bad in ["", "   \n ", "a\u{1b}[2J", "a\u{202e}b", "a\rb"] {
            assert!(ChatText::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
        assert!(ChatText::try_from("é".repeat(ChatText::MAX_CHARS)).is_ok());
        assert!(ChatText::try_from("é".repeat(ChatText::MAX_CHARS + 1)).is_err());
        // Three bytes each: within the character limit, over the byte limit.
        assert!(ChatText::try_from("語".repeat(ChatText::MAX_CHARS)).is_err());
        for hidden in [
            "tag\u{E0041}",
            "vs\u{FE0F}",
            "line\u{2028}sep",
            "blank\u{2800}",
        ] {
            assert!(ChatText::try_from(hidden.to_owned()).is_err(), "{hidden:?}");
        }
    }

    #[test]
    fn hidden_characters_are_stripped_from_model_text() {
        assert_eq!(
            crate::strip_hidden("ok\u{1b}]52;c;ZXZpbA==\u{7}\n\tfim\u{200b}\u{E0041}"),
            "ok]52;c;ZXZpbA==\n\tfim"
        );
    }

    #[test]
    fn proposals_are_one_plain_line() {
        assert!(ClipboardProposal::try_from("Reunião às 15h — sala 2".to_owned()).is_ok());
        for bad in [
            "",
            " ",
            "two\nlines",
            "tab\there",
            "bidi\u{202e}x",
            "zero\u{200b}width",
            "bell\u{7}",
        ] {
            assert!(
                ClipboardProposal::try_from(bad.to_owned()).is_err(),
                "{bad:?}"
            );
        }
        assert!(ClipboardProposal::try_from("x".repeat(1025)).is_err());
    }
}
