use std::fmt;

use serde::{Deserialize, Serialize};

/// Machine-readable error codes sent to workers. Messages are for humans;
/// code paths must branch on the code only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The frame is not valid JSON, not an object, or does not match a
    /// message schema (missing field, unknown field, unknown type).
    MalformedFrame,
    /// The frame exceeded the session's size limit and was discarded.
    FrameTooLarge,
    /// The frame's `protocol` field is not the version the Core speaks.
    UnsupportedProtocolVersion,
    /// A request arrived before the `hello` handshake.
    HandshakeRequired,
    /// A valid message arrived in the wrong state, such as a second `hello`.
    UnexpectedMessage,
    /// The `request_id` was already used in this session.
    DuplicateRequest,
    /// The tool name is well-formed but no such tool exists.
    UnknownTool,
    /// The arguments do not match the tool's schema or its rules.
    InvalidArguments,
    /// The tool ran and reported an error.
    ToolFailed,
    /// The tool did not finish within its time limit.
    Timeout,
    /// The Core cancelled the tool, usually during shutdown.
    Cancelled,
    /// The tool's output failed verification and was discarded.
    ResultRejected,
    /// A session limit was reached; the session is closing.
    LimitExceeded,
    /// The Core failed internally. Details stay in the Core's logs.
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedFrame => "malformed_frame",
            Self::FrameTooLarge => "frame_too_large",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::HandshakeRequired => "handshake_required",
            Self::UnexpectedMessage => "unexpected_message",
            Self::DuplicateRequest => "duplicate_request",
            Self::UnknownTool => "unknown_tool",
            Self::InvalidArguments => "invalid_arguments",
            Self::ToolFailed => "tool_failed",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::ResultRejected => "result_rejected",
            Self::LimitExceeded => "limit_exceeded",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error as it appears on the wire and in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
}

impl WireError {
    /// Longest message the Core sends. Longer text is cut at a character
    /// boundary so that error details cannot inflate frames.
    pub const MAX_MESSAGE_LEN: usize = 512;

    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > Self::MAX_MESSAGE_LEN {
            let mut end = Self::MAX_MESSAGE_LEN;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Self { code, message }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_serde_name() {
        let codes = [
            ErrorCode::MalformedFrame,
            ErrorCode::FrameTooLarge,
            ErrorCode::UnsupportedProtocolVersion,
            ErrorCode::HandshakeRequired,
            ErrorCode::UnexpectedMessage,
            ErrorCode::DuplicateRequest,
            ErrorCode::UnknownTool,
            ErrorCode::InvalidArguments,
            ErrorCode::ToolFailed,
            ErrorCode::Timeout,
            ErrorCode::Cancelled,
            ErrorCode::ResultRejected,
            ErrorCode::LimitExceeded,
            ErrorCode::Internal,
        ];
        for code in codes {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{}\"", code.as_str())
            );
        }
    }

    #[test]
    fn long_messages_are_truncated_on_a_char_boundary() {
        let error = WireError::new(ErrorCode::Internal, "é".repeat(400));
        assert!(error.message.len() <= WireError::MAX_MESSAGE_LEN);
        assert!(error.message.chars().all(|c| c == 'é'));
    }
}
