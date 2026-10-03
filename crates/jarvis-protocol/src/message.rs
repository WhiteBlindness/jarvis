//! Messages exchanged over a worker session, and their strict JSON encoding.
//!
//! Every frame is a JSON object with a `protocol` field and a `type` tag:
//!
//! ```json
//! {"protocol":1,"type":"tool_request","request_id":"r1","tool":"system.info","args":{}}
//! ```

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    Capability, ErrorCode, ProtocolVersion, RequestId, SessionId, TaskId, ToolName, ToolResult,
    WireError,
};

/// First message of a session, sent by the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub worker: Label,
    pub worker_version: Label,
}

/// A request to run one tool. The worker names the tool and its arguments,
/// nothing else: there is no field for capabilities, approvals or task IDs,
/// and adding one makes the frame malformed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest {
    pub request_id: RequestId,
    pub tool: ToolName,
    pub args: serde_json::Value,
}

/// Messages a worker may send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMessage {
    Hello(Hello),
    ToolRequest(ToolRequest),
}

/// Limits the Core enforces for the session, announced at handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLimits {
    pub max_frame_bytes: u32,
    pub tool_timeout_ms: u64,
    pub max_requests: u32,
}

/// Reply to `hello`. Opens the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub session_id: SessionId,
    pub core_version: String,
    pub tools: Vec<ToolName>,
    pub limits: SessionLimits,
}

/// What happened to a tool request that became a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolOutcome {
    /// Policy allowed the call, the tool ran, and its result passed verification.
    Completed { result: ToolResult },
    /// Policy denied at least one required capability. Nothing ran.
    Denied {
        capabilities: Vec<Capability>,
        reason: String,
    },
    /// A human must confirm this call. Nothing ran, and the task expires
    /// when the session ends.
    ConfirmationRequired {
        capabilities: Vec<Capability>,
        reason: String,
    },
    /// The tool does not exist or its arguments are invalid. Nothing ran.
    Rejected { error: WireError },
    /// The tool ran but failed, timed out, was cancelled, or produced a
    /// result that failed verification.
    Failed { error: WireError },
}

/// Reply to a `tool_request` that created a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResponse {
    pub request_id: RequestId,
    pub task_id: TaskId,
    pub outcome: ToolOutcome,
}

/// A problem with a frame that did not create a task. `request_id` is set
/// when it could be recovered from the frame. When `fatal` is true the Core
/// is closing the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorMessage {
    /// Required on the wire; `null` when no request ID could be recovered.
    #[serde(deserialize_with = "Option::deserialize")]
    pub request_id: Option<RequestId>,
    pub error: WireError,
    pub fatal: bool,
}

/// Messages the Core may send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreMessage {
    Welcome(Welcome),
    ToolResponse(ToolResponse),
    Error(ErrorMessage),
}

/// Short printable token used for worker names and versions:
/// 1 to 64 ASCII letters, digits, `.`, `_`, `+` or `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label(String);

impl Label {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Label {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > 64 {
            return Err("label must be 1 to 64 characters");
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        {
            return Err("label may contain only ASCII letters, digits, '.', '_', '+' and '-'");
        }
        Ok(Self(value))
    }
}

impl From<Label> for String {
    fn from(value: Label) -> Self {
        value.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A frame that could not be decoded into a message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("malformed frame: {reason}")]
    Malformed {
        request_id: Option<RequestId>,
        reason: String,
    },
    #[error(
        "unsupported protocol version {found}; this side speaks {}",
        ProtocolVersion::CURRENT
    )]
    UnsupportedVersion {
        request_id: Option<RequestId>,
        found: u64,
    },
}

impl DecodeError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Malformed { .. } => ErrorCode::MalformedFrame,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedProtocolVersion,
        }
    }

    /// Request ID recovered from the frame, if it had a valid one. Used only
    /// to correlate the error reply; it never creates a task.
    pub fn request_id(&self) -> Option<&RequestId> {
        match self {
            Self::Malformed { request_id, .. } | Self::UnsupportedVersion { request_id, .. } => {
                request_id.as_ref()
            }
        }
    }

    pub fn to_wire(&self) -> WireError {
        WireError::new(self.code(), self.to_string())
    }
}

/// Decode a frame sent by a worker.
pub fn decode_worker_message(frame: &[u8]) -> Result<WorkerMessage, DecodeError> {
    decode(frame)
}

/// Decode a frame sent by the Core. Used by tests and Rust-side clients.
pub fn decode_core_message(frame: &[u8]) -> Result<CoreMessage, DecodeError> {
    decode(frame)
}

/// Encode a Core message as one JSON object, without the trailing newline.
pub fn encode_core_message(message: &CoreMessage) -> Result<Vec<u8>, serde_json::Error> {
    encode(message)
}

/// Encode a worker message as one JSON object, without the trailing newline.
pub fn encode_worker_message(message: &WorkerMessage) -> Result<Vec<u8>, serde_json::Error> {
    encode(message)
}

#[derive(Serialize)]
struct Envelope<'a, T> {
    protocol: ProtocolVersion,
    #[serde(flatten)]
    message: &'a T,
}

fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&Envelope {
        protocol: ProtocolVersion::CURRENT,
        message,
    })
}

/// Strict decoding in a fixed order: JSON, object, version, schema. The
/// version is checked before the schema because a frame from another version
/// may legitimately have a different shape.
fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T, DecodeError> {
    let value: serde_json::Value =
        serde_json::from_slice(frame).map_err(|error| DecodeError::Malformed {
            request_id: None,
            reason: format!("invalid JSON: {error}"),
        })?;
    let serde_json::Value::Object(mut object) = value else {
        return Err(DecodeError::Malformed {
            request_id: None,
            reason: "frame must be a JSON object".to_owned(),
        });
    };

    let request_id = object
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|id| RequestId::try_from(id.to_owned()).ok());

    match object.remove("protocol") {
        None => {
            return Err(DecodeError::Malformed {
                request_id,
                reason: "missing field `protocol`".to_owned(),
            });
        }
        Some(version) => match version.as_u64() {
            Some(found) if found == u64::from(ProtocolVersion::CURRENT.0) => {}
            Some(found) => return Err(DecodeError::UnsupportedVersion { request_id, found }),
            None => {
                return Err(DecodeError::Malformed {
                    request_id,
                    reason: "`protocol` must be a non-negative integer".to_owned(),
                });
            }
        },
    }

    T::deserialize(serde_json::Value::Object(object)).map_err(|error| DecodeError::Malformed {
        request_id,
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn frame(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn decodes_hello_and_tool_request() {
        let hello = decode_worker_message(&frame(json!({
            "protocol": 1, "type": "hello", "worker": "jarvis-worker", "worker_version": "0.1.0"
        })))
        .unwrap();
        assert!(matches!(hello, WorkerMessage::Hello(_)));

        let request = decode_worker_message(&frame(json!({
            "protocol": 1, "type": "tool_request", "request_id": "r1",
            "tool": "system.info", "args": {}
        })))
        .unwrap();
        assert!(matches!(request, WorkerMessage::ToolRequest(_)));
    }

    #[test]
    fn encoding_puts_protocol_first_and_round_trips() {
        let message = WorkerMessage::Hello(Hello {
            worker: Label::try_from("w".to_owned()).unwrap(),
            worker_version: Label::try_from("1".to_owned()).unwrap(),
        });
        let bytes = encode_worker_message(&message).unwrap();
        assert!(bytes.starts_with(br#"{"protocol":1,"type":"hello""#));
        assert_eq!(decode_worker_message(&bytes).unwrap(), message);
    }

    #[test]
    fn version_is_checked_before_schema() {
        let error = decode_worker_message(&frame(json!({
            "protocol": 2, "type": "something_new", "request_id": "r9"
        })))
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsupportedProtocolVersion);
        assert_eq!(error.request_id().map(RequestId::as_str), Some("r9"));
    }

    #[test]
    fn smuggled_authority_fields_are_malformed() {
        for extra in [
            json!({"capabilities": ["system.info"]}),
            json!({"approved": true}),
            json!({"task_id": "0190f5c8-0000-7000-8000-000000000000"}),
            json!({"policy": "allow"}),
        ] {
            let mut value = json!({
                "protocol": 1, "type": "tool_request", "request_id": "r1",
                "tool": "system.info", "args": {}
            });
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let error = decode_worker_message(&frame(value)).unwrap_err();
            assert_eq!(error.code(), ErrorCode::MalformedFrame, "{extra}");
            assert_eq!(error.request_id().map(RequestId::as_str), Some("r1"));
        }
    }

    #[test]
    fn workers_cannot_send_core_messages() {
        let error = decode_worker_message(&frame(json!({
            "protocol": 1, "type": "welcome", "session_id": SessionId::new(),
            "core_version": "0", "tools": [],
            "limits": {"max_frame_bytes": 1, "tool_timeout_ms": 1, "max_requests": 1}
        })))
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedFrame);
    }

    #[test]
    fn malformed_frames_are_classified() {
        let cases: &[&[u8]] = &[
            b"",
            b"not json",
            b"[1,2,3]",
            b"\"hello\"",
            b"{}",
            br#"{"protocol":"1","type":"hello","worker":"w","worker_version":"1"}"#,
            br#"{"protocol":-1,"type":"hello","worker":"w","worker_version":"1"}"#,
            br#"{"protocol":1}"#,
            br#"{"protocol":1,"type":"hello"}"#,
            br#"{"protocol":1,"type":"hello","worker":"bad name","worker_version":"1"}"#,
            br#"{"protocol":1,"type":"tool_request","request_id":"r 1","tool":"system.info","args":{}}"#,
            br#"{"protocol":1,"type":"tool_request","request_id":"r1","tool":"System","args":{}}"#,
            b"\xff\xfe{}",
        ];
        for case in cases {
            let error = decode_worker_message(case).unwrap_err();
            assert_eq!(
                error.code(),
                ErrorCode::MalformedFrame,
                "{}",
                String::from_utf8_lossy(case)
            );
        }
    }

    #[test]
    fn core_messages_round_trip() {
        let message = CoreMessage::Error(ErrorMessage {
            request_id: None,
            error: WireError::new(ErrorCode::HandshakeRequired, "send hello first"),
            fatal: true,
        });
        let bytes = encode_core_message(&message).unwrap();
        assert_eq!(decode_core_message(&bytes).unwrap(), message);
    }
}
