"""Worker side of the wire protocol, version 2.

The reference implementation is the Rust crate ``jarvis-protocol``; the rules here mirror it and
are checked against the shared fixtures in ``tests/protocol``. A worker encodes the messages a
worker may send (``hello``, ``tool_request``, ``job_result``) and strictly decodes the messages
the Core may send (``welcome``, ``job``, ``tool_response``, ``error``).

Decoding follows a fixed order: UTF-8, JSON, object, protocol version, schema. The version is
checked before the schema because a frame from another version may have a different shape. Any
unknown type, unknown field, missing field or value of the wrong type makes the whole frame
malformed; a frame is never partly accepted.
"""

import json
import math
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeAlias, assert_never

__all__ = [
    "PROTOCOL_VERSION",
    "TOOL_READ_FIXTURE",
    "TOOL_SYSTEM_INFO",
    "TOOL_WRITE_FILE",
    "Capability",
    "Completed",
    "CoreMessage",
    "Declined",
    "Denied",
    "ErrorCode",
    "ErrorMessage",
    "Expired",
    "Failed",
    "FixtureContent",
    "Hello",
    "Job",
    "JobOutcome",
    "JobResult",
    "JsonValue",
    "ProtocolError",
    "Rejected",
    "SessionLimits",
    "SystemInfo",
    "ToolOutcome",
    "ToolRequest",
    "ToolResponse",
    "ToolResult",
    "Welcome",
    "WireError",
    "WorkerMessage",
    "WriteOutcome",
    "decode_core_message",
    "encode_worker_message",
    "validate_goal",
    "validate_label",
    "validate_relative_path",
    "validate_request_id",
    "validate_summary",
    "validate_tool_name",
    "validate_uuid",
]

PROTOCOL_VERSION = 2

TOOL_SYSTEM_INFO = "system.info"
TOOL_READ_FIXTURE = "filesystem.read_fixture"
TOOL_WRITE_FILE = "workspace.write_file"

JsonValue: TypeAlias = "bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None"


class ErrorCode(StrEnum):
    """Machine-readable error codes. Messages are for humans; branch on the code only."""

    MALFORMED_FRAME = "malformed_frame"
    FRAME_TOO_LARGE = "frame_too_large"
    UNSUPPORTED_PROTOCOL_VERSION = "unsupported_protocol_version"
    HANDSHAKE_REQUIRED = "handshake_required"
    UNEXPECTED_MESSAGE = "unexpected_message"
    DUPLICATE_REQUEST = "duplicate_request"
    UNKNOWN_TOOL = "unknown_tool"
    INVALID_ARGUMENTS = "invalid_arguments"
    TOOL_FAILED = "tool_failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RESULT_REJECTED = "result_rejected"
    LIMIT_EXCEEDED = "limit_exceeded"
    INTERNAL = "internal"


class Capability(StrEnum):
    """Permissions the Core's policy can grant. The worker only ever reads them."""

    SYSTEM_INFO = "system.info"
    FILESYSTEM_READ_FIXTURE = "filesystem.read.fixture"
    WORKSPACE_WRITE = "workspace.write"


class JobOutcome(StrEnum):
    """How the worker ended a job."""

    COMPLETED = "completed"
    FAILED = "failed"


class ProtocolError(Exception):
    """A frame violated the protocol, whether received from or about to be sent to the Core.

    ``code`` is normally ``malformed_frame`` or ``unsupported_protocol_version``; the client also
    uses ``unexpected_message`` and ``frame_too_large``.
    """

    def __init__(self, code: ErrorCode | str, message: str) -> None:
        super().__init__(message)
        self.code = ErrorCode(code)
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _malformed(detail: str) -> ProtocolError:
    return ProtocolError(ErrorCode.MALFORMED_FRAME, detail)


def _show(value: object) -> str:
    """Short repr for error messages, so a hostile frame cannot inflate them."""
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


# --- Identifier syntax -------------------------------------------------------------------------

_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_LABEL = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_UUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._-]+")

_TOOL_NAME_MAX_LEN = 64
_PATH_MAX_LEN = 255
_PATH_MAX_COMPONENTS = 16
_GOAL_MIN_CHARS = 1
_GOAL_MAX_CHARS = 2000
_SUMMARY_MIN_CHARS = 0
_SUMMARY_MAX_CHARS = 1000
_WINDOWS_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"} | {f"com{n}" for n in range(10)} | {f"lpt{n}" for n in range(10)}
)


def validate_request_id(value: str) -> str:
    """Return ``value`` if it is 1 to 64 characters from ``[A-Za-z0-9_-]``."""
    if _REQUEST_ID.fullmatch(value) is None:
        raise _malformed(f"invalid request_id: {_show(value)}")
    return value


def validate_label(value: str, name: str) -> str:
    """Return ``value`` if it is 1 to 64 characters from ``[A-Za-z0-9._+-]``."""
    if _LABEL.fullmatch(value) is None:
        raise _malformed(f"invalid {name}: {_show(value)}")
    return value


def validate_tool_name(value: str) -> str:
    """Return ``value`` if it has at least two dot-separated lowercase segments.

    Each segment starts with a letter and continues with letters, digits or ``_``. This checks
    syntax only; whether the tool exists is decided by the Core.
    """
    if len(value) > _TOOL_NAME_MAX_LEN or _TOOL_NAME.fullmatch(value) is None:
        raise _malformed(f"invalid tool name: {_show(value)}")
    return value


def validate_uuid(value: str, name: str) -> str:
    """Return ``value`` if it is a UUID in its canonical hyphenated form.

    The Core only ever emits that form, so the other spellings its UUID parser tolerates are
    refused here.
    """
    if _UUID.fullmatch(value) is None:
        raise _malformed(f"invalid {name}: must be a UUID, got {_show(value)}")
    return value


def validate_relative_path(value: str) -> str:
    """Return ``value`` if it is a syntactically valid path relative to a tool's root directory.

    A path is at most 255 characters and 16 components separated by ``/``. A component is made
    of ASCII letters, digits, ``.``, ``_`` and ``-``, starts with a letter or digit, does not end
    with ``.`` and is not a Windows device name. The same rules apply to the fixture directory
    and to the workspace.
    """
    problem = _path_problem(value)
    if problem is not None:
        raise _malformed(f"invalid path {_show(value)}: {problem}")
    return value


def _path_problem(value: str) -> str | None:
    if not value:
        return "path must not be empty"
    if len(value) > _PATH_MAX_LEN:
        return f"path must be at most {_PATH_MAX_LEN} characters"
    components = value.split("/")
    if len(components) > _PATH_MAX_COMPONENTS:
        return f"path must have at most {_PATH_MAX_COMPONENTS} components"
    for component in components:
        problem = _path_component_problem(component)
        if problem is not None:
            return problem
    return None


def _path_component_problem(component: str) -> str | None:
    if not component:
        return "path must be relative and must not contain empty components"
    first = component[0]
    if not (first.isascii() and first.isalnum()):
        return f"component {_show(component)} must start with a letter or digit"
    if component.endswith("."):
        return f"component {_show(component)} must not end with '.'"
    if _PATH_COMPONENT.fullmatch(component) is None:
        return f"component {_show(component)} may contain only letters, digits, '.', '_' and '-'"
    if component.split(".", 1)[0].lower() in _WINDOWS_DEVICE_NAMES:
        return f"component {_show(component)} is a reserved device name"
    return None


def _bounded_text(value: str, what: str, min_chars: int, max_chars: int) -> str:
    """Return ``value`` if it has ``min_chars`` to ``max_chars`` characters and no control ones.

    Length counts characters, not bytes. A control character is one in Unicode category ``Cc``
    (U+0000 to U+001F and U+007F to U+009F), which is what Rust's ``char::is_control`` means.
    """
    if not min_chars <= len(value) <= max_chars:
        raise _malformed(f"invalid {what}: must be {min_chars} to {max_chars} characters")
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise _malformed(f"invalid {what}: must not contain control characters")
    return value


def validate_goal(value: str) -> str:
    """Return ``value`` if it is a valid goal: 1 to 2000 characters, no control characters."""
    return _bounded_text(value, "goal", _GOAL_MIN_CHARS, _GOAL_MAX_CHARS)


def validate_summary(value: str) -> str:
    """Return ``value`` if it is a valid summary: 0 to 1000 characters, no control characters.

    Summaries are single-line reports a person may read in a terminal, such as a job summary or
    the reason a person gave for declining an approval.
    """
    return _bounded_text(value, "summary", _SUMMARY_MIN_CHARS, _SUMMARY_MAX_CHARS)


# --- Worker messages ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Hello:
    """First message of a session. Both fields are labels (see ``validate_label``)."""

    worker: str
    worker_version: str

    def __post_init__(self) -> None:
        validate_label(self.worker, "worker")
        validate_label(self.worker_version, "worker_version")


@dataclass(frozen=True, slots=True)
class ToolRequest:
    """A request to run one tool while working on a job.

    The worker names the job, the tool and its arguments and nothing else. There is deliberately
    no field for capabilities, approvals or task IDs: the Core derives and decides those.
    """

    request_id: str
    job_id: str
    tool: str
    args: dict[str, JsonValue]

    def __post_init__(self) -> None:
        validate_request_id(self.request_id)
        validate_uuid(self.job_id, "job_id")
        validate_tool_name(self.tool)


@dataclass(frozen=True, slots=True)
class JobResult:
    """The worker has finished the job it was given.

    ``summary`` is a short single-line report (see ``validate_summary``).
    """

    job_id: str
    outcome: JobOutcome
    summary: str

    def __post_init__(self) -> None:
        validate_uuid(self.job_id, "job_id")
        try:
            JobOutcome(self.outcome)
        except ValueError:
            raise _malformed(f"invalid outcome: {_show(self.outcome)}") from None
        validate_summary(self.summary)


WorkerMessage: TypeAlias = Hello | ToolRequest | JobResult


# --- Core messages -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionLimits:
    """Limits the Core enforces for the session, announced in ``welcome``."""

    max_frame_bytes: int
    tool_timeout_ms: int
    max_requests: int


@dataclass(frozen=True, slots=True)
class Welcome:
    """Reply to ``hello``. Opens the session."""

    session_id: str
    core_version: str
    tools: tuple[str, ...]
    limits: SessionLimits


@dataclass(frozen=True, slots=True)
class Job:
    """A goal the Core assigns to the worker, which works on one job at a time."""

    job_id: str
    goal: str


@dataclass(frozen=True, slots=True)
class WireError:
    """An error as it appears on the wire."""

    code: ErrorCode
    message: str


@dataclass(frozen=True, slots=True)
class SystemInfo:
    """Result of ``system.info``."""

    os: str
    os_family: str
    arch: str
    logical_cpus: int
    core_version: str
    protocol_version: int
    core_uptime_ms: int


@dataclass(frozen=True, slots=True)
class FixtureContent:
    """Result of ``filesystem.read_fixture``."""

    path: str
    bytes: int
    content: str


@dataclass(frozen=True, slots=True)
class WriteOutcome:
    """Result of ``workspace.write_file``."""

    path: str
    bytes: int
    created: bool


ToolResult: TypeAlias = SystemInfo | FixtureContent | WriteOutcome


@dataclass(frozen=True, slots=True)
class Completed:
    """Policy allowed the call, the tool ran and its result passed verification."""

    result: ToolResult


@dataclass(frozen=True, slots=True)
class Denied:
    """Policy denied at least one required capability. Nothing ran."""

    capabilities: tuple[Capability, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class Declined:
    """A person refused to approve the call. Nothing ran.

    ``approval_id`` is informational: the worker has no way to act on an approval.
    """

    approval_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class Expired:
    """Nobody decided before the approval expired. Nothing ran."""

    approval_id: str


@dataclass(frozen=True, slots=True)
class Rejected:
    """The tool is unknown or its arguments are invalid. Nothing ran."""

    error: WireError


@dataclass(frozen=True, slots=True)
class Failed:
    """The tool failed, timed out, was cancelled or produced a result that was rejected."""

    error: WireError


ToolOutcome: TypeAlias = Completed | Denied | Declined | Expired | Rejected | Failed


@dataclass(frozen=True, slots=True)
class ToolResponse:
    """Reply to a ``tool_request`` that became a task."""

    request_id: str
    task_id: str
    outcome: ToolOutcome


@dataclass(frozen=True, slots=True)
class ErrorMessage:
    """A problem with a frame that did not create a task.

    ``request_id`` is set when the Core recovered a valid one from the frame. When ``fatal`` is
    true the Core is closing the session.
    """

    request_id: str | None
    error: WireError
    fatal: bool


CoreMessage: TypeAlias = Welcome | Job | ToolResponse | ErrorMessage


# --- Encoding ----------------------------------------------------------------------------------


def encode_worker_message(message: WorkerMessage) -> bytes:
    """Encode ``message`` as one compact UTF-8 JSON object, without the trailing newline.

    The object starts with ``protocol`` and ``type``. Raises ``ProtocolError`` if the message
    cannot be represented as JSON, for example when ``args`` holds a NaN or a lone surrogate.
    """
    match message:
        case Hello(worker=worker, worker_version=worker_version):
            body: dict[str, JsonValue] = {
                "type": "hello",
                "worker": worker,
                "worker_version": worker_version,
            }
        case ToolRequest(request_id=request_id, job_id=job_id, tool=tool, args=args):
            body = {
                "type": "tool_request",
                "request_id": request_id,
                "job_id": job_id,
                "tool": tool,
                "args": args,
            }
        case JobResult(job_id=job_id, outcome=outcome, summary=summary):
            body = {
                "type": "job_result",
                "job_id": job_id,
                "outcome": JobOutcome(outcome).value,
                "summary": summary,
            }
        case _:
            assert_never(message)
    envelope = {"protocol": PROTOCOL_VERSION, **body}
    try:
        text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return text.encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise _malformed(f"message cannot be encoded as JSON: {error}") from error


# --- Decoding ----------------------------------------------------------------------------------

_U32 = 32
_U64 = 64

_WELCOME_FIELDS = frozenset({"session_id", "core_version", "tools", "limits"})
_LIMITS_FIELDS = frozenset({"max_frame_bytes", "tool_timeout_ms", "max_requests"})
_JOB_FIELDS = frozenset({"job_id", "goal"})
_TOOL_RESPONSE_FIELDS = frozenset({"request_id", "task_id", "outcome"})
_ERROR_MESSAGE_FIELDS = frozenset({"request_id", "error", "fatal"})
_WIRE_ERROR_FIELDS = frozenset({"code", "message"})
_SYSTEM_INFO_FIELDS = frozenset(
    {
        "os",
        "os_family",
        "arch",
        "logical_cpus",
        "core_version",
        "protocol_version",
        "core_uptime_ms",
    }
)
_FIXTURE_CONTENT_FIELDS = frozenset({"path", "bytes", "content"})
_WRITE_OUTCOME_FIELDS = frozenset({"path", "bytes", "created"})


def decode_core_message(frame: bytes) -> CoreMessage:
    """Decode one frame sent by the Core, without its trailing newline.

    Raises ``ProtocolError`` with code ``unsupported_protocol_version`` when the frame speaks
    another version and ``malformed_frame`` for every other defect.
    """
    document = _parse_frame(frame)
    _check_version(document)
    body = {key: value for key, value in document.items() if key not in ("protocol", "type")}
    message_type = document.get("type")
    match message_type:
        case "welcome":
            return _decode_welcome(body)
        case "job":
            return _decode_job(body)
        case "tool_response":
            return _decode_tool_response(body)
        case "error":
            return _decode_error_message(body)
        case _:
            raise _malformed(f"unknown message type {_show(message_type)}")


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(f"{name} is not valid JSON")


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"number {text} is out of range")
    return value


def _parse_frame(frame: bytes) -> dict[str, object]:
    try:
        text = frame.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _malformed("frame is not valid UTF-8") from error
    try:
        document = json.loads(text, parse_constant=_reject_constant, parse_float=_parse_float)
    except (ValueError, RecursionError) as error:
        raise _malformed(f"frame is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise _malformed("frame must be a JSON object")
    return document


def _check_version(document: dict[str, object]) -> None:
    if "protocol" not in document:
        raise _malformed("missing field `protocol`")
    version = document["protocol"]
    if type(version) is not int or not 0 <= version < 1 << _U64:
        raise _malformed("`protocol` must be a non-negative integer")
    if version != PROTOCOL_VERSION:
        raise ProtocolError(
            ErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
            f"unsupported protocol version {version}; this side speaks {PROTOCOL_VERSION}",
        )


def _mapping(value: object, what: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _malformed(f"{what} must be an object")
    return value


def _exact(value: object, keys: frozenset[str], what: str) -> dict[str, object]:
    """Return ``value`` as a dict after checking that it has exactly the fields ``keys``."""
    fields = _mapping(value, what)
    missing = keys - fields.keys()
    if missing:
        raise _malformed(f"{what}: missing field `{min(missing)}`")
    unknown = fields.keys() - keys
    if unknown:
        raise _malformed(f"{what}: unknown field {_show(min(unknown))}")
    return fields


def _text(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise _malformed(f"{what} must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise _malformed(f"{what} must not contain lone surrogates") from error
    return value


def _uint(value: object, what: str, bits: int) -> int:
    """Unsigned integer of at most ``bits`` bits. Booleans and floats are refused."""
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise _malformed(f"{what} must be an unsigned {bits}-bit integer")
    return value


def _flag(value: object, what: str) -> bool:
    if not isinstance(value, bool):
        raise _malformed(f"{what} must be a boolean")
    return value


def _items(value: object, what: str) -> list[object]:
    if not isinstance(value, list):
        raise _malformed(f"{what} must be an array")
    return value


def _decode_welcome(body: dict[str, object]) -> Welcome:
    fields = _exact(body, _WELCOME_FIELDS, "welcome")
    return Welcome(
        session_id=validate_uuid(_text(fields["session_id"], "session_id"), "session_id"),
        core_version=_text(fields["core_version"], "core_version"),
        tools=tuple(
            validate_tool_name(_text(tool, "tools[]")) for tool in _items(fields["tools"], "tools")
        ),
        limits=_decode_limits(fields["limits"]),
    )


def _decode_limits(value: object) -> SessionLimits:
    fields = _exact(value, _LIMITS_FIELDS, "limits")
    return SessionLimits(
        max_frame_bytes=_uint(fields["max_frame_bytes"], "max_frame_bytes", _U32),
        tool_timeout_ms=_uint(fields["tool_timeout_ms"], "tool_timeout_ms", _U64),
        max_requests=_uint(fields["max_requests"], "max_requests", _U32),
    )


def _decode_job(body: dict[str, object]) -> Job:
    fields = _exact(body, _JOB_FIELDS, "job")
    return Job(
        job_id=validate_uuid(_text(fields["job_id"], "job_id"), "job_id"),
        goal=validate_goal(_text(fields["goal"], "goal")),
    )


def _decode_tool_response(body: dict[str, object]) -> ToolResponse:
    fields = _exact(body, _TOOL_RESPONSE_FIELDS, "tool_response")
    return ToolResponse(
        request_id=validate_request_id(_text(fields["request_id"], "request_id")),
        task_id=validate_uuid(_text(fields["task_id"], "task_id"), "task_id"),
        outcome=_decode_outcome(fields["outcome"]),
    )


def _decode_error_message(body: dict[str, object]) -> ErrorMessage:
    fields = _exact(body, _ERROR_MESSAGE_FIELDS, "error")
    request_id = fields["request_id"]
    return ErrorMessage(
        request_id=None
        if request_id is None
        else validate_request_id(_text(request_id, "request_id")),
        error=_decode_wire_error(fields["error"]),
        fatal=_flag(fields["fatal"], "fatal"),
    )


def _decode_wire_error(value: object) -> WireError:
    fields = _exact(value, _WIRE_ERROR_FIELDS, "error")
    code = _text(fields["code"], "error code")
    try:
        error_code = ErrorCode(code)
    except ValueError:
        raise _malformed(f"unknown error code {_show(code)}") from None
    return WireError(code=error_code, message=_text(fields["message"], "error message"))


def _decode_capabilities(value: object) -> tuple[Capability, ...]:
    capabilities = []
    for item in _items(value, "capabilities"):
        name = _text(item, "capabilities[]")
        try:
            capabilities.append(Capability(name))
        except ValueError:
            raise _malformed(f"unknown capability {_show(name)}") from None
    return tuple(capabilities)


def _decode_outcome(value: object) -> ToolOutcome:
    status = _mapping(value, "outcome").get("status")
    match status:
        case "completed":
            fields = _exact(value, frozenset({"status", "result"}), "outcome")
            return Completed(result=_decode_result(fields["result"]))
        case "denied":
            fields = _exact(value, frozenset({"status", "capabilities", "reason"}), "outcome")
            return Denied(
                capabilities=_decode_capabilities(fields["capabilities"]),
                reason=_text(fields["reason"], "reason"),
            )
        case "declined":
            fields = _exact(value, frozenset({"status", "approval_id", "reason"}), "outcome")
            return Declined(
                approval_id=validate_uuid(
                    _text(fields["approval_id"], "approval_id"), "approval_id"
                ),
                reason=validate_summary(_text(fields["reason"], "reason")),
            )
        case "expired":
            fields = _exact(value, frozenset({"status", "approval_id"}), "outcome")
            return Expired(
                approval_id=validate_uuid(
                    _text(fields["approval_id"], "approval_id"), "approval_id"
                )
            )
        case "rejected" | "failed":
            fields = _exact(value, frozenset({"status", "error"}), "outcome")
            error = _decode_wire_error(fields["error"])
            return Rejected(error=error) if status == "rejected" else Failed(error=error)
        case _:
            raise _malformed(f"unknown outcome status {_show(status)}")


def _decode_result(value: object) -> ToolResult:
    """Decode an untagged tool result by its exact field set."""
    fields = _mapping(value, "result")
    if fields.keys() == _SYSTEM_INFO_FIELDS:
        return SystemInfo(
            os=_text(fields["os"], "os"),
            os_family=_text(fields["os_family"], "os_family"),
            arch=_text(fields["arch"], "arch"),
            logical_cpus=_uint(fields["logical_cpus"], "logical_cpus", _U32),
            core_version=_text(fields["core_version"], "core_version"),
            protocol_version=_uint(fields["protocol_version"], "protocol_version", _U32),
            core_uptime_ms=_uint(fields["core_uptime_ms"], "core_uptime_ms", _U64),
        )
    if fields.keys() == _FIXTURE_CONTENT_FIELDS:
        return FixtureContent(
            path=validate_relative_path(_text(fields["path"], "path")),
            bytes=_uint(fields["bytes"], "bytes", _U64),
            content=_text(fields["content"], "content"),
        )
    if fields.keys() == _WRITE_OUTCOME_FIELDS:
        return WriteOutcome(
            path=validate_relative_path(_text(fields["path"], "path")),
            bytes=_uint(fields["bytes"], "bytes", _U64),
            created=_flag(fields["created"], "created"),
        )
    raise _malformed("result does not match any tool result schema")
