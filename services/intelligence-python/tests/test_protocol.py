"""Strict decoding of Core frames, compact encoding of worker frames, identifier syntax."""

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

import support
from jarvis_worker.protocol import (
    PROTOCOL_VERSION,
    Capability,
    Denied,
    ErrorCode,
    ErrorMessage,
    Hello,
    ProtocolError,
    ToolRequest,
    ToolResponse,
    Welcome,
    decode_core_message,
    encode_worker_message,
    validate_fixture_path,
    validate_label,
    validate_request_id,
    validate_tool_name,
    validate_uuid,
)

MALFORMED = ErrorCode.MALFORMED_FRAME
Mutation = Callable[[dict[str, Any]], None]


def assert_rejected(frame: bytes, code: ErrorCode = MALFORMED) -> None:
    with pytest.raises(ProtocolError) as raised:
        decode_core_message(frame)
    assert raised.value.code == code


def mutated(base: dict[str, Any], mutation: Mutation) -> bytes:
    document = copy.deepcopy(base)
    mutation(document)
    return support.to_frame(document)


def set_path(*path: str, value: object) -> Mutation:
    """Mutation that sets ``document[path[0]][path[1]]...`` to ``value``."""

    def apply(document: dict[str, Any]) -> None:
        target = document
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return apply


def delete_path(*path: str) -> Mutation:
    def apply(document: dict[str, Any]) -> None:
        target = document
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]

    return apply


WELCOME = support.welcome()
COMPLETED = support.completed_system_info("r1")
FIXTURE = support.completed_fixture("r1")
DENIED = support.denied("r1")
ERROR = support.error("internal", fatal=True)


# --- protocol version -------------------------------------------------------------------------


@pytest.mark.parametrize("version", [True, False, "1", 1.0, None, -1, 2**64, [1], {"v": 1}])
def test_protocol_must_be_a_non_negative_integer(version: object) -> None:
    assert_rejected(mutated(WELCOME, set_path("protocol", value=version)))


def test_protocol_may_not_be_a_boolean_even_though_true_is_an_int() -> None:
    assert_rejected(
        b'{"protocol":true,"type":"error","request_id":null,'
        b'"error":{"code":"internal","message":"x"},"fatal":true}'
    )


@pytest.mark.parametrize("version", [0, 2, 99, 2**64 - 1])
def test_another_protocol_version_is_unsupported(version: int) -> None:
    assert_rejected(
        mutated(WELCOME, set_path("protocol", value=version)),
        ErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
    )


def test_version_is_checked_before_the_schema() -> None:
    frame = b'{"protocol":2,"type":"something_new","anything":[1,2,3]}'
    assert_rejected(frame, ErrorCode.UNSUPPORTED_PROTOCOL_VERSION)


def test_missing_protocol_is_malformed() -> None:
    assert_rejected(mutated(WELCOME, delete_path("protocol")))


def test_the_current_version_is_one() -> None:
    assert PROTOCOL_VERSION == 1


# --- frame shape -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"   ",
        b"not json",
        b"{",
        b'{"protocol":1,}',
        b"[1,2,3]",
        b'"hello"',
        b"1",
        b"null",
        b"true",
        b"{}",
        b'{"protocol":1}',
        b'{"protocol":1,"type":"welcome"}',
    ],
)
def test_frames_that_are_not_messages_are_malformed(frame: bytes) -> None:
    assert_rejected(frame)


@pytest.mark.parametrize(
    "frame",
    [
        b"\xff\xfe{}",
        b'{"protocol":1,"type":"error","x":"\xc3("}',
        "{}".encode("utf-16"),
        "{}".encode("utf-32"),
        b"\xef\xbb\xbf" + support.to_frame(ERROR),
    ],
    ids=["invalid_bytes", "invalid_continuation", "utf16", "utf32", "utf8_bom"],
)
def test_frames_must_be_plain_utf8(frame: bytes) -> None:
    assert_rejected(frame)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_are_not_json(constant: str) -> None:
    document = support.welcome()
    document["limits"]["max_frame_bytes"] = float(constant)
    frame = support.to_frame(document)
    assert constant.encode() in frame
    assert_rejected(frame)


@pytest.mark.parametrize("number", ["NaN", "Infinity", "1e999", "-1e999"])
def test_json_is_checked_before_the_version(number: str) -> None:
    """Numbers JSON cannot represent make the frame malformed even if it is from another version."""
    frame = b'{"protocol":2,"type":"welcome","extra":' + number.encode() + b"}"
    assert_rejected(frame)


def test_deeply_nested_json_is_malformed_not_a_crash() -> None:
    assert_rejected(b"[" * 100_000)
    assert_rejected(b'{"protocol":1,"type":"error","x":' + b"[" * 100_000)


def test_lone_surrogates_are_malformed() -> None:
    frame = support.to_frame(support.error("internal", fatal=True)).replace(
        b"core says internal", b"\\ud800 lone"
    )
    assert b"\\ud800" in frame
    assert_rejected(frame)


def test_whitespace_around_the_object_is_tolerated() -> None:
    message = decode_core_message(b" \t" + support.to_frame(ERROR) + b" \r ")
    assert isinstance(message, ErrorMessage)


@pytest.mark.parametrize("message_type", ["hello", "tool_request", "shell", "", None, 1, ["error"]])
def test_unknown_or_foreign_message_types_are_malformed(message_type: object) -> None:
    assert_rejected(mutated(ERROR, set_path("type", value=message_type)))


def test_type_is_required() -> None:
    assert_rejected(mutated(ERROR, delete_path("type")))


# --- unknown and missing fields ----------------------------------------------------------------

EXTRA_FIELDS: list[tuple[dict[str, Any], tuple[str, ...]]] = [
    (WELCOME, ()),
    (WELCOME, ("limits",)),
    (COMPLETED, ()),
    (COMPLETED, ("outcome",)),
    (COMPLETED, ("outcome", "result")),
    (DENIED, ("outcome",)),
    (support.rejected("r1"), ("outcome", "error")),
    (ERROR, ()),
    (ERROR, ("error",)),
]


@pytest.mark.parametrize(
    ("base", "path"), EXTRA_FIELDS, ids=["/".join(path) or "top" for _, path in EXTRA_FIELDS]
)
def test_unknown_fields_are_malformed_at_every_level(
    base: dict[str, Any], path: tuple[str, ...]
) -> None:
    document = copy.deepcopy(base)
    target = document
    for key in path:
        target = target[key]
    target["retry"] = True
    assert_rejected(support.to_frame(document))


@pytest.mark.parametrize(
    ("base", "path"),
    [
        (WELCOME, ("session_id",)),
        (WELCOME, ("core_version",)),
        (WELCOME, ("tools",)),
        (WELCOME, ("limits",)),
        (WELCOME, ("limits", "max_frame_bytes")),
        (WELCOME, ("limits", "tool_timeout_ms")),
        (WELCOME, ("limits", "max_requests")),
        (COMPLETED, ("request_id",)),
        (COMPLETED, ("task_id",)),
        (COMPLETED, ("outcome",)),
        (COMPLETED, ("outcome", "status")),
        (COMPLETED, ("outcome", "result")),
        (COMPLETED, ("outcome", "result", "arch")),
        (FIXTURE, ("outcome", "result", "content")),
        (DENIED, ("outcome", "capabilities")),
        (DENIED, ("outcome", "reason")),
        (support.rejected("r1"), ("outcome", "error")),
        (support.rejected("r1"), ("outcome", "error", "code")),
        (support.rejected("r1"), ("outcome", "error", "message")),
        (ERROR, ("request_id",)),
        (ERROR, ("error",)),
        (ERROR, ("fatal",)),
    ],
    ids=lambda value: "/".join(value) if isinstance(value, tuple) else "",
)
def test_missing_fields_are_malformed(base: dict[str, Any], path: tuple[str, ...]) -> None:
    assert_rejected(mutated(base, delete_path(*path)))


# --- wrong types and values ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("base", "path", "value"),
    [
        (WELCOME, ("session_id",), 7),
        (WELCOME, ("session_id",), None),
        (WELCOME, ("core_version",), 1),
        (WELCOME, ("tools",), "system.info"),
        (WELCOME, ("tools",), [1]),
        (WELCOME, ("limits",), []),
        (WELCOME, ("limits", "max_frame_bytes"), True),
        (WELCOME, ("limits", "max_frame_bytes"), 65536.0),
        (WELCOME, ("limits", "max_frame_bytes"), "65536"),
        (WELCOME, ("limits", "max_frame_bytes"), -1),
        (WELCOME, ("limits", "max_frame_bytes"), 2**32),
        (WELCOME, ("limits", "max_requests"), 2**32),
        (WELCOME, ("limits", "tool_timeout_ms"), 2**64),
        (WELCOME, ("limits", "tool_timeout_ms"), None),
        (COMPLETED, ("request_id",), 1),
        (COMPLETED, ("outcome",), "completed"),
        (COMPLETED, ("outcome", "status"), 1),
        (COMPLETED, ("outcome", "result"), []),
        (COMPLETED, ("outcome", "result", "logical_cpus"), "8"),
        (COMPLETED, ("outcome", "result", "logical_cpus"), True),
        (COMPLETED, ("outcome", "result", "logical_cpus"), 8.0),
        (COMPLETED, ("outcome", "result", "logical_cpus"), 2**32),
        (COMPLETED, ("outcome", "result", "protocol_version"), True),
        (COMPLETED, ("outcome", "result", "core_uptime_ms"), -1),
        (COMPLETED, ("outcome", "result", "os"), 1),
        (FIXTURE, ("outcome", "result", "bytes"), "6"),
        (FIXTURE, ("outcome", "result", "bytes"), False),
        (FIXTURE, ("outcome", "result", "content"), None),
        (DENIED, ("outcome", "capabilities"), "system.info"),
        (DENIED, ("outcome", "capabilities"), [1]),
        (DENIED, ("outcome", "reason"), ["no"]),
        (ERROR, ("request_id",), 7),
        (ERROR, ("error",), "internal"),
        (ERROR, ("error", "message"), 7),
        (ERROR, ("fatal",), "true"),
        (ERROR, ("fatal",), 1),
        (ERROR, ("fatal",), None),
    ],
    ids=lambda value: "/".join(value) if isinstance(value, tuple) else "",
)
def test_values_of_the_wrong_type_are_malformed(
    base: dict[str, Any], path: tuple[str, ...], value: object
) -> None:
    assert_rejected(mutated(base, set_path(*path, value=value)))


@pytest.mark.parametrize(
    "session_id",
    [
        "not-a-uuid",
        "",
        "01928f5e7c3a7d109a2b3c4d5e6f7a8b",
        "urn:uuid:01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b",
        "{01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b}",
        "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b\n",
        " 01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b",
        "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8",
        "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8bc",
        "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8g",
        "\u0661928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b",
    ],
)
def test_session_and_task_ids_must_be_canonical_uuids(session_id: str) -> None:
    assert_rejected(mutated(WELCOME, set_path("session_id", value=session_id)))
    assert_rejected(mutated(COMPLETED, set_path("task_id", value=session_id)))


def test_uuids_may_be_upper_case() -> None:
    upper = support.SESSION_ID.upper()
    message = decode_core_message(mutated(WELCOME, set_path("session_id", value=upper)))
    assert isinstance(message, Welcome)
    assert message.session_id == upper


@pytest.mark.parametrize(
    "request_id", ["", "../r1", "has space", "slash/", "r\u00e9", "x" * 65, "r1\n"]
)
def test_request_ids_follow_the_identifier_rules(request_id: str) -> None:
    assert_rejected(mutated(COMPLETED, set_path("request_id", value=request_id)))
    assert_rejected(
        mutated(support.error(request_id="r1"), set_path("request_id", value=request_id))
    )


@pytest.mark.parametrize(
    "tool", ["", "system", "System.info", "a..b", "a.1b", ".a", "a.", "rm -rf /"]
)
def test_announced_tool_names_follow_the_tool_rules(tool: str) -> None:
    assert_rejected(mutated(WELCOME, set_path("tools", value=["system.info", tool])))


@pytest.mark.parametrize(
    "capability", ["shell.exec", "", "system.info ", "SYSTEM.INFO", "filesystem.read_fixture"]
)
def test_unknown_capabilities_are_malformed(capability: str) -> None:
    assert_rejected(mutated(DENIED, set_path("outcome", "capabilities", value=[capability])))


@pytest.mark.parametrize("code", ["teapot", "", "MALFORMED_FRAME", "malformed_frame ", "Internal"])
def test_unknown_error_codes_are_malformed(code: str) -> None:
    assert_rejected(mutated(ERROR, set_path("error", "code", value=code)))
    assert_rejected(
        mutated(support.rejected("r1"), set_path("outcome", "error", "code", value=code))
    )


@pytest.mark.parametrize("status", ["maybe", "", "Completed", "pending", None, 3])
def test_unknown_outcome_statuses_are_malformed(status: object) -> None:
    assert_rejected(mutated(COMPLETED, set_path("outcome", "status", value=status)))


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "/etc/passwd",
        "a//b",
        "a/",
        "a\\b",
        ".hidden",
        "file.txt.",
        "CON",
        "nul.txt",
        "caf\u00e9",
    ],
)
def test_fixture_paths_in_results_must_be_valid(path: str) -> None:
    assert_rejected(mutated(FIXTURE, set_path("outcome", "result", "path", value=path)))


def test_a_result_is_decoded_by_its_exact_field_set() -> None:
    mixed = {**support.system_info_result(), "path": "welcome.txt"}
    assert_rejected(mutated(COMPLETED, set_path("outcome", "result", value=mixed)))
    assert_rejected(mutated(COMPLETED, set_path("outcome", "result", value={})))
    assert_rejected(mutated(COMPLETED, set_path("outcome", "result", value={"path": "a.txt"})))
    partial = {"path": "a.txt", "bytes": 1, "content": "x", "extra": 1}
    assert_rejected(mutated(FIXTURE, set_path("outcome", "result", value=partial)))


def test_fields_that_do_not_belong_to_a_status_are_malformed() -> None:
    assert_rejected(mutated(DENIED, set_path("outcome", "result", value={})))
    assert_rejected(mutated(COMPLETED, set_path("outcome", "reason", value="x")))


def test_decoding_does_not_change_typed_values() -> None:
    message = decode_core_message(support.to_frame(DENIED))
    assert isinstance(message, ToolResponse)
    assert message.outcome == Denied(
        capabilities=(Capability.FILESYSTEM_READ_FIXTURE,),
        reason="policy denies capability filesystem.read.fixture",
    )


def test_non_ascii_text_survives_decoding() -> None:
    document = support.error("internal", fatal=True)
    document["error"]["message"] = "caf\u00e9 \u2603 \U0001f600"
    message = decode_core_message(support.to_frame(document))
    assert isinstance(message, ErrorMessage)
    assert message.error.message == "caf\u00e9 \u2603 \U0001f600"


# --- encoding ------------------------------------------------------------------------------------


def test_encoding_is_compact_with_protocol_and_type_first() -> None:
    hello = encode_worker_message(Hello("jarvis-worker", "0.1.0"))
    assert hello == (
        b'{"protocol":1,"type":"hello","worker":"jarvis-worker","worker_version":"0.1.0"}'
    )
    request = encode_worker_message(
        ToolRequest("req-1", "filesystem.read_fixture", {"path": "a/b.txt"})
    )
    assert request == (
        b'{"protocol":1,"type":"tool_request","request_id":"req-1",'
        b'"tool":"filesystem.read_fixture","args":{"path":"a/b.txt"}}'
    )


def test_encoding_keeps_non_ascii_text_as_utf8() -> None:
    frame = encode_worker_message(
        ToolRequest("r1", "filesystem.read_fixture", {"path": "caf\u00e9"})
    )
    assert "caf\u00e9".encode() in frame
    assert json.loads(frame)["args"] == {"path": "caf\u00e9"}


def test_encoded_frames_stay_on_one_line() -> None:
    args: dict[str, Any] = {"path": "a\nb\r\nc\u2028d"}
    frame = encode_worker_message(ToolRequest("r1", "filesystem.read_fixture", args))
    assert b"\n" not in frame
    assert b"\r" not in frame
    assert json.loads(frame)["args"] == args


def test_encoding_preserves_argument_order_and_nesting() -> None:
    args: dict[str, Any] = {"z": 1, "a": [1, 2.5, None, True, {"k": "v"}]}
    frame = encode_worker_message(ToolRequest("r1", "system.info", args))
    assert frame.endswith(b'"args":{"z":1,"a":[1,2.5,null,true,{"k":"v"}]}}')


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), "\ud800", object(), {1, 2}])
def test_arguments_that_are_not_json_cannot_be_encoded(bad: object) -> None:
    request = ToolRequest("r1", "system.info", {"value": bad})  # type: ignore[dict-item]
    with pytest.raises(ProtocolError) as raised:
        encode_worker_message(request)
    assert raised.value.code == MALFORMED


@pytest.mark.parametrize("worker", ["", "bad name", "w" * 65, "w\u00e9", "w\n"])
def test_hello_labels_are_validated(worker: str) -> None:
    with pytest.raises(ProtocolError):
        Hello(worker=worker, worker_version="1")
    with pytest.raises(ProtocolError):
        Hello(worker="w", worker_version=worker)


@pytest.mark.parametrize("request_id", ["", "../r1", "x" * 65])
def test_tool_requests_validate_their_request_id(request_id: str) -> None:
    with pytest.raises(ProtocolError):
        ToolRequest(request_id=request_id, tool="system.info", args={})


@pytest.mark.parametrize("tool", ["", "system", "System.info", "rm -rf /", "a." + "b" * 64])
def test_tool_requests_validate_their_tool_name(tool: str) -> None:
    with pytest.raises(ProtocolError):
        ToolRequest(request_id="r1", tool=tool, args={})


# --- identifier syntax (mirrors the Rust unit tests) ---------------------------------------------


def test_request_id_accepts_simple_tokens() -> None:
    for good in ["r1", "req-001", "a_b-C", "x" * 64]:
        assert validate_request_id(good) == good


def test_tool_name_syntax() -> None:
    for good in ["system.info", "filesystem.read_fixture", "a.b.c2", "a." + "b" * 62]:
        assert validate_tool_name(good) == good
    for bad in [
        "",
        "system",
        ".info",
        "system.",
        "System.info",
        "system..info",
        "system.1nfo",
        "system.info;rm",
        "shell exec",
        "system.info\n",
        "a." + "b" * 63,
    ]:
        with pytest.raises(ProtocolError):
            validate_tool_name(bad)


def test_label_syntax() -> None:
    for good in ["w", "jarvis-worker", "0.1.0", "1.2.3+build_5", "x" * 64]:
        assert validate_label(good, "worker") == good
    for bad in ["", "bad name", "w/x", "w" * 65, "caf\u00e9", "w\n"]:
        with pytest.raises(ProtocolError):
            validate_label(bad, "worker")


def test_uuid_syntax() -> None:
    assert validate_uuid(support.SESSION_ID, "session_id") == support.SESSION_ID
    with pytest.raises(ProtocolError):
        validate_uuid("not-a-uuid", "session_id")


def test_fixture_path_accepts_plain_relative_paths() -> None:
    for good in ["welcome.txt", "notes/today.md", "a/b/c-d_e.1.txt", "2026", "a/" * 15 + "a"]:
        assert validate_fixture_path(good) == good


def test_fixture_path_rejects_escapes_and_ambiguous_forms() -> None:
    for bad in [
        "",
        "..",
        ".",
        "../secret",
        "a/../../b",
        "a/./b",
        "/etc/passwd",
        "a//b",
        "a/",
        "C:/Windows/win.ini",
        "C:secret",
        "a\\..\\b",
        "\\\\server\\share",
        ".hidden",
        "a/.ssh/id_rsa",
        "file.txt.",
        "file.txt:stream",
        "CON",
        "nul.txt",
        "dir/com1.log",
        "LPT9.TXT",
        "white space.txt",
        "caf\u00e9.txt",
        "a\0b",
        "a\n",
        "a" * 256,
        "/".join(["a"] * 17),
    ]:
        with pytest.raises(ProtocolError):
            validate_fixture_path(bad)


# --- ProtocolError -----------------------------------------------------------------------------


def test_protocol_error_carries_a_wire_code() -> None:
    error = ProtocolError("unexpected_message", "wrong state")
    assert isinstance(error.code, ErrorCode)
    assert error.code == "unexpected_message"
    assert error.message == "wrong state"
    assert str(error) == "unexpected_message: wrong state"


def test_protocol_error_rejects_codes_outside_the_protocol() -> None:
    with pytest.raises(ValueError, match="teapot"):
        ProtocolError("teapot", "x")


def test_the_protocol_has_exactly_fourteen_error_codes() -> None:
    assert sorted(code.value for code in ErrorCode) == sorted(
        [
            "malformed_frame",
            "frame_too_large",
            "unsupported_protocol_version",
            "handshake_required",
            "unexpected_message",
            "duplicate_request",
            "unknown_tool",
            "invalid_arguments",
            "tool_failed",
            "timeout",
            "cancelled",
            "result_rejected",
            "limit_exceeded",
            "internal",
        ]
    )
