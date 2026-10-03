"""The shared contract fixtures in ``tests/protocol`` at the repository root.

The Rust and Python test suites check the same files, so neither side can change the wire format
alone. Valid Core frames must decode to the expected typed messages, invalid ones must fail with
the expected code, and what the worker encodes must equal the worker fixtures as JSON values.
"""

import json
from pathlib import Path

import pytest

from jarvis_worker.protocol import (
    Capability,
    Completed,
    ConfirmationRequired,
    CoreMessage,
    Denied,
    ErrorCode,
    ErrorMessage,
    Failed,
    FixtureContent,
    Hello,
    ProtocolError,
    Rejected,
    SessionLimits,
    SystemInfo,
    ToolRequest,
    ToolResponse,
    Welcome,
    WireError,
    WorkerMessage,
    decode_core_message,
    encode_worker_message,
)
from support import PROTOCOL_DIR, load_json

CORE_DIR = PROTOCOL_DIR / "core"
WORKER_DIR = PROTOCOL_DIR / "worker"
INVALID_CORE_DIR = PROTOCOL_DIR / "invalid" / "core"
INVALID_WORKER_DIR = PROTOCOL_DIR / "invalid" / "worker"

EXPECTED_CORE: dict[str, CoreMessage] = {
    "welcome.json": Welcome(
        session_id="01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b",
        core_version="0.1.0",
        tools=("filesystem.read_fixture", "system.info"),
        limits=SessionLimits(max_frame_bytes=65536, tool_timeout_ms=5000, max_requests=1000),
    ),
    "tool_response_completed_system_info.json": ToolResponse(
        request_id="req-0001",
        task_id="01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c",
        outcome=Completed(
            SystemInfo(
                os="linux",
                os_family="unix",
                arch="x86_64",
                logical_cpus=8,
                core_version="0.1.0",
                protocol_version=1,
                core_uptime_ms=42,
            )
        ),
    ),
    "tool_response_completed_fixture.json": ToolResponse(
        request_id="req-0002",
        task_id="01928f5e-7c3c-7b30-9c4d-5e6f7a8b9cad",
        outcome=Completed(FixtureContent(path="welcome.txt", bytes=6, content="hello\n")),
    ),
    "tool_response_denied.json": ToolResponse(
        request_id="req-0003",
        task_id="01928f5e-7c3d-7c40-ad5e-6f7a8b9cadbe",
        outcome=Denied(
            capabilities=(Capability.FILESYSTEM_READ_FIXTURE,),
            reason="policy denies capability filesystem.read.fixture",
        ),
    ),
    "tool_response_confirmation_required.json": ToolResponse(
        request_id="req-0004",
        task_id="01928f5e-7c3e-7d50-be6f-7a8b9cadbecf",
        outcome=ConfirmationRequired(
            capabilities=(Capability.FILESYSTEM_READ_FIXTURE,),
            reason="policy requires confirmation for capability filesystem.read.fixture",
        ),
    ),
    "tool_response_rejected.json": ToolResponse(
        request_id="req-0005",
        task_id="01928f5e-7c3f-7e60-8f70-8b9cadbecfd0",
        outcome=Rejected(WireError(ErrorCode.UNKNOWN_TOOL, "unknown tool `shell.exec`")),
    ),
    "tool_response_failed_timeout.json": ToolResponse(
        request_id="req-0006",
        task_id="01928f5e-7c40-7f70-9081-9cadbecfd0e1",
        outcome=Failed(WireError(ErrorCode.TIMEOUT, "tool did not finish within 5000 ms")),
    ),
    "error_duplicate_request.json": ErrorMessage(
        request_id="req-0001",
        error=WireError(
            ErrorCode.DUPLICATE_REQUEST, "request_id `req-0001` was already used in this session"
        ),
        fatal=False,
    ),
    "error_unsupported_version.json": ErrorMessage(
        request_id=None,
        error=WireError(
            ErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
            "unsupported protocol version 2; this side speaks 1",
        ),
        fatal=True,
    ),
}

EXPECTED_WORKER: dict[str, WorkerMessage] = {
    "hello.json": Hello(worker="jarvis-worker", worker_version="0.1.0"),
    "tool_request_system_info.json": ToolRequest(
        request_id="req-0001", tool="system.info", args={}
    ),
    "tool_request_read_fixture.json": ToolRequest(
        request_id="req-0002",
        tool="filesystem.read_fixture",
        args={"path": "welcome.txt"},
    ),
}


def fixture_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.json"))


def test_every_valid_fixture_has_an_expectation() -> None:
    """A new fixture must come with an expectation here, so none goes unchecked."""
    assert {path.name for path in fixture_files(CORE_DIR)} == set(EXPECTED_CORE)
    assert {path.name for path in fixture_files(WORKER_DIR)} == set(EXPECTED_WORKER)


@pytest.mark.parametrize("path", fixture_files(CORE_DIR), ids=lambda path: path.stem)
def test_valid_core_frames_decode_to_typed_messages(path: Path) -> None:
    frame = path.read_bytes()
    assert decode_core_message(frame) == EXPECTED_CORE[path.name]


@pytest.mark.parametrize("path", fixture_files(CORE_DIR), ids=lambda path: path.stem)
def test_valid_core_frames_decode_when_compacted(path: Path) -> None:
    """The fixtures are pretty-printed; the wire form is compact. Both must decode alike."""
    compact = json.dumps(load_json(path), separators=(",", ":")).encode("utf-8")
    assert decode_core_message(compact) == EXPECTED_CORE[path.name]


@pytest.mark.parametrize("path", fixture_files(INVALID_CORE_DIR), ids=lambda path: path.stem)
def test_invalid_core_frames_are_rejected_with_the_expected_code(path: Path) -> None:
    fixture = load_json(path)
    with pytest.raises(ProtocolError) as raised:
        decode_core_message(fixture["frame"].encode("utf-8"))
    assert raised.value.code == fixture["error"]


@pytest.mark.parametrize("path", fixture_files(WORKER_DIR), ids=lambda path: path.stem)
def test_encoded_worker_messages_equal_the_fixtures(path: Path) -> None:
    message = EXPECTED_WORKER[path.name]
    assert json.loads(encode_worker_message(message)) == load_json(path)


@pytest.mark.parametrize("path", fixture_files(WORKER_DIR), ids=lambda path: path.stem)
def test_worker_frames_are_not_core_messages(path: Path) -> None:
    with pytest.raises(ProtocolError) as raised:
        decode_core_message(path.read_bytes())
    assert raised.value.code == ErrorCode.MALFORMED_FRAME


@pytest.mark.parametrize(
    "name", ["bad_request_id", "bad_tool_name"], ids=["bad_request_id", "bad_tool_name"]
)
def test_the_worker_cannot_build_the_invalid_tool_requests(name: str) -> None:
    """Identifier rules are enforced when the worker builds a request, before anything is sent."""
    fixture = load_json(INVALID_WORKER_DIR / f"{name}.json")
    frame = json.loads(fixture["frame"])
    with pytest.raises(ProtocolError) as raised:
        ToolRequest(request_id=frame["request_id"], tool=frame["tool"], args=frame["args"])
    assert raised.value.code == fixture["error"]
