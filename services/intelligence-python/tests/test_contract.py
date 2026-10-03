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
    CoreMessage,
    Declined,
    Denied,
    ErrorCode,
    ErrorMessage,
    Expired,
    Failed,
    FixtureContent,
    Hello,
    Job,
    JobOutcome,
    JobResult,
    ProtocolError,
    Rejected,
    SessionLimits,
    SystemInfo,
    ToolRequest,
    ToolResponse,
    Welcome,
    WireError,
    WorkerMessage,
    WriteOutcome,
    decode_core_message,
    encode_worker_message,
)
from support import PROTOCOL_DIR, load_json

CORE_DIR = PROTOCOL_DIR / "core"
WORKER_DIR = PROTOCOL_DIR / "worker"
INVALID_CORE_DIR = PROTOCOL_DIR / "invalid" / "core"
INVALID_WORKER_DIR = PROTOCOL_DIR / "invalid" / "worker"

JOB_ID = "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b"
APPROVAL_ID = "01928f5e-7c41-7a80-a192-adbecfd0e1f2"

EXPECTED_CORE: dict[str, CoreMessage] = {
    "welcome.json": Welcome(
        session_id="01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8c",
        core_version="0.2.0",
        tools=("filesystem.read_fixture", "system.info", "workspace.write_file"),
        limits=SessionLimits(max_frame_bytes=65536, tool_timeout_ms=5000, max_requests=1000),
    ),
    "job.json": Job(job_id=JOB_ID, goal="describe the runtime, then read welcome.txt"),
    "tool_response_completed_system_info.json": ToolResponse(
        request_id="req-0001",
        task_id="01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c",
        outcome=Completed(
            SystemInfo(
                os="linux",
                os_family="unix",
                arch="x86_64",
                logical_cpus=8,
                core_version="0.2.0",
                protocol_version=2,
                core_uptime_ms=42,
            )
        ),
    ),
    "tool_response_completed_fixture.json": ToolResponse(
        request_id="req-0002",
        task_id="01928f5e-7c3c-7b30-9c4d-5e6f7a8b9cad",
        outcome=Completed(FixtureContent(path="welcome.txt", bytes=6, content="hello\n")),
    ),
    "tool_response_completed_write.json": ToolResponse(
        request_id="req-0003",
        task_id="01928f5e-7c3d-7c40-ad5e-6f7a8b9cadbe",
        outcome=Completed(WriteOutcome(path="notes/today.md", bytes=9, created=True)),
    ),
    "tool_response_denied.json": ToolResponse(
        request_id="req-0004",
        task_id="01928f5e-7c3e-7d50-be6f-7a8b9cadbecf",
        outcome=Denied(
            capabilities=(Capability.FILESYSTEM_READ_FIXTURE,),
            reason="policy denies capability filesystem.read.fixture",
        ),
    ),
    "tool_response_declined.json": ToolResponse(
        request_id="req-0005",
        task_id="01928f5e-7c3f-7e60-8f70-8b9cadbecfd0",
        outcome=Declined(approval_id=APPROVAL_ID, reason="not today"),
    ),
    "tool_response_expired.json": ToolResponse(
        request_id="req-0006",
        task_id="01928f5e-7c40-7f70-9081-9cadbecfd0e1",
        outcome=Expired(approval_id=APPROVAL_ID),
    ),
    "tool_response_rejected.json": ToolResponse(
        request_id="req-0007",
        task_id="01928f5e-7c42-7b90-b2a3-becfd0e1f203",
        outcome=Rejected(WireError(ErrorCode.UNKNOWN_TOOL, "unknown tool `shell.exec`")),
    ),
    "tool_response_failed_timeout.json": ToolResponse(
        request_id="req-0008",
        task_id="01928f5e-7c43-7ca0-83b4-cfd0e1f20314",
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
            "unsupported protocol version 3; this side speaks 2",
        ),
        fatal=True,
    ),
}

EXPECTED_WORKER: dict[str, WorkerMessage] = {
    "hello.json": Hello(worker="jarvis-worker", worker_version="0.2.0"),
    "tool_request_system_info.json": ToolRequest(
        request_id="req-0001", job_id=JOB_ID, tool="system.info", args={}
    ),
    "tool_request_read_fixture.json": ToolRequest(
        request_id="req-0002",
        job_id=JOB_ID,
        tool="filesystem.read_fixture",
        args={"path": "welcome.txt"},
    ),
    "tool_request_write_file.json": ToolRequest(
        request_id="req-0003",
        job_id=JOB_ID,
        tool="workspace.write_file",
        args={"path": "notes/today.md", "content": "buy milk\n"},
    ),
    "job_result_completed.json": JobResult(
        job_id=JOB_ID, outcome=JobOutcome.COMPLETED, summary="2 call(s): completed=2"
    ),
    "job_result_failed.json": JobResult(job_id=JOB_ID, outcome=JobOutcome.FAILED, summary=""),
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
        ToolRequest(
            request_id=frame["request_id"],
            job_id=frame["job_id"],
            tool=frame["tool"],
            args=frame["args"],
        )
    assert raised.value.code == fixture["error"]


@pytest.mark.parametrize(
    "name",
    ["job_result_control_characters", "job_result_unknown_outcome"],
    ids=["control_characters", "unknown_outcome"],
)
def test_the_worker_cannot_build_the_invalid_job_results(name: str) -> None:
    fixture = load_json(INVALID_WORKER_DIR / f"{name}.json")
    frame = json.loads(fixture["frame"])
    with pytest.raises(ProtocolError) as raised:
        JobResult(job_id=frame["job_id"], outcome=frame["outcome"], summary=frame["summary"])
    assert raised.value.code == fixture["error"]
