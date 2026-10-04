"""Helpers shared by the tests: fixture locations, Core frame builders and a worker-frame check."""

import json
from pathlib import Path
from typing import Any

from jarvis_worker.protocol import (
    JobOutcome,
    validate_label,
    validate_request_id,
    validate_summary,
    validate_tool_name,
    validate_uuid,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PACKAGE_ROOT / "src"
PROTOCOL_DIR = Path(__file__).resolve().parents[3] / "tests" / "protocol"

PROTOCOL = 2
SESSION_ID = "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b"
TASK_ID = "01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c"
JOB_ID = "01928f5e-7c3c-7b30-9c4d-5e6f7a8b9c0d"
APPROVAL_ID = "01928f5e-7c3d-7c40-8d5e-6f7a8b9c0d1e"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def to_frame(document: Any) -> bytes:
    """Encode ``document`` as one frame, without the newline."""
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def to_line(document: Any) -> bytes:
    """Encode ``document`` as one newline-terminated line, as the Core would write it."""
    return to_frame(document) + b"\n"


def welcome(max_frame_bytes: int = 65536) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "type": "welcome",
        "session_id": SESSION_ID,
        "core_version": "0.2.0",
        "tools": ["filesystem.read_fixture", "system.info", "workspace.write_file"],
        "limits": {
            "max_frame_bytes": max_frame_bytes,
            "tool_timeout_ms": 5000,
            "max_requests": 1000,
        },
    }


def job(goal: str, job_id: str = JOB_ID) -> dict[str, Any]:
    return {"protocol": PROTOCOL, "type": "job", "job_id": job_id, "goal": goal}


def tool_response(request_id: str, outcome: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "type": "tool_response",
        "request_id": request_id,
        "task_id": TASK_ID,
        "outcome": outcome,
    }


def system_info_result() -> dict[str, Any]:
    return {
        "os": "linux",
        "os_family": "unix",
        "arch": "x86_64",
        "logical_cpus": 8,
        "core_version": "0.2.0",
        "protocol_version": 2,
        "core_uptime_ms": 42,
    }


def completed_system_info(request_id: str) -> dict[str, Any]:
    return tool_response(request_id, {"status": "completed", "result": system_info_result()})


def completed_fixture(request_id: str, path: str = "welcome.txt") -> dict[str, Any]:
    result = {"path": path, "bytes": 6, "content": "hello\n"}
    return tool_response(request_id, {"status": "completed", "result": result})


def denied(request_id: str) -> dict[str, Any]:
    outcome = {
        "status": "denied",
        "capabilities": ["filesystem.read.fixture"],
        "reason": "policy denies capability filesystem.read.fixture",
    }
    return tool_response(request_id, outcome)


def completed_write(request_id: str, path: str = "notes.txt") -> dict[str, Any]:
    result = {"path": path, "bytes": 5, "created": True}
    return tool_response(request_id, {"status": "completed", "result": result})


def declined(request_id: str, reason: str = "not now") -> dict[str, Any]:
    outcome = {"status": "declined", "approval_id": APPROVAL_ID, "reason": reason}
    return tool_response(request_id, outcome)


def expired(request_id: str) -> dict[str, Any]:
    return tool_response(request_id, {"status": "expired", "approval_id": APPROVAL_ID})


def rejected(request_id: str, code: str = "invalid_arguments") -> dict[str, Any]:
    outcome = {"status": "rejected", "error": {"code": code, "message": "invalid path"}}
    return tool_response(request_id, outcome)


def error(
    code: str = "internal", *, fatal: bool = False, request_id: str | None = None
) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "type": "error",
        "request_id": request_id,
        "error": {"code": code, "message": f"core says {code}"},
        "fatal": fatal,
    }


def check_worker_frame(line: bytes) -> dict[str, Any]:
    """Assert that ``line`` is a well-formed worker frame under the protocol's rules.

    This is an independent, deliberately strict reading of ``docs/protocol.md``: one line, compact
    JSON, ``protocol`` then ``type`` first, exactly the documented fields, valid identifiers.
    """
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    document = json.loads(line)
    assert isinstance(document, dict)
    assert to_line(document) == line, "frame is not compact, key order must be preserved"
    assert list(document)[:2] == ["protocol", "type"]
    assert type(document["protocol"]) is int
    assert document["protocol"] == PROTOCOL
    if document["type"] == "hello":
        assert set(document) == {"protocol", "type", "worker", "worker_version"}
        validate_label(document["worker"], "worker")
        validate_label(document["worker_version"], "worker_version")
    elif document["type"] == "tool_request":
        assert set(document) == {"protocol", "type", "request_id", "job_id", "tool", "args"}
        validate_request_id(document["request_id"])
        validate_uuid(document["job_id"], "job_id")
        validate_tool_name(document["tool"])
        assert isinstance(document["args"], dict)
    else:
        assert document["type"] == "job_result"
        assert set(document) == {"protocol", "type", "job_id", "outcome", "summary"}
        validate_uuid(document["job_id"], "job_id")
        assert document["outcome"] in {outcome.value for outcome in JobOutcome}
        validate_summary(document["summary"])
    return document
