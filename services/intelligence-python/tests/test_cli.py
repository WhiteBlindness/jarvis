"""The command line: ``python -m jarvis_worker --goal "..."``.

Most tests run the worker as a real subprocess, the way the Core does: working directory
``src``, a cleared environment, and a fake Core on the other end of its stdin and stdout. The
fake Core is this test process; it answers each request using the request ID the worker chose.
"""

import io
import json
import logging
import os
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import pytest

import support
from jarvis_worker import __main__ as cli
from jarvis_worker.client import CoreClient
from jarvis_worker.planner import PlannedCall, StubPlanner

TIMEOUT_SECONDS = 20

Reply = Callable[[str], dict[str, Any]]
"""Builds the Core's reply to a request, given the request's ID."""


@dataclass
class Run:
    exit_code: int
    frames: list[dict[str, Any]]  # every frame the worker wrote to stdout, in order
    stdout: bytes
    stderr: str


def core_environment() -> dict[str, str]:
    """What the Core leaves a worker: PATH, and SYSTEMROOT where it exists."""
    kept = ("PATH", "SYSTEMROOT")
    return {name: os.environ[name] for name in kept if name in os.environ}


@contextmanager
def worker_process(args: Sequence[str]) -> Iterator[subprocess.Popen[bytes]]:
    command = [sys.executable, "-m", "jarvis_worker", *args]
    process = subprocess.Popen(  # noqa: S603 (fixed command, no shell)
        command,
        cwd=support.SRC_DIR,
        env=core_environment(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    watchdog = threading.Timer(TIMEOUT_SECONDS, process.kill)
    watchdog.start()
    try:
        yield process
    finally:
        watchdog.cancel()
        process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def run_worker(
    args: Sequence[str],
    *,
    welcome: dict[str, Any] | None = None,
    replies: Sequence[Reply] = (),
    close_stdin_after_welcome: bool = False,
) -> Run:
    """Play the Core: send ``welcome``, answer one request per entry of ``replies``, then close."""
    with worker_process(args) as process:
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        lines: list[bytes] = []

        def read_line() -> bytes:
            line = process.stdout.readline()  # type: ignore[union-attr]
            if line:
                lines.append(line)
            return line

        if welcome is not None:
            process.stdin.write(support.to_line(welcome))
            process.stdin.flush()
        if close_stdin_after_welcome:
            process.stdin.close()
        elif welcome is not None and welcome.get("type") == "welcome":
            assert read_line(), "the worker did not send hello"
            for reply in replies:
                request = read_line()
                assert request, "the worker did not send the expected request"
                request_id = json.loads(request)["request_id"]
                process.stdin.write(support.to_line(reply(request_id)))
                process.stdin.flush()
            process.stdin.close()
        else:
            process.stdin.close()
        while read_line():
            pass
        exit_code = process.wait()
        stderr = process.stderr.read().decode("utf-8")
    frames = [support.check_worker_frame(line) for line in lines]
    return Run(exit_code=exit_code, frames=frames, stdout=b"".join(lines), stderr=stderr)


def tool_calls(run: Run) -> list[tuple[str, dict[str, Any]]]:
    return [
        (frame["tool"], frame["args"]) for frame in run.frames if frame["type"] == "tool_request"
    ]


# --- a session over real pipes ---------------------------------------------------------------


def test_a_goal_is_planned_and_every_call_is_sent_in_order() -> None:
    run = run_worker(
        ["--goal", "describe the runtime, then read welcome.txt"],
        welcome=support.welcome(),
        replies=[support.completed_system_info, support.completed_fixture],
    )
    assert run.exit_code == 0
    assert [frame["type"] for frame in run.frames] == ["hello", "tool_request", "tool_request"]
    assert run.frames[0]["worker"] == "jarvis-worker"
    assert run.frames[0]["worker_version"] == "0.1.0"
    assert tool_calls(run) == [
        ("system.info", {}),
        ("filesystem.read_fixture", {"path": "welcome.txt"}),
    ]
    ids = [frame["request_id"] for frame in run.frames[1:]]
    assert len(set(ids)) == 2


def test_stdout_carries_only_protocol_frames_and_logs_go_to_stderr() -> None:
    run = run_worker(
        ["--goal", "system"], welcome=support.welcome(), replies=[support.completed_system_info]
    )
    assert run.exit_code == 0
    assert run.stdout.endswith(b"\n")
    assert b"\r" not in run.stdout
    assert all(json.loads(line) for line in run.stdout.splitlines())
    assert run.stderr
    for line in run.stderr.splitlines():
        assert line.split(" ", 2)[1] == "jarvis_worker:", line


def test_each_outcome_is_logged_on_one_line() -> None:
    run = run_worker(
        ["--goal", "system, read a.txt, read b.txt, read c.txt, read d.txt"],
        welcome=support.welcome(),
        replies=[
            support.completed_system_info,
            support.denied,
            lambda request_id: support.tool_response(
                request_id,
                {
                    "status": "confirmation_required",
                    "capabilities": ["filesystem.read.fixture"],
                    "reason": "needs a human",
                },
            ),
            lambda request_id: support.rejected(request_id, "invalid_arguments"),
            lambda request_id: support.tool_response(
                request_id,
                {"status": "failed", "error": {"code": "timeout", "message": "too slow"}},
            ),
        ],
    )
    assert run.exit_code == 0
    task = support.TASK_ID
    assert f"INFO jarvis_worker: task {task} system.info: completed\n" in run.stderr + "\n"
    expected = [
        f"task {task} filesystem.read_fixture: denied: policy denies capability "
        "filesystem.read.fixture",
        f"task {task} filesystem.read_fixture: confirmation_required: needs a human",
        f"task {task} filesystem.read_fixture: rejected: invalid_arguments",
        f"task {task} filesystem.read_fixture: failed: timeout",
        "summary: 5 call(s): completed=1 denied=1 confirmation_required=1 rejected=1 failed=1",
    ]
    for text in expected:
        assert f"INFO jarvis_worker: {text}" in run.stderr.splitlines()


def test_a_dangerous_path_is_sent_unchanged_and_the_cores_rejection_is_not_a_failure() -> None:
    run = run_worker(
        ["--goal", "read ../secret"],
        welcome=support.welcome(),
        replies=[support.rejected],
    )
    assert run.exit_code == 0
    assert tool_calls(run) == [("filesystem.read_fixture", {"path": "../secret"})]
    assert "rejected: invalid_arguments" in run.stderr


def test_a_goal_without_matches_sends_only_hello() -> None:
    run = run_worker(["--goal", "say hello"], welcome=support.welcome())
    assert run.exit_code == 0
    assert [frame["type"] for frame in run.frames] == ["hello"]
    assert "planned 0 call(s)" in run.stderr
    assert "summary: 0 call(s)" in run.stderr


def test_an_empty_goal_is_allowed() -> None:
    run = run_worker(["--goal", ""], welcome=support.welcome())
    assert run.exit_code == 0
    assert [frame["type"] for frame in run.frames] == ["hello"]


def test_non_ascii_text_in_a_goal_reaches_the_core_as_utf8() -> None:
    run = run_worker(
        ["--goal", "read café.txt"], welcome=support.welcome(), replies=[support.rejected]
    )
    assert run.exit_code == 0
    assert tool_calls(run) == [("filesystem.read_fixture", {"path": "café.txt"})]
    assert "café.txt".encode() in run.stdout


# --- failures: exit code 3 ----------------------------------------------------------------------


def assert_clean_failure(run: Run) -> None:
    assert run.exit_code == 3
    assert "Traceback" not in run.stderr
    assert "ERROR jarvis_worker:" in run.stderr


def test_a_fatal_error_during_the_handshake_exits_with_3() -> None:
    reply = support.error("unsupported_protocol_version", fatal=True)
    run = run_worker(["--goal", "system"], welcome=reply)
    assert_clean_failure(run)
    assert [frame["type"] for frame in run.frames] == ["hello"]
    assert "unsupported_protocol_version" in run.stderr
    assert "fatal" in run.stderr


def test_end_of_input_during_the_handshake_exits_with_3() -> None:
    run = run_worker(["--goal", "system"], close_stdin_after_welcome=True)
    assert_clean_failure(run)
    assert "closed" in run.stderr


def test_a_malformed_welcome_exits_with_3() -> None:
    document = support.welcome()
    document["protocol"] = 2
    run = run_worker(["--goal", "system"], welcome=document)
    assert_clean_failure(run)
    assert "unsupported_protocol_version" in run.stderr


def test_the_core_closing_the_session_mid_plan_exits_with_3() -> None:
    run = run_worker(
        ["--goal", "system, read a.txt"],
        welcome=support.welcome(),
        replies=[support.completed_system_info],
    )
    assert_clean_failure(run)
    assert [frame["type"] for frame in run.frames] == ["hello", "tool_request", "tool_request"]
    assert "summary:" not in run.stderr


def test_a_fatal_error_mid_plan_stops_the_plan_and_exits_with_3() -> None:
    run = run_worker(
        ["--goal", "system, read a.txt"],
        welcome=support.welcome(),
        replies=[lambda request_id: support.error("limit_exceeded", fatal=True)],
    )
    assert_clean_failure(run)
    assert len(tool_calls(run)) == 1
    assert "limit_exceeded" in run.stderr


def test_a_response_for_the_wrong_request_exits_with_3() -> None:
    run = run_worker(
        ["--goal", "system"],
        welcome=support.welcome(),
        replies=[lambda request_id: support.completed_system_info("req-other")],
    )
    assert_clean_failure(run)
    assert "unexpected_message" in run.stderr


def test_a_core_message_that_is_not_json_exits_with_3() -> None:
    with worker_process(["--goal", "system"]) as process:
        assert process.stdin is not None
        assert process.stderr is not None
        process.stdin.write(b"this is not a frame\n")
        process.stdin.close()
        exit_code = process.wait()
        stderr = process.stderr.read().decode("utf-8")
    assert exit_code == 3
    assert "Traceback" not in stderr
    assert "malformed_frame" in stderr


def test_a_core_that_stops_reading_is_a_session_failure_not_a_crash() -> None:
    """A closed stdout must give exit code 3, not a broken-pipe traceback or status 120."""
    with worker_process(["--goal", "system"]) as process:
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdout.close()
        process.stdin.write(support.to_line(support.welcome()))
        process.stdin.close()
        exit_code = process.wait()
        stderr = process.stderr.read().decode("utf-8")
    assert exit_code == 3
    assert "Traceback" not in stderr
    assert "Exception ignored" not in stderr
    assert "session closed" in stderr


def test_control_characters_from_the_core_cannot_forge_log_lines() -> None:
    reply = support.error("internal", fatal=True)
    reply["error"]["message"] = "bad\nINFO jarvis_worker: summary: forged\x1b[31m"
    run = run_worker(["--goal", "system"], welcome=reply)
    assert run.exit_code == 3
    assert "\x1b" not in run.stderr
    assert not any(
        line.startswith("INFO jarvis_worker: summary") for line in run.stderr.splitlines()
    )


# --- usage errors: exit code 2 -------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [[], ["--goal"], ["--unknown"], ["--go", "system"], ["system"], ["--goal", "a", "extra"]],
)
def test_usage_errors_exit_with_2_and_leave_stdout_empty(args: list[str]) -> None:
    run = run_worker(args)
    assert run.exit_code == 2
    assert run.stdout == b""
    assert "usage:" in run.stderr


def test_help_goes_to_stderr_not_stdout() -> None:
    run = run_worker(["--help"])
    assert run.exit_code == 0
    assert run.stdout == b""
    assert "--goal" in run.stderr


def test_a_goal_that_is_not_valid_unicode_is_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["--goal", "read \udcff"])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "valid Unicode" in captured.err


# --- run_session in-process ----------------------------------------------------------------------


def session(*replies: bytes) -> tuple[CoreClient, io.BytesIO]:
    ids = iter(f"req-{n:04d}" for n in range(1, 10))
    writer = io.BytesIO()
    client = CoreClient(io.BytesIO(b"".join(replies)), writer, request_ids=lambda: next(ids))
    return client, writer


def test_run_session_returns_zero_when_every_call_got_a_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client, _ = session(
        support.to_line(support.welcome()),
        support.to_line(support.completed_system_info("req-0001")),
        support.to_line(support.denied("req-0002")),
    )
    with caplog.at_level(logging.INFO, logger="jarvis_worker"):
        code = cli.run_session(client, StubPlanner(), "system and read a.txt")
    assert code == 0
    messages = [record.getMessage() for record in caplog.records]
    assert f"task {support.TASK_ID} system.info: completed" in messages
    assert messages[-1].startswith("summary: 2 call(s): completed=1 denied=1")


def test_run_session_uses_the_planner_it_is_given() -> None:
    class Fixed:
        def plan(self, goal: str) -> list[PlannedCall]:
            return [PlannedCall("system.info", {})]

    client, writer = session(
        support.to_line(support.welcome()),
        support.to_line(support.completed_system_info("req-0001")),
    )
    assert cli.run_session(client, Fixed(), "ignored") == 0
    assert b'"tool":"system.info"' in writer.getvalue()


def test_run_session_returns_three_on_a_session_error(caplog: pytest.LogCaptureFixture) -> None:
    client, _ = session(
        support.to_line(support.welcome()),
        support.to_line(support.error("duplicate_request", request_id="req-0001")),
    )
    with caplog.at_level(logging.INFO, logger="jarvis_worker"):
        assert cli.run_session(client, StubPlanner(), "system") == 3
    assert any("non-fatal" in record.getMessage() for record in caplog.records)


def test_run_session_returns_three_on_end_of_input() -> None:
    client, _ = session()
    assert cli.run_session(client, StubPlanner(), "system") == 3
