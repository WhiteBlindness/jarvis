"""The command line: ``python -m jarvis_worker``.

Most tests run the worker as a real subprocess, the way the Core does: working directory
``src``, a cleared environment, and a fake Core on the other end of its stdin and stdout. The
fake Core is this test process: it sends ``welcome``, hands out jobs, answers each request using
the request ID the worker chose, and reads each ``job_result``.
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
from dataclasses import dataclass, field
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
class FakeJob:
    goal: str
    replies: Sequence[Reply] = ()
    job_id: str = support.JOB_ID


@dataclass
class Run:
    exit_code: int
    frames: list[dict[str, Any]]  # every frame the worker wrote to stdout, in order
    stdout: bytes
    stderr: str
    results: list[dict[str, Any]] = field(default_factory=list)


def core_environment() -> dict[str, str]:
    """What the Core leaves a worker: PATH, and SYSTEMROOT where it exists."""
    kept = ("PATH", "SYSTEMROOT")
    return {name: os.environ[name] for name in kept if name in os.environ}


@contextmanager
def worker_process(args: Sequence[str] = ()) -> Iterator[subprocess.Popen[bytes]]:
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
    args: Sequence[str] = (),
    *,
    welcome: dict[str, Any] | None = None,
    jobs: Sequence[FakeJob] = (),
    close_stdin_after_welcome: bool = False,
) -> Run:
    """Play the Core: send ``welcome``, run each job to its ``job_result``, then close.

    If a job's replies run out before the worker reports the result, the fake Core closes the
    session there, as a Core that stops would.
    """
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

        def send(document: dict[str, Any]) -> None:
            process.stdin.write(support.to_line(document))  # type: ignore[union-attr]
            process.stdin.flush()  # type: ignore[union-attr]

        if welcome is not None:
            send(welcome)
        if not close_stdin_after_welcome and welcome is not None and welcome["type"] == "welcome":
            assert read_line(), "the worker did not send hello"
            for job in jobs:
                send(support.job(job.goal, job.job_id))
                replies = list(job.replies)
                frame = json.loads(read_line() or b"null")
                while frame is not None and frame["type"] == "tool_request" and replies:
                    send(replies.pop(0)(frame["request_id"]))
                    frame = json.loads(read_line() or b"null")
                if frame is None or frame["type"] != "job_result":
                    break
        process.stdin.close()
        while read_line():
            pass
        exit_code = process.wait()
        stderr = process.stderr.read().decode("utf-8")
    frames = [support.check_worker_frame(line) for line in lines]
    results = [frame for frame in frames if frame["type"] == "job_result"]
    return Run(exit_code, frames, b"".join(lines), stderr, results)


def tool_calls(run: Run) -> list[tuple[str, dict[str, Any]]]:
    return [
        (frame["tool"], frame["args"]) for frame in run.frames if frame["type"] == "tool_request"
    ]


# --- jobs over real pipes ----------------------------------------------------------------------


def test_a_job_is_planned_and_every_call_is_sent_in_order() -> None:
    run = run_worker(
        welcome=support.welcome(),
        jobs=[
            FakeJob(
                "describe the runtime, then read welcome.txt",
                [support.completed_system_info, support.completed_fixture],
            )
        ],
    )
    assert run.exit_code == 0
    assert [frame["type"] for frame in run.frames] == [
        "hello",
        "tool_request",
        "tool_request",
        "job_result",
    ]
    assert run.frames[0]["worker"] == "jarvis-worker"
    assert run.frames[0]["worker_version"] == "0.2.0"
    assert tool_calls(run) == [
        ("system.info", {}),
        ("filesystem.read_fixture", {"path": "welcome.txt"}),
    ]
    assert {frame["job_id"] for frame in run.frames[1:]} == {support.JOB_ID}
    ids = [frame["request_id"] for frame in run.frames[1:3]]
    assert len(set(ids)) == 2
    assert run.results == [
        {
            "protocol": 2,
            "type": "job_result",
            "job_id": support.JOB_ID,
            "outcome": "completed",
            "summary": "2 call(s): completed=2 denied=0 declined=0 expired=0 rejected=0 failed=0",
        }
    ]


def test_jobs_are_handled_one_after_another_in_one_session() -> None:
    second = "01928f5e-7c3c-7b30-9c4d-5e6f7a8b9cff"
    run = run_worker(
        welcome=support.welcome(),
        jobs=[
            FakeJob("system", [support.completed_system_info]),
            FakeJob("write notes.txt: hello", [support.completed_write], job_id=second),
        ],
    )
    assert run.exit_code == 0
    assert [frame["type"] for frame in run.frames] == [
        "hello",
        "tool_request",
        "job_result",
        "tool_request",
        "job_result",
    ]
    assert [result["job_id"] for result in run.results] == [support.JOB_ID, second]
    assert run.frames[3]["job_id"] == second
    assert tool_calls(run)[1] == ("workspace.write_file", {"path": "notes.txt", "content": "hello"})
    assert "session closed by the core after 2 job(s)" in run.stderr


def test_the_core_closing_the_session_while_idle_is_a_clean_exit() -> None:
    run = run_worker(welcome=support.welcome())
    assert run.exit_code == 0
    assert [frame["type"] for frame in run.frames] == ["hello"]
    assert "after 0 job(s)" in run.stderr


def test_stdout_carries_only_protocol_frames_and_logs_go_to_stderr() -> None:
    run = run_worker(
        welcome=support.welcome(), jobs=[FakeJob("system", [support.completed_system_info])]
    )
    assert run.exit_code == 0
    assert run.stdout.endswith(b"\n")
    assert b"\r" not in run.stdout
    assert all(json.loads(line) for line in run.stdout.splitlines())
    assert run.stderr
    for line in run.stderr.splitlines():
        assert line.split(" ", 2)[1] == "jarvis_worker:", line


def test_each_outcome_is_logged_on_one_line_and_any_non_completion_fails_the_job() -> None:
    run = run_worker(
        welcome=support.welcome(),
        jobs=[
            FakeJob(
                "system, read a.txt, read b.txt, read c.txt, read d.txt, write e.txt: x",
                [
                    support.completed_system_info,
                    support.denied,
                    lambda request_id: support.rejected(request_id, "invalid_arguments"),
                    lambda request_id: support.tool_response(
                        request_id,
                        {"status": "failed", "error": {"code": "timeout", "message": "too slow"}},
                    ),
                    support.expired,
                    lambda request_id: support.declined(request_id, "not today"),
                ],
            )
        ],
    )
    assert run.exit_code == 0
    task = support.TASK_ID
    expected = [
        f"task {task} system.info: completed",
        f"task {task} filesystem.read_fixture: denied: policy denies capability "
        "filesystem.read.fixture",
        f"task {task} filesystem.read_fixture: rejected: invalid_arguments",
        f"task {task} filesystem.read_fixture: failed: timeout",
        f"task {task} filesystem.read_fixture: approval expired",
        f"task {task} workspace.write_file: declined by a person: not today",
    ]
    for text in expected:
        assert f"INFO jarvis_worker: {text}" in run.stderr.splitlines()
    assert run.results[0]["outcome"] == "failed"
    assert run.results[0]["summary"] == (
        "6 call(s): completed=1 denied=1 declined=1 expired=1 rejected=1 failed=1"
    )


def test_a_goal_without_matches_fails_the_job_without_any_call() -> None:
    run = run_worker(welcome=support.welcome(), jobs=[FakeJob("say hello")])
    assert run.exit_code == 0
    assert [frame["type"] for frame in run.frames] == ["hello", "job_result"]
    assert run.results[0]["outcome"] == "failed"
    assert run.results[0]["summary"] == "nothing in the goal matches a known action"


def test_a_dangerous_path_is_sent_unchanged_and_the_cores_rejection_is_not_a_crash() -> None:
    run = run_worker(
        welcome=support.welcome(), jobs=[FakeJob("read ../secret", [support.rejected])]
    )
    assert run.exit_code == 0
    assert tool_calls(run) == [("filesystem.read_fixture", {"path": "../secret"})]
    assert "rejected: invalid_arguments" in run.stderr
    assert run.results[0]["outcome"] == "failed"


def test_non_ascii_text_in_a_goal_reaches_the_core_as_utf8() -> None:
    run = run_worker(welcome=support.welcome(), jobs=[FakeJob("read café.txt", [support.rejected])])
    assert run.exit_code == 0
    assert tool_calls(run) == [("filesystem.read_fixture", {"path": "café.txt"})]
    assert "café.txt".encode() in run.stdout


# --- failures: exit code 3 ----------------------------------------------------------------------


def assert_clean_failure(run: Run) -> None:
    assert run.exit_code == 3
    assert "Traceback" not in run.stderr
    assert "ERROR jarvis_worker:" in run.stderr


def test_a_fatal_error_during_the_handshake_exits_with_3() -> None:
    run = run_worker(welcome=support.error("unsupported_protocol_version", fatal=True))
    assert_clean_failure(run)
    assert [frame["type"] for frame in run.frames] == ["hello"]
    assert "unsupported_protocol_version" in run.stderr
    assert "fatal" in run.stderr


def test_end_of_input_during_the_handshake_exits_with_3() -> None:
    run = run_worker(close_stdin_after_welcome=True)
    assert_clean_failure(run)
    assert "closed" in run.stderr


def test_a_welcome_from_another_protocol_version_exits_with_3() -> None:
    document = support.welcome()
    document["protocol"] = 1
    run = run_worker(welcome=document)
    assert_clean_failure(run)
    assert "unsupported_protocol_version" in run.stderr


def test_the_core_closing_the_session_mid_job_exits_with_3() -> None:
    run = run_worker(
        welcome=support.welcome(),
        jobs=[FakeJob("system, read a.txt", [support.completed_system_info])],
    )
    assert_clean_failure(run)
    assert [frame["type"] for frame in run.frames] == ["hello", "tool_request", "tool_request"]
    assert run.results == []


def test_a_fatal_error_mid_job_stops_the_plan_and_exits_with_3() -> None:
    run = run_worker(
        welcome=support.welcome(),
        jobs=[
            FakeJob(
                "system, read a.txt",
                [lambda request_id: support.error("limit_exceeded", fatal=True)],
            )
        ],
    )
    assert_clean_failure(run)
    assert len(tool_calls(run)) == 1
    assert "limit_exceeded" in run.stderr


def test_a_response_for_the_wrong_request_exits_with_3() -> None:
    run = run_worker(
        welcome=support.welcome(),
        jobs=[FakeJob("system", [lambda request_id: support.completed_system_info("req-other")])],
    )
    assert_clean_failure(run)
    assert "unexpected_message" in run.stderr


def test_a_core_message_that_is_not_json_exits_with_3() -> None:
    with worker_process() as process:
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
    with worker_process() as process:
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
    reply["error"]["message"] = "bad\nINFO jarvis_worker: job forged\x1b[31m"
    run = run_worker(welcome=reply)
    assert run.exit_code == 3
    assert "\x1b" not in run.stderr
    assert not any(line.startswith("INFO jarvis_worker: job") for line in run.stderr.splitlines())


# --- usage errors: exit code 2 -------------------------------------------------------------------


@pytest.mark.parametrize("args", [["--goal", "system"], ["--unknown"], ["system"], ["--goal"]])
def test_usage_errors_exit_with_2_and_leave_stdout_empty(args: list[str]) -> None:
    run = run_worker(args)
    assert run.exit_code == 2
    assert run.stdout == b""
    assert "usage:" in run.stderr


def test_help_goes_to_stderr_not_stdout() -> None:
    run = run_worker(["--help"])
    assert run.exit_code == 0
    assert run.stdout == b""
    assert "wait for jobs" in run.stderr


# --- run_session in-process ----------------------------------------------------------------------


def session(*replies: bytes) -> tuple[CoreClient, io.BytesIO]:
    ids = iter(f"req-{n:04d}" for n in range(1, 10))
    writer = io.BytesIO()
    client = CoreClient(io.BytesIO(b"".join(replies)), writer, request_ids=lambda: next(ids))
    return client, writer


def test_run_session_returns_zero_when_the_core_ends_an_idle_session(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client, writer = session(
        support.to_line(support.welcome()),
        support.to_line(support.job("system and read a.txt")),
        support.to_line(support.completed_system_info("req-0001")),
        support.to_line(support.denied("req-0002")),
    )
    with caplog.at_level(logging.INFO, logger="jarvis_worker"):
        code = cli.run_session(client, StubPlanner())
    assert code == 0
    messages = [record.getMessage() for record in caplog.records]
    assert f"task {support.TASK_ID} system.info: completed" in messages
    assert any(
        message.startswith(f"job {support.JOB_ID} failed: 2 call(s)") for message in messages
    )
    result = support.check_worker_frame(writer.getvalue().splitlines(keepends=True)[-1])
    assert result["outcome"] == "failed"


def test_run_session_uses_the_planner_it_is_given() -> None:
    class Fixed:
        def plan(self, goal: str) -> list[PlannedCall]:
            return [PlannedCall("system.info", {})]

    client, writer = session(
        support.to_line(support.welcome()),
        support.to_line(support.job("ignored")),
        support.to_line(support.completed_system_info("req-0001")),
    )
    assert cli.run_session(client, Fixed()) == 0
    assert b'"tool":"system.info"' in writer.getvalue()
    assert b'"outcome":"completed"' in writer.getvalue()


def test_run_session_returns_three_on_a_session_error(caplog: pytest.LogCaptureFixture) -> None:
    client, _ = session(
        support.to_line(support.welcome()),
        support.to_line(support.job("system")),
        support.to_line(support.error("duplicate_request", request_id="req-0001")),
    )
    with caplog.at_level(logging.INFO, logger="jarvis_worker"):
        assert cli.run_session(client, StubPlanner()) == 3
    assert any("non-fatal" in record.getMessage() for record in caplog.records)


def test_run_session_returns_three_on_end_of_input_before_the_welcome() -> None:
    client, _ = session()
    assert cli.run_session(client, StubPlanner()) == 3
