"""Command-line entry point: ``python -m jarvis_worker``.

The Core spawns this process and talks to it over stdin and stdout, so stdout carries protocol
frames and nothing else. Diagnostics go to stderr. After the handshake the worker waits for jobs:
for each one it plans the goal, asks the Core to run every planned call, and reports a one-line
summary. It exits when the Core closes its input between jobs.

Exit codes:

- ``0``: the Core closed the session while the worker was idle.
- ``2``: usage error.
- ``3``: session or protocol failure: handshake rejected, error reply from the Core, end of
  input in the middle of a job or a malformed frame. The first failure ends the run.
"""

import argparse
import io
import logging
import sys
from collections import Counter
from collections.abc import Sequence
from typing import Any

from jarvis_worker import __version__
from jarvis_worker.client import CoreClient, SessionClosed, SessionError
from jarvis_worker.planner import Planner, StubPlanner
from jarvis_worker.protocol import (
    Completed,
    Declined,
    Denied,
    Expired,
    Failed,
    Job,
    JobOutcome,
    ProtocolError,
    Rejected,
    ToolOutcome,
)

EXIT_OK = 0
EXIT_SESSION_FAILED = 3

LOG_FORMAT = "%(levelname)s jarvis_worker: %(message)s"
STATUSES = ("completed", "denied", "declined", "expired", "rejected", "failed")

logger = logging.getLogger("jarvis_worker")


class _Parser(argparse.ArgumentParser):
    """Argument parser that never writes to stdout, which is reserved for protocol frames."""

    def print_help(self, file: Any = None) -> None:
        super().print_help(sys.stderr if file is None else file)


def _build_parser() -> argparse.ArgumentParser:
    return _Parser(
        prog="python -m jarvis_worker",
        description=(
            "Speak the worker protocol over stdin and stdout: wait for jobs from the Core, plan "
            "each goal and ask the Core to run the resulting tool calls."
        ),
        allow_abbrev=False,
    )


def _printable(text: str) -> str:
    """Escape control characters so that Core-supplied text stays on one log line."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def _describe(outcome: ToolOutcome) -> tuple[str, str]:
    """Return the outcome's status name and the log text for it."""
    match outcome:
        case Completed():
            return "completed", "completed"
        case Denied(reason=reason):
            return "denied", f"denied: {_printable(reason)}"
        case Declined(reason=reason):
            return "declined", f"declined by a person: {_printable(reason)}"
        case Expired():
            return "expired", "approval expired"
        case Rejected(error=error):
            return "rejected", f"rejected: {error.code}"
        case Failed(error=error):
            return "failed", f"failed: {error.code}"


def run_job(client: CoreClient, planner: Planner, job: Job) -> None:
    """Plan one job, run every planned call and report the result to the Core.

    The job is ``completed`` if at least one call was planned and every call completed, and
    ``failed`` otherwise. The summary counts the outcomes.
    """
    logger.info("job %s started", job.job_id)
    calls = planner.plan(job.goal)
    logger.info("planned %d call(s)", len(calls))
    tally: Counter[str] = Counter()
    for call in calls:
        response = client.call(call.tool, call.args)
        status, text = _describe(response.outcome)
        tally[status] += 1
        logger.info("task %s %s: %s", response.task_id, call.tool, text)
    counts = " ".join(f"{status}={tally[status]}" for status in STATUSES)
    summary = f"{len(calls)} call(s): {counts}"
    if not calls:
        summary = "nothing in the goal matches a known action"
    ok = bool(calls) and tally["completed"] == len(calls)
    outcome = JobOutcome.COMPLETED if ok else JobOutcome.FAILED
    logger.info("job %s %s: %s", job.job_id, outcome, summary)
    client.finish(outcome, summary)


def run_session(client: CoreClient, planner: Planner) -> int:
    """Handshake, then work on jobs until the Core closes the session.

    Returns the process exit code.
    """
    try:
        welcome = client.handshake()
        logger.info("session %s opened (core %s)", welcome.session_id, welcome.core_version)
        jobs = 0
        while (job := client.next_job()) is not None:
            run_job(client, planner, job)
            jobs += 1
    except SessionError as error:
        scope = "fatal" if error.fatal else "non-fatal"
        logger.error("core replied with a %s error: %s", scope, _printable(str(error)))
        return EXIT_SESSION_FAILED
    except ProtocolError as error:
        logger.error("protocol error: %s", _printable(str(error)))
        return EXIT_SESSION_FAILED
    except SessionClosed as error:
        logger.error("session closed: %s", _printable(str(error)))
        return EXIT_SESSION_FAILED
    logger.info("session closed by the core after %d job(s)", jobs)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the command line and run one session over stdin and stdout."""
    _build_parser().parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=LOG_FORMAT)
    logger.info("jarvis-worker %s starting", __version__)
    # Frames go through an unbuffered binary writer on the stdout descriptor. A buffered one
    # would keep the bytes of a frame the Core never read, and flushing them again at interpreter
    # shutdown would fail and replace the exit code. Nothing else ever writes to sys.stdout.
    stdout = io.FileIO(sys.stdout.fileno(), mode="wb", closefd=False)
    client = CoreClient(sys.stdin.buffer, stdout)
    return run_session(client, StubPlanner())


if __name__ == "__main__":
    sys.exit(main())
