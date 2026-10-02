"""Command-line entry point: ``python -m jarvis_worker --goal "<text>"``.

The Core spawns this process and talks to it over stdin and stdout, so stdout carries protocol
frames and nothing else. Diagnostics go to stderr.

Exit codes:

- ``0``: the handshake succeeded and every planned call received a ``tool_response``, whatever
  its outcome (completed, denied, rejected, ...).
- ``2``: usage error.
- ``3``: session or protocol failure: handshake rejected, error reply from the Core, end of
  input or a malformed frame. The first failure ends the run.
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
    ConfirmationRequired,
    Denied,
    Failed,
    ProtocolError,
    Rejected,
    ToolOutcome,
)

EXIT_OK = 0
EXIT_SESSION_FAILED = 3

LOG_FORMAT = "%(levelname)s jarvis_worker: %(message)s"
STATUSES = ("completed", "denied", "confirmation_required", "rejected", "failed")

logger = logging.getLogger("jarvis_worker")


class _Parser(argparse.ArgumentParser):
    """Argument parser that never writes to stdout, which is reserved for protocol frames."""

    def print_help(self, file: Any = None) -> None:
        super().print_help(sys.stderr if file is None else file)


def _goal(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise argparse.ArgumentTypeError("must be valid Unicode text") from None
    return text


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m jarvis_worker",
        description="Plan a goal and ask the Core to run the resulting tool calls.",
        allow_abbrev=False,
    )
    parser.add_argument("--goal", required=True, type=_goal, help="what the worker should do")
    return parser


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
        case ConfirmationRequired(reason=reason):
            return "confirmation_required", f"confirmation_required: {_printable(reason)}"
        case Rejected(error=error):
            return "rejected", f"rejected: {error.code}"
        case Failed(error=error):
            return "failed", f"failed: {error.code}"


def run_session(client: CoreClient, planner: Planner, goal: str) -> int:
    """Handshake, plan ``goal``, run every planned call and log the outcomes.

    Returns the process exit code.
    """
    try:
        welcome = client.handshake()
        logger.info("session %s opened (core %s)", welcome.session_id, welcome.core_version)
        calls = planner.plan(goal)
        logger.info("planned %d call(s)", len(calls))
        tally: Counter[str] = Counter()
        for call in calls:
            response = client.call(call.tool, call.args)
            status, text = _describe(response.outcome)
            tally[status] += 1
            logger.info("task %s %s: %s", response.task_id, call.tool, text)
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
    counts = " ".join(f"{status}={tally[status]}" for status in STATUSES)
    logger.info("summary: %d call(s): %s", len(calls), counts)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the command line and run one session over stdin and stdout."""
    goal: str = _build_parser().parse_args(argv).goal
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=LOG_FORMAT)
    logger.info("jarvis-worker %s starting", __version__)
    # Frames go through an unbuffered binary writer on the stdout descriptor. A buffered one
    # would keep the bytes of a frame the Core never read, and flushing them again at interpreter
    # shutdown would fail and replace the exit code. Nothing else ever writes to sys.stdout.
    stdout = io.FileIO(sys.stdout.fileno(), mode="wb", closefd=False)
    client = CoreClient(sys.stdin.buffer, stdout)
    return run_session(client, StubPlanner(), goal)


if __name__ == "__main__":
    sys.exit(main())
