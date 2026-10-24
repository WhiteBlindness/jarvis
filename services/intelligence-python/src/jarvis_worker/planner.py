"""Planning: turn a goal into a list of typed tool calls.

``StubPlanner`` is a deterministic stand-in for a future model-backed planner. It looks for a few
keywords and produces the same plan for the same goal, which keeps the whole system testable
without a model. Whatever a planner proposes is only a proposal: the Core validates every
request, derives the capabilities it needs and applies policy before anything runs.
"""

import re
from dataclasses import dataclass
from typing import Protocol

from jarvis_worker.protocol import (
    TOOL_DESKTOP_WRITE_CLIPBOARD_TEXT,
    TOOL_READ_FIXTURE,
    TOOL_SESSION_AGENT_HEALTHCHECK,
    TOOL_SYSTEM_INFO,
    TOOL_WRITE_FILE,
    JsonValue,
)


@dataclass(frozen=True, slots=True)
class PlannedCall:
    """One tool call a planner proposes."""

    tool: str
    args: dict[str, JsonValue]


class Planner(Protocol):
    """Turns a natural-language goal into the tool calls that would serve it."""

    def plan(self, goal: str) -> list[PlannedCall]:
        """Return the calls for ``goal`` in the order they should run; empty if none apply."""
        ...


# One left-to-right scan. ``read <target>`` consumes its target, so a word inside it (as in
# ``read system.txt``) is not mistaken for a topic, and ``write <path>: <text>`` consumes the
# rest of the goal.
_SCAN = re.compile(
    r"\bwrite\s+(?P<write_path>[^\s:]+):\s?(?P<content>.*)"
    r"|\bread\s+(?P<target>\S+)"
    r"|\bhealthcheck\s+(?P<check_label>\S+)"
    r"|\bcopy\s+payload:(?P<payload_id>(?-i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))"
    r":(?P<payload_sha256>(?-i:[0-9a-f]{64}))\b"
    r"|\b(?P<topic>system|runtime|machine|environment)\b",
    re.IGNORECASE,
)
_TRAILING_PUNCTUATION = ",.;:!?"


class StubPlanner:
    """Keyword rules, applied in order of appearance in the goal (case-insensitive).

    - The first of the words ``system``, ``runtime``, ``machine`` or ``environment`` yields one
      ``system.info`` call; later occurrences add nothing.
    - Each ``read <target>`` yields a ``filesystem.read_fixture`` call. The target is the next
      whitespace-delimited word without trailing ``,.;:!?``. It is passed through unchanged even
      if it looks dangerous: judging paths is the Core's job. A target that is empty after
      stripping is skipped.
    - ``write <path>: <text>`` yields one ``workspace.write_file`` call that writes ``<text>``
      (everything after the colon and one optional space, to the end of the goal) to
      ``<path>``. Because it takes the rest of the goal, a write is always the last call. Policy
      decides whether a person must approve it; the planner does not know or care.
    - ``healthcheck <label>`` yields one ``session_agent.healthcheck`` call asking the Session
      Agent to echo ``<label>`` (the next word, without trailing ``,.;:!?``). It touches no
      desktop data; it exercises the approval and Session Agent path end to end.
    - ``copy payload:<id>:<sha256>`` yields one ``desktop.write_clipboard_text`` call that names
      the payload by its identifier (a lowercase hyphenated UUID) and its SHA-256 (64 lowercase
      hexadecimal characters). The clipboard text itself never reaches the worker: the Core
      keeps it under that identifier while the job exists, shows it to a person, and checks it
      against the SHA-256 before anything is copied. Any other form of ``copy``, including
      ``copy "<text>"``, yields no call. The planner never reads the clipboard.
    - A goal that matches nothing yields an empty plan.
    """

    def plan(self, goal: str) -> list[PlannedCall]:
        calls: list[PlannedCall] = []
        wants_system_info = False
        for match in _SCAN.finditer(goal):
            target = match.group("target")
            write_path = match.group("write_path")
            if write_path is not None:
                calls.append(
                    PlannedCall(TOOL_WRITE_FILE, {"path": write_path, "content": match["content"]})
                )
            elif (check_label := match.group("check_label")) is not None:
                label = check_label.rstrip(_TRAILING_PUNCTUATION)
                if label:
                    calls.append(PlannedCall(TOOL_SESSION_AGENT_HEALTHCHECK, {"label": label}))
            elif (payload_id := match.group("payload_id")) is not None:
                calls.append(
                    PlannedCall(
                        TOOL_DESKTOP_WRITE_CLIPBOARD_TEXT,
                        {"payload_id": payload_id, "sha256": match["payload_sha256"]},
                    )
                )
            elif target is not None:
                path = target.rstrip(_TRAILING_PUNCTUATION)
                if path:
                    calls.append(PlannedCall(TOOL_READ_FIXTURE, {"path": path}))
            elif not wants_system_info:
                wants_system_info = True
                calls.append(PlannedCall(TOOL_SYSTEM_INFO, {}))
        return calls
