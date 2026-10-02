"""Planning: turn a goal into a list of typed tool calls.

``StubPlanner`` is a deterministic stand-in for a future model-backed planner. It looks for a few
keywords and produces the same plan for the same goal, which keeps the whole system testable
without a model. Whatever a planner proposes is only a proposal: the Core validates every
request, derives the capabilities it needs and applies policy before anything runs.
"""

import re
from dataclasses import dataclass
from typing import Protocol

from jarvis_worker.protocol import TOOL_READ_FIXTURE, TOOL_SYSTEM_INFO, JsonValue


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
# ``read system.txt``) is not mistaken for a topic.
_SCAN = re.compile(
    r"\bread\s+(?P<target>\S+)|\b(?P<topic>system|runtime|machine|environment)\b",
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
    - A goal that matches nothing yields an empty plan.
    """

    def plan(self, goal: str) -> list[PlannedCall]:
        calls: list[PlannedCall] = []
        wants_system_info = False
        for match in _SCAN.finditer(goal):
            target = match.group("target")
            if target is not None:
                path = target.rstrip(_TRAILING_PUNCTUATION)
                if path:
                    calls.append(PlannedCall(TOOL_READ_FIXTURE, {"path": path}))
            elif not wants_system_info:
                wants_system_info = True
                calls.append(PlannedCall(TOOL_SYSTEM_INFO, {}))
        return calls
