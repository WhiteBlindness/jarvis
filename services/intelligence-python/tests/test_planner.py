"""StubPlanner: keyword rules, order of appearance, pass-through of dangerous targets."""

import pytest

from jarvis_worker.planner import PlannedCall, Planner, StubPlanner

SYSTEM_INFO = PlannedCall("system.info", {})


def read(path: str) -> PlannedCall:
    return PlannedCall("filesystem.read_fixture", {"path": path})


def plan(goal: str) -> list[PlannedCall]:
    return StubPlanner().plan(goal)


def test_the_stub_planner_satisfies_the_planner_protocol() -> None:
    planner: Planner = StubPlanner()
    assert planner.plan("") == []


def test_the_documented_example() -> None:
    assert plan("describe the runtime, then read welcome.txt") == [
        SYSTEM_INFO,
        read("welcome.txt"),
    ]


@pytest.mark.parametrize("word", ["system", "runtime", "machine", "environment"])
def test_each_topic_word_asks_for_system_info(word: str) -> None:
    assert plan(f"tell me about the {word}") == [SYSTEM_INFO]


@pytest.mark.parametrize("goal", ["SYSTEM", "Runtime", "what MaChInE is this", "ENVIRONMENT?"])
def test_topic_words_are_case_insensitive(goal: str) -> None:
    assert plan(goal) == [SYSTEM_INFO]


def test_system_info_is_requested_at_most_once() -> None:
    assert plan("system runtime machine environment, the system again") == [SYSTEM_INFO]


@pytest.mark.parametrize("goal", ["filesystem", "systems", "runtimes", "subsystem", "machinery"])
def test_topic_words_must_be_whole_words(goal: str) -> None:
    assert plan(goal) == []


def test_each_read_asks_for_a_fixture() -> None:
    assert plan("read a.txt and read notes/b.md") == [read("a.txt"), read("notes/b.md")]


@pytest.mark.parametrize("goal", ["READ a.txt", "Read a.txt", "please rEaD a.txt"])
def test_read_is_case_insensitive_but_the_target_is_not(goal: str) -> None:
    assert plan(goal) == [read("a.txt")]
    assert plan("read A.TXT") == [read("A.TXT")]


@pytest.mark.parametrize(
    ("goal", "path"),
    [
        ("read welcome.txt.", "welcome.txt"),
        ("read welcome.txt, then", "welcome.txt"),
        ("read welcome.txt; stop", "welcome.txt"),
        ("read welcome.txt: ok", "welcome.txt"),
        ("read welcome.txt!", "welcome.txt"),
        ("read welcome.txt?", "welcome.txt"),
        ("read welcome.txt?!...", "welcome.txt"),
        ("read   welcome.txt", "welcome.txt"),
        ("read\twelcome.txt", "welcome.txt"),
        ("read\nwelcome.txt", "welcome.txt"),
    ],
)
def test_the_target_is_the_next_word_without_trailing_punctuation(goal: str, path: str) -> None:
    assert plan(goal) == [read(path)]


@pytest.mark.parametrize(
    "target",
    [
        "../secret",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "a\\..\\b",
        "~/.ssh/id_rsa",
        ".env",
        "a//b",
        "$(id)",
        "file;rm",
        '"quoted.txt"',
        "caf\u00e9.txt",
    ],
)
def test_dangerous_targets_are_passed_through_unchanged(target: str) -> None:
    """Judging a path is the Core's job; its rejection is part of the demo."""
    assert plan(f"read {target}") == [read(target)]


def test_trailing_punctuation_is_the_only_thing_stripped() -> None:
    assert plan("read ../secret.") == [read("../secret")]
    assert plan("read ...secret...") == [read("...secret")]


def test_calls_follow_the_order_of_appearance() -> None:
    assert plan("read a.txt then the machine, then read b.txt") == [
        read("a.txt"),
        SYSTEM_INFO,
        read("b.txt"),
    ]
    assert plan("read a.txt, system") == [read("a.txt"), SYSTEM_INFO]
    assert plan("system, read a.txt") == [SYSTEM_INFO, read("a.txt")]


def test_a_topic_word_inside_a_read_target_is_part_of_the_target() -> None:
    assert plan("read system.txt") == [read("system.txt")]
    assert plan("read runtime") == [read("runtime")]


def test_read_must_be_a_whole_word_followed_by_a_target() -> None:
    assert plan("already thread bread readme") == []
    assert plan("reading a.txt") == []
    assert plan("read") == []
    assert plan("read ") == []


def test_a_target_that_is_only_punctuation_is_skipped() -> None:
    assert plan("read ... then read !?") == []
    assert plan("read ..., then read a.txt") == [read("a.txt")]


@pytest.mark.parametrize("goal", ["", " ", "hello there", "what time is it"])
def test_a_goal_without_matches_has_an_empty_plan(goal: str) -> None:
    assert plan(goal) == []


@pytest.mark.parametrize(
    "goal",
    [
        "describe the runtime, then read welcome.txt",
        "read a.txt read b.txt machine",
        "nothing to see",
    ],
)
def test_planning_is_deterministic(goal: str) -> None:
    first = plan(goal)
    assert plan(goal) == first
    assert StubPlanner().plan(goal) == first


def test_plans_do_not_share_state_between_calls_or_planners() -> None:
    planner = StubPlanner()
    assert planner.plan("system") == [SYSTEM_INFO]
    assert planner.plan("system") == [SYSTEM_INFO]
    first = planner.plan("system")
    first[0].args["mutated"] = True
    assert planner.plan("system") == [SYSTEM_INFO]


def write(path: str, content: str) -> PlannedCall:
    return PlannedCall("workspace.write_file", {"path": path, "content": content})


def test_write_takes_the_rest_of_the_goal_as_content() -> None:
    assert plan("write notes/todo.txt: buy milk, then read a.txt") == [
        write("notes/todo.txt", "buy milk, then read a.txt")
    ]


def test_write_comes_after_earlier_calls() -> None:
    assert plan("check the system, read a.txt, write out.txt: done") == [
        SYSTEM_INFO,
        read("a.txt"),
        write("out.txt", "done"),
    ]


@pytest.mark.parametrize(
    ("goal", "content"),
    [
        ("write a.txt:x", "x"),
        ("write a.txt: x", "x"),
        ("write a.txt:  x", " x"),
        ("write a.txt:", ""),
    ],
)
def test_one_optional_space_after_the_colon_is_dropped(goal: str, content: str) -> None:
    assert plan(goal) == [write("a.txt", content)]


def test_topic_words_inside_the_content_are_not_calls() -> None:
    assert plan("WRITE status.txt: the system is fine") == [
        write("status.txt", "the system is fine")
    ]


@pytest.mark.parametrize("goal", ["write a letter", "write", "rewrite a.txt: x", "write : x"])
def test_write_needs_a_path_and_a_colon(goal: str) -> None:
    assert [call for call in plan(goal) if call.tool == "workspace.write_file"] == []


def test_a_dangerous_write_path_is_passed_through_for_the_core_to_judge() -> None:
    assert plan("write ../../etc/passwd: x") == [write("../../etc/passwd", "x")]
