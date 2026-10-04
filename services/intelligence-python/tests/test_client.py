"""CoreClient against a fake Core on in-memory streams.

The fake Core is a pre-scripted byte string the client reads from and a buffer the client writes
to. Request IDs are injected so that the scripted replies can name them.
"""

import io
import re
from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest

import support
from jarvis_worker.client import (
    ClientStateError,
    CoreClient,
    SessionClosed,
    SessionError,
)
from jarvis_worker.protocol import (
    Completed,
    Declined,
    Denied,
    ErrorCode,
    Expired,
    FixtureContent,
    Job,
    JobOutcome,
    ProtocolError,
    Rejected,
    SystemInfo,
    WriteOutcome,
    validate_request_id,
)

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

HELLO = b'{"protocol":2,"type":"hello","worker":"jarvis-worker","worker_version":"0.2.0"}\n'
JOB = support.to_line(support.job("system"))


def request_ids(*values: str) -> Callable[[], str]:
    remaining = iter(values)
    return lambda: next(remaining)


def client_for(
    *replies: bytes, ids: tuple[str, ...] = ("req-0001", "req-0002", "req-0003")
) -> tuple[CoreClient, io.BytesIO]:
    """A client reading the given replies, and the buffer holding what it writes."""
    writer = io.BytesIO()
    client = CoreClient(io.BytesIO(b"".join(replies)), writer, request_ids=request_ids(*ids))
    return client, writer


def written_lines(writer: io.BytesIO) -> list[bytes]:
    return writer.getvalue().splitlines(keepends=True)


def welcomed(*replies: bytes) -> tuple[CoreClient, io.BytesIO]:
    """A client that has completed the handshake and holds a job; the hello is dropped."""
    client, writer = client_for(support.to_line(support.welcome()), JOB, *replies)
    client.handshake()
    assert client.next_job() is not None
    writer.seek(0)
    writer.truncate()
    return client, writer


# --- handshake -----------------------------------------------------------------------------------


def test_handshake_sends_hello_and_returns_welcome() -> None:
    client, writer = client_for(support.to_line(support.welcome()))
    assert client.welcome is None
    welcome = client.handshake()
    assert writer.getvalue() == HELLO
    assert welcome.session_id == support.SESSION_ID
    assert welcome.tools == ("filesystem.read_fixture", "system.info", "workspace.write_file")
    assert client.welcome is welcome


def test_handshake_announces_the_given_worker() -> None:
    client, writer = client_for(support.to_line(support.welcome()))
    client.handshake(worker="other-worker", worker_version="9.9.9")
    assert b'"worker":"other-worker","worker_version":"9.9.9"' in writer.getvalue()


def test_handshake_rejects_invalid_labels_without_writing() -> None:
    client, writer = client_for()
    with pytest.raises(ProtocolError):
        client.handshake(worker="not valid")
    assert writer.getvalue() == b""


def test_a_fatal_error_during_the_handshake_raises_session_error() -> None:
    reply = support.to_line(
        {
            "protocol": 2,
            "type": "error",
            "request_id": None,
            "error": {"code": "unsupported_protocol_version", "message": "speak 1"},
            "fatal": True,
        }
    )
    client, _ = client_for(reply)
    with pytest.raises(SessionError) as raised:
        client.handshake()
    assert raised.value.fatal is True
    assert raised.value.error.code is ErrorCode.UNSUPPORTED_PROTOCOL_VERSION
    assert raised.value.error.message == "speak 1"
    assert raised.value.request_id is None
    assert client.welcome is None


def test_a_non_fatal_error_during_the_handshake_also_raises_session_error() -> None:
    client, _ = client_for(support.to_line(support.error("malformed_frame", fatal=False)))
    with pytest.raises(SessionError) as raised:
        client.handshake()
    assert raised.value.fatal is False


def test_anything_but_welcome_or_error_during_the_handshake_is_unexpected() -> None:
    client, _ = client_for(support.to_line(support.completed_system_info("req-0001")))
    with pytest.raises(ProtocolError) as raised:
        client.handshake()
    assert raised.value.code is ErrorCode.UNEXPECTED_MESSAGE


def test_a_malformed_welcome_is_a_protocol_error() -> None:
    document = support.welcome()
    document["surprise"] = 1
    client, _ = client_for(support.to_line(document))
    with pytest.raises(ProtocolError) as raised:
        client.handshake()
    assert raised.value.code is ErrorCode.MALFORMED_FRAME


def test_the_handshake_may_only_happen_once() -> None:
    client, writer = welcomed()
    with pytest.raises(ClientStateError):
        client.handshake()
    assert writer.getvalue() == b""


def test_end_of_input_during_the_handshake_is_session_closed() -> None:
    client, writer = client_for()
    with pytest.raises(SessionClosed):
        client.handshake()
    assert writer.getvalue() == HELLO


# --- jobs ----------------------------------------------------------------------------------------


def handshaken(*replies: bytes) -> tuple[CoreClient, io.BytesIO]:
    """A client that has completed the handshake but holds no job; the hello is dropped."""
    client, writer = client_for(support.to_line(support.welcome()), *replies)
    client.handshake()
    writer.seek(0)
    writer.truncate()
    return client, writer


def test_next_job_returns_the_assigned_job() -> None:
    client, writer = handshaken(JOB)
    assert client.next_job() == Job(job_id=support.JOB_ID, goal="system")
    assert writer.getvalue() == b""


def test_next_job_returns_none_when_the_core_closes_the_session_between_jobs() -> None:
    client, _ = handshaken()
    assert client.next_job() is None


def test_a_job_cut_off_before_its_newline_is_session_closed() -> None:
    client, _ = handshaken(JOB[:-1])
    with pytest.raises(SessionClosed, match="middle of a frame"):
        client.next_job()


def test_next_job_before_the_handshake_fails() -> None:
    client, _ = client_for(JOB)
    with pytest.raises(ClientStateError, match="handshake"):
        client.next_job()


def test_an_error_instead_of_a_job_raises_session_error() -> None:
    client, _ = handshaken(support.to_line(support.error("limit_exceeded", fatal=True)))
    with pytest.raises(SessionError) as raised:
        client.next_job()
    assert raised.value.fatal is True


def test_a_tool_response_instead_of_a_job_is_unexpected() -> None:
    client, _ = handshaken(support.to_line(support.completed_system_info("req-0001")))
    with pytest.raises(ProtocolError) as raised:
        client.next_job()
    assert raised.value.code is ErrorCode.UNEXPECTED_MESSAGE
    assert "expected job, got tool_response" in raised.value.message


def test_a_job_while_waiting_for_a_tool_response_is_unexpected() -> None:
    client, _ = welcomed(JOB)
    with pytest.raises(ProtocolError) as raised:
        client.call("system.info", {})
    assert raised.value.code is ErrorCode.UNEXPECTED_MESSAGE


def test_a_job_must_be_finished_before_the_next_one() -> None:
    client, _ = welcomed(JOB)
    with pytest.raises(ClientStateError, match="not been finished"):
        client.next_job()


def test_call_and_finish_need_a_job() -> None:
    client, writer = handshaken()
    with pytest.raises(ClientStateError, match="next_job"):
        client.call("system.info", {})
    with pytest.raises(ClientStateError, match="next_job"):
        client.finish(JobOutcome.COMPLETED, "")
    assert writer.getvalue() == b""


def test_finish_reports_the_job_and_frees_the_client_for_the_next() -> None:
    other = "01928f5e-7c3c-7b30-9c4d-5e6f7a8b9cff"
    client, writer = welcomed(support.to_line(support.job("read a.txt", job_id=other)))
    client.finish(JobOutcome.COMPLETED, "0 call(s)")
    frame = support.check_worker_frame(writer.getvalue())
    assert frame == {
        "protocol": 2,
        "type": "job_result",
        "job_id": support.JOB_ID,
        "outcome": "completed",
        "summary": "0 call(s)",
    }
    assert client.next_job() == Job(job_id=other, goal="read a.txt")


def test_an_invalid_summary_is_refused_before_anything_is_written() -> None:
    client, writer = welcomed()
    with pytest.raises(ProtocolError):
        client.finish(JobOutcome.COMPLETED, "line\nbreak")
    assert writer.getvalue() == b""
    client.finish(JobOutcome.COMPLETED, "fixed")
    assert support.check_worker_frame(writer.getvalue())["summary"] == "fixed"


# --- calls ---------------------------------------------------------------------------------------


def test_call_sends_a_request_and_returns_the_matching_response() -> None:
    client, writer = welcomed(support.to_line(support.completed_system_info("req-0001")))
    response = client.call("system.info", {})
    assert response.request_id == "req-0001"
    assert response.task_id == support.TASK_ID
    assert isinstance(response.outcome, Completed)
    assert isinstance(response.outcome.result, SystemInfo)
    assert response.outcome.result.os == "linux"
    assert writer.getvalue() == (
        b'{"protocol":2,"type":"tool_request","request_id":"req-0001",'
        b'"job_id":"' + support.JOB_ID.encode() + b'","tool":"system.info","args":{}}\n'
    )


def test_calls_run_one_at_a_time_in_order() -> None:
    client, writer = welcomed(
        support.to_line(support.completed_system_info("req-0001")),
        support.to_line(support.completed_fixture("req-0002")),
    )
    first = client.call("system.info", {})
    second = client.call("filesystem.read_fixture", {"path": "welcome.txt"})
    assert isinstance(first.outcome, Completed)
    assert isinstance(second.outcome, Completed)
    assert second.outcome.result == FixtureContent(path="welcome.txt", bytes=6, content="hello\n")
    lines = written_lines(writer)
    assert [support.check_worker_frame(line)["request_id"] for line in lines] == [
        "req-0001",
        "req-0002",
    ]


def test_denied_and_rejected_outcomes_are_results_not_exceptions() -> None:
    client, _ = welcomed(
        support.to_line(support.denied("req-0001")),
        support.to_line(support.rejected("req-0002")),
    )
    denied = client.call("filesystem.read_fixture", {"path": "a.txt"})
    rejected = client.call("filesystem.read_fixture", {"path": "../secret"})
    assert isinstance(denied.outcome, Denied)
    assert isinstance(rejected.outcome, Rejected)
    assert rejected.outcome.error.code is ErrorCode.INVALID_ARGUMENTS


def test_approval_outcomes_are_results_not_exceptions() -> None:
    client, _ = welcomed(
        support.to_line(support.completed_write("req-0001")),
        support.to_line(support.declined("req-0002")),
        support.to_line(support.expired("req-0003")),
    )
    written = client.call("workspace.write_file", {"path": "notes.txt", "content": "hello"})
    declined = client.call("workspace.write_file", {"path": "notes.txt", "content": "x"})
    expired = client.call("workspace.write_file", {"path": "notes.txt", "content": "y"})
    assert written.outcome == Completed(WriteOutcome(path="notes.txt", bytes=5, created=True))
    assert declined.outcome == Declined(approval_id=support.APPROVAL_ID, reason="not now")
    assert expired.outcome == Expired(approval_id=support.APPROVAL_ID)


def test_arguments_are_sent_unchanged() -> None:
    client, writer = welcomed(support.to_line(support.rejected("req-0001")))
    client.call("filesystem.read_fixture", {"path": "../secret"})
    frame = support.check_worker_frame(writer.getvalue())
    assert frame["args"] == {"path": "../secret"}


def test_call_before_the_handshake_fails_without_writing() -> None:
    client, writer = client_for(support.to_line(support.completed_system_info("req-0001")))
    with pytest.raises(ClientStateError, match="handshake"):
        client.call("system.info", {})
    assert writer.getvalue() == b""


def test_a_response_for_another_request_is_a_protocol_error() -> None:
    client, _ = welcomed(support.to_line(support.completed_system_info("req-9999")))
    with pytest.raises(ProtocolError) as raised:
        client.call("system.info", {})
    assert raised.value.code is ErrorCode.UNEXPECTED_MESSAGE
    assert "req-9999" in raised.value.message


def test_a_welcome_in_reply_to_a_call_is_a_protocol_error() -> None:
    client, _ = welcomed(support.to_line(support.welcome()))
    with pytest.raises(ProtocolError) as raised:
        client.call("system.info", {})
    assert raised.value.code is ErrorCode.UNEXPECTED_MESSAGE


@pytest.mark.parametrize("fatal", [True, False])
def test_an_error_reply_raises_session_error_with_the_fatal_flag(fatal: bool) -> None:
    reply = support.error("limit_exceeded", fatal=fatal, request_id="req-0001")
    client, _ = welcomed(support.to_line(reply))
    with pytest.raises(SessionError) as raised:
        client.call("system.info", {})
    assert raised.value.fatal is fatal
    assert raised.value.error.code is ErrorCode.LIMIT_EXCEEDED
    assert raised.value.request_id == "req-0001"
    assert "limit_exceeded" in str(raised.value)


def test_a_client_survives_a_non_fatal_error() -> None:
    client, _ = welcomed(
        support.to_line(support.error("duplicate_request", request_id="req-0001")),
        support.to_line(support.completed_system_info("req-0002")),
    )
    with pytest.raises(SessionError):
        client.call("system.info", {})
    assert client.call("system.info", {}).request_id == "req-0002"


def test_end_of_input_after_a_request_is_session_closed() -> None:
    client, writer = welcomed()
    with pytest.raises(SessionClosed):
        client.call("system.info", {})
    assert len(written_lines(writer)) == 1


def test_a_frame_cut_off_before_its_newline_is_session_closed() -> None:
    reply = support.to_line(support.completed_system_info("req-0001"))
    client, _ = welcomed(reply[:-1])
    with pytest.raises(SessionClosed, match="middle of a frame"):
        client.call("system.info", {})


def test_a_malformed_reply_is_a_protocol_error() -> None:
    client, _ = welcomed(b"this is not json\n")
    with pytest.raises(ProtocolError) as raised:
        client.call("system.info", {})
    assert raised.value.code is ErrorCode.MALFORMED_FRAME


def test_an_empty_line_is_a_protocol_error_not_end_of_input() -> None:
    client, _ = welcomed(b"\n")
    with pytest.raises(ProtocolError) as raised:
        client.call("system.info", {})
    assert raised.value.code is ErrorCode.MALFORMED_FRAME


def test_a_trailing_carriage_return_is_tolerated() -> None:
    client, _ = welcomed(support.to_frame(support.completed_system_info("req-0001")) + b"\r\n")
    assert client.call("system.info", {}).request_id == "req-0001"


def test_a_carriage_return_is_tolerated_in_the_welcome_too() -> None:
    client, _ = client_for(support.to_frame(support.welcome()) + b"\r\n")
    assert client.handshake().core_version == "0.2.0"


def test_an_invalid_tool_name_is_refused_before_anything_is_written() -> None:
    client, writer = welcomed()
    with pytest.raises(ProtocolError) as raised:
        client.call("rm -rf /", {})
    assert raised.value.code is ErrorCode.MALFORMED_FRAME
    assert writer.getvalue() == b""


# --- frame size ----------------------------------------------------------------------------------


def error_frame_of_length(length: int) -> bytes:
    """A valid fatal error frame of exactly ``length`` bytes, without its newline."""

    def frame(padding: int) -> bytes:
        document = support.error("internal", fatal=True)
        document["error"]["message"] = "x" * padding
        return support.to_frame(document)

    return frame(length - len(frame(0)))


def test_a_frame_at_the_announced_limit_is_accepted_and_one_byte_more_is_not() -> None:
    limit = 300
    at_limit = error_frame_of_length(limit)
    assert len(at_limit) == limit
    client, _ = client_for(
        support.to_line(support.welcome(max_frame_bytes=limit)),
        JOB,
        at_limit + b"\n",
        at_limit + b"\r\n",
        error_frame_of_length(limit + 1) + b"\n",
    )
    client.handshake()
    client.next_job()
    for _ in range(2):
        with pytest.raises(SessionError):  # within the limit, so it decodes as an error message
            client.call("system.info", {})
    with pytest.raises(ProtocolError) as raised:
        client.call("system.info", {})
    assert raised.value.code is ErrorCode.FRAME_TOO_LARGE


def test_the_welcome_is_read_with_the_default_limit_and_later_frames_with_the_announced_one() -> (
    None
):
    client, _ = client_for(
        support.to_line(support.welcome(max_frame_bytes=150)),
        JOB,
        error_frame_of_length(200) + b"\n",
    )
    client.handshake()
    client.next_job()
    with pytest.raises(ProtocolError) as raised:
        client.call("system.info", {})
    assert raised.value.code is ErrorCode.FRAME_TOO_LARGE
    assert "from the Core" in raised.value.message


def test_an_endless_line_is_not_buffered_without_bound() -> None:
    reader = io.BytesIO(b"x" * 1_000_000)
    client = CoreClient(reader, io.BytesIO(), max_frame_bytes=128)
    with pytest.raises(ProtocolError) as raised:
        client.handshake()
    assert raised.value.code is ErrorCode.FRAME_TOO_LARGE
    assert "from the Core" in raised.value.message
    assert reader.tell() <= 128 + 2


def test_a_request_larger_than_the_limit_is_refused_before_writing() -> None:
    client, writer = client_for(
        support.to_line(support.welcome(max_frame_bytes=200)), JOB, ids=("req-0001",)
    )
    client.handshake()
    client.next_job()
    writer.seek(0)
    writer.truncate()
    with pytest.raises(ProtocolError) as raised:
        client.call("filesystem.read_fixture", {"path": "a" * 300})
    assert raised.value.code is ErrorCode.FRAME_TOO_LARGE
    assert writer.getvalue() == b""


# --- stream failures -----------------------------------------------------------------------------


class BrokenPipeWriter(io.BytesIO):
    def write(self, buffer: "ReadableBuffer", /) -> int:
        raise BrokenPipeError(32, "Broken pipe")


def test_a_broken_pipe_is_session_closed() -> None:
    client = CoreClient(io.BytesIO(), BrokenPipeWriter())
    with pytest.raises(SessionClosed, match="could not write"):
        client.handshake()


class PartialWriter(io.BytesIO):
    """Accepts at most three bytes per write, as a raw pipe may."""

    def write(self, buffer: "ReadableBuffer", /) -> int:
        return super().write(bytes(buffer)[:3])


def test_partial_writes_are_completed() -> None:
    writer = PartialWriter()
    client = CoreClient(io.BytesIO(support.to_line(support.welcome())), writer)
    client.handshake()
    assert writer.getvalue() == HELLO


class StalledWriter(io.BytesIO):
    def write(self, buffer: "ReadableBuffer", /) -> int:
        return 0


def test_a_writer_that_accepts_nothing_is_session_closed() -> None:
    client = CoreClient(io.BytesIO(), StalledWriter())
    with pytest.raises(SessionClosed, match="stopped accepting"):
        client.handshake()


class FailingReader(io.BytesIO):
    def readline(self, size: int | None = -1, /) -> bytes:
        raise ConnectionResetError(104, "Connection reset by peer")


def test_a_failing_read_is_session_closed() -> None:
    client = CoreClient(FailingReader(), io.BytesIO())
    with pytest.raises(SessionClosed, match="could not read"):
        client.handshake()


# --- what is written -----------------------------------------------------------------------------


class CountingWriter(io.BytesIO):
    """Records how often it was flushed and how many bytes had been written at each flush."""

    def __init__(self) -> None:
        super().__init__()
        self.flushed_at: list[int] = []

    def flush(self) -> None:
        self.flushed_at.append(len(self.getvalue()))


def test_every_frame_is_flushed_as_soon_as_it_is_written() -> None:
    writer = CountingWriter()
    replies = [
        support.to_line(support.welcome()),
        JOB,
        support.to_line(support.completed_system_info("req-0001")),
        support.to_line(support.completed_system_info("req-0002")),
    ]
    client = CoreClient(
        io.BytesIO(b"".join(replies)), writer, request_ids=request_ids("req-0001", "req-0002")
    )
    client.handshake()
    client.next_job()
    client.call("system.info", {})
    client.call("system.info", {})
    client.finish(JobOutcome.COMPLETED, "2 call(s)")
    lines = written_lines(writer)
    assert len(lines) == 4
    assert writer.flushed_at == [len(b"".join(lines[: n + 1])) for n in range(4)]


def test_every_frame_written_is_a_valid_worker_frame() -> None:
    client, writer = client_for(
        support.to_line(support.welcome()),
        JOB,
        support.to_line(support.completed_system_info("req-0001")),
        support.to_line(support.completed_fixture("req-0002")),
        support.to_line(support.denied("req-0003")),
    )
    client.handshake()
    client.next_job()
    client.call("system.info", {})
    client.call("filesystem.read_fixture", {"path": "welcome.txt"})
    client.call("filesystem.read_fixture", {"path": "café\nx"})
    client.finish(JobOutcome.FAILED, "3 call(s): completed=2 denied=1")
    lines = written_lines(writer)
    assert [support.check_worker_frame(line)["type"] for line in lines] == [
        "hello",
        "tool_request",
        "tool_request",
        "tool_request",
        "job_result",
    ]
    assert lines[0] == HELLO


class EchoCore(io.BytesIO):
    """Reader half of a fake Core that answers each frame the worker wrote to ``writer``."""

    def __init__(self, writer: io.BytesIO) -> None:
        super().__init__()
        self._writer = writer
        self._reads = 0

    def readline(self, size: int | None = -1, /) -> bytes:
        self._reads += 1
        if self._reads == 1:
            return support.to_line(support.welcome())
        if self._reads == 2:
            return JOB
        last = support.check_worker_frame(self._writer.getvalue().splitlines()[-1] + b"\n")
        return support.to_line(support.completed_system_info(last["request_id"]))


def test_default_request_ids_are_req_and_a_uuid_hex_and_unique() -> None:
    writer = io.BytesIO()
    client = CoreClient(EchoCore(writer), writer)
    client.handshake()
    client.next_job()
    ids = [client.call("system.info", {}).request_id for _ in range(5)]
    for request_id in ids:
        assert re.fullmatch(r"req-[0-9a-f]{32}", request_id)
        assert validate_request_id(request_id) == request_id
    assert len(set(ids)) == len(ids)
