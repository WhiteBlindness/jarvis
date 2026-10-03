"""Client side of a worker session: handshake, then jobs, one tool call at a time.

The client owns the framing. It reads and writes binary streams, one JSON object per line, and
flushes after every frame. Everything it does is a request to the Core; it has no other way to
affect the outside world.
"""

import uuid
from collections.abc import Callable
from typing import BinaryIO, assert_never

from jarvis_worker import __version__
from jarvis_worker.protocol import (
    CoreMessage,
    ErrorCode,
    ErrorMessage,
    Hello,
    Job,
    JobOutcome,
    JobResult,
    JsonValue,
    ProtocolError,
    ToolRequest,
    ToolResponse,
    Welcome,
    WireError,
    WorkerMessage,
    decode_core_message,
    encode_worker_message,
)

DEFAULT_MAX_FRAME_BYTES = 64 * 1024
"""Frame size limit used until the Core announces its own in ``welcome``."""


class SessionError(Exception):
    """The Core answered with an ``error`` message instead of the expected reply."""

    def __init__(self, error: WireError, *, fatal: bool, request_id: str | None = None) -> None:
        super().__init__(f"{error.code}: {error.message}")
        self.error = error
        self.fatal = fatal
        self.request_id = request_id


class SessionClosed(Exception):  # noqa: N818
    """The Core closed the connection: end of input, a truncated frame or a broken pipe.

    It has no ``Error`` suffix because it reports how a session ends, not a fault in the worker.
    """


class ClientStateError(RuntimeError):
    """The client was used out of order, for example ``call`` before ``handshake``."""


def _random_request_id() -> str:
    return f"req-{uuid.uuid4().hex}"


class CoreClient:
    """Speaks the worker protocol to the Core over a pair of binary streams.

    ``request_ids`` supplies the ID of each request; the default is ``req-`` followed by a random
    UUID in hex. Tests inject a deterministic sequence.
    """

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        request_ids: Callable[[], str] = _random_request_id,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._max_frame_bytes = max_frame_bytes
        self._request_ids = request_ids
        self._welcome: Welcome | None = None
        self._job: str | None = None

    @property
    def welcome(self) -> Welcome | None:
        """The Core's ``welcome``, once the handshake has succeeded."""
        return self._welcome

    def handshake(
        self, worker: str = "jarvis-worker", worker_version: str = __version__
    ) -> Welcome:
        """Send ``hello`` and wait for ``welcome``.

        From here on frames from the Core are limited to the size the Core announced.
        """
        if self._welcome is not None:
            raise ClientStateError("handshake already completed")
        self._send(Hello(worker=worker, worker_version=worker_version))
        reply = self._receive()
        if isinstance(reply, Welcome):
            self._welcome = reply
            self._max_frame_bytes = reply.limits.max_frame_bytes
            return reply
        raise _unexpected(reply, "welcome")

    def next_job(self) -> Job | None:
        """Wait for the Core to assign a job.

        Returns ``None`` when the Core closes the session between jobs, which is how it tells an
        idle worker to exit.
        """
        self._require_session("next_job")
        if self._job is not None:
            raise ClientStateError(f"job {self._job} has not been finished")
        frame = self._read_frame()
        if frame is None:
            return None
        reply = decode_core_message(frame)
        if isinstance(reply, Job):
            self._job = reply.job_id
            return reply
        raise _unexpected(reply, "job")

    def call(self, tool: str, args: dict[str, JsonValue]) -> ToolResponse:
        """Ask the Core to run ``tool`` for the current job and return its ``tool_response``.

        Whether the call was allowed, declined, rejected or failed is in the response's outcome;
        those are normal results, not exceptions. The reply can take as long as a person needs to
        decide on an approval. Raises ``SessionError`` if the Core answers with an ``error``
        instead, ``ProtocolError`` for any other unexpected reply and ``SessionClosed`` if the
        Core goes away.
        """
        job_id = self._require_job("call")
        request = ToolRequest(request_id=self._request_ids(), job_id=job_id, tool=tool, args=args)
        self._send(request)
        reply = self._receive()
        if isinstance(reply, ToolResponse):
            if reply.request_id != request.request_id:
                raise ProtocolError(
                    ErrorCode.UNEXPECTED_MESSAGE,
                    f"response is for request {reply.request_id}, expected {request.request_id}",
                )
            return reply
        raise _unexpected(reply, "tool_response")

    def finish(self, outcome: JobOutcome, summary: str) -> None:
        """Report the end of the current job. ``summary`` must be a valid summary."""
        job_id = self._require_job("finish")
        self._send(JobResult(job_id=job_id, outcome=outcome, summary=summary))
        self._job = None

    def _require_session(self, method: str) -> None:
        if self._welcome is None:
            raise ClientStateError(f"{method}() requires a completed handshake")

    def _require_job(self, method: str) -> str:
        self._require_session(method)
        if self._job is None:
            raise ClientStateError(f"{method}() requires a job from next_job()")
        return self._job

    def _send(self, message: WorkerMessage) -> None:
        frame = encode_worker_message(message)
        if len(frame) > self._max_frame_bytes:
            raise ProtocolError(
                ErrorCode.FRAME_TOO_LARGE,
                f"frame of {len(frame)} bytes exceeds the limit of {self._max_frame_bytes}",
            )
        try:
            pending = memoryview(frame + b"\n")
            while pending:
                written = self._writer.write(pending)
                if not written:
                    raise SessionClosed("the Core stopped accepting data")
                pending = pending[written:]
            self._writer.flush()
        except OSError as error:
            raise SessionClosed(f"could not write to the Core: {error}") from error

    def _receive(self) -> CoreMessage:
        frame = self._read_frame()
        if frame is None:
            raise SessionClosed("the Core closed the connection")
        return decode_core_message(frame)

    def _read_frame(self) -> bytes | None:
        """Read one line and return it without its terminator, or ``None`` at end of input.

        Reads at most two bytes more than the limit (room for ``\\r\\n``), so a Core that never
        sends a newline cannot make the worker buffer an unbounded line.
        """
        limit = self._max_frame_bytes
        try:
            line = self._reader.readline(limit + 2)
        except OSError as error:
            raise SessionClosed(f"could not read from the Core: {error}") from error
        if not line:
            return None
        if not line.endswith(b"\n"):
            if len(line) > limit:
                raise _frame_too_large(limit)
            raise SessionClosed("the Core closed the connection in the middle of a frame")
        frame = line.removesuffix(b"\n").removesuffix(b"\r")
        if len(frame) > limit:
            raise _frame_too_large(limit)
        return frame


def _session_error(message: ErrorMessage) -> SessionError:
    return SessionError(message.error, fatal=message.fatal, request_id=message.request_id)


def _unexpected(reply: CoreMessage, expected: str) -> Exception:
    """The exception for a reply that is not ``expected``: the Core's error, or a violation."""
    match reply:
        case ErrorMessage():
            return _session_error(reply)
        case Welcome():
            got = "welcome"
        case Job():
            got = "job"
        case ToolResponse():
            got = "tool_response"
        case _:
            assert_never(reply)
    return ProtocolError(ErrorCode.UNEXPECTED_MESSAGE, f"expected {expected}, got {got}")


def _frame_too_large(limit: int) -> ProtocolError:
    return ProtocolError(ErrorCode.FRAME_TOO_LARGE, f"frame from the Core exceeds {limit} bytes")
