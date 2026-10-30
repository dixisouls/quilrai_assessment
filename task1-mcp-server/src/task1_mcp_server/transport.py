"""Stdio transport: the SDK's ``stdio_server`` plus three things it doesn't guarantee.

1. **stdout belongs to the protocol for the whole process, not just the session.**
   :func:`reserve_stdout` runs first in ``main()``. It moves the JSON-RPC
   channel to a private duplicate of fd 1, then points fd 1 *and*
   ``sys.stdout`` at stderr for the rest of the process. Every later write,
   whether ``print``, ``sys.stdout``, ``sys.__stdout__``, ``os.write(1)``,
   third-party libraries, or ``atexit`` handlers, lands on stderr. The SDK's
   own per-session fd claim only covered the session window, and Python-level
   buffers flushed after it, so stray text still reached stdout (see
   MISTAKES.md T1, Review #2 finding 5).

2. **Every request gets its answer, even if stdin closes immediately.** When
   stdin hits EOF the SDK cancels in-flight handlers *and* its stdout writer,
   so a refund could commit while its receipt was dropped. Two waits, both
   bounded by :data:`DRAIN_TIMEOUT_S`, run before shutdown is allowed: until
   every accepted request has been answered, and then until every answer has
   actually been written to stdout. Being handed to the SDK's writer isn't
   enough; the writer is cancelled too.

3. **Undecodable input gets the reply JSON-RPC 2.0 requires.** The SDK drops
   such lines silently:

   * invalid JSON → ``-32700 Parse error``, ``id: null``
   * JSON that isn't a valid request (wrong ``jsonrpc``, missing ``method``,
     batch arrays, which MCP doesn't support) → ``-32600 Invalid Request``,
     echoing ``id`` when it can be read, otherwise ``null``
   * a ``tools/call`` whose ``params.name`` isn't a string or whose
     ``params.arguments`` isn't an object → ``-32602`` in our own envelope
     (the SDK would answer ``data: ""``)
"""

from __future__ import annotations

import io
import os
import sys
from collections import Counter
from types import TracebackType
from typing import Any, Final, Self, TextIO

import anyio
import mcp_types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared._stream_protocols import ReadStream, WriteStream
from mcp.shared.message import SessionMessage
from pydantic import ValidationError

from quilr_common.log import get_logger
from task1_mcp_server.errors import ErrorDetail, error_data, new_request_id

log = get_logger(__name__)

DRAIN_TIMEOUT_S: Final = 10.0
_PARSE_ERROR_TYPES: Final = frozenset({"json_invalid", "json_type"})


# --- 1. stdout reservation ---------------------------------------------------


def reserve_stdout() -> TextIO:
    """Take fd 1 for the protocol; send every other stdout write to stderr.

    Returns a text stream on a private duplicate of the original stdout. It is
    the only handle that writes to the real stdout from here on.
    """
    sys.stdout.flush()
    wire_fd = os.dup(1)
    os.dup2(2, 1)  # fd 1 (and so sys.__stdout__, C extensions, children) now -> stderr
    sys.stdout = sys.stderr
    return io.TextIOWrapper(
        os.fdopen(wire_fd, "wb", closefd=True), encoding="utf-8", write_through=True
    )


# --- 2. response tracking ------------------------------------------------------


class CountingWire:
    """The protocol stream, counting complete lines (= messages) actually written."""

    def __init__(self, inner: TextIO) -> None:
        self._inner = inner
        self.lines_written = 0

    def write(self, text: str) -> int:
        written = self._inner.write(text)
        self.lines_written += text.count("\n")
        return written

    def flush(self) -> None:
        self._inner.flush()


class _AnswerTracker:
    """Wraps the server's write stream and tracks requests still awaiting an answer."""

    def __init__(self, inner: WriteStream[SessionMessage], wire: CountingWire) -> None:
        self._inner = inner
        self._wire = wire
        self._outstanding: Counter[str | int] = Counter()
        self._sent = 0

    def expect(self, request_id: str | int) -> None:
        self._outstanding[request_id] += 1

    @property
    def outstanding(self) -> int:
        return sum(self._outstanding.values())

    async def send(self, item: SessionMessage, /) -> None:
        msg = item.message
        if isinstance(msg, types.JSONRPCResponse | types.JSONRPCError) and msg.id is not None:
            if self._outstanding[msg.id] > 0:
                self._outstanding[msg.id] -= 1
            if self._outstanding[msg.id] <= 0:
                del self._outstanding[msg.id]
        # Count before awaiting the hand-off: while send() is suspended the request is
        # no longer "outstanding", so the drain must already see an unwritten message.
        self._sent += 1
        await self._inner.send(item)

    async def wait_until_delivered(self) -> None:
        """Return once every accepted request is answered and every answer is on stdout.

        Polls because ``lines_written`` is advanced by anyio's file-writer worker
        *thread*; signalling an ``anyio.Event`` from there would need cross-thread
        plumbing for a wait that's at most a few milliseconds. Callers bound it
        with ``move_on_after``.
        """
        while self.outstanding or self._wire.lines_written < self._sent:  # noqa: ASYNC110
            await anyio.sleep(0.005)

    def log_if_undelivered(self) -> None:
        undelivered = self._sent - self._wire.lines_written
        if self.outstanding or undelivered > 0:
            log.warning(
                "shutting down with undelivered responses",
                extra={"unanswered": self.outstanding, "unwritten": undelivered},
            )

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        await self.aclose()
        return None


# --- 3. protocol errors for undecodable input --------------------------------


def _readable_id(exc: ValidationError) -> str | int | None:
    """The request id, if the rejected message had one we can trust."""
    for err in exc.errors(include_url=False):
        candidate = err.get("input")
        if isinstance(candidate, dict):
            rid = candidate.get("id")
            if isinstance(rid, str) or (isinstance(rid, int) and not isinstance(rid, bool)):
                return rid
    return None


def protocol_error_for(exc: Exception) -> types.JSONRPCError:
    """Map a message-decoding failure to the JSON-RPC error the spec requires."""
    request_id = new_request_id()
    if isinstance(exc, ValidationError) and any(
        e["type"] in _PARSE_ERROR_TYPES for e in exc.errors(include_input=False)
    ):
        code, message, rid = types.PARSE_ERROR, "Parse error", None
    else:
        code, message = types.INVALID_REQUEST, "Invalid Request"
        rid = _readable_id(exc) if isinstance(exc, ValidationError) else None
    log.info("rejected undecodable message", extra={"code": code, "request_id": request_id})
    return types.JSONRPCError(
        jsonrpc="2.0",
        id=rid,
        error=types.ErrorData(code=code, message=message, data=error_data(request_id)),
    )


def _malformed_tool_call(msg: types.JSONRPCRequest) -> types.JSONRPCError | None:
    """Shape-check ``tools/call`` params before the SDK answers with ``data: ""``."""
    if msg.method != "tools/call":
        return None
    params: Any = msg.params if msg.params is not None else {}
    details: list[ErrorDetail] = []
    if not isinstance(params.get("name"), str):
        details.append(ErrorDetail(field="name", message="must be a string", type="string_type"))
    if params.get("arguments") is not None and not isinstance(params.get("arguments"), dict):
        details.append(
            ErrorDetail(field="arguments", message="must be an object", type="dict_type")
        )
    if not details:
        return None
    request_id = new_request_id()
    log.info("rejected malformed tools/call", extra={"request_id": request_id})
    return types.JSONRPCError(
        jsonrpc="2.0",
        id=msg.id,
        error=types.ErrorData(
            code=types.INVALID_PARAMS,
            message="Invalid params",
            data=error_data(request_id, details),
        ),
    )


# --- Serving -------------------------------------------------------------------


async def serve_stdio(server: Server, wire: TextIO) -> None:
    """Serve one MCP session: read stdin, write JSON-RPC only to ``wire``."""
    counting = CountingWire(wire)
    async with stdio_server(stdout=anyio.wrap_file(counting)) as (wire_in, wire_out):  # type: ignore[arg-type]  # duck-typed TextIO
        await _serve(server, wire_in, _AnswerTracker(wire_out, counting))


async def _serve(
    server: Server, wire_in: ReadStream[SessionMessage | Exception], wire_out: _AnswerTracker
) -> None:
    to_server, from_wire = anyio.create_memory_object_stream[SessionMessage | Exception](0)

    async def pump() -> None:
        async with to_server:
            async for item in wire_in:
                if isinstance(item, Exception):
                    await wire_out.send(SessionMessage(protocol_error_for(item)))
                    continue
                msg = item.message
                if isinstance(msg, types.JSONRPCRequest):
                    if (reply := _malformed_tool_call(msg)) is not None:
                        await wire_out.send(SessionMessage(reply))
                        continue
                    wire_out.expect(msg.id)
                await to_server.send(item)
            # stdin closed: answer everything already accepted before stopping the server.
            with anyio.move_on_after(DRAIN_TIMEOUT_S):
                await wire_out.wait_until_delivered()
            wire_out.log_if_undelivered()

    async with anyio.create_task_group() as tg:
        tg.start_soon(pump)
        await server.run(from_wire, wire_out, server.create_initialization_options())
