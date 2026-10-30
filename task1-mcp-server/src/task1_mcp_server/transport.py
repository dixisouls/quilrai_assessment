"""Stdio transport: the SDK's ``stdio_server`` plus spec-compliant handling of bad lines.

**stdout isolation, in two layers** (both proven by ``test_stdio_integration``):

1. The SDK's ``stdio_server`` points fd 1 at stderr while serving and writes
   the wire through a private duplicate, so raw ``os.write(1, ...)`` can't
   reach the wire.
2. That isn't enough for Python-level writes. ``print()`` and
   ``sys.stdout.write`` go into ``sys.stdout``'s buffer (block-buffered on a
   pipe), which is flushed *after* the SDK restores fd 1, so they end up on the
   real stdout after the session. This module therefore flushes ``sys.stdout``
   once fd 1 is diverted (moving anything buffered before startup to stderr),
   redirects ``sys.stdout`` to stderr for the whole session, and flushes again
   before fd 1 is restored. The redirect must happen *after* the SDK claims
   fd 1: the SDK picks the wire from ``sys.stdout``, so redirecting first
   would send the protocol itself to stderr.

**Undecodable input.** The SDK silently drops a line that isn't valid JSON,
or is JSON but not a valid JSON-RPC message. JSON-RPC 2.0 requires a reply:

* invalid JSON → ``-32700 Parse error``, ``id: null``
* valid JSON, not a valid request (wrong ``jsonrpc`` version, missing
  ``method``, a batch array, which MCP doesn't support) → ``-32600 Invalid
  Request``, ``id: null``

``id`` is always ``null`` here: the spec only allows echoing an id that could
be reliably read, and a request that failed validation doesn't provide one.
"""

from __future__ import annotations

import contextlib
import sys
from typing import Final

import anyio
import mcp_types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared._stream_protocols import ReadStream, WriteStream
from mcp.shared.message import SessionMessage
from pydantic import ValidationError

from quilr_common.log import get_logger

log = get_logger(__name__)

_PARSE_ERROR_TYPES: Final = frozenset({"json_invalid", "json_type"})


def protocol_error_for(exc: Exception) -> types.JSONRPCError:
    """Map a message-decoding failure to the JSON-RPC error the spec requires."""
    if isinstance(exc, ValidationError) and any(
        e["type"] in _PARSE_ERROR_TYPES for e in exc.errors(include_input=False)
    ):
        error = types.ErrorData(code=types.PARSE_ERROR, message="Parse error")
    else:
        error = types.ErrorData(code=types.INVALID_REQUEST, message="Invalid Request")
    return types.JSONRPCError(jsonrpc="2.0", id=None, error=error)


async def serve_stdio(server: Server) -> None:
    """Serve one MCP session over this process's stdin/stdout until stdin closes."""
    async with stdio_server() as (wire_in, wire_out):
        original_stdout = sys.stdout
        original_stdout.flush()  # fd 1 is diverted now: earlier buffered junk goes to stderr
        try:
            with contextlib.redirect_stdout(sys.stderr):
                await _serve(server, wire_in, wire_out)
        finally:
            original_stdout.flush()  # before the SDK restores fd 1


async def _serve(
    server: Server,
    wire_in: ReadStream[SessionMessage | Exception],
    wire_out: WriteStream[SessionMessage],
) -> None:
    to_server, from_wire = anyio.create_memory_object_stream[SessionMessage | Exception](0)

    async def pump() -> None:
        async with to_server:
            async for item in wire_in:
                if isinstance(item, Exception):
                    reply = protocol_error_for(item)
                    log.info("rejected undecodable message", extra={"code": reply.error.code})
                    await wire_out.send(SessionMessage(reply))
                    continue
                await to_server.send(item)

    async with anyio.create_task_group() as tg:
        tg.start_soon(pump)
        await server.run(from_wire, wire_out, server.create_initialization_options())
