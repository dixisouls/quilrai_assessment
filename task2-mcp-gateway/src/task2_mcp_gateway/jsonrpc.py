"""Strict JSON-RPC 2.0 parsing for messages entering the gateway.

The gateway authorizes what it parses, and the downstream server executes
what *it* parses. Any difference between the two parsers is a bypass, so this
module rejects everything ambiguous instead of guessing:

* **Duplicate keys** (``{"name": "admin_x", "name": "get_status"}``) →
  ``-32600``. Python keeps the last key, and other parsers keep the first.
* **NaN / Infinity** literals (accepted by Python's ``json``) → ``-32700``.
* **Batches** (top-level arrays) → ``-32600``. MCP removed JSON-RPC batching
  in 2025-06-18, and inspecting each element of a batch is a classic
  smuggling surface.
* Nesting deeper than :data:`MAX_DEPTH` → ``-32600`` (including nesting so deep
  the parser itself would recurse out).
* Anything that can't be re-encoded as strict JSON, such as lone surrogates
  (``"\\ud800"``) or numbers that overflow to infinity (``1e400``) →
  ``-32600``.

:attr:`Message.canonical` holds the exact bytes the gateway forwards: the
parsed object re-serialised as strict JSON, never the client's raw bytes.
Downstream therefore sees exactly what was authorized.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Final

PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603

MAX_DEPTH: Final = 32

type JsonRpcId = str | int


class JsonRpcError(Exception):
    """A JSON-RPC error to send back instead of forwarding the message."""

    def __init__(
        self,
        code: int,
        message: str,
        *,
        id: JsonRpcId | None = None,  # noqa: A002 - mirrors the JSON-RPC field name
        details: list[dict[str, str]] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.id = id
        self.details = details


@dataclass(frozen=True, slots=True)
class Message:
    raw: dict[str, Any] = field(repr=False)
    id: JsonRpcId | None
    method: str | None
    params: dict[str, Any] | None
    canonical: bytes = field(repr=False)

    @property
    def is_request(self) -> bool:
        return self.method is not None and self.id is not None

    @property
    def is_notification(self) -> bool:
        return self.method is not None and self.id is None

    @property
    def is_response(self) -> bool:
        return self.method is None


class _DuplicateKeyError(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKeyError(key)
        obj[key] = value
    return obj


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON constant {name}")


def _too_deep(value: Any) -> bool:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_DEPTH:
            return True
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current)
    return False


def _readable_id(value: Any) -> JsonRpcId | None:
    if isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    return None


def parse_message(body: bytes) -> Message:
    """Parse one JSON-RPC message or raise :class:`JsonRpcError`."""
    try:
        obj = json.loads(body, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except _DuplicateKeyError:
        raise JsonRpcError(INVALID_REQUEST, "Invalid Request: duplicate JSON keys") from None
    except RecursionError:
        raise JsonRpcError(INVALID_REQUEST, "Invalid Request: nested too deeply") from None
    except (ValueError, UnicodeDecodeError):
        raise JsonRpcError(PARSE_ERROR, "Parse error") from None

    if not isinstance(obj, dict):
        message = "batches are not supported" if isinstance(obj, list) else "must be an object"
        raise JsonRpcError(INVALID_REQUEST, f"Invalid Request: {message}")

    rid = _readable_id(obj.get("id"))
    if "id" in obj and rid is None:
        raise JsonRpcError(INVALID_REQUEST, "Invalid Request: id must be a string or integer")
    if _too_deep(obj):
        raise JsonRpcError(INVALID_REQUEST, "Invalid Request: nested too deeply", id=rid)
    if obj.get("jsonrpc") != "2.0":
        raise JsonRpcError(INVALID_REQUEST, 'Invalid Request: jsonrpc must be "2.0"', id=rid)
    try:
        canonical = json.dumps(
            obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (ValueError, UnicodeEncodeError):
        raise JsonRpcError(
            INVALID_REQUEST, "Invalid Request: not representable as strict JSON", id=rid
        ) from None

    if "method" in obj:
        method = obj["method"]
        if not isinstance(method, str):
            raise JsonRpcError(INVALID_REQUEST, "Invalid Request: method must be a string", id=rid)
        params = obj.get("params")
        if "params" in obj and not isinstance(params, dict):
            raise JsonRpcError(INVALID_REQUEST, "Invalid Request: params must be an object", id=rid)
        return Message(raw=obj, id=rid, method=method, params=params, canonical=canonical)

    # A client's response to a server-initiated request (sampling, elicitation, ...).
    if rid is None or ("result" in obj) == ("error" in obj):
        raise JsonRpcError(
            INVALID_REQUEST,
            "Invalid Request: needs a method, or an id with result or error",
            id=rid,
        )
    return Message(raw=obj, id=rid, method=None, params=None, canonical=canonical)
