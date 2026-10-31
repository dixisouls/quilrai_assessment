"""Method-level authorization. Decided *before* anything reaches downstream.

The brief's rules, implemented literally:

* ``tools/list`` is forwarded transparently, for every role.
* ``tools/call`` whose ``params.name`` starts with ``admin_`` requires role
  ``admin``. Otherwise the gateway answers ``-32001 Unauthorized Tool Call``
  itself, and downstream is never called.

Hardening around those rules (fail closed):

* The ``admin_`` check runs on the NFKC-normalised, trimmed, case-folded name,
  so ``ADMIN_x``, ``" admin_x"`` and ``admin_x`` spelled in full-width letters can't slip past
  a downstream that resolves names leniently. A false positive only denies a
  viewer; a false negative would be a privilege escalation.
* Only methods defined by MCP are forwarded; anything else gets ``-32601``
  (decision recorded in the README).
* ``Mcp-Method`` / ``Mcp-Name`` routing headers (MCP 2026-07-28) must match the
  body, so a downstream that routes on headers can't be steered to a tool the
  gateway never authorized.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from typing import Final

from mcp.shared.inbound import decode_header_value

from task2_mcp_gateway.auth import Principal, Role
from task2_mcp_gateway.jsonrpc import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    JsonRpcError,
    Message,
)

UNAUTHORIZED_TOOL_CALL: Final = -32001
ADMIN_TOOL_PREFIX: Final = "admin_"

# Client-to-server methods defined by the MCP spec, as listed by the installed
# SDK's ClientRequest / ClientNotification unions (mcp 2.3, protocol 2026-07-28).
REQUEST_METHODS: Final = frozenset(
    {
        "initialize",
        "ping",
        "server/discover",
        "subscriptions/listen",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
    }
)
NOTIFICATION_METHODS: Final = frozenset(
    {
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/roots/list_changed",
    }
)


def is_admin_tool(name: str) -> bool:
    return unicodedata.normalize("NFKC", name).strip().casefold().startswith(ADMIN_TOOL_PREFIX)


def _detail(field: str, message: str, kind: str) -> list[dict[str, str]]:
    return [{"field": field, "message": message, "type": kind}]


def authorize(principal: Principal, msg: Message, headers: Mapping[str, str]) -> None:
    """Return if ``msg`` may be forwarded; raise :class:`JsonRpcError` otherwise.

    ``headers`` must be keyed by lowercase header name.
    """
    if msg.is_response:
        return  # answers to server-initiated requests; they invoke nothing

    allowed = REQUEST_METHODS if msg.is_request else NOTIFICATION_METHODS
    if msg.method not in allowed:
        raise JsonRpcError(METHOD_NOT_FOUND, "Method not found", id=msg.id)

    header_method = headers.get("mcp-method")
    if header_method is not None and header_method != msg.method:
        raise JsonRpcError(
            INVALID_REQUEST, "Invalid Request: Mcp-Method header does not match the body", id=msg.id
        )

    if msg.method != "tools/call":
        return

    name = (msg.params or {}).get("name")
    if not isinstance(name, str):
        raise JsonRpcError(
            INVALID_PARAMS,
            "Invalid params",
            id=msg.id,
            details=_detail("params.name", "must be a string", "string_type"),
        )
    raw_header_name = headers.get("mcp-name")
    # Decode exactly like the SDK server does (=?base64?...?= wrapper). A malformed
    # wrapper decodes to None and therefore never matches (fail closed).
    if raw_header_name is not None and decode_header_value(raw_header_name) != name:
        raise JsonRpcError(
            INVALID_REQUEST, "Invalid Request: Mcp-Name header does not match the body", id=msg.id
        )
    if is_admin_tool(name) and principal.role is not Role.ADMIN:
        raise JsonRpcError(
            UNAUTHORIZED_TOOL_CALL,
            "Unauthorized Tool Call",
            id=msg.id,
            details=_detail("params.name", "this tool requires role 'admin'", "insufficient_role"),
        )
