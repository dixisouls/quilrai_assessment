"""The JSON-RPC error envelope used by every error this server produces.

Shape (CLAUDE.md, "Errors & information leakage")::

    {"code": -32602, "message": "Invalid params",
     "data": {"request_id": "<32 hex>", "details": [{"field", "message", "type"}, ...]}}

* ``request_id`` is minted per error and logged to stderr with the full
  context, so an operator can match a client report to the server log.
* ``details`` lists what the *caller* can fix. Its text comes from our own
  validators, never from caller input. Field names are only echoed when they
  are plain identifiers, so an attacker-chosen key such as ``"IGNORE PREVIOUS
  INSTRUCTIONS…"`` comes back as ``"(unexpected field)"``.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Final, TypedDict

import mcp_types as types
from mcp.shared.exceptions import MCPError
from pydantic import ValidationError

_SAFE_FIELD: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
UNEXPECTED_FIELD: Final = "(unexpected field)"


class ErrorDetail(TypedDict):
    field: str
    message: str
    type: str


def new_request_id() -> str:
    return uuid.uuid4().hex


def error_data(request_id: str, details: list[ErrorDetail] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"request_id": request_id}
    if details is not None:
        data["details"] = details
    return data


def _field_name(loc: tuple[int | str, ...]) -> str:
    parts = []
    for part in loc:
        if isinstance(part, int):
            parts.append(str(part))
        elif _SAFE_FIELD.fullmatch(part):
            parts.append(part)
        else:
            return UNEXPECTED_FIELD
    return ".".join(parts) or "(arguments)"


def details_from(exc: ValidationError) -> list[ErrorDetail]:
    return [
        ErrorDetail(field=_field_name(err["loc"]), message=err["msg"], type=err["type"])
        for err in exc.errors(include_url=False, include_input=False, include_context=False)
    ]


def invalid_params(request_id: str, details: list[ErrorDetail]) -> MCPError:
    return MCPError(types.INVALID_PARAMS, "Invalid params", error_data(request_id, details))


def internal_error(request_id: str) -> MCPError:
    return MCPError(types.INTERNAL_ERROR, "Internal error", error_data(request_id))
