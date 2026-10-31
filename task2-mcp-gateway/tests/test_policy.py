"""Unit tests for JSON-RPC parsing and the tool-level authorization policy."""

from __future__ import annotations

import json
from typing import Any

import pytest

from task2_mcp_gateway.auth import Principal, Role
from task2_mcp_gateway.jsonrpc import JsonRpcError, parse_message
from task2_mcp_gateway.policy import UNAUTHORIZED_TOOL_CALL, authorize, is_admin_tool

ADMIN = Principal("root", Role.ADMIN)
VIEWER = Principal("alice", Role.VIEWER)


def _msg(obj: Any) -> bytes:
    return json.dumps(obj).encode()


def _call(name: Any, req_id: Any = 1, arguments: Any = None) -> bytes:
    params: dict[str, Any] = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return _msg({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params})


def _parse_error(body: bytes) -> JsonRpcError:
    with pytest.raises(JsonRpcError) as exc:
        parse_message(body)
    return exc.value


def _deny(principal: Principal, body: bytes, headers: dict[str, str] | None = None) -> JsonRpcError:
    with pytest.raises(JsonRpcError) as exc:
        authorize(principal, parse_message(body), headers or {})
    return exc.value


# --- Parsing ----------------------------------------------------------------------


def test_parses_request_notification_and_response() -> None:
    req = parse_message(_msg({"jsonrpc": "2.0", "id": "a", "method": "tools/list"}))
    assert (req.id, req.method, req.is_request) == ("a", "tools/list", True)
    note = parse_message(_msg({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    assert (note.id, note.is_request) == (None, False)
    resp = parse_message(_msg({"jsonrpc": "2.0", "id": 7, "result": {}}))
    assert (resp.method, resp.is_response) == (None, True)


@pytest.mark.parametrize("body", [b"{not json", b"", b"   ", b'{"a": NaN}', b'{"a": Infinity}'])
def test_unparseable_bodies_are_parse_errors(body: bytes) -> None:
    err = _parse_error(body)
    assert (err.code, err.id) == (-32700, None)


@pytest.mark.parametrize(
    ("body", "echo_id"),
    [
        (b"[]", None),  # batch (not part of MCP since 2025-06-18)
        (_msg([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]), None),
        (b'"text"', None),
        (_msg({"jsonrpc": "1.0", "id": 3, "method": "ping"}), 3),
        (_msg({"id": 3, "method": "ping"}), 3),
        (_msg({"jsonrpc": "2.0", "id": 3, "method": 7}), 3),
        (_msg({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": []}), 3),
        (_msg({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}), None),
        (_msg({"jsonrpc": "2.0", "id": True, "method": "ping"}), None),
        (_msg({"jsonrpc": "2.0", "id": None, "method": "ping"}), None),
        (_msg({"jsonrpc": "2.0", "id": 3}), 3),  # neither method nor result/error
    ],
)
def test_invalid_requests(body: bytes, echo_id: Any) -> None:
    err = _parse_error(body)
    assert (err.code, err.id) == (-32600, echo_id)


def test_duplicate_keys_are_rejected_to_prevent_parser_differentials() -> None:
    # A downstream parser that keeps the *first* key would run admin_reset_key
    # while a gateway keeping the *last* would authorize get_status.
    body = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"admin_reset_key","name":"get_status"}}'
    )
    err = _parse_error(body)
    assert err.code == -32600


def test_excessive_nesting_is_rejected() -> None:
    deep: Any = {}
    for _ in range(100):
        deep = {"a": deep}
    err = _parse_error(_call("get_status", arguments=deep))
    assert (err.code, err.id) == (-32600, 1)


# --- Authorization: the brief's rules ---------------------------------------------


@pytest.mark.parametrize("principal", [ADMIN, VIEWER])
def test_tools_list_is_allowed_for_every_role(principal: Principal) -> None:
    authorize(
        principal, parse_message(_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})), {}
    )


def test_viewer_calling_admin_tool_gets_unauthorized_tool_call() -> None:
    err = _deny(VIEWER, _call("admin_reset_key", req_id=42))
    assert err.code == UNAUTHORIZED_TOOL_CALL == -32001
    assert err.message == "Unauthorized Tool Call"
    assert err.id == 42
    assert err.details == [
        {
            "field": "params.name",
            "message": "this tool requires role 'admin'",
            "type": "insufficient_role",
        }
    ]


def test_admin_may_call_admin_tools() -> None:
    authorize(ADMIN, parse_message(_call("admin_reset_key")), {})


@pytest.mark.parametrize("principal", [ADMIN, VIEWER])
def test_non_admin_tools_are_allowed_for_every_role(principal: Principal) -> None:
    authorize(principal, parse_message(_call("get_status")), {})


# --- Authorization: bypass attempts -------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "admin_reset_key",
        "ADMIN_reset_key",
        "Admin_Reset_Key",
        " admin_reset_key",
        "admin_reset_key ",
        "\tadmin_reset_key",
        "\uff41\uff44\uff4d\uff49\uff4e_reset_key",  # full-width letters (NFKC -> admin_)
        "admin\uff3freset_key",  # full-width low line
        "\u212aelvin",  # not admin: Kelvin sign must not be a false positive
    ],
)
def test_admin_tool_detection_is_normalisation_robust(name: str) -> None:
    expected = not name.endswith("elvin")
    assert is_admin_tool(name) is expected


@pytest.mark.parametrize(
    "name", ["ADMIN_reset_key", " admin_reset_key", "\uff41\uff44\uff4d\uff49\uff4e_reset_key"]
)
def test_viewer_cannot_bypass_with_case_whitespace_or_width(name: str) -> None:
    assert _deny(VIEWER, _call(name)).code == -32001


@pytest.mark.parametrize("name", [None, 7, ["admin_reset_key"], {"n": "admin_reset_key"}])
def test_tool_name_must_be_a_string(name: Any) -> None:
    err = _deny(VIEWER, _call(name))
    assert err.code == -32602


def test_tools_call_without_params_is_invalid_params() -> None:
    err = _deny(VIEWER, _msg({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}))
    assert err.code == -32602


def test_routing_header_mismatch_is_rejected() -> None:
    # MCP 2026-07-28 mirrors the tool name in an Mcp-Name header. A downstream that
    # routed on the header would run the admin tool the body never names.
    err = _deny(VIEWER, _call("get_status"), {"mcp-name": "admin_reset_key"})
    assert err.code == -32600
    err = _deny(VIEWER, _call("get_status"), {"mcp-method": "tools/list"})
    assert err.code == -32600


def test_matching_routing_headers_are_fine() -> None:
    authorize(
        VIEWER,
        parse_message(_call("get_status")),
        {"mcp-name": "get_status", "mcp-method": "tools/call"},
    )


# --- Method allowlist ------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "initialize",
        "ping",
        "resources/list",
        "resources/read",
        "prompts/get",
        "completion/complete",
        "server/discover",
        "subscriptions/listen",
        "logging/setLevel",
    ],
)
def test_standard_mcp_methods_are_forwarded(method: str) -> None:
    authorize(VIEWER, parse_message(_msg({"jsonrpc": "2.0", "id": 1, "method": method})), {})


@pytest.mark.parametrize(
    "method", ["admin/shutdown", "tools/call_raw", "Tools/Call", "debug/eval", "rpc.discover"]
)
def test_unknown_methods_are_denied(method: str) -> None:
    err = _deny(ADMIN, _msg({"jsonrpc": "2.0", "id": 5, "method": method}))
    assert (err.code, err.id) == (-32601, 5)


def test_standard_notifications_pass_and_unknown_ones_do_not() -> None:
    authorize(
        VIEWER, parse_message(_msg({"jsonrpc": "2.0", "method": "notifications/initialized"})), {}
    )
    err = _deny(VIEWER, _msg({"jsonrpc": "2.0", "method": "notifications/evil"}))
    assert (err.code, err.id) == (-32601, None)


def test_client_responses_to_server_requests_are_forwarded() -> None:
    authorize(VIEWER, parse_message(_msg({"jsonrpc": "2.0", "id": "srv-1", "result": {}})), {})
