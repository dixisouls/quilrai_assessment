"""HTTP-layer tests: the gateway app in-process, a recording fake downstream.

The fake downstream records every request it receives, which lets the tests
assert the property that matters most: **denied requests never reach
downstream**.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import task2_mcp_gateway.proxy as proxy_mod
from task2_mcp_gateway.auth import TokenVerifier
from task2_mcp_gateway.config import GatewaySettings
from task2_mcp_gateway.proxy import create_app

ISSUER = "https://idp.test.local/"
AUDIENCE = "quilr-mcp-gateway"
DOWNSTREAM = "http://downstream.internal:9000/mcp"
Minter = Callable[..., str]


class RecordingDownstream:
    """Fake MCP server: records requests, answers like a JSON-mode MCP server."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.behaviour: Callable[[httpx.Request], httpx.Response] | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.behaviour is not None:
            return self.behaviour(request)
        if request.method != "POST":
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=b"")
        body = json.loads(request.content)
        if "id" not in body:
            return httpx.Response(202)
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "mcp-session-id": "sess-1",
                "set-cookie": "internal=1",
                "server": "internal-mcp/1.0",
            },
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"echo": body.get("method")}},
        )

    @property
    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests if r.content]


@pytest.fixture
def downstream() -> RecordingDownstream:
    return RecordingDownstream()


@pytest.fixture
async def client(
    downstream: RecordingDownstream, rsa_public_pem: bytes
) -> AsyncIterator[httpx.AsyncClient]:
    settings = GatewaySettings(
        downstream_url=DOWNSTREAM, jwt_issuer=ISSUER, jwt_audience=AUDIENCE, max_body_bytes=4096
    )
    verifier = TokenVerifier.from_pem([rsa_public_pem], issuer=ISSUER, audience=AUDIENCE)
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(downstream.handler))
    app = create_app(settings, verifier, upstream)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway"
    ) as c:
        yield c
    await upstream.aclose()


def _auth(mint: Minter, role: str = "viewer") -> dict[str, str]:
    return {"authorization": f"Bearer {mint(role=role)}", "content-type": "application/json"}


def _rpc(method: str, req_id: Any = 1, **params: Any) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params:
        msg["params"] = params
    return msg


# --- The brief's behaviour ----------------------------------------------------------


async def test_tools_list_is_forwarded_transparently(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    resp = await client.post("/mcp", json=_rpc("tools/list"), headers=_auth(mint))
    assert resp.status_code == 200
    assert resp.json() == {"jsonrpc": "2.0", "id": 1, "result": {"echo": "tools/list"}}
    assert downstream.bodies == [_rpc("tools/list")]


async def test_viewer_admin_call_is_intercepted_and_never_forwarded(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    resp = await client.post(
        "/mcp", json=_rpc("tools/call", 7, name="admin_reset_key"), headers=_auth(mint)
    )
    assert resp.status_code == 200  # JSON-RPC convention (decided with the user)
    body = resp.json()
    assert body["id"] == 7
    assert body["error"]["code"] == -32001
    assert body["error"]["message"] == "Unauthorized Tool Call"
    assert body["error"]["data"]["request_id"] == resp.headers["x-request-id"]
    assert downstream.requests == []  # the downstream server was never called


async def test_admin_may_call_admin_tools(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    resp = await client.post(
        "/mcp", json=_rpc("tools/call", name="admin_reset_key"), headers=_auth(mint, "admin")
    )
    assert resp.json()["result"] == {"echo": "tools/call"}
    assert len(downstream.requests) == 1


async def test_viewer_may_call_non_admin_tools(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    resp = await client.post(
        "/mcp", json=_rpc("tools/call", name="get_status"), headers=_auth(mint)
    )
    assert resp.json()["result"] == {"echo": "tools/call"}


# --- Authentication -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "error"),
    [
        ({}, None),  # no credentials: RFC 6750 says no error attribute
        ({"authorization": "Bearer garbage"}, "invalid_token"),
        ({"authorization": "Basic dXNlcjpwYXNz"}, "invalid_token"),
    ],
)
async def test_unauthenticated_requests_get_401_and_are_not_forwarded(
    client: httpx.AsyncClient,
    downstream: RecordingDownstream,
    headers: dict[str, str],
    error: str | None,
) -> None:
    resp = await client.post("/mcp", json=_rpc("tools/list"), headers=headers)
    assert resp.status_code == 401
    challenge = resp.headers["www-authenticate"]
    assert challenge.startswith("Bearer")
    assert (f'error="{error}"' in challenge) if error else ("error=" not in challenge)
    assert resp.json()["error"]["code"] == -32000
    assert downstream.requests == []


async def test_expired_token_says_so(client: httpx.AsyncClient, mint: Minter) -> None:
    past = int(time.time()) - 3600
    headers = {"authorization": f"Bearer {mint(iat=past - 60, exp=past)}"}
    resp = await client.post("/mcp", json=_rpc("tools/list"), headers=headers)
    assert resp.status_code == 401
    assert 'error_description="token expired"' in resp.headers["www-authenticate"]


async def test_auth_is_checked_before_the_body_is_read(
    client: httpx.AsyncClient, downstream: RecordingDownstream
) -> None:
    # An unauthenticated caller can't make the gateway buffer or parse anything.
    resp = await client.post("/mcp", content=b"x" * 100_000, headers={})
    assert resp.status_code == 401


async def test_forged_admin_token_is_rejected(
    client: httpx.AsyncClient,
    downstream: RecordingDownstream,
    other_rsa_key: rsa.RSAPrivateKey,
) -> None:
    now = int(time.time())
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "role": "admin", "exp": now + 60},
        other_rsa_key,
        algorithm="RS256",
    )
    resp = await client.post(
        "/mcp",
        json=_rpc("tools/call", name="admin_reset_key"),
        headers={"authorization": f"Bearer {forged}"},
    )
    assert resp.status_code == 401
    assert downstream.requests == []


# --- Malformed input -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "status", "code"),
    [
        (b"{not json", 400, -32700),
        (b"[]", 400, -32600),
        (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}',
            400,
            -32600,
        ),
        (b'{"jsonrpc":"2.0","id":1,"method":"admin/shutdown"}', 200, -32601),
        (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}', 200, -32602),
    ],
)
async def test_bad_messages_are_answered_by_the_gateway(
    client: httpx.AsyncClient,
    downstream: RecordingDownstream,
    mint: Minter,
    content: bytes,
    status: int,
    code: int,
) -> None:
    resp = await client.post("/mcp", content=content, headers=_auth(mint))
    assert resp.status_code == status
    assert resp.json()["error"]["code"] == code
    assert downstream.requests == []


async def test_oversized_body_is_rejected_with_413(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    big = _rpc("tools/call", name="get_status", arguments={"blob": "x" * 10_000})
    resp = await client.post("/mcp", json=big, headers=_auth(mint))
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == -32600
    assert downstream.requests == []


async def test_wrong_content_type_is_rejected(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    headers = {**_auth(mint), "content-type": "text/plain"}
    resp = await client.post("/mcp", content=json.dumps(_rpc("tools/list")), headers=headers)
    assert resp.status_code == 415
    assert downstream.requests == []


# --- What crosses the gateway ---------------------------------------------------------------


async def test_client_credentials_and_unknown_headers_are_not_forwarded(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    headers = {
        **_auth(mint),
        "cookie": "session=abc",
        "origin": "https://evil.example",
        "x-forwarded-for": "1.2.3.4",
        "mcp-session-id": "sess-1",
        "mcp-protocol-version": "2025-11-25",
        "accept": "application/json, text/event-stream",
    }
    await client.post("/mcp", json=_rpc("tools/list"), headers=headers)
    [forwarded] = downstream.requests
    names = {k.lower() for k in forwarded.headers}
    assert "authorization" not in names
    assert {"cookie", "origin", "x-forwarded-for"}.isdisjoint(names)
    assert forwarded.headers["mcp-session-id"] == "sess-1"
    assert forwarded.headers["mcp-protocol-version"] == "2025-11-25"
    assert forwarded.headers["accept"] == "application/json, text/event-stream"
    assert str(forwarded.url) == DOWNSTREAM  # fixed by config, never by the client


async def test_downstream_internal_headers_are_not_returned(
    client: httpx.AsyncClient, mint: Minter
) -> None:
    resp = await client.post("/mcp", json=_rpc("tools/list"), headers=_auth(mint))
    assert resp.headers["mcp-session-id"] == "sess-1"
    assert "set-cookie" not in resp.headers
    assert "server" not in resp.headers or "internal" not in resp.headers["server"]


async def test_forwarded_body_is_the_reserialised_authorized_message(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    raw = b'{ "jsonrpc" : "2.0", "id":1,  "method":"tools/call","params":{"name":"get_status"} }'
    await client.post("/mcp", content=raw, headers=_auth(mint))
    assert downstream.requests[0].content == (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status"}}'
    )


async def test_notifications_pass_through_with_202(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    resp = await client.post("/mcp", json=note, headers=_auth(mint))
    assert resp.status_code == 202
    assert downstream.bodies == [note]


async def test_sse_responses_are_streamed_through(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    events = b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'
    downstream.behaviour = lambda _r: httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=events
    )
    resp = await client.post("/mcp", json=_rpc("tools/list"), headers=_auth(mint))
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert resp.content == events


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_get_and_delete_require_auth_then_forward(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter, method: str
) -> None:
    assert (await client.request(method, "/mcp")).status_code == 401
    assert downstream.requests == []
    resp = await client.request(
        method, "/mcp", headers={"authorization": f"Bearer {mint()}", "mcp-session-id": "s"}
    )
    assert resp.status_code == 200
    assert downstream.requests[0].method == method


# --- Downstream failures ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "status"),
    [(httpx.ConnectError("refused: 10.0.0.7:9000"), 502), (httpx.ReadTimeout("slow"), 504)],
)
async def test_downstream_failures_are_sanitised(
    client: httpx.AsyncClient,
    downstream: RecordingDownstream,
    mint: Minter,
    exc: Exception,
    status: int,
) -> None:
    def fail(_request: httpx.Request) -> httpx.Response:
        raise exc

    downstream.behaviour = fail
    resp = await client.post("/mcp", json=_rpc("tools/list", 9), headers=_auth(mint))
    assert resp.status_code == status
    body = resp.json()
    assert body["id"] == 9
    assert body["error"]["code"] == -32002
    assert body["error"]["message"] == "Downstream unavailable"
    assert "10.0.0.7" not in resp.text
    assert "downstream.internal" not in resp.text


# --- Correlation ----------------------------------------------------------------------------------


async def test_every_response_carries_a_request_id(client: httpx.AsyncClient, mint: Minter) -> None:
    ok = await client.post("/mcp", json=_rpc("tools/list"), headers=_auth(mint))
    denied = await client.post("/mcp", json=_rpc("tools/list"), headers={})
    assert len(ok.headers["x-request-id"]) == 32
    assert denied.json()["error"]["data"]["request_id"] == denied.headers["x-request-id"]


async def test_safe_client_request_id_is_kept_and_forwarded(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter
) -> None:
    headers = {**_auth(mint), "x-request-id": "trace-abc.123"}
    resp = await client.post("/mcp", json=_rpc("tools/list"), headers=headers)
    assert resp.headers["x-request-id"] == "trace-abc.123"
    assert downstream.requests[0].headers["x-request-id"] == "trace-abc.123"


async def test_healthz(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert (resp.status_code, resp.json()) == (200, {"status": "ok"})


# --- Review regressions --------------------------------------------------------


async def test_unexpected_errors_get_the_envelope_not_a_bare_500(
    client: httpx.AsyncClient, mint: Minter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("internal detail /srv/secret")

    monkeypatch.setattr(proxy_mod, "authorize", boom)
    resp = await client.post("/mcp", json=_rpc("tools/list", 3), headers=_auth(mint))
    assert resp.status_code == 500
    body = resp.json()
    assert body["error"]["code"] == -32603
    assert body["error"]["message"] == "Internal error"
    assert body["error"]["data"]["request_id"] == resp.headers["x-request-id"]
    assert "secret" not in resp.text


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "PUT", "PATCH"])
async def test_other_http_methods_are_refused_at_the_gateway(
    client: httpx.AsyncClient, downstream: RecordingDownstream, mint: Minter, method: str
) -> None:
    resp = await client.request(method, "/mcp", headers={"authorization": f"Bearer {mint()}"})
    assert resp.status_code == 405
    assert "x-request-id" in resp.headers
    if method != "HEAD":
        assert resp.json()["error"]["data"]["request_id"] == resp.headers["x-request-id"]
    assert downstream.requests == []


async def test_unknown_paths_are_404_with_envelope_and_no_redirect(
    client: httpx.AsyncClient,
) -> None:
    for path in ("/mcp/", "/admin", "/"):
        resp = await client.post(path, json=_rpc("tools/list"))
        assert resp.status_code == 404, path
        assert resp.json()["error"]["data"]["request_id"] == resp.headers["x-request-id"]
