"""Real processes, real sockets: gateway → mock downstream MCP server (official SDK).

Each test session starts two uvicorn processes on free ports:

    test client ──HTTP──► gateway (task2_mcp_gateway) ──HTTP──► mock downstream (MCP SDK)

Tokens are minted with a key pair generated into a temp dir by ``devtokens``.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from task2_mcp_gateway import devtokens

pytestmark = pytest.mark.integration

ISSUER, AUDIENCE = "https://idp.it.local/", "quilr-mcp-gateway"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_healthy(url: str, proc: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited early with code {proc.returncode}; see its log")
        try:
            httpx.get(url, timeout=0.5)
        except httpx.HTTPError:
            time.sleep(0.1)
        else:
            return
    raise RuntimeError(f"{url} never came up")


@dataclass
class Stack:
    gateway: str
    downstream_log: Path
    private_key: Path

    def token(self, role: str, sub: str = "it-user") -> str:
        return devtokens.mint(
            self.private_key, role=role, subject=sub, issuer=ISSUER, audience=AUDIENCE
        )

    def executed_tools(self) -> list[str]:
        tools = []
        for line in self.downstream_log.read_text().splitlines():
            if line.startswith("{"):
                rec = json.loads(line)
                if rec.get("msg") == "downstream tool executed":
                    tools.append(rec["tool"])
        return tools


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    tmp = tmp_path_factory.mktemp("stack")
    private, public = devtokens.keygen(tmp / "keys")
    down_port, gw_port = _free_port(), _free_port()
    down_log = tmp / "downstream.log"
    with down_log.open("w") as log_fh:
        downstream = subprocess.Popen(  # noqa: S603 - fixed argv to our own module
            [sys.executable, "-m", "task2_mcp_gateway.mock_downstream", "--port", str(down_port)],
            stdout=subprocess.DEVNULL,
            stderr=log_fh,
            text=True,
        )
    env = {
        **os.environ,
        "GATEWAY_DOWNSTREAM_URL": f"http://127.0.0.1:{down_port}/mcp",
        "GATEWAY_JWT_ISSUER": ISSUER,
        "GATEWAY_JWT_AUDIENCE": AUDIENCE,
        "GATEWAY_JWT_PUBLIC_KEY_FILE": str(public),
        "GATEWAY_PORT": str(gw_port),
    }
    with (tmp / "gateway.log").open("w") as gw_log:
        gateway = subprocess.Popen(
            [sys.executable, "-m", "task2_mcp_gateway"],
            stdout=subprocess.DEVNULL,
            stderr=gw_log,
            text=True,
            env=env,
        )
    try:
        _wait_healthy(f"http://127.0.0.1:{down_port}/mcp", downstream)
        _wait_healthy(f"http://127.0.0.1:{gw_port}/healthz", gateway)
        yield Stack(f"http://127.0.0.1:{gw_port}/mcp", down_log, private)
    finally:
        for proc in (gateway, downstream):
            proc.terminate()
            proc.wait(timeout=10)


class RawSession:
    """A minimal MCP Streamable HTTP client over plain httpx, to see the raw wire."""

    def __init__(self, url: str, token: str) -> None:
        self.url = url
        self.headers = {
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
        }
        init = self.post(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "it", "version": "1"},
                },
            }
        )
        self.headers["mcp-session-id"] = init.response.headers["mcp-session-id"]
        self.headers["mcp-protocol-version"] = "2025-11-25"
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    @dataclass
    class Reply:
        response: httpx.Response
        message: dict[str, Any] | None

    def post(self, message: dict[str, Any]) -> RawSession.Reply:
        resp = httpx.post(self.url, json=message, headers=self.headers, timeout=10)
        return self.Reply(resp, _decode(resp))

    def call(self, name: str, req_id: int, **arguments: Any) -> RawSession.Reply:
        params = {"name": name, "arguments": arguments}
        return self.post({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params})


def _decode(resp: httpx.Response) -> dict[str, Any] | None:
    if not resp.content:
        return None
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        data = [ln[5:].strip() for ln in resp.text.splitlines() if ln.startswith("data:")]
        return json.loads(data[-1]) if data else None
    result: dict[str, Any] = resp.json()
    return result


# --- The brief, end to end -------------------------------------------------------------------


def test_viewer_lists_tools_through_the_gateway(stack: Stack) -> None:
    session = RawSession(stack.gateway, stack.token("viewer"))
    reply = session.post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert reply.message is not None
    names = {t["name"] for t in reply.message["result"]["tools"]}
    assert names == {"get_status", "list_users", "admin_reset_key", "admin_delete_user"}


def test_viewer_admin_call_is_denied_and_never_executed(stack: Stack) -> None:
    session = RawSession(stack.gateway, stack.token("viewer", sub="viewer-deny"))
    reply = session.call("admin_reset_key", 2, user_id="u1")
    assert reply.response.status_code == 200
    assert reply.message is not None
    assert reply.message["id"] == 2
    assert reply.message["error"]["code"] == -32001
    assert reply.message["error"]["message"] == "Unauthorized Tool Call"
    time.sleep(0.2)  # let the downstream log flush
    assert "admin_reset_key" not in stack.executed_tools()


def test_viewer_runs_ordinary_tools_and_admin_runs_admin_tools(stack: Stack) -> None:
    viewer = RawSession(stack.gateway, stack.token("viewer"))
    ok = viewer.call("get_status", 3)
    assert ok.message is not None
    assert ok.message["result"]["structuredContent"] == {"tool": "get_status", "status": "executed"}

    admin = RawSession(stack.gateway, stack.token("admin", sub="root"))
    done = admin.call("admin_reset_key", 4, user_id="u1")
    assert done.message is not None
    assert done.message["result"]["structuredContent"]["tool"] == "admin_reset_key"
    time.sleep(0.2)
    assert "admin_reset_key" in stack.executed_tools()


def test_missing_and_forged_tokens_are_rejected_before_downstream(stack: Stack) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert httpx.post(stack.gateway, json=body, timeout=10).status_code == 401
    forged = httpx.post(
        stack.gateway, json=body, headers={"authorization": "Bearer a.b.c"}, timeout=10
    )
    assert forged.status_code == 401
    assert 'error="invalid_token"' in forged.headers["www-authenticate"]


def test_official_sdk_client_works_through_the_gateway(stack: Stack) -> None:
    client = textwrap.dedent(
        """
        import sys, anyio
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
        from mcp.shared.exceptions import MCPError

        async def main(url, token):
            http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
            async with http, streamable_http_client(url, http_client=http) as (r, w), \\
                    ClientSession(r, w) as session:
                await session.initialize()
                names = sorted(t.name for t in (await session.list_tools()).tools)
                ok = await session.call_tool("get_status", {})
                try:
                    await session.call_tool("admin_delete_user", {})
                    code = None
                except MCPError as exc:
                    code = (exc.code, exc.message)
                print(names, ok.structured_content["status"], code, file=sys.stderr)

        anyio.run(main, sys.argv[1], sys.argv[2])
        """
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", client, stack.gateway, stack.token("viewer", sub="sdk")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert (
        "['admin_delete_user', 'admin_reset_key', 'get_status', 'list_users'] executed "
        "(-32001, 'Unauthorized Tool Call')"
    ) in proc.stderr
    assert "admin_delete_user" not in stack.executed_tools()
