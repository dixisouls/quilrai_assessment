"""End to end: every service as a real process, configured only by a ``.env`` file.

    agent  ──► MCP gateway (Task 2: JWT, RBAC) ──► Task 1 tools over HTTP
    client ──► LLM gateway (Tasks 3 + 4: auth, token rate limit, failover,
               streaming PII redaction) ──► mock Anthropic (primary) / mock OpenAI (backup)

The services get no settings through their process environment. The fixture
writes one ``.env`` and points ``QUILR_ENV_FILE`` at it, so these tests also
prove that every service loads its own configuration from the file.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from task2_mcp_gateway import devtokens

pytestmark = pytest.mark.integration

ISSUER, AUDIENCE = "https://idp.e2e.local/", "quilr-mcp-gateway"
CLIENT_KEY = secrets.token_urlsafe(24)  # generated per run; never a literal in the repo
BUDGET_KEY = secrets.token_urlsafe(24)  # a second tenant, used only by the rate-limit test
TOKENS_PER_MINUTE = 3000  # not the 50,000 default, so a test can see the file was read
SERVICE_PREFIXES = (
    "LOG_",
    "APP_",
    "MCP_SERVER_",
    "GATEWAY_",
    "LLM_GATEWAY_",
    "LLM_ROUTER_",
    "ANTHROPIC_",
    "OPENAI_",
    "QUILR_",
)


# --- Process management ------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _clean_env(env_file: Path) -> dict[str, str]:
    """This process's environment minus every service variable, plus the file to load."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(SERVICE_PREFIXES)}
    env["QUILR_ENV_FILE"] = str(env_file)
    return env


def _spawn(args: list[str], log: Path, env: dict[str, str]) -> subprocess.Popen[str]:
    with log.open("w") as fh:
        return subprocess.Popen(  # noqa: S603 - fixed argv to our own modules
            [sys.executable, "-m", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=fh,
            text=True,
            env=env,
        )


def _wait_until_up(url: str, proc: subprocess.Popen[str], log: Path) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{url}: exited with {proc.returncode}:\n{log.read_text()[-2000:]}")
        try:
            httpx.get(url, timeout=0.5)  # any HTTP answer means the server is listening
        except httpx.HTTPError:
            time.sleep(0.1)
        else:
            return
    raise RuntimeError(f"{url} never came up")


@dataclass
class System:
    mcp_url: str
    llm_url: str
    private_key: Path
    task1_log: Path
    db_path: Path

    def token(self, role: str, sub: str = "e2e-user") -> str:
        return devtokens.mint(
            self.private_key, role=role, subject=sub, issuer=ISSUER, audience=AUDIENCE
        )

    def task1_events(self, msg: str) -> int:
        """How many times Task 1 logged ``msg`` (its log is one JSON object per line)."""
        count = 0
        for line in self.task1_log.read_text().splitlines():
            if line.startswith("{") and json.loads(line).get("msg") == msg:
                count += 1
        return count


@pytest.fixture(scope="module")
def system(tmp_path_factory: pytest.TempPathFactory) -> Iterator[System]:
    tmp = tmp_path_factory.mktemp("system")
    _private, public = devtokens.keygen(tmp / "keys")
    task1, mcp_gw, anthropic, openai, llm_gw = (_free_port() for _ in range(5))
    db_path = tmp / "ratelimit.sqlite3"
    env_file = tmp / "system.env"
    env_file.write_text(
        "\n".join(
            [
                "LOG_LEVEL=INFO",
                "APP_ENV=e2e",
                # Task 1 over HTTP, behind the MCP gateway
                f"MCP_SERVER_PORT={task1}",
                # Task 2: MCP security gateway
                f"GATEWAY_DOWNSTREAM_URL=http://127.0.0.1:{task1}/mcp",
                f"GATEWAY_JWT_ISSUER={ISSUER}",
                f"GATEWAY_JWT_AUDIENCE={AUDIENCE}",
                f"GATEWAY_JWT_PUBLIC_KEY_FILE={public}",
                f"GATEWAY_PORT={mcp_gw}",
                # Tasks 3 + 4: LLM gateway, against the mocks
                "ANTHROPIC_API_KEY=mock-not-a-real-key",
                "OPENAI_API_KEY=mock-not-a-real-key",
                f"LLM_GATEWAY_API_KEYS='{json.dumps([CLIENT_KEY, BUDGET_KEY])}'",
                f"LLM_GATEWAY_ANTHROPIC_BASE_URL=http://127.0.0.1:{anthropic}",
                "LLM_GATEWAY_DEFAULT_MAX_TOKENS=100",
                f"LLM_GATEWAY_PORT={llm_gw}",
                f"LLM_ROUTER_OPENAI_BASE_URL=http://127.0.0.1:{openai}/v1",
                f"LLM_ROUTER_DB_PATH={db_path}",
                f"LLM_ROUTER_TOKENS_PER_MINUTE={TOKENS_PER_MINUTE}",
                "",
            ]
        )
    )
    env = _clean_env(env_file)
    services = [
        (["task1_mcp_server.serve_http"], f"http://127.0.0.1:{task1}/mcp", "task1.log"),
        (
            ["task3_pii_guardrail.mock_provider", "--port", str(anthropic)],
            f"http://127.0.0.1:{anthropic}/v1/messages",
            "anthropic.log",
        ),
        (
            ["task4_model_router.mock_openai", "--port", str(openai)],
            f"http://127.0.0.1:{openai}/v1/chat/completions",
            "openai.log",
        ),
        (["task2_mcp_gateway"], f"http://127.0.0.1:{mcp_gw}/healthz", "mcp_gateway.log"),
        (["task4_model_router"], f"http://127.0.0.1:{llm_gw}/healthz", "llm_gateway.log"),
    ]
    procs = [(_spawn(args, tmp / log, env), url, tmp / log) for args, url, log in services]
    try:
        for proc, url, log in procs:
            _wait_until_up(url, proc, log)
        yield System(
            mcp_url=f"http://127.0.0.1:{mcp_gw}/mcp",
            llm_url=f"http://127.0.0.1:{llm_gw}/v1/chat/completions",
            private_key=tmp / "keys" / "private.pem",
            task1_log=tmp / "task1.log",
            db_path=db_path,
        )
    finally:
        for proc, _url, _log in reversed(procs):
            proc.terminate()
            proc.wait(timeout=10)


# --- Clients -----------------------------------------------------------------------------


def _decode(resp: httpx.Response) -> dict[str, Any]:
    """The JSON-RPC message in a JSON or SSE (Streamable HTTP) response."""
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        data = [ln[5:].strip() for ln in resp.text.splitlines() if ln.startswith("data:")]
        message: dict[str, Any] = json.loads(data[-1])
        return message
    body: dict[str, Any] = resp.json()
    return body


class McpSession:
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
                    "clientInfo": {"name": "e2e", "version": "1"},
                },
            }
        )
        self.headers["mcp-session-id"] = init.headers["mcp-session-id"]
        self.headers["mcp-protocol-version"] = "2025-11-25"
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def post(self, message: dict[str, Any]) -> httpx.Response:
        return httpx.post(self.url, json=message, headers=self.headers, timeout=10)

    def call(self, name: str, req_id: int, **arguments: Any) -> dict[str, Any]:
        params = {"name": name, "arguments": arguments}
        resp = self.post({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params})
        assert resp.status_code == 200
        return _decode(resp)


def _chat(system: System, content: str, *, key: str = CLIENT_KEY, **extra: Any) -> httpx.Response:
    body = {
        "model": "claude-opus-5-5",
        "messages": [{"role": "user", "content": content}],
        "stream": True,
        **extra,
    }
    return httpx.post(
        system.llm_url, json=body, headers={"authorization": f"Bearer {key}"}, timeout=20
    )


def _streamed_text(resp: httpx.Response) -> str:
    text = []
    for line in resp.text.splitlines():
        if line.startswith("data: {"):
            event = json.loads(line[len("data: ") :])
            if "choices" in event:
                text.append(event["choices"][0]["delta"].get("content") or "")
    return "".join(text)


# --- Configuration comes from the .env file --------------------------------------------


def test_every_service_is_configured_from_the_env_file(system: System) -> None:
    # Ports, keys, issuer, downstream URL and the rate limit all came from the file.
    resp = _chat(system, "hello")
    assert resp.status_code == 200
    assert resp.headers["x-ratelimit-limit-tokens"] == str(TOKENS_PER_MINUTE)  # not 50,000
    assert system.db_path.is_file()  # LLM_ROUTER_DB_PATH from the file, on disk
    session = McpSession(system.mcp_url, system.token("viewer"))  # issuer/audience from file
    assert session.headers["mcp-session-id"]


# --- Agent ──► MCP gateway (Task 2) ──► Task 1 tools ---------------------------------------


def test_agent_lists_task1_tools_through_the_gateway(system: System) -> None:
    session = McpSession(system.mcp_url, system.token("viewer"))
    reply = _decode(session.post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    assert {t["name"] for t in reply["result"]["tools"]} == {
        "get_customer_record",
        "trigger_refund",
    }


def test_viewer_reads_a_customer_record_through_the_gateway(system: System) -> None:
    session = McpSession(system.mcp_url, system.token("viewer"))
    reply = session.call("get_customer_record", 2, customer_id="CUST-00042")
    record = reply["result"]["structuredContent"]
    assert record["customer_id"] == "CUST-00042"
    assert record["email"] == "ada@example.com"


@pytest.mark.parametrize(
    ("tool", "arguments", "field"),
    [
        ("get_customer_record", {"customer_id": "cust-42"}, "customer_id"),
        (
            "trigger_refund",
            {"customer_id": "CUST-00042", "amount": "12", "reason": "damaged item on arrival"},
            "amount",
        ),
        ("trigger_refund", {"customer_id": "CUST-00042", "amount": 5, "reason": "short"}, "reason"),
    ],
)
def test_task1_validation_errors_reach_the_agent_through_the_gateway(
    system: System, tool: str, arguments: dict[str, Any], field: str
) -> None:
    session = McpSession(system.mcp_url, system.token("viewer"))
    reply = session.call(tool, 3, **arguments)
    assert reply["id"] == 3
    assert reply["error"]["code"] == -32602
    assert reply["error"]["message"] == "Invalid params"
    assert field in {d["field"] for d in reply["error"]["data"]["details"]}


def test_viewer_admin_call_is_refused_before_it_reaches_task1(system: System) -> None:
    before = system.task1_events("unknown tool requested")
    viewer = McpSession(system.mcp_url, system.token("viewer", sub="viewer-deny"))
    denied = viewer.call("admin_reset_key", 4, user_id="u1")
    assert denied["error"]["code"] == -32001
    assert denied["error"]["message"] == "Unauthorized Tool Call"
    time.sleep(0.3)  # let Task 1's log flush
    assert system.task1_events("unknown tool requested") == before  # Task 1 never saw it


def test_admin_calls_are_forwarded_to_task1(system: System) -> None:
    # Task 1 has no admin_* tool, so it answers "unknown tool" itself. The point is
    # that the gateway let an admin's call through to it.
    before = system.task1_events("unknown tool requested")
    admin = McpSession(system.mcp_url, system.token("admin", sub="root"))
    reply = admin.call("admin_reset_key", 5, user_id="u1")
    assert reply["error"]["code"] == -32602
    time.sleep(0.3)
    assert system.task1_events("unknown tool requested") == before + 1


def test_missing_and_forged_tokens_never_reach_task1(system: System) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    missing = httpx.post(system.mcp_url, json=body, timeout=10)
    forged = httpx.post(
        system.mcp_url, json=body, headers={"authorization": "Bearer a.b.c"}, timeout=10
    )
    assert (missing.status_code, forged.status_code) == (401, 401)
    assert forged.json()["error"]["data"]["request_id"] == forged.headers["x-request-id"]


# --- The two gateways together: tool output with PII, then an LLM call -----------------------


def test_customer_pii_from_a_tool_is_redacted_on_the_llm_response(system: System) -> None:
    session = McpSession(system.mcp_url, system.token("viewer"))
    record = session.call("get_customer_record", 6, customer_id="CUST-00042")
    record_json = json.dumps(record["result"]["structuredContent"])
    assert "ada@example.com" in record_json

    # The mock model repeats the prompt back, so the record's email comes back in the
    # response stream, split across chunks, and must be redacted there.
    resp = _chat(system, f"Summarise this customer for the support ticket: {record_json}")
    assert resp.status_code == 200
    assert resp.headers["x-gateway-provider"] == "anthropic"
    text = _streamed_text(resp)
    assert "CUST-00042" in text
    assert "[REDACTED]" in text
    assert "ada@example.com" not in resp.text


def test_failover_to_the_backup_keeps_redaction(system: System) -> None:
    resp = _chat(system, "[[status:429]] contact grace@example.com today")
    assert resp.status_code == 200
    assert resp.headers["x-gateway-provider"] == "openai"
    text = _streamed_text(resp)
    assert text.startswith("Backup says:")
    assert "[REDACTED]" in text
    assert "grace@example.com" not in resp.text


async def test_over_budget_tenant_gets_the_standard_429(system: System) -> None:
    headers = {"authorization": f"Bearer {BUDGET_KEY}"}

    def body(content: str) -> dict[str, Any]:
        return {
            "model": "claude-opus-5-5",
            "messages": [{"role": "user", "content": content}],
            "max_tokens": TOKENS_PER_MINUTE - 100,
        }

    async with httpx.AsyncClient(timeout=20) as client:
        # The first request holds a reservation for ~2,900 tokens while the model "thinks".
        first = asyncio.create_task(
            client.post(system.llm_url, json=body("[[hang:2]] hold the budget"), headers=headers)
        )
        await asyncio.sleep(0.5)
        second = await client.post(system.llm_url, json=body("me too"), headers=headers)
        assert (await first).status_code == 200

    assert second.status_code == 429
    error = second.json()["error"]
    assert error["type"] == "rate_limit_error"
    assert error["code"] == "token_rate_limit_exceeded"
    assert error["request_id"] == second.headers["x-request-id"]
    assert int(second.headers["retry-after"]) >= 1
    assert second.headers["x-ratelimit-limit-tokens"] == str(TOKENS_PER_MINUTE)
    for internal in ("sqlite", "Traceback", "127.0.0.1", "anthropic"):
        assert internal not in second.text
