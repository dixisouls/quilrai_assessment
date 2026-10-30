"""Integration tests over the real stdio transport (subprocess, raw bytes on the wire).

These are the tests that matter most for Task 1's grading criteria:

* **STDIO isolation**: every byte on stdout must be a JSON-RPC message.
* **Protocol compliance**: correct ids, result/error shapes and spec error codes.
* **Validation**: malformed arguments are rejected end to end.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import subprocess
import sys
import textwrap
import time
from typing import Any

import pytest

pytestmark = pytest.mark.integration

INIT = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "1"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


def _call(req_id: int, name: str, arguments: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _run(
    lines: list[str], expect: set[Any], *, argv: list[str] | None = None
) -> tuple[list[str], str]:
    """Drive a fresh server process the way a real MCP client does.

    Writes the handshake and ``lines``, reads stdout until a response for every
    id in ``expect`` has arrived (``None`` = an id-less error reply), and only
    then closes stdin. Per the MCP stdio lifecycle the client closes stdin after
    it has its answers, so a server may cancel work still in flight at EOF.
    """
    proc = subprocess.Popen(  # noqa: S603 - fixed argv to our own module
        argv or [sys.executable, "-m", "task1_mcp_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "LOG_LEVEL": "INFO"},
    )
    assert proc.stdin is not None and proc.stdout is not None
    for line in [json.dumps(INIT), json.dumps(INITIALIZED), *lines]:
        proc.stdin.write(line + "\n")
    proc.stdin.flush()

    stdout: list[str] = []
    pending = {0, *expect}
    deadline = time.monotonic() + 30
    while pending and time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 0.5)
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            break  # server exited early: the assertions below will say why
        stdout.append(line.rstrip("\n"))
        with contextlib.suppress(json.JSONDecodeError, TypeError, KeyError):
            pending.discard(json.loads(line)["id"])
    rest, stderr = proc.communicate(timeout=30)  # closes stdin: the client is done
    stdout.extend(rest.splitlines())
    assert proc.returncode == 0, stderr[-2000:]
    assert not pending, f"no response for ids {pending}; stderr: {stderr[-2000:]}"
    return stdout, stderr


def _responses(stdout: list[str]) -> dict[Any, dict[str, Any]]:
    """Parse every stdout line strictly as JSON-RPC 2.0; index responses by id."""
    out: dict[Any, dict[str, Any]] = {}
    for line in stdout:
        msg = json.loads(line)  # any non-JSON byte on stdout fails the test here
        assert msg["jsonrpc"] == "2.0"
        assert ("result" in msg) != ("error" in msg)
        out[msg["id"]] = msg
    return out


def test_full_session_over_raw_stdio() -> None:
    stdout, stderr = _run(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            json.dumps(_call(2, "get_customer_record", {"customer_id": "CUST-00042"})),
            json.dumps(
                _call(
                    3,
                    "trigger_refund",
                    {"customer_id": "CUST-00042", "amount": 10.5, "reason": "Duplicate charge"},
                )
            ),
            json.dumps(_call(4, "get_customer_record", {"customer_id": "CUST-9"})),
            json.dumps(_call(5, "trigger_refund", {"customer_id": "CUST-00042", "amount": "5"})),
            json.dumps(_call(6, "get_customer_record", {"customer_id": "CUST-99999"})),
            json.dumps(_call(7, "nope", {})),
            json.dumps({"jsonrpc": "2.0", "id": 8, "method": "no/such/method"}),
            json.dumps({"jsonrpc": "2.0", "id": "str-id", "method": "ping"}),
        ],
        expect={1, 2, 3, 4, 5, 6, 7, 8, "str-id"},
    )
    res = _responses(stdout)
    assert set(res) == {0, 1, 2, 3, 4, 5, 6, 7, 8, "str-id"}

    tools = {t["name"] for t in res[1]["result"]["tools"]}
    assert tools == {"get_customer_record", "trigger_refund"}

    assert res[2]["result"]["isError"] is False
    assert res[2]["result"]["structuredContent"]["customer_id"] == "CUST-00042"

    receipt = res[3]["result"]["structuredContent"]
    assert (receipt["amount"], receipt["remaining_refundable_balance"]) == ("10.50", "239.50")

    assert res[4]["error"]["code"] == -32602
    assert res[4]["error"]["data"]["errors"][0]["field"] == "customer_id"

    assert res[5]["error"]["code"] == -32602
    assert {e["field"] for e in res[5]["error"]["data"]["errors"]} == {"amount", "reason"}

    assert res[6]["result"]["isError"] is True  # business outcome, not protocol error
    assert res[7]["error"] == {
        "code": -32602,
        "message": "Unknown tool",
        "data": {"available_tools": ["get_customer_record", "trigger_refund"]},
    }
    assert res[8]["error"]["code"] == -32601
    assert res["str-id"]["result"] == {}

    # Logs went to stderr as structured JSON, including the refund audit event.
    records = [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]
    audits = [r for r in records if r.get("log_type") == "audit"]
    assert [a["audit"]["decision"] for a in audits] == ["allow"]


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("{not json", -32700),
        ('{"jsonrpc": "2.0", "id": 9, "method": "tools/list"', -32700),  # truncated
        ('{"foo": 1}', -32600),
        ("[]", -32600),  # batches are not part of MCP
        ('[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]', -32600),
        ('{"jsonrpc": "1.0", "id": 1, "method": "ping"}', -32600),
        ('"just a string"', -32600),
    ],
)
def test_malformed_messages_get_spec_errors_and_server_survives(line: str, code: int) -> None:
    stdout, _ = _run(
        [line, json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"})], expect={None, 99}
    )
    res = _responses(stdout)
    assert res[None]["error"]["code"] == code
    assert res[99]["result"] == {}  # still serving after the bad line


def test_internal_errors_do_not_leak_and_stdout_survives_stray_writes() -> None:
    # A harness server whose store misbehaves in every way that could corrupt stdout.
    harness = textwrap.dedent(
        """
        import os, sys
        from task1_mcp_server.__main__ import run
        from task1_mcp_server.store import seeded_store

        class LeakyStore(type(seeded_store())):
            def get(self, customer_id):
                print("STRAY PRINT")
                sys.stdout.write("STRAY sys.stdout\\n")
                os.write(1, b"STRAY fd1\\n")
                raise RuntimeError("password=hunter2 at /srv/secret.db")

        run(store=LeakyStore(seeded_store().all()))
        """
    )
    stdout, stderr = _run(
        [json.dumps(_call(1, "get_customer_record", {"customer_id": "CUST-00042"}))],
        expect={1},
        argv=[sys.executable, "-c", harness],
    )
    res = _responses(stdout)  # proves stdout is pure JSON-RPC despite the stray writes
    error = res[1]["error"]
    assert error["code"] == -32603
    assert error["message"] == "Internal error"
    assert "hunter2" not in json.dumps(error)
    assert "STRAY" in stderr  # diverted, not dropped
    assert error["data"]["correlation_id"] in stderr  # operator can find the traceback


def test_official_sdk_client_interoperates() -> None:
    client = textwrap.dedent(
        """
        import sys, anyio
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from mcp.shared.exceptions import MCPError

        async def main():
            params = StdioServerParameters(command=sys.executable, args=["-m", "task1_mcp_server"])
            async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
                await s.initialize()
                names = sorted(t.name for t in (await s.list_tools()).tools)
                ok = await s.call_tool("get_customer_record", {"customer_id": "CUST-00101"})
                try:
                    await s.call_tool("trigger_refund", {"customer_id": "x"})
                    code = None
                except MCPError as e:
                    code = e.code
                print(names, ok.structured_content["name"], code, file=sys.stderr)

        anyio.run(main)
        """
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", client], capture_output=True, text=True, timeout=60, check=False
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "['get_customer_record', 'trigger_refund'] Alan Turing -32602" in proc.stderr
