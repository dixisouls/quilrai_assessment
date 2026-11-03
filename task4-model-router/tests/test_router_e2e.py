"""Real processes, real sockets: the full LLM gateway with mock Anthropic and mock OpenAI.

client -> gateway (auth, rate limit, failover, redaction)
            -> mock Anthropic (primary, task3_pii_guardrail.mock_provider)
            -> mock OpenAI   (backup,  task4_model_router.mock_openai)
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.integration

KEY_A = secrets.token_urlsafe(24)  # generated per run; never a literal in the repo
KEY_B = secrets.token_urlsafe(24)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(url: str, proc: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited early with code {proc.returncode}; see its log")
        try:
            httpx.post(url, timeout=0.5)
        except httpx.HTTPError:
            time.sleep(0.1)
        else:
            return
    raise RuntimeError(f"{url} never came up")


@dataclass
class Stack:
    url: str
    log: Path
    db: Path


def _spawn(argv: list[str], log: Path, env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    with log.open("w") as fh:
        return subprocess.Popen(  # noqa: S603 - fixed argv to our own modules
            argv, stdout=subprocess.DEVNULL, stderr=fh, text=True, env=env
        )


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    tmp = tmp_path_factory.mktemp("router")
    anthropic_port, openai_port, gw_port = _free_port(), _free_port(), _free_port()
    procs = [
        _spawn(
            [
                sys.executable,
                "-m",
                "task3_pii_guardrail.mock_provider",
                "--port",
                str(anthropic_port),
            ],
            tmp / "anthropic.log",
        ),
        _spawn(
            [sys.executable, "-m", "task4_model_router.mock_openai", "--port", str(openai_port)],
            tmp / "openai.log",
        ),
    ]
    env = {
        **os.environ,
        "LLM_GATEWAY_API_KEYS": json.dumps([KEY_A, KEY_B]),
        "LLM_GATEWAY_ANTHROPIC_BASE_URL": f"http://127.0.0.1:{anthropic_port}",
        "LLM_GATEWAY_DEFAULT_MAX_TOKENS": "100",
        "LLM_GATEWAY_PORT": str(gw_port),
        "LLM_ROUTER_OPENAI_BASE_URL": f"http://127.0.0.1:{openai_port}/v1",
        "LLM_ROUTER_DB_PATH": str(tmp / "ratelimit.sqlite3"),
        "LLM_ROUTER_TOKENS_PER_MINUTE": "2000",
        "LLM_ROUTER_BACKUP_MAX_RETRIES": "0",
        "ANTHROPIC_API_KEY": "mock-not-real",
        "OPENAI_API_KEY": "mock-not-real",
    }
    procs.append(_spawn([sys.executable, "-m", "task4_model_router"], tmp / "gateway.log", env))
    try:
        _wait(f"http://127.0.0.1:{anthropic_port}/v1/messages", procs[0])
        _wait(f"http://127.0.0.1:{openai_port}/v1/chat/completions", procs[1])
        _wait(f"http://127.0.0.1:{gw_port}/healthz", procs[2])
        yield Stack(
            f"http://127.0.0.1:{gw_port}/v1/chat/completions",
            tmp / "gateway.log",
            tmp / "ratelimit.sqlite3",
        )
    finally:
        for proc in procs:
            proc.terminate()
            proc.wait(timeout=10)


def _post(stack: Stack, prompt: str, *, key: str = KEY_A, **extra: Any) -> httpx.Response:
    body = {"model": "any", "messages": [{"role": "user", "content": prompt}], **extra}
    return httpx.post(stack.url, json=body, headers={"authorization": f"Bearer {key}"}, timeout=30)


def _text(resp: httpx.Response) -> str:
    return str(resp.json()["choices"][0]["message"]["content"])


def _audits(stack: Stack, action: str) -> list[dict[str, Any]]:
    time.sleep(0.2)
    return [
        json.loads(line)["audit"]
        for line in stack.log.read_text().splitlines()
        if '"log_type": "audit"' in line and f'"action": "{action}"' in line
    ]


# --- Failover ----------------------------------------------------------------------------------


def test_healthy_primary_serves(stack: Stack) -> None:
    resp = _post(stack, "hello mail a@b.io")
    assert resp.status_code == 200
    assert resp.headers["x-gateway-provider"] == "anthropic"
    assert _text(resp) == "You said: hello mail [REDACTED]"


def test_primary_429_fails_over_to_openai_with_redaction_intact(stack: Stack) -> None:
    resp = _post(stack, "[[status:429]] card 4111 1111 1111 1111 please")
    assert resp.status_code == 200
    assert resp.headers["x-gateway-provider"] == "openai"
    assert resp.json()["model"] == "gpt-6.1-sol"
    assert _text(resp) == "Backup says: card [REDACTED] please"
    assert any(a["metadata"]["reason"] == "rate_limited" for a in _audits(stack, "llm.failover"))


def test_primary_timeout_fails_over_at_3000ms(stack: Stack) -> None:
    started = time.perf_counter()
    resp = _post(stack, "[[hang:6]] are you there", stream=True)
    elapsed = time.perf_counter() - started
    assert resp.status_code == 200
    assert resp.headers["x-gateway-provider"] == "openai"
    assert 3.0 <= elapsed < 4.5, elapsed  # the brief's 3000 ms, not the primary's 6 s
    assert any(a["metadata"]["reason"] == "timeout" for a in _audits(stack, "llm.failover"))


def test_other_primary_errors_do_not_fail_over(stack: Stack) -> None:
    resp = _post(stack, "[[status:529]] overloaded")
    assert resp.status_code == 502
    assert resp.json()["error"]["type"] == "provider_error"


def test_both_providers_failing_returns_the_standard_error(stack: Stack) -> None:
    resp = _post(stack, "[[status:429]] [[openai:429]] hi")
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "4"
    err = resp.json()["error"]
    assert set(err) == {"message", "type", "code", "param", "request_id"}
    assert err["type"] == "rate_limit_error"
    for internal in ("mock", "openai.com", "anthropic.com", "Traceback", "127.0.0.1"):
        assert internal not in resp.text


# --- Rate limiting -----------------------------------------------------------------------------


def test_concurrent_requests_cannot_overspend_the_window_and_budget_comes_back(
    stack: Stack,
) -> None:
    # Each [[slow]] request reserves ~900 tokens while in flight; limit is 2000/min.
    def call(_: int) -> httpx.Response:
        return _post(stack, "[[slow]] long answer please", key=KEY_B, max_tokens=890)

    with concurrent.futures.ThreadPoolExecutor(3) as pool:
        results = list(pool.map(call, range(3)))
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200, 200, 429]
    limited = next(r for r in results if r.status_code == 429)
    assert int(limited.headers["retry-after"]) >= 1
    assert limited.json()["error"]["code"] == "token_rate_limit_exceeded"
    assert int(limited.headers["x-ratelimit-remaining-tokens"]) < 900

    # Settled to real (small) usage, so the budget is available again at once.
    ok = _post(stack, "short", key=KEY_B, max_tokens=890)
    assert ok.status_code == 200
    assert int(ok.headers["x-ratelimit-remaining-tokens"]) > 0


def test_request_larger_than_the_budget_is_rejected_up_front(stack: Stack) -> None:
    resp = _post(stack, "hi", max_tokens=5000)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "request_exceeds_token_budget"


def test_usage_lives_in_an_on_disk_sqlite_file(stack: Stack) -> None:
    _post(stack, "persist me")
    assert stack.db.exists()
    with sqlite3.connect(stack.db) as db:
        (rows,) = db.execute("SELECT COUNT(*) FROM token_usage").fetchone()
        (tenants,) = db.execute("SELECT COUNT(DISTINCT tenant) FROM token_usage").fetchone()
    assert rows > 0
    assert tenants >= 1


# --- Live providers (opt-in: real API calls cost money) -----------------------------------------

LIVE = pytest.mark.skipif(
    not (
        os.environ.get("RUN_LIVE_TESTS") == "1"
        and os.environ.get("ANTHROPIC_API_KEY")
        and os.environ.get("OPENAI_API_KEY")
    ),
    reason="set RUN_LIVE_TESTS=1 plus ANTHROPIC_API_KEY and OPENAI_API_KEY",
)


@pytest.fixture(scope="module")
def live_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    """Real Anthropic primary and real OpenAI backup; a tiny budget so limiting is cheap."""
    tmp = tmp_path_factory.mktemp("live")
    port = _free_port()
    env = {
        **os.environ,
        "LLM_GATEWAY_API_KEYS": json.dumps([KEY_A]),
        "LLM_GATEWAY_DEFAULT_MAX_TOKENS": "20",
        "LLM_GATEWAY_PORT": str(port),
        "LLM_ROUTER_DB_PATH": str(tmp / "ratelimit.sqlite3"),
        "LLM_ROUTER_TOKENS_PER_MINUTE": "60",
    }
    proc = _spawn([sys.executable, "-m", "task4_model_router"], tmp / "gateway.log", env)
    try:
        _wait(f"http://127.0.0.1:{port}/healthz", proc)
        yield Stack(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            tmp / "gateway.log",
            tmp / "ratelimit.sqlite3",
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.mark.live
@LIVE
def test_live_primary_and_live_rate_limit(live_stack: Stack) -> None:
    # A real call settles to the provider's real usage (~20 tokens for this prompt),
    # and each new request reserves prompt + max_tokens (~28) against a 60-token budget,
    # so the gateway itself must refuse the third call before contacting any provider.
    statuses = []
    for _ in range(4):
        resp = _post(live_stack, "Reply with the single word: ok")
        statuses.append(resp.status_code)
        if resp.status_code == 200:
            assert resp.headers["x-gateway-provider"] == "anthropic"
        if resp.status_code == 429:
            assert resp.json()["error"]["code"] == "token_rate_limit_exceeded"
            break
    assert statuses == [200, 200, 429], statuses
    with sqlite3.connect(live_stack.db) as db:
        settled = [row[0] for row in db.execute("SELECT tokens FROM token_usage ORDER BY id")]
    reservation = 31 // 4 + 1 + 20  # ceil(prompt chars / 4) + max_tokens
    assert len(settled) == 2
    assert all(0 < tokens != reservation for tokens in settled), settled  # real usage, not estimate


@pytest.mark.live
@LIVE
def test_live_failover_to_real_openai(tmp_path: Path) -> None:
    mock_port, gw_port = _free_port(), _free_port()
    mock = _spawn(
        [sys.executable, "-m", "task3_pii_guardrail.mock_provider", "--port", str(mock_port)],
        tmp_path / "mock.log",
    )
    env = {
        **os.environ,
        "LLM_GATEWAY_API_KEYS": json.dumps([KEY_A]),
        "LLM_GATEWAY_ANTHROPIC_BASE_URL": f"http://127.0.0.1:{mock_port}",  # primary always 429s
        "LLM_GATEWAY_DEFAULT_MAX_TOKENS": "20",
        "LLM_GATEWAY_PORT": str(gw_port),
        "LLM_ROUTER_DB_PATH": str(tmp_path / "ratelimit.sqlite3"),
    }
    gateway = _spawn([sys.executable, "-m", "task4_model_router"], tmp_path / "gw.log", env)
    try:
        _wait(f"http://127.0.0.1:{mock_port}/v1/messages", mock)
        _wait(f"http://127.0.0.1:{gw_port}/healthz", gateway)
        resp = _post(
            Stack(f"http://127.0.0.1:{gw_port}/v1/chat/completions", tmp_path, tmp_path),
            "[[status:429]] Repeat exactly: my email is jane.doe@example.com",
        )
        assert resp.status_code == 200, resp.text
        assert resp.headers["x-gateway-provider"] == "openai"
        assert "jane.doe@example.com" not in resp.text
    finally:
        for proc in (gateway, mock):
            proc.terminate()
            proc.wait(timeout=10)
