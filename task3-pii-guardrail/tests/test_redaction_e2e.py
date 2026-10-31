"""Real processes, real sockets: client → gateway → (Anthropic SDK) → mock Anthropic API.

The mock echoes the prompt in 3-character deltas, so PII in the prompt is
guaranteed to be split across stream chunks on its way back.
"""

from __future__ import annotations

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

pytestmark = pytest.mark.integration

API_KEY = secrets.token_urlsafe(24)  # generated per run; never a literal in the repo


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
            httpx.get(url, timeout=0.5)
        except httpx.HTTPError:
            time.sleep(0.1)
        else:
            return
    raise RuntimeError(f"{url} never came up")


@dataclass
class Stack:
    url: str
    gateway_log: Path


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    tmp = tmp_path_factory.mktemp("llm")
    mock_port, gw_port = _free_port(), _free_port()
    with (tmp / "mock.log").open("w") as mock_log:
        mock = subprocess.Popen(  # noqa: S603 - fixed argv to our own module
            [sys.executable, "-m", "task3_pii_guardrail.mock_provider", "--port", str(mock_port)],
            stdout=subprocess.DEVNULL,
            stderr=mock_log,
            text=True,
        )
    env = {
        **os.environ,
        "LLM_GATEWAY_API_KEYS": json.dumps([API_KEY]),
        "LLM_GATEWAY_ANTHROPIC_BASE_URL": f"http://127.0.0.1:{mock_port}",
        "LLM_GATEWAY_PROVIDER_MAX_RETRIES": "0",
        "LLM_GATEWAY_PORT": str(gw_port),
        "ANTHROPIC_API_KEY": "mock-not-a-real-key",
    }
    gw_log_path = tmp / "gateway.log"
    with gw_log_path.open("w") as gw_log:
        gateway = subprocess.Popen(
            [sys.executable, "-m", "task3_pii_guardrail"],
            stdout=subprocess.DEVNULL,
            stderr=gw_log,
            text=True,
            env=env,
        )
    try:
        _wait(f"http://127.0.0.1:{gw_port}/healthz", gateway)
        yield Stack(f"http://127.0.0.1:{gw_port}/v1/chat/completions", gw_log_path)
    finally:
        for proc in (gateway, mock):
            proc.terminate()
            proc.wait(timeout=10)


def _request(prompt: str, *, stream: bool = True) -> dict[str, Any]:
    return {"model": "any", "messages": [{"role": "user", "content": prompt}], "stream": stream}


HEADERS = {"authorization": f"Bearer {API_KEY}"}


def _stream_events(url: str, prompt: str) -> tuple[list[Any], list[float]]:
    events: list[Any] = []
    arrival: list[float] = []
    start = time.perf_counter()
    with httpx.stream("POST", url, json=_request(prompt), headers=HEADERS, timeout=30) as resp:
        assert resp.status_code == 200, resp.read()
        for line in resp.iter_lines():
            if line.startswith("data: "):
                payload = line[6:]
                events.append(payload if payload == "[DONE]" else json.loads(payload))
                arrival.append(time.perf_counter() - start)
    return events, arrival


def _text(events: list[Any]) -> str:
    return "".join(
        str(e["choices"][0]["delta"].get("content") or "")
        for e in events
        if isinstance(e, dict) and "choices" in e
    )


PII_PROMPT = "mail jane.doe@example.com, ssn 123-45-6789, card 4111 1111 1111 1111 thanks"
REDACTED_ECHO = "You said: mail [REDACTED], ssn [REDACTED], card [REDACTED] thanks"


def test_pii_split_across_real_sdk_stream_chunks_is_redacted(stack: Stack) -> None:
    events, _ = _stream_events(stack.url, PII_PROMPT)
    assert events[-1] == "[DONE]"
    assert _text(events) == REDACTED_ECHO
    time.sleep(0.2)
    audits = [
        json.loads(line)
        for line in stack.gateway_log.read_text().splitlines()
        if '"log_type": "audit"' in line
    ]
    assert any(a["audit"]["metadata"].get("count") == 3 for a in audits)
    assert "jane.doe" not in stack.gateway_log.read_text()  # nor in the gateway's own logs


def test_non_streaming_is_redacted(stack: Stack) -> None:
    resp = httpx.post(
        stack.url, json=_request(PII_PROMPT, stream=False), headers=HEADERS, timeout=30
    )
    assert resp.json()["choices"][0]["message"]["content"] == REDACTED_ECHO


def test_first_token_is_not_held_until_the_stream_ends(stack: Stack) -> None:
    # The mock sends "You", " sa", then pauses 1 s. "You" alone could still grow
    # into an email, but once " sa" arrives "You " is safe and must leave at once.
    events, arrival = _stream_events(stack.url, "[[slow]] hello there friend")
    content_times = [
        t
        for e, t in zip(events, arrival, strict=True)
        if isinstance(e, dict) and "choices" in e and e["choices"][0]["delta"].get("content")
    ]
    first = next(
        e
        for e in events
        if isinstance(e, dict) and e.get("choices") and e["choices"][0]["delta"].get("content")
    )
    assert first["choices"][0]["delta"]["content"] == "You "
    assert content_times[0] < 0.5, content_times  # released before the pause ended
    assert content_times[-1] > 1.0


def test_provider_rate_limit_becomes_429_with_retry_after(stack: Stack) -> None:
    resp = httpx.post(stack.url, json=_request("[[status:429]] hi"), headers=HEADERS, timeout=30)
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "3"
    assert resp.json()["error"]["type"] == "rate_limit_error"


def test_provider_overload_becomes_sanitised_502(stack: Stack) -> None:
    resp = httpx.post(stack.url, json=_request("[[status:529]] hi"), headers=HEADERS, timeout=30)
    assert resp.status_code == 502
    assert "overloaded" not in resp.text.lower() or "provider" in resp.json()["error"]["message"]


def test_midstream_provider_error_ends_cleanly(stack: Stack) -> None:
    events, _ = _stream_events(stack.url, "[[midstream-error]] tell me jane.doe@example.com")
    assert events[-1] == "[DONE]"
    assert events[-2]["error"]["type"] == "provider_error"
    # An SSE error event inside a 200 stream is an outage, not "rejected the request".
    assert events[-2]["error"]["message"] == "The model provider is unavailable."
    assert "jane" not in json.dumps(events)


def test_values_meeting_at_real_content_block_boundaries_are_redacted(stack: Stack) -> None:
    events, _ = _stream_events(stack.url, "[[blocks]]")
    assert _text(events) == "Card: [REDACTED]0 is the code. SSN [REDACTED]0 too."
    resp = httpx.post(
        stack.url, json=_request("[[blocks]]", stream=False), headers=HEADERS, timeout=30
    )
    assert resp.json()["choices"][0]["message"]["content"] == _text(events)


def test_wrong_key_is_rejected(stack: Stack) -> None:
    resp = httpx.post(
        stack.url, json=_request("hi"), headers={"authorization": "Bearer nope"}, timeout=30
    )
    assert resp.status_code == 401


# --- Live provider (opt-in: real API calls cost money) ------------------------------------


@pytest.mark.live
@pytest.mark.skipif(
    not (os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("RUN_LIVE_TESTS") == "1"),
    reason="set ANTHROPIC_API_KEY and RUN_LIVE_TESTS=1 to call the real Anthropic API",
)
def test_live_anthropic_output_is_redacted(tmp_path: Path) -> None:
    port = _free_port()
    env = {
        **os.environ,
        "LLM_GATEWAY_API_KEYS": json.dumps([API_KEY]),
        "LLM_GATEWAY_PORT": str(port),
        "LLM_GATEWAY_DEFAULT_MAX_TOKENS": "200",
    }
    with (tmp_path / "gw.log").open("w") as log:
        gateway = subprocess.Popen(
            [sys.executable, "-m", "task3_pii_guardrail"],
            stdout=subprocess.DEVNULL,
            stderr=log,
            env=env,
            text=True,
        )
    try:
        _wait(f"http://127.0.0.1:{port}/healthz", gateway)
        prompt = (
            "Repeat exactly, with no other text: Contact jane.doe@example.com "
            "or card 4111 1111 1111 1111."
        )
        events, _ = _stream_events(f"http://127.0.0.1:{port}/v1/chat/completions", prompt)
        text = _text(events)
        assert text  # the model answered
        assert "jane.doe@example.com" not in text
        assert "4111 1111 1111 1111" not in text
    finally:
        gateway.terminate()
        gateway.wait(timeout=10)
