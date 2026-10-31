"""HTTP-layer tests: the gateway in-process with a scripted fake provider."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from task3_pii_guardrail.api import create_app
from task3_pii_guardrail.config import GatewaySettings
from task3_pii_guardrail.models import ChatRequest
from task3_pii_guardrail.providers import BlockEnd, Finish, ProviderError, ProviderEvent

API_KEY = secrets.token_urlsafe(24)  # generated per run; never a literal in the repo


@dataclass
class FakeProvider:
    """Yields scripted events; records requests and whether the stream was closed."""

    script: list[ProviderEvent | float | Exception] = field(default_factory=list)
    requests: list[ChatRequest] = field(default_factory=list)
    closed: bool = False

    async def stream(self, request: ChatRequest) -> AsyncGenerator[ProviderEvent, None]:
        self.requests.append(request)
        try:
            for step in self.script:
                if isinstance(step, float):
                    await asyncio.sleep(step)
                elif isinstance(step, Exception):
                    raise step
                else:
                    yield step
        finally:
            self.closed = True


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
async def client(provider: FakeProvider) -> AsyncIterator[httpx.AsyncClient]:
    settings = GatewaySettings(api_keys=[API_KEY], max_body_bytes=8192)
    app = create_app(settings, provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw", timeout=10
    ) as c:
        yield c


HEADERS = {"authorization": f"Bearer {API_KEY}"}


def _body(stream: bool = True, **extra: Any) -> dict[str, Any]:
    return {
        "model": "claude-opus-5-5",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": stream,
        **extra,
    }


def _sse_events(raw: str) -> list[Any]:
    events = []
    for block in raw.split("\n\n"):
        if block.startswith("data: "):
            payload = block[len("data: ") :]
            events.append(payload if payload == "[DONE]" else json.loads(payload))
    return events


def _content(events: list[Any]) -> str:
    return "".join(
        str(e["choices"][0]["delta"].get("content") or "")
        for e in events
        if isinstance(e, dict) and "choices" in e
    )


# --- Streaming redaction ----------------------------------------------------------------


async def test_pii_split_across_provider_chunks_is_redacted(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = [
        "Email jane.do",
        "e@exam",
        "ple.com, SSN 123-4",
        "5-6789, card 4111 11",
        "11 1111 1111. Bye",
        Finish("stop"),
    ]
    resp = await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    events = _sse_events(resp.text)
    assert events[-1] == "[DONE]"
    text = _content(events)
    assert text == "Email [REDACTED], SSN [REDACTED], card [REDACTED]. Bye"
    for leaked in ("jane", "example", "123-45", "4111"):
        assert leaked not in resp.text


async def test_stream_chunks_follow_the_openai_format(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = ["Hello ", "world", Finish("stop")]
    events = _sse_events(
        (await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)).text
    )
    chunks = [e for e in events if isinstance(e, dict)]
    assert {c["object"] for c in chunks} == {"chat.completion.chunk"}
    assert len({c["id"] for c in chunks}) == 1
    assert chunks[0]["choices"][0]["delta"] == {"role": "assistant", "content": ""}
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    assert chunks[-1]["choices"][0]["delta"] == {}
    assert _content(events) == "Hello world"


async def test_finish_reason_length_is_passed_through(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = ["partial", Finish("length")]
    events = _sse_events(
        (await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)).text
    )
    assert [e for e in events if isinstance(e, dict)][-1]["choices"][0]["finish_reason"] == "length"


# --- Non-streaming ----------------------------------------------------------------------------


async def test_non_streaming_response_is_redacted(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = ["Reach me at a@b.io", Finish("stop")]
    resp = await client.post("/v1/chat/completions", json=_body(stream=False), headers=HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"] == {
        "role": "assistant",
        "content": "Reach me at [REDACTED]",
    }
    assert body["choices"][0]["finish_reason"] == "stop"


# --- Errors -------------------------------------------------------------------------------------


async def test_provider_errors_before_first_token_become_http_errors(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = [
        ProviderError("rate_limited", "upstream said 429 for key sk-ant-xyz", retry_after=7)
    ]
    resp = await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "7"
    err = resp.json()["error"]
    assert err["type"] == "rate_limit_error"
    assert err["request_id"] == resp.headers["x-request-id"]
    assert "sk-ant" not in resp.text


@pytest.mark.parametrize(
    ("kind", "status"), [("unavailable", 502), ("timeout", 504), ("bad_request", 502)]
)
async def test_provider_failure_kinds_map_to_sanitised_statuses(
    client: httpx.AsyncClient, provider: FakeProvider, kind: str, status: int
) -> None:
    provider.script = [ProviderError(kind, "internal detail api.anthropic.com/v1/messages")]  # type: ignore[arg-type]
    resp = await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    assert resp.status_code == status
    assert "anthropic.com" not in resp.text


async def test_mid_stream_failure_ends_with_an_error_event(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = [
        "Some text, contact jane.do",
        ProviderError("unavailable", "connection reset by 10.1.2.3"),
    ]
    resp = await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    events = _sse_events(resp.text)
    assert events[-1] == "[DONE]"
    assert events[-2]["error"]["type"] == "provider_error"
    assert "10.1.2.3" not in resp.text
    # The held partial value is discarded, never flushed as a fragment of PII.
    assert _content(events) == "Some text, contact "
    assert "jane" not in resp.text


async def test_unexpected_exception_mid_stream_is_contained(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = ["ok ", RuntimeError("boom /srv/secret")]
    resp = await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    events = _sse_events(resp.text)
    assert events[-2]["error"]["type"] == "internal_error"
    assert "secret" not in resp.text


# --- Auth and input validation -----------------------------------------------------------------


@pytest.mark.parametrize(
    "headers", [{}, {"authorization": "Bearer wrong"}, {"authorization": f"Basic {API_KEY}"}]
)
async def test_requests_without_a_valid_key_are_rejected(
    client: httpx.AsyncClient, provider: FakeProvider, headers: dict[str, str]
) -> None:
    resp = await client.post("/v1/chat/completions", json=_body(), headers=headers)
    assert resp.status_code == 401
    assert resp.json()["error"]["type"] == "authentication_error"
    assert provider.requests == []


@pytest.mark.parametrize(
    ("body", "param"),
    [
        ({"model": "m", "messages": []}, "messages"),
        ({"model": "m", "messages": [{"role": "tool", "content": "x"}]}, "messages.0.role"),
        ({"model": "m", "messages": [{"role": "user", "content": 5}]}, "messages.0.content"),
        ({"model": "m", "messages": [{"role": "system", "content": "x"}]}, "messages"),
        (
            {"model": "m", "messages": [{"role": "user", "content": "x"}], "max_tokens": 0},
            "max_tokens",
        ),
        ({"model": "m", "messages": [{"role": "user", "content": "x"}], "stream": "yes"}, "stream"),
        (
            {"model": "m", "messages": [{"role": "user", "content": "x"}], "temperature": 2},
            "temperature",
        ),
    ],
)
async def test_invalid_requests_get_400_with_the_offending_param(
    client: httpx.AsyncClient, provider: FakeProvider, body: dict[str, Any], param: str
) -> None:
    resp = await client.post("/v1/chat/completions", json=body, headers=HEADERS)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["type"] == "invalid_request_error"
    assert err["param"] == param
    assert provider.requests == []


async def test_malformed_json_and_oversize_bodies(client: httpx.AsyncClient) -> None:
    bad = await client.post(
        "/v1/chat/completions",
        content=b"{nope",
        headers={**HEADERS, "content-type": "application/json"},
    )
    assert bad.status_code == 400
    big = _body(messages=[{"role": "user", "content": "x" * 20_000}])
    assert (await client.post("/v1/chat/completions", json=big, headers=HEADERS)).status_code == 413


# --- Resource handling ----------------------------------------------------------------------------


async def test_provider_stream_is_closed_when_the_response_completes(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = ["a", Finish("stop")]
    await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    assert provider.closed


async def test_healthz(client: httpx.AsyncClient) -> None:
    assert (await client.get("/healthz")).json() == {"status": "ok"}


# --- Review #4 regressions ----------------------------------------------------------


async def test_values_at_text_block_boundaries_are_redacted(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    # Separate content blocks (citations, fallback switch) must not merge into one
    # digit run that defeats the card and SSN checks.
    provider.script = [
        "Card: 4111111111111111",
        BlockEnd(),
        "0 is the code. SSN 123-45-6789",
        BlockEnd(),
        "0 too.",
        BlockEnd(),
        Finish("stop"),
    ]
    streamed = _content(
        _sse_events((await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)).text)
    )
    assert streamed == "Card: [REDACTED]0 is the code. SSN [REDACTED]0 too."
    provider.script = list(provider.script)
    whole = await client.post("/v1/chat/completions", json=_body(stream=False), headers=HEADERS)
    assert whole.json()["choices"][0]["message"]["content"] == streamed


async def test_deeply_nested_json_gets_a_400_envelope(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/v1/chat/completions",
        content=b"[" * 5000,
        headers={**HEADERS, "content-type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["type"] == "invalid_request_error"
    assert resp.json()["error"]["request_id"] == resp.headers["x-request-id"]


async def test_streaming_audit_event_carries_request_and_principal(
    client: httpx.AsyncClient, provider: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    provider.script = ["mail a@b.io ok", Finish("stop")]
    with caplog.at_level(logging.INFO):
        resp = await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    [record] = [r for r in caplog.records if getattr(r, "audit", None)]
    audit = record.audit  # type: ignore[attr-defined]  # set by emit_audit
    assert audit["request_id"] == resp.headers["x-request-id"]
    assert audit["principal"] is not None and audit["principal"].startswith("key-")


@pytest.mark.parametrize("retry_after", [float("inf"), float("nan"), -5.0, 1e12])
async def test_hostile_retry_after_values_do_not_crash(
    client: httpx.AsyncClient, provider: FakeProvider, retry_after: float
) -> None:
    provider.script = [ProviderError("rate_limited", "x", retry_after=retry_after)]
    resp = await client.post("/v1/chat/completions", json=_body(), headers=HEADERS)
    assert resp.status_code == 429
    assert "retry-after" not in resp.headers or resp.headers["retry-after"].isdigit()


async def test_non_streaming_unexpected_error_gets_an_envelope(
    client: httpx.AsyncClient, provider: FakeProvider
) -> None:
    provider.script = ["ok", RuntimeError("boom /srv/secret")]
    resp = await client.post("/v1/chat/completions", json=_body(stream=False), headers=HEADERS)
    assert resp.status_code == 500
    assert resp.json()["error"]["type"] == "internal_error"
    assert "secret" not in resp.text


@pytest.mark.parametrize("token", [b"", b" ", b"\t", b"\xa0"])  # raw bytes, incl. an NBSP
async def test_blank_bearer_tokens_are_rejected(client: httpx.AsyncClient, token: bytes) -> None:
    resp = await client.post(
        "/v1/chat/completions", json=_body(), headers={b"authorization": b"Bearer " + token}
    )
    assert resp.status_code == 401


def test_short_or_empty_configured_keys_are_refused() -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(api_keys=[""])
    with pytest.raises(ValidationError):
        GatewaySettings(api_keys=["short"])
