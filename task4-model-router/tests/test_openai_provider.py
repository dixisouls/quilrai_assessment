"""OpenAI backup provider, driven through the real OpenAI SDK against the in-process mock."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx2
import pytest

from task3_pii_guardrail.models import ChatRequest
from task3_pii_guardrail.providers import Finish, ProviderError, ProviderEvent, Started, Usage
from task4_model_router import mock_openai
from task4_model_router.openai_provider import OpenAIProvider


@pytest.fixture
async def provider() -> AsyncIterator[OpenAIProvider]:
    mock_openai.REQUESTS.clear()
    client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=mock_openai.create_mock_app()))
    yield OpenAIProvider(
        api_key="mock-not-real",
        model="gpt-6.1-sol",
        default_max_tokens=64,
        timeout_s=10,
        max_retries=0,
        base_url="http://mock/v1",
        http_client=client,
    )
    await client.aclose()


def _request(text: str, **extra: object) -> ChatRequest:
    return ChatRequest.model_validate(
        {"model": "any", "messages": [{"role": "user", "content": text}], **extra}
    )


async def _events(provider: OpenAIProvider, request: ChatRequest) -> list[ProviderEvent]:
    return [e async for e in provider.stream(request)]


async def test_streams_text_then_usage_then_finish(provider: OpenAIProvider) -> None:
    events = await _events(provider, _request("hello there"))
    assert events[0] == Started("openai", "gpt-6.1-sol")
    text = "".join(e for e in events if isinstance(e, str))
    assert text == "Backup says: hello there"
    assert isinstance(events[-2], Usage) and events[-2].input_tokens == 11
    assert events[-1] == Finish("stop")


async def test_request_maps_to_chat_completions_with_usage_reporting(
    provider: OpenAIProvider,
) -> None:
    system = {"role": "system", "content": "be brief"}
    request = ChatRequest.model_validate(
        {
            "model": "client-choice",
            "messages": [system, {"role": "user", "content": "hi"}],
            "max_tokens": 20,
        }
    )
    await _events(provider, request)
    [sent] = mock_openai.REQUESTS
    assert sent["model"] == "gpt-6.1-sol"  # the gateway's model, not the client's
    assert sent["messages"][0] == system
    assert sent["max_completion_tokens"] == 20
    assert sent["stream"] is True
    assert sent["stream_options"] == {"include_usage": True}


async def test_default_max_tokens_applies(provider: OpenAIProvider) -> None:
    await _events(provider, _request("hi"))
    assert mock_openai.REQUESTS[0]["max_completion_tokens"] == 64


@pytest.mark.parametrize(
    ("marker", "kind", "retry_after"),
    [("[[openai:429]]", "rate_limited", 4.0), ("[[openai:500]]", "unavailable", None)],
)
async def test_errors_map_to_provider_failures(
    provider: OpenAIProvider, marker: str, kind: str, retry_after: float | None
) -> None:
    with pytest.raises(ProviderError) as exc:
        await _events(provider, _request(f"{marker} hi"))
    assert (exc.value.kind, exc.value.retry_after) == (kind, retry_after)
