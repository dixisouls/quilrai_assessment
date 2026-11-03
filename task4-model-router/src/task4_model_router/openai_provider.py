"""OpenAI backup provider, on the official OpenAI SDK (Chat Completions, streaming).

Same contract as Task 3's ``AnthropicProvider``: ``Started`` once the endpoint
has answered, text deltas, ``Usage`` from the final usage chunk
(``stream_options.include_usage``), then ``Finish``. SDK errors map to the
same coarse provider failures, and the SDK's detail stays in the log.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any, Final

import httpx2
import openai

from task3_pii_guardrail.models import ChatRequest
from task3_pii_guardrail.providers import (
    Finish,
    FinishReason,
    ProviderError,
    ProviderEvent,
    Started,
    Usage,
    parse_retry_after,
)

_FINISH: Final[dict[str | None, FinishReason]] = {
    "stop": "stop",
    "length": "length",
    "content_filter": "content_filter",
}


def _map_error(exc: openai.APIError) -> ProviderError:
    detail = f"{type(exc).__name__}: {exc}"
    if isinstance(exc, openai.RateLimitError):
        return ProviderError(
            "rate_limited",
            detail,
            retry_after=parse_retry_after(exc.response.headers.get("retry-after")),
        )
    if isinstance(exc, openai.APITimeoutError):
        return ProviderError("timeout", detail)
    if isinstance(exc, openai.APIConnectionError):
        return ProviderError("unavailable", detail)
    if isinstance(exc, openai.APIStatusError) and exc.status_code < 500:  # noqa: PLR2004
        return ProviderError("bad_request", detail)
    return ProviderError("unavailable", detail)


class OpenAIProvider:
    def __init__(
        self,
        *,
        api_key: str | None,
        model: str,
        default_max_tokens: int,
        timeout_s: float,
        max_retries: int,
        base_url: str | None = None,
        http_client: httpx2.AsyncClient | None = None,  # openai 3.x is built on httpx2
    ) -> None:
        # api_key=None lets the SDK read OPENAI_API_KEY itself.
        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout_s,
            max_retries=max_retries,
            http_client=http_client,
        )
        self._model = model
        self._default_max_tokens = default_max_tokens

    async def stream(self, request: ChatRequest) -> AsyncGenerator[ProviderEvent, None]:
        messages: Any = [{"role": m.role, "content": m.content} for m in request.messages]
        try:
            chunks = await self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_completion_tokens=request.max_tokens or self._default_max_tokens,
                stream=True,
                stream_options={"include_usage": True},
            )
        except openai.APIError as exc:
            raise _map_error(exc) from None

        finish: str | None = None
        usage: Usage | None = None
        try:
            yield Started("openai", self._model)
            async for chunk in chunks:
                if chunk.choices:
                    choice = chunk.choices[0]
                    if choice.delta.content:
                        yield choice.delta.content
                    finish = choice.finish_reason or finish
                if chunk.usage is not None:
                    usage = Usage(chunk.usage.prompt_tokens, chunk.usage.completion_tokens)
        except openai.APIError as exc:
            raise _map_error(exc) from None
        finally:
            await chunks.close()
        if usage is not None:
            yield usage
        yield Finish(_FINISH.get(finish, "stop"))
