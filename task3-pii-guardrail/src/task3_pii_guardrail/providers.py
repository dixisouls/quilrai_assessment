"""LLM providers: a minimal streaming interface and the Anthropic implementation.

A provider turns a :class:`ChatRequest` into an async stream of text deltas
ending with a :class:`Finish`. Failures are raised as :class:`ProviderError`
with a coarse ``kind``; provider-specific detail stays in the server log.
"""

from __future__ import annotations

import math
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol

import anthropic

from quilr_common.log import get_logger
from task3_pii_guardrail.models import ChatRequest

log = get_logger(__name__)

FinishReason = Literal["stop", "length", "content_filter"]
ProviderFailure = Literal["rate_limited", "unavailable", "timeout", "bad_request"]


@dataclass(frozen=True, slots=True)
class Finish:
    reason: FinishReason


@dataclass(frozen=True, slots=True)
class BlockEnd:
    """End of one content block. Text from different blocks (citations, a
    fallback-model switch, ...) is concatenated for the client but must be
    redacted independently: otherwise a card ending one block and a digit
    starting the next merge into a single run that defeats the Luhn and
    boundary checks."""


type ProviderEvent = str | BlockEnd | Finish


class ProviderError(Exception):
    """Provider call failed. ``detail`` is for logs only; never sent to clients."""

    def __init__(
        self, kind: ProviderFailure, detail: str, *, retry_after: float | None = None
    ) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind: ProviderFailure = kind
        self.detail = detail
        self.retry_after = retry_after


class Provider(Protocol):
    def stream(self, request: ChatRequest) -> AsyncGenerator[ProviderEvent, None]: ...


_STOP_REASONS: Final[dict[str | None, FinishReason]] = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "refusal": "content_filter",
}
_FALLBACK_BETA: Final = "server-side-fallback-2026-07-01"
_MAX_RETRY_AFTER_S: Final = 3600.0


def _retry_after(raw: str | None) -> float | None:
    """Upstream is only semi-trusted: accept finite, non-negative, bounded values."""
    try:
        value = float(raw) if raw is not None else None
    except ValueError:
        return None
    if value is None or not math.isfinite(value) or not 0 <= value <= _MAX_RETRY_AFTER_S:
        return None
    return value


def _map_error(exc: anthropic.APIError) -> ProviderError:
    detail = f"{type(exc).__name__}: {exc}"
    if isinstance(exc, anthropic.RateLimitError):
        return ProviderError(
            "rate_limited",
            detail,
            retry_after=_retry_after(exc.response.headers.get("retry-after")),
        )
    if isinstance(exc, anthropic.APITimeoutError):
        return ProviderError("timeout", detail)
    if isinstance(exc, anthropic.APIConnectionError):
        return ProviderError("unavailable", detail)
    if isinstance(exc, anthropic.APIStatusError) and exc.status_code < 400:  # noqa: PLR2004
        # An SSE `error` event inside a 200 stream: classify by the event's error type.
        body = exc.body if isinstance(exc.body, dict) else {}
        error = body.get("error") if isinstance(body.get("error"), dict) else body
        kind = error.get("type") if isinstance(error, dict) else None
        return ProviderError(
            "rate_limited" if kind == "rate_limit_error" else "unavailable", detail
        )
    if isinstance(exc, anthropic.APIStatusError) and exc.status_code < 500:  # noqa: PLR2004
        # 4xx other than 429: our request or credentials are wrong, not the caller's.
        return ProviderError("bad_request", detail)
    return ProviderError("unavailable", detail)  # 5xx and 529 overloaded


class AnthropicProvider:
    """Streams from the Anthropic Messages API with the official SDK.

    Uses the low-level ``stream=True`` iterator (no message accumulation) and
    forwards only ``text_delta`` events. With ``refusal_fallback`` on, the
    request opts into Anthropic's server-side fallback (``fallbacks:
    "default"``): if the model declines on safety grounds, Anthropic re-runs it
    on a fallback model within the same call.
    """

    def __init__(
        self,
        *,
        api_key: str | None,
        model: str,
        default_max_tokens: int,
        timeout_s: float,
        max_retries: int,
        base_url: str | None = None,
        refusal_fallback: bool = True,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key, base_url=base_url, timeout=timeout_s, max_retries=max_retries
        )
        self._model = model
        self._default_max_tokens = default_max_tokens
        self._refusal_fallback = refusal_fallback

    @property
    def model(self) -> str:
        return self._model

    def _params(self, request: ChatRequest) -> dict[str, Any]:
        system = "\n\n".join(m.content for m in request.messages if m.role == "system")
        params: dict[str, Any] = {
            "model": self._model,
            "max_tokens": request.max_tokens or self._default_max_tokens,
            "messages": [
                {"role": m.role, "content": m.content}
                for m in request.messages
                if m.role != "system"
            ],
            "stream": True,
        }
        if system:
            params["system"] = system
        return params

    async def stream(self, request: ChatRequest) -> AsyncGenerator[ProviderEvent, None]:
        params = self._params(request)
        try:
            if self._refusal_fallback:
                events: Any = await self._client.beta.messages.create(
                    **params, betas=[_FALLBACK_BETA], fallbacks="default"
                )
            else:
                events = await self._client.messages.create(**params)
        except anthropic.APIError as exc:
            raise _map_error(exc) from None

        stop_reason: str | None = None
        try:
            async for event in events:
                if event.type == "content_block_delta" and event.delta.type == "text_delta":
                    yield event.delta.text
                elif event.type == "content_block_stop":
                    yield BlockEnd()
                elif event.type == "message_delta" and event.delta.stop_reason is not None:
                    stop_reason = event.delta.stop_reason
        except anthropic.APIError as exc:
            raise _map_error(exc) from None
        finally:
            await events.close()
        yield Finish(_STOP_REASONS.get(stop_reason, "stop"))
