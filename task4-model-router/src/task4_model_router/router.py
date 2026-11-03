"""Primary/backup failover for the LLM gateway.

:class:`FailoverProvider` is itself a ``Provider``, so the Task 3 gateway
(auth, rate limit, streaming redaction) uses it unchanged.

Failover happens in exactly the two cases the brief names:

* **429:** the primary raises ``rate_limited`` before it starts serving.
* **Timeout:** the primary hasn't *answered* within ``primary_timeout_s``
  (3000 ms by default). "Answered" means its first event, the provider's
  ``Started``, which the providers emit as soon as the HTTP response begins.
  A model that is thinking before its first token has already answered and
  is not timed out.

When the timeout fires, the primary's pending request is **cancelled**
(``asyncio.timeout`` cancels the awaiting task, and the SDK aborts the HTTP
request), so the losing side never keeps running beside the backup.

Not failed over, on purpose:

* Other primary failures (outage, rejected request). The brief limits the
  triggers to 429 and timeout. They surface as the gateway's standard error.
* Failures *after* the primary started serving. The client may already
  have text, and switching providers mid-answer would splice two different
  responses together. They end the stream with an error event instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Final

from quilr_common.log import AuditEvent, Decision, emit_audit, get_logger
from task3_pii_guardrail.models import ChatRequest
from task3_pii_guardrail.providers import Provider, ProviderError, ProviderEvent

log = get_logger(__name__)

FAILOVER_ON: Final = frozenset({"rate_limited", "timeout"})


class FailoverProvider:
    def __init__(
        self,
        primary: Provider,
        backup: Provider,
        *,
        primary_timeout_s: float = 3.0,
        secondary_timeout_s: float = 30.0,
    ) -> None:
        if primary_timeout_s <= 0 or secondary_timeout_s <= 0:
            raise ValueError("timeouts must be positive")
        self._primary = primary
        self._backup = backup
        self._primary_timeout = primary_timeout_s
        self._backup_timeout = secondary_timeout_s

    async def stream(self, request: ChatRequest) -> AsyncGenerator[ProviderEvent, None]:
        try:
            events, first = await _start(self._primary, request, self._primary_timeout)
        except ProviderError as exc:
            if exc.kind not in FAILOVER_ON:
                raise
            log.warning(
                "primary failed; failing over", extra={"reason": exc.kind, "detail": exc.detail}
            )
            emit_audit(
                AuditEvent(
                    action="llm.failover",
                    decision=Decision.FAILOVER,
                    reason=f"primary provider {exc.kind}; served by backup",
                    metadata={"reason": exc.kind, "from": "primary", "to": "backup"},
                )
            )
            events, first = await _start(self._backup, request, self._backup_timeout)

        try:
            if first is not None:
                yield first
            async for event in events:
                yield event
        finally:
            await events.aclose()


async def _start(
    provider: Provider, request: ChatRequest, timeout_s: float
) -> tuple[AsyncGenerator[ProviderEvent, None], ProviderEvent | None]:
    """Open ``provider``'s stream and wait at most ``timeout_s`` for it to answer."""
    events = provider.stream(request)
    try:
        async with asyncio.timeout(timeout_s):
            first: ProviderEvent | None = await anext(events)
    except StopAsyncIteration:
        first = None
    except TimeoutError:
        await events.aclose()
        raise ProviderError("timeout", f"no response within {timeout_s:.1f}s") from None
    except BaseException:
        await events.aclose()
        raise
    return events, first
