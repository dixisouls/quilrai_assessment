"""Unit tests for the primary/backup failover router (fake providers, real asyncio timing)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field

import pytest

from task3_pii_guardrail.models import ChatRequest
from task3_pii_guardrail.providers import Finish, ProviderError, ProviderEvent, Started
from task4_model_router.router import FailoverProvider

REQUEST = ChatRequest.model_validate(
    {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
)


@dataclass
class FakeProvider:
    name: str
    hang_s: float = 0.0  # delay before the endpoint "answers"
    fail: ProviderError | None = None  # raised before answering
    events: list[ProviderEvent | float | ProviderError] = field(default_factory=list)
    calls: int = 0
    closed: bool = False
    cancelled: bool = False

    async def stream(self, request: ChatRequest) -> AsyncGenerator[ProviderEvent, None]:
        self.calls += 1
        try:
            if self.hang_s:
                await asyncio.sleep(self.hang_s)
            if self.fail is not None:
                raise self.fail
            yield Started(self.name, f"{self.name}-model")
            for step in self.events or [f"from {self.name}", Finish("stop")]:
                if isinstance(step, float):
                    await asyncio.sleep(step)
                elif isinstance(step, ProviderError):
                    raise step
                else:
                    yield step
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        finally:
            self.closed = True


async def collect(router: FailoverProvider) -> list[ProviderEvent]:
    return [e async for e in router.stream(REQUEST)]


def _router(
    primary: FakeProvider, secondary: FakeProvider, timeout: float = 0.3
) -> FailoverProvider:
    return FailoverProvider(primary, secondary, primary_timeout_s=timeout, secondary_timeout_s=2.0)


async def test_healthy_primary_serves_and_backup_is_untouched() -> None:
    primary, secondary = FakeProvider("anthropic"), FakeProvider("openai")
    events = await collect(_router(primary, secondary))
    assert events == [Started("anthropic", "anthropic-model"), "from anthropic", Finish("stop")]
    assert secondary.calls == 0


async def test_primary_429_fails_over_to_backup(caplog: pytest.LogCaptureFixture) -> None:
    primary = FakeProvider("anthropic", fail=ProviderError("rate_limited", "429", retry_after=5))
    secondary = FakeProvider("openai")
    with caplog.at_level(logging.INFO):
        events = await collect(_router(primary, secondary))
    assert events[0] == Started("openai", "openai-model")
    assert "from openai" in events
    [audit] = [r.audit for r in caplog.records if getattr(r, "audit", None)]  # type: ignore[attr-defined]
    assert audit["decision"] == "failover"
    assert audit["metadata"] == {"reason": "rate_limited", "from": "primary", "to": "backup"}


async def test_primary_timeout_fails_over_at_the_deadline_and_cancels_primary() -> None:
    primary = FakeProvider("anthropic", hang_s=10)
    secondary = FakeProvider("openai")
    started = time.perf_counter()
    events = await collect(_router(primary, secondary, timeout=0.3))
    elapsed = time.perf_counter() - started
    assert events[0] == Started("openai", "openai-model")
    assert 0.29 <= elapsed < 0.6  # failed over at the deadline, not after the primary's 10 s
    assert primary.cancelled and primary.closed  # the losing request doesn't keep running


async def test_primary_answering_just_before_the_deadline_is_kept() -> None:
    primary = FakeProvider("anthropic", hang_s=0.2, events=["slow text", 0.5, Finish("stop")])
    secondary = FakeProvider("openai")
    events = await collect(_router(primary, secondary, timeout=0.3))
    assert events[0] == Started("anthropic", "anthropic-model")
    assert secondary.calls == 0  # slow *text* after answering is not a timeout


@pytest.mark.parametrize("kind", ["unavailable", "bad_request"])
async def test_other_primary_failures_do_not_fail_over(kind: str) -> None:
    # The brief names exactly two triggers: 429 and timeout.
    primary = FakeProvider("anthropic", fail=ProviderError(kind, "x"))  # type: ignore[arg-type]
    secondary = FakeProvider("openai")
    with pytest.raises(ProviderError) as exc:
        await collect(_router(primary, secondary))
    assert exc.value.kind == kind
    assert secondary.calls == 0


async def test_failure_after_the_primary_started_is_not_retried_elsewhere() -> None:
    # Switching mid-answer would splice two different responses together.
    primary = FakeProvider(
        "anthropic", events=["partial ", ProviderError("rate_limited", "mid-stream 429")]
    )
    secondary = FakeProvider("openai")
    with pytest.raises(ProviderError):
        await collect(_router(primary, secondary))
    assert secondary.calls == 0


async def test_both_providers_failing_raises_the_backup_error() -> None:
    primary = FakeProvider("anthropic", fail=ProviderError("rate_limited", "429"))
    secondary = FakeProvider("openai", fail=ProviderError("rate_limited", "429 too", retry_after=9))
    with pytest.raises(ProviderError) as exc:
        await collect(_router(primary, secondary))
    assert (exc.value.kind, exc.value.retry_after) == ("rate_limited", 9)


async def test_backup_that_never_answers_times_out_too() -> None:
    primary = FakeProvider("anthropic", fail=ProviderError("rate_limited", "429"))
    secondary = FakeProvider("openai", hang_s=10)
    router = FailoverProvider(primary, secondary, primary_timeout_s=0.2, secondary_timeout_s=0.3)
    with pytest.raises(ProviderError) as exc:
        await collect(router)
    assert exc.value.kind == "timeout"
    assert secondary.cancelled


async def test_consumer_closing_early_closes_the_serving_provider() -> None:
    primary = FakeProvider("anthropic", events=["a", 1.0, "b", Finish("stop")])
    stream = _router(primary, FakeProvider("openai")).stream(REQUEST)
    assert await anext(stream) == Started("anthropic", "anthropic-model")
    assert await anext(stream) == "a"
    await stream.aclose()  # e.g. the client disconnected
    assert primary.closed


async def test_concurrent_requests_fail_over_independently() -> None:
    # Half the requests hit a rate-limited primary; nothing leaks between them.
    @dataclass
    class Flaky(FakeProvider):
        async def stream(self, request: ChatRequest) -> AsyncGenerator[ProviderEvent, None]:
            self.calls += 1
            if self.calls % 2:
                raise ProviderError("rate_limited", "429")
            yield Started(self.name, "m")
            yield Finish("stop")

    router = _router(Flaky("anthropic"), FakeProvider("openai"))
    results = await asyncio.gather(*(collect(router) for _ in range(20)))
    servers = sorted(r[0].provider for r in results)  # type: ignore[union-attr]
    assert servers == ["anthropic"] * 10 + ["openai"] * 10


def test_timeouts_must_be_positive() -> None:
    with pytest.raises(ValueError, match="timeout"):
        FailoverProvider(FakeProvider("a"), FakeProvider("b"), primary_timeout_s=0)
