"""Unit tests for the SQLite-backed, token-aware sliding-window rate limiter."""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from task4_model_router.ratelimit import TokenRateLimiter


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
async def limiter(tmp_path: Path, clock: Clock) -> AsyncIterator[TokenRateLimiter]:
    lim = TokenRateLimiter(tmp_path / "rl.sqlite3", limit=1000, window_s=60, clock=clock)
    yield lim
    lim.close()


async def test_allows_until_the_budget_is_spent(limiter: TokenRateLimiter) -> None:
    first = await limiter.reserve("tenant-a", 600)
    assert first.allowed and first.remaining == 400
    second = await limiter.reserve("tenant-a", 400)
    assert second.allowed and second.remaining == 0
    third = await limiter.reserve("tenant-a", 1)
    assert not third.allowed
    assert third.remaining == 0


async def test_window_slides_rather_than_resetting(limiter: TokenRateLimiter, clock: Clock) -> None:
    await limiter.reserve("t", 600)  # t=0
    clock.now += 30
    await limiter.reserve("t", 400)  # t=30
    clock.now += 29.9  # t=59.9: both still inside the window
    assert not (await limiter.reserve("t", 1)).allowed
    clock.now += 0.2  # t=60.1: the first 600 have slid out, the 400 have not
    decision = await limiter.reserve("t", 600)
    assert decision.allowed
    assert decision.remaining == 0
    assert not (await limiter.reserve("t", 1)).allowed


async def test_retry_after_is_when_enough_tokens_expire(
    limiter: TokenRateLimiter, clock: Clock
) -> None:
    await limiter.reserve("t", 300)  # t=0
    clock.now += 10
    await limiter.reserve("t", 700)  # t=10
    clock.now += 5  # t=15, window full
    blocked = await limiter.reserve("t", 500)
    assert not blocked.allowed
    # Freeing 300 (at t=60) isn't enough for 500; freeing the 700 (at t=70) is.
    assert blocked.retry_after_s == pytest.approx(55.0)
    small = await limiter.reserve("t", 200)
    assert small.retry_after_s == pytest.approx(45.0)


async def test_tenants_are_isolated(limiter: TokenRateLimiter) -> None:
    assert (await limiter.reserve("a", 1000)).allowed
    assert not (await limiter.reserve("a", 1)).allowed
    assert (await limiter.reserve("b", 1000)).allowed


async def test_settle_corrects_the_reservation_to_actual_usage(
    limiter: TokenRateLimiter,
) -> None:
    held = await limiter.reserve("t", 900)  # worst case: prompt + max_tokens
    await limiter.settle(held, actual_tokens=120)  # what the provider really used
    assert (await limiter.reserve("t", 880)).allowed
    assert not (await limiter.reserve("t", 1)).allowed


async def test_settle_can_also_raise_usage(limiter: TokenRateLimiter) -> None:
    held = await limiter.reserve("t", 100)
    await limiter.settle(held, actual_tokens=950)  # estimate was too low
    assert not (await limiter.reserve("t", 51)).allowed
    assert (await limiter.reserve("t", 50)).allowed


async def test_refund_on_failure(limiter: TokenRateLimiter) -> None:
    held = await limiter.reserve("t", 1000)
    await limiter.settle(held, actual_tokens=0)  # both providers failed: nothing used
    assert (await limiter.reserve("t", 1000)).allowed


async def test_request_larger_than_the_whole_budget_can_never_pass(
    limiter: TokenRateLimiter,
) -> None:
    decision = await limiter.reserve("t", 1001)
    assert not decision.allowed
    assert decision.retry_after_s is None  # waiting won't help: tell the caller so


async def test_expired_rows_are_evicted(
    limiter: TokenRateLimiter, clock: Clock, tmp_path: Path
) -> None:
    for _ in range(10):
        await limiter.reserve("t", 10)
    clock.now += 61
    await limiter.reserve("t", 10)
    with sqlite3.connect(tmp_path / "rl.sqlite3") as db:
        (rows,) = db.execute("SELECT COUNT(*) FROM token_usage WHERE tenant = 't'").fetchone()
    assert rows == 1


async def test_inactive_tenants_are_swept_too(tmp_path: Path, clock: Clock) -> None:
    lim = TokenRateLimiter(
        tmp_path / "rl.sqlite3", limit=1000, window_s=60, clock=clock, sweep_every=5
    )
    await lim.reserve("idle", 10)
    clock.now += 61
    for _ in range(5):
        await lim.reserve("busy", 1)
    with sqlite3.connect(tmp_path / "rl.sqlite3") as db:
        (rows,) = db.execute("SELECT COUNT(*) FROM token_usage WHERE tenant = 'idle'").fetchone()
    lim.close()
    assert rows == 0


async def test_state_is_on_disk_and_survives_restart(tmp_path: Path, clock: Clock) -> None:
    path = tmp_path / "rl.sqlite3"
    first = TokenRateLimiter(path, limit=1000, window_s=60, clock=clock)
    await first.reserve("t", 900)
    first.close()
    assert path.exists()
    second = TokenRateLimiter(path, limit=1000, window_s=60, clock=clock)
    assert not (await second.reserve("t", 200)).allowed
    second.close()


async def test_concurrent_reservations_never_exceed_the_limit(limiter: TokenRateLimiter) -> None:
    results = await asyncio.gather(*(limiter.reserve("t", 40) for _ in range(100)))
    assert sum(r.allowed for r in results) == 25  # exactly 1000 / 40, no over-admission


async def test_two_connections_sharing_the_file_never_over_admit(
    tmp_path: Path, clock: Clock
) -> None:
    # Two limiter instances = two SQLite connections in one process.
    path = tmp_path / "shared.sqlite3"
    a = TokenRateLimiter(path, limit=1000, window_s=60, clock=clock)
    b = TokenRateLimiter(path, limit=1000, window_s=60, clock=clock)
    results = await asyncio.gather(*(lim.reserve("t", 40) for lim in [a, b] * 50))
    a.close()
    b.close()
    assert sum(r.allowed for r in results) == 25


@pytest.mark.parametrize("tenant", ["t'; DROP TABLE token_usage; --", "a\x00b", "x" * 300])
async def test_hostile_tenant_ids_are_just_data(limiter: TokenRateLimiter, tenant: str) -> None:
    assert (await limiter.reserve(tenant, 10)).allowed
    assert (await limiter.reserve("normal", 10)).allowed  # table still intact


def test_invalid_configuration_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="limit"):
        TokenRateLimiter(tmp_path / "x.db", limit=0, window_s=60)
    with pytest.raises(ValueError, match="window"):
        TokenRateLimiter(tmp_path / "x.db", limit=10, window_s=0)


@pytest.mark.integration
def test_separate_processes_sharing_the_file_never_over_admit(tmp_path: Path) -> None:
    # Real gateway workers are separate processes: BEGIN IMMEDIATE must hold across them.
    script = (
        "import asyncio, sys\n"
        "from pathlib import Path\n"
        "from task4_model_router.ratelimit import TokenRateLimiter\n"
        "async def main():\n"
        "    lim = TokenRateLimiter(Path(sys.argv[1]), limit=1000, window_s=60)\n"
        "    results = await asyncio.gather(*(lim.reserve('t', 40) for _ in range(25)))\n"
        "    lim.close()\n"
        "    print(sum(r.allowed for r in results))\n"
        "asyncio.run(main())\n"
    )
    db = tmp_path / "shared.sqlite3"
    procs = [
        subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-c", script, str(db)], stdout=subprocess.PIPE, text=True
        )
        for _ in range(4)
    ]
    admitted = sum(int(p.communicate(timeout=60)[0].strip()) for p in procs)
    assert admitted == 25  # 4 processes x 25 requests x 40 tokens against 1000: exactly 25
