"""Token-aware sliding-window rate limiter, per tenant API key, stored in on-disk SQLite.

**Sliding window, not fixed buckets.** Every admitted request is a row
``(tenant, ts, tokens)``. A tenant's usage is the sum of its rows from the last
``window_s`` seconds, measured from *now*. There is no bucket edge where a
tenant could spend twice the limit in a moment straddling two windows.

**Reserve, then settle.** A response's true size is only known at the end, so
admission reserves the request's worst case (estimated prompt + ``max_tokens``),
which can never under-count. When the response finishes, :meth:`settle`
rewrites the row to the tokens the provider actually reported, or to 0 when no
provider served the request. Over time the window therefore holds real usage,
not estimates.

**Atomic under concurrency.** The read-check-insert runs inside one
``BEGIN IMMEDIATE`` transaction, which takes SQLite's write lock first. Two
concurrent requests (same process or separate gateway workers sharing the
file) can never both see room for the same tokens. Inside one process a lock
also serialises use of the single connection; calls run in a worker thread so
the event loop never blocks on disk.

**Eviction.** Each check deletes the tenant's expired rows before summing.
Every ``sweep_every`` calls a global sweep removes expired rows of tenants
that have gone quiet, so the table only ever holds about one window of data.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS token_usage (
    id      INTEGER PRIMARY KEY,
    tenant  TEXT    NOT NULL,
    ts      REAL    NOT NULL,
    tokens  INTEGER NOT NULL CHECK (tokens >= 0)
);
CREATE INDEX IF NOT EXISTS ix_token_usage_tenant_ts ON token_usage (tenant, ts);
CREATE INDEX IF NOT EXISTS ix_token_usage_ts ON token_usage (ts);
"""


@dataclass(frozen=True, slots=True)
class LimitDecision:
    allowed: bool
    limit: int
    remaining: int
    # Seconds until enough tokens leave the window; None when waiting can't help
    # (the request alone exceeds the whole budget) or when allowed.
    retry_after_s: float | None
    reservation_id: int | None


class TokenRateLimiter:
    def __init__(
        self,
        path: Path,
        *,
        limit: int,
        window_s: float,
        clock: Callable[[], float] = time.time,
        sweep_every: int = 1000,
    ) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self._limit = limit
        self._window = window_s
        self._clock = clock
        self._sweep_every = sweep_every
        self._calls = 0
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: transactions are explicit (BEGIN IMMEDIATE below).
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self._db.execute("PRAGMA busy_timeout=10000")
        self._enable_wal()
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)

    def _enable_wal(self, deadline_s: float = 10.0) -> None:
        """Switch to WAL, tolerating other workers starting at the same moment.

        Changing the journal mode needs an exclusive lock and fails immediately
        (busy_timeout doesn't apply) while another connection holds a lock, which
        is exactly what happens when several gateway workers start together.
        Already-WAL databases need no switch; otherwise retry with backoff.
        """
        stop = time.monotonic() + deadline_s
        delay = 0.01
        while True:
            try:
                (mode,) = self._db.execute("PRAGMA journal_mode").fetchone()
                if str(mode).lower() != "wal":
                    self._db.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) or time.monotonic() > stop:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 0.2)
            else:
                return

    @property
    def limit(self) -> int:
        return self._limit

    async def reserve(self, tenant: str, tokens: int) -> LimitDecision:
        """Atomically admit ``tokens`` for ``tenant`` if the window has room."""
        return await asyncio.to_thread(self._reserve, tenant, tokens)

    async def settle(self, decision: LimitDecision, actual_tokens: int) -> None:
        """Replace a reservation's estimate with the tokens actually used."""
        if decision.reservation_id is not None:
            await asyncio.to_thread(self._settle, decision.reservation_id, max(0, actual_tokens))

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # --- synchronous core (runs in a worker thread) ------------------------------------

    def _reserve(self, tenant: str, tokens: int) -> LimitDecision:
        with self._lock:
            now = self._clock()
            cutoff = now - self._window
            db = self._db
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM token_usage WHERE tenant = ? AND ts <= ?", (tenant, cutoff))
                (used,) = db.execute(
                    "SELECT COALESCE(SUM(tokens), 0) FROM token_usage WHERE tenant = ?", (tenant,)
                ).fetchone()
                if tokens <= self._limit and used + tokens <= self._limit:
                    cur = db.execute(
                        "INSERT INTO token_usage (tenant, ts, tokens) VALUES (?, ?, ?)",
                        (tenant, now, tokens),
                    )
                    decision = LimitDecision(
                        True, self._limit, self._limit - used - tokens, None, cur.lastrowid
                    )
                else:
                    retry = (
                        None
                        if tokens > self._limit
                        else self._retry_after(tenant, used, tokens, now)
                    )
                    decision = LimitDecision(
                        False, self._limit, max(0, self._limit - used), retry, None
                    )
                self._calls += 1
                if self._calls % self._sweep_every == 0:
                    db.execute("DELETE FROM token_usage WHERE ts <= ?", (cutoff,))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            return decision

    def _retry_after(self, tenant: str, used: int, tokens: int, now: float) -> float:
        """When will enough of the oldest rows have expired to fit ``tokens``?"""
        need = used + tokens - self._limit
        freed = 0
        for ts, row_tokens in self._db.execute(
            "SELECT ts, tokens FROM token_usage WHERE tenant = ? ORDER BY ts", (tenant,)
        ):
            freed += row_tokens
            if freed >= need:
                return max(0.0, float(ts) + self._window - now)  # sqlite rows are untyped
        return self._window  # unreachable while tokens <= limit; safe upper bound

    def _settle(self, reservation_id: int, actual: int) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE token_usage SET tokens = ? WHERE id = ?", (actual, reservation_id)
            )
