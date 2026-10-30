"""Unit tests for request-scoped logging context."""

from __future__ import annotations

import asyncio
import re

import pytest

from quilr_common.log.context import (
    bind_context,
    get_context,
    new_request_id,
    sanitize_request_id,
)


def test_context_is_empty_by_default() -> None:
    assert get_context() == {}


def test_bind_context_sets_and_restores() -> None:
    with bind_context(request_id="r1", tenant_id="t1"):
        assert get_context() == {"request_id": "r1", "tenant_id": "t1"}
    assert get_context() == {}


def test_nested_bind_merges_and_inner_wins_then_restores() -> None:
    with bind_context(request_id="r1", tenant_id="t1"):
        with bind_context(tenant_id="t2", principal="alice"):
            assert get_context() == {"request_id": "r1", "tenant_id": "t2", "principal": "alice"}
        assert get_context() == {"request_id": "r1", "tenant_id": "t1"}


def test_context_restored_even_on_exception() -> None:
    with pytest.raises(RuntimeError), bind_context(request_id="r1"):
        raise RuntimeError("boom")
    assert get_context() == {}


def test_get_context_returns_a_copy() -> None:
    with bind_context(request_id="r1"):
        snapshot = get_context()
        snapshot["request_id"] = "mutated"
        assert get_context()["request_id"] == "r1"


async def test_context_is_isolated_between_concurrent_tasks() -> None:
    seen: dict[str, str] = {}

    async def worker(rid: str) -> None:
        with bind_context(request_id=rid):
            await asyncio.sleep(0.01)  # force interleaving
            seen[rid] = get_context()["request_id"]

    await asyncio.gather(*(worker(f"r{i}") for i in range(20)))
    assert seen == {f"r{i}": f"r{i}" for i in range(20)}


def test_new_request_id_is_unique_and_safe() -> None:
    ids = {new_request_id() for _ in range(1000)}
    assert len(ids) == 1000
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)


@pytest.mark.parametrize("value", ["abc-123", "A.b_c-9", "x" * 128])
def test_sanitize_request_id_accepts_safe_client_ids(value: str) -> None:
    assert sanitize_request_id(value) == value


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "x" * 129,  # too long
        'abc\n{"level":"CRITICAL"}',  # log-injection attempt
        "abc def",
        "<script>",
        "id\u202e",  # unicode bidi override
    ],
)
def test_sanitize_request_id_replaces_unsafe_values(value: str | None) -> None:
    out = sanitize_request_id(value)
    assert out != value
    assert re.fullmatch(r"[0-9a-f]{32}", out)
