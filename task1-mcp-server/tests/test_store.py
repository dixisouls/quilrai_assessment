"""Unit tests for the in-memory customer store."""

from __future__ import annotations

from decimal import Decimal

import pytest

from task1_mcp_server.store import (
    AccountNotActiveError,
    Customer,
    CustomerNotFoundError,
    InMemoryCustomerStore,
    InsufficientBalanceError,
    seeded_store,
)

ADA = Customer("CUST-00042", "Ada Lovelace", "ada@example.com", "gold", "active", Decimal("100"))


def test_get_returns_customer_or_none() -> None:
    store = InMemoryCustomerStore([ADA])
    assert store.get("CUST-00042") == ADA
    assert store.get("CUST-00043") is None


def test_duplicate_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        InMemoryCustomerStore([ADA, ADA])


def test_refund_deducts_balance_and_returns_receipt() -> None:
    store = InMemoryCustomerStore([ADA])
    receipt = store.refund("CUST-00042", Decimal("40.00"))
    assert receipt.amount == Decimal("40.00")
    assert receipt.remaining_balance == Decimal("60.00")
    assert store.get("CUST-00042").refundable_balance == Decimal("60.00")  # type: ignore[union-attr]


def test_refund_errors() -> None:
    suspended = Customer("CUST-00001", "S", "s@example.com", "standard", "suspended", Decimal(10))
    store = InMemoryCustomerStore([ADA, suspended])
    with pytest.raises(CustomerNotFoundError):
        store.refund("CUST-99999", Decimal(1))
    with pytest.raises(AccountNotActiveError):
        store.refund("CUST-00001", Decimal(1))
    with pytest.raises(InsufficientBalanceError):
        store.refund("CUST-00042", Decimal("100.01"))
    assert store.get("CUST-00042") == ADA  # unchanged after failures


def test_full_balance_can_be_refunded() -> None:
    store = InMemoryCustomerStore([ADA])
    assert store.refund("CUST-00042", Decimal(100)).remaining_balance == Decimal(0)


def test_seeded_store_contains_valid_demo_data() -> None:
    store = seeded_store()
    customers = store.all()
    assert len(customers) >= 3
    statuses = {c.status for c in customers}
    assert {"active", "suspended"} <= statuses
    for c in customers:
        assert c.email.endswith("@example.com")  # reserved domain: never a real person
