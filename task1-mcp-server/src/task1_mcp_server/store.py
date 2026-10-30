"""Customer data store.

The assessment needs a system of record behind the tools, but not a real one.
:class:`InMemoryCustomerStore` is a deliberately small stand-in with the same
shape a real backend (CRM / payments API) would have. Swapping it out means
implementing :class:`CustomerStore`, with no change to validation or protocol code.

Demo data uses the reserved ``example.com`` domain (RFC 2606), so nothing here
can refer to a real person.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Literal, Protocol

Tier = Literal["standard", "gold", "platinum"]
Status = Literal["active", "suspended", "closed"]


@dataclass(frozen=True, slots=True)
class Customer:
    customer_id: str
    name: str
    email: str
    tier: Tier
    status: Status
    refundable_balance: Decimal


@dataclass(frozen=True, slots=True)
class Refund:
    refund_id: str
    customer_id: str
    amount: Decimal
    remaining_balance: Decimal


class RefundError(Exception):
    """A refund that is valid input but not allowed by business rules."""

    public_message = "Refund could not be processed."


class CustomerNotFoundError(RefundError):
    public_message = "Customer not found."


class AccountNotActiveError(RefundError):
    public_message = "Customer account is not active."


class InsufficientBalanceError(RefundError):
    public_message = "Refund exceeds the refundable balance."


class CustomerStore(Protocol):
    def get(self, customer_id: str) -> Customer | None: ...

    def refund(self, customer_id: str, amount: Decimal) -> Refund: ...


class InMemoryCustomerStore:
    """Process-local store. Each operation is synchronous, so under asyncio's
    single-threaded event loop every check-then-update is atomic. A networked
    backend would need its own transaction or idempotency key instead."""

    def __init__(self, customers: Iterable[Customer]) -> None:
        self._customers: dict[str, Customer] = {}
        for c in customers:
            if c.customer_id in self._customers:
                raise ValueError(f"duplicate customer_id {c.customer_id}")
            self._customers[c.customer_id] = c

    def get(self, customer_id: str) -> Customer | None:
        return self._customers.get(customer_id)

    def all(self) -> list[Customer]:
        return list(self._customers.values())

    def refund(self, customer_id: str, amount: Decimal) -> Refund:
        customer = self.get(customer_id)
        if customer is None:
            raise CustomerNotFoundError
        if customer.status != "active":
            raise AccountNotActiveError
        if amount > customer.refundable_balance:
            raise InsufficientBalanceError
        remaining = customer.refundable_balance - amount
        self._customers[customer_id] = replace(customer, refundable_balance=remaining)
        return Refund(
            refund_id=f"RF-{uuid.uuid4().hex[:16].upper()}",
            customer_id=customer_id,
            amount=amount,
            remaining_balance=remaining,
        )


def seeded_store() -> InMemoryCustomerStore:
    """Demo data used when the server runs standalone."""
    return InMemoryCustomerStore(
        [
            Customer(
                "CUST-00042", "Ada Lovelace", "ada@example.com", "gold", "active", Decimal("250")
            ),
            Customer(
                "CUST-00101", "Alan Turing", "alan@example.com", "platinum", "active", Decimal(1000)
            ),
            Customer(
                "CUST-10001", "Grace Hopper", "grace@example.com", "standard", "active", Decimal(75)
            ),
            Customer(
                "CUST-00666",
                "Mallory Example",
                "mallory@example.com",
                "standard",
                "suspended",
                Decimal(50),
            ),
            Customer(
                "CUST-00999",
                "Closed Account",
                "closed@example.com",
                "standard",
                "closed",
                Decimal(0),
            ),
        ]
    )
