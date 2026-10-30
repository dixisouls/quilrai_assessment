"""Strict input and output schemas for the customer tools.

These Pydantic models are the **single source of truth**. They validate
incoming ``tools/call`` arguments *and* generate the JSON Schemas advertised in
``tools/list``, so what clients are told and what the server enforces can't
drift apart.

Validation rules (and why):

* ``customer_id`` must fully match ``^CUST-[0-9]{5}$``. ``[0-9]`` instead of
  ``\\d``: in Python, ``\\d`` also matches Arabic-Indic, full-width and other
  Unicode digits. There is no case-folding or trimming. An identifier is
  either exactly right or rejected.
* ``amount`` must be a JSON number (not a numeric string, not a boolean),
  finite, > 0, at most :data:`MAX_REFUND_AMOUNT`, with at most 2 decimal places.
  It is converted to :class:`~decimal.Decimal` via the float's shortest
  ``repr`` so ``0.1`` becomes exactly ``0.10``, and all arithmetic after that is
  decimal. **Limitation:** the SDK parses the JSON line into a binary float
  *before* any validator runs, so digits beyond float precision (about 17
  significant digits) are gone by then. ``19.989999999999999`` reaches us as
  ``19.99`` and is accepted. Closing this gap means changing the input
  contract (integer cents, or a decimal *string*). The brief specifies a
  float, so the contract is kept and the limit documented.
* ``reason`` is trimmed, must then be 10 to 500 characters, and may not contain
  any code point in categories Cc/Cf/Zl/Zp/Co/Cn/Cs: control characters,
  bidi and zero-width format characters, line/paragraph separators, private
  use, unassigned and surrogates. Any of these would allow log or record
  injection, or text that renders differently from what it says.
* Unknown fields are rejected (``additionalProperties: false``).
"""

from __future__ import annotations

import math
import unicodedata
from decimal import Decimal
from typing import Annotated, Final, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PlainValidator,
    WithJsonSchema,
)

CUSTOMER_ID_PATTERN: Final = r"^CUST-[0-9]{5}$"
MAX_REFUND_AMOUNT: Final = 10_000
MIN_REASON_CHARS: Final = 10
MAX_REASON_CHARS: Final = 500
_CENT: Final = Decimal("0.01")
_FORBIDDEN_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cn", "Cs"})

# The advertised JSON Schema pattern for ``reason``. It is an ECMA-262 character
# class covering the common members of the forbidden categories (all controls,
# bidi/zero-width format chars, line separators, BMP private use, surrogates).
# The validator above remains authoritative for the long tail (e.g. unassigned
# code points), so clients get a close, never a looser, description.
_BS: Final = chr(92)  # backslash, kept out of literals so no tool decodes the escapes
_REASON_EXCLUDED_RANGES: Final = (
    (0x0000, 0x001F),
    (0x007F, 0x009F),
    (0x00AD, 0x00AD),
    (0x061C, 0x061C),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xD800, 0xDFFF),
    (0xE000, 0xF8FF),
    (0xFEFF, 0xFEFF),
)
REASON_SCHEMA_PATTERN: Final = (
    "^[^"
    + "".join(
        f"{_BS}u{lo:04x}" if lo == hi else f"{_BS}u{lo:04x}-{_BS}u{hi:04x}"
        for lo, hi in _REASON_EXCLUDED_RANGES
    )
    + "]*$"
)


def _parse_amount(value: object) -> Decimal:
    # bool is a subclass of int in Python; JSON true/false is not an amount.
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("amount must be a JSON number")  # noqa: TRY004 - pydantic needs ValueError
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("amount must be a finite number")
    amount = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    if amount <= 0:
        raise ValueError("amount must be greater than 0")
    if amount > MAX_REFUND_AMOUNT:
        raise ValueError(f"amount must not exceed {MAX_REFUND_AMOUNT}")
    exponent = amount.as_tuple().exponent
    if isinstance(exponent, int) and exponent < -2:  # noqa: PLR2004 - cents
        raise ValueError("amount must have at most 2 decimal places")
    return amount.quantize(_CENT)


def _clean_reason(value: str) -> str:
    value = value.strip()
    if len(value) < MIN_REASON_CHARS:
        raise ValueError(f"reason must be at least {MIN_REASON_CHARS} characters after trimming")
    if any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value):
        raise ValueError(
            "reason must not contain control, formatting, line-separator or unassigned characters"
        )
    return value


CustomerId = Annotated[
    str,
    Field(
        pattern=CUSTOMER_ID_PATTERN,
        description="Customer identifier: 'CUST-' followed by exactly 5 digits.",
        examples=["CUST-00042"],
    ),
]

RefundAmount = Annotated[
    Decimal,
    PlainValidator(_parse_amount),
    WithJsonSchema(
        {
            "type": "number",
            "exclusiveMinimum": 0,
            "maximum": MAX_REFUND_AMOUNT,
            # No "multipleOf": 0.01 on purpose. Validators doing float division
            # (e.g. Python jsonschema) would reject ~11% of valid amounts such as 0.07.
            "description": "Refund amount in USD: positive, at most 2 decimal places.",
        }
    ),
]

RefundReason = Annotated[
    str,
    Field(
        min_length=MIN_REASON_CHARS,
        max_length=MAX_REASON_CHARS,
        description="Why the refund is issued (10-500 characters, single line).",
        json_schema_extra={"pattern": REASON_SCHEMA_PATTERN},
    ),
    AfterValidator(_clean_reason),
]


class _StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class GetCustomerRecordInput(_StrictInput):
    """Arguments for ``get_customer_record``."""

    customer_id: CustomerId


class TriggerRefundInput(_StrictInput):
    """Arguments for ``trigger_refund``."""

    customer_id: CustomerId
    amount: RefundAmount
    reason: RefundReason


# --- Outputs ------------------------------------------------------------------
# Money is serialised as a decimal *string* ("25.50") so no client parses it
# into a binary float.


class CustomerRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    customer_id: str
    name: str
    email: str
    tier: Literal["standard", "gold", "platinum"]
    status: Literal["active", "suspended", "closed"]
    refundable_balance: str = Field(description="USD, decimal string")


class RefundReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    refund_id: str
    customer_id: str
    amount: str = Field(description="USD, decimal string")
    currency: Literal["USD"] = "USD"
    status: Literal["accepted"] = "accepted"
    remaining_refundable_balance: str = Field(description="USD, decimal string")
