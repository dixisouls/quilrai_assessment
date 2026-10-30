"""Unit tests for the tool input schemas: the strict validation layer."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from task1_mcp_server.models import (
    MAX_REFUND_AMOUNT,
    GetCustomerRecordInput,
    TriggerRefundInput,
)

VALID_REFUND: dict[str, Any] = {
    "customer_id": "CUST-00042",
    "amount": 25.5,
    "reason": "Duplicate charge on invoice",
}


def _refund(**overrides: Any) -> dict[str, Any]:
    return {**VALID_REFUND, **overrides}


def _error_types(exc: pytest.ExceptionInfo[ValidationError]) -> set[str]:
    return {e["type"] for e in exc.value.errors()}


# --- customer_id --------------------------------------------------------------


@pytest.mark.parametrize("cid", ["CUST-00000", "CUST-12345", "CUST-99999"])
def test_valid_customer_ids(cid: str) -> None:
    assert GetCustomerRecordInput.model_validate({"customer_id": cid}).customer_id == cid


@pytest.mark.parametrize(
    "cid",
    [
        "CUST-1234",  # too short
        "CUST-123456",  # too long
        "cust-12345",  # wrong case: strict, no normalisation
        "CUST_12345",  # wrong separator
        "CUST-1234A",  # non-digit
        " CUST-12345",  # leading whitespace
        "CUST-12345 ",  # trailing whitespace
        "CUST-12345\n",  # trailing newline ($ in some regex engines allows this)
        "CUST-\u0661\u0662\u0663\u0664\u0665",  # Arabic-Indic digits: \d would accept these
        "CUST-\uff11\uff12\uff13\uff14\uff15",  # full-width digits
        "",
        "CUST-",
    ],
)
def test_invalid_customer_ids_are_rejected(cid: str) -> None:
    with pytest.raises(ValidationError):
        GetCustomerRecordInput.model_validate({"customer_id": cid})


@pytest.mark.parametrize("cid", [12345, None, ["CUST-12345"], {"id": "CUST-12345"}, True])
def test_non_string_customer_ids_are_rejected(cid: object) -> None:
    with pytest.raises(ValidationError):
        GetCustomerRecordInput.model_validate({"customer_id": cid})


def test_get_customer_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError) as exc:
        GetCustomerRecordInput.model_validate({"customer_id": "CUST-12345", "include_ssn": True})
    assert "extra_forbidden" in _error_types(exc)


def test_get_customer_requires_customer_id() -> None:
    with pytest.raises(ValidationError) as exc:
        GetCustomerRecordInput.model_validate({})
    assert "missing" in _error_types(exc)


# --- amount -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (25.5, Decimal("25.50")),
        (0.01, Decimal("0.01")),
        (100, Decimal("100.00")),  # JSON integer is a valid number
        (0.1, Decimal("0.10")),  # no binary-float artefacts (0.1000000000000000055...)
        (MAX_REFUND_AMOUNT, Decimal(MAX_REFUND_AMOUNT).quantize(Decimal("0.01"))),
    ],
)
def test_valid_amounts_become_exact_decimals(amount: float, expected: Decimal) -> None:
    model = TriggerRefundInput.model_validate(_refund(amount=amount))
    assert model.amount == expected
    assert isinstance(model.amount, Decimal)


@pytest.mark.parametrize(
    "amount",
    [
        0,
        0.0,
        -1,
        -0.01,
        float("nan"),
        float("inf"),
        float("-inf"),
        MAX_REFUND_AMOUNT + 0.01,
        10.001,  # sub-cent precision
        1e-9,
    ],
)
def test_invalid_amounts_are_rejected(amount: float) -> None:
    with pytest.raises(ValidationError):
        TriggerRefundInput.model_validate(_refund(amount=amount))


@pytest.mark.parametrize("amount", ["25.50", "25", True, False, None, [25], {"value": 25}])
def test_non_numeric_amounts_are_rejected_not_coerced(amount: object) -> None:
    with pytest.raises(ValidationError):
        TriggerRefundInput.model_validate(_refund(amount=amount))


def test_nan_and_infinity_in_raw_json_are_rejected() -> None:
    # Python's json module accepts these non-standard literals; we must not.
    for literal in ("NaN", "Infinity", "-Infinity"):
        raw = f'{{"customer_id":"CUST-00042","amount":{literal},"reason":"Duplicate charge"}}'
        with pytest.raises(ValidationError):
            TriggerRefundInput.model_validate_json(raw)


# --- reason -------------------------------------------------------------------


def test_reason_is_trimmed() -> None:
    model = TriggerRefundInput.model_validate(_refund(reason="  Duplicate charge  "))
    assert model.reason == "Duplicate charge"


@pytest.mark.parametrize(
    "reason",
    [
        "too short",  # 9 chars
        "",
        " " * 20,  # whitespace only
        "  short   ",  # 5 chars once trimmed
        "x" * 501,  # over the cap
        "valid reason\nINJECTED",  # control character
        "valid reason\u202e",  # bidi override
        "valid\x00reason",  # NUL
    ],
)
def test_invalid_reasons_are_rejected(reason: str) -> None:
    with pytest.raises(ValidationError):
        TriggerRefundInput.model_validate(_refund(reason=reason))


def test_reason_of_exactly_ten_characters_is_accepted() -> None:
    assert TriggerRefundInput.model_validate(_refund(reason="0123456789")).reason == "0123456789"


@pytest.mark.parametrize("reason", [1234567890, None, ["Duplicate charge"]])
def test_non_string_reason_is_rejected(reason: object) -> None:
    with pytest.raises(ValidationError):
        TriggerRefundInput.model_validate(_refund(reason=reason))


# --- whole-object rules -------------------------------------------------------


def test_refund_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError) as exc:
        TriggerRefundInput.model_validate(_refund(override_limit=True))
    assert "extra_forbidden" in _error_types(exc)


@pytest.mark.parametrize("missing", ["customer_id", "amount", "reason"])
def test_refund_requires_every_field(missing: str) -> None:
    data = _refund()
    del data[missing]
    with pytest.raises(ValidationError) as exc:
        TriggerRefundInput.model_validate(data)
    assert "missing" in _error_types(exc)


def test_all_errors_are_reported_together() -> None:
    with pytest.raises(ValidationError) as exc:
        TriggerRefundInput.model_validate({"customer_id": "bad", "amount": -1, "reason": "short"})
    assert {tuple(e["loc"]) for e in exc.value.errors()} == {
        ("customer_id",),
        ("amount",),
        ("reason",),
    }


# --- JSON Schema advertised to clients -----------------------------------------


def test_published_schemas_are_strict() -> None:
    for model in (GetCustomerRecordInput, TriggerRefundInput):
        schema = model.model_json_schema()
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])


def test_published_schema_carries_the_constraints() -> None:
    props = TriggerRefundInput.model_json_schema()["properties"]
    assert props["customer_id"]["pattern"] == "^CUST-[0-9]{5}$"
    assert props["amount"]["type"] == "number"
    assert props["amount"]["exclusiveMinimum"] == 0
    assert props["amount"]["maximum"] == MAX_REFUND_AMOUNT
    assert props["reason"]["minLength"] == 10


# --- Review #2 regressions ----------------------------------------------------


@pytest.mark.parametrize(
    "codepoint",
    [
        0x2028,  # LINE SEPARATOR (category Zl)
        0x2029,  # PARAGRAPH SEPARATOR (Zp)
        0xE000,  # private use (Co)
        0x0378,  # unassigned (Cn)
        0x0085,  # NEXT LINE (Cc)
    ],
)
def test_reason_rejects_line_breaking_and_invisible_categories(codepoint: int) -> None:
    with pytest.raises(ValidationError):
        TriggerRefundInput.model_validate(_refund(reason=f"Line one{chr(codepoint)}line two"))


def test_reason_rejects_lone_surrogates() -> None:
    with pytest.raises(ValidationError):
        TriggerRefundInput.model_validate(_refund(reason="valid reason " + chr(0xD800)))


@pytest.mark.parametrize(
    ("raw_amount", "accepted"),
    [
        ("10.001", False),
        ("0.001", False),
        ("1e-3", False),
        ("19.99", True),
        ("1e2", True),
        ("1E-2", True),
        ("-0", False),
        ("10000.00", True),
        ("10000.01", False),
    ],
)
def test_amount_rules_hold_for_raw_json_text(raw_amount: str, *, accepted: bool) -> None:
    # The SDK hands us JSON already parsed to Python numbers; exercise that path too.
    raw = f'{{"customer_id":"CUST-00042","amount":{raw_amount},"reason":"Duplicate charge"}}'
    if accepted:
        assert TriggerRefundInput.model_validate_json(raw).amount > 0
    else:
        with pytest.raises(ValidationError):
            TriggerRefundInput.model_validate_json(raw)


def test_published_amount_schema_never_rejects_a_valid_amount() -> None:
    # "multipleOf": 0.01 looks right but float-dividing validators reject e.g. 0.07.
    # The schema may be looser than the server on precision, never stricter.
    jsonschema = pytest.importorskip("jsonschema")
    schema = TriggerRefundInput.model_json_schema()
    assert "multipleOf" not in schema["properties"]["amount"]
    assert "2 decimal places" in schema["properties"]["amount"]["description"]
    validator = jsonschema.Draft202012Validator(schema)
    # Every cent up to 100.00 (where float artefacts are densest), then a sweep to the cap.
    for cents in [*range(1, 10_001), *range(10_001, MAX_REFUND_AMOUNT * 100 + 1, 997)]:
        amount = cents / 100
        assert validator.is_valid(_refund(amount=amount)), amount
        TriggerRefundInput.model_validate(_refund(amount=amount))


def test_published_reason_pattern_agrees_with_the_validator() -> None:
    pattern = re.compile(TriggerRefundInput.model_json_schema()["properties"]["reason"]["pattern"])
    samples = [
        "Duplicate charge on invoice",
        "Line one" + chr(0x2028) + "line two",
        "tab" + chr(9) + "separated reason",
        "bidi" + chr(0x202E) + " reason text",
        "zero" + chr(0x200B) + "width reason",
        "Ünïcödé reason ok",
    ]
    for text in samples:
        try:
            TriggerRefundInput.model_validate(_refund(reason=text))
            enforced = True
        except ValidationError:
            enforced = False
        assert bool(pattern.fullmatch(text)) == enforced, repr(text)
