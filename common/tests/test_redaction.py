"""Unit + property tests for the sensitive-data redaction used by logging and audit."""

from __future__ import annotations

import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from quilr_common.redaction import REDACTED, is_luhn_valid, redact_text, redact_value

# --- Emails -------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "contact jane.doe@example.com now",
        "JANE+tag@Sub.Example.co.uk",
        "a_b-c%d@x-y.io",
    ],
)
def test_email_is_redacted(text: str) -> None:
    out = redact_text(text)
    assert "@" not in out
    assert REDACTED in out


def test_email_redaction_preserves_surrounding_text() -> None:
    assert redact_text("mail jane@example.com, thanks") == f"mail {REDACTED}, thanks"


# --- SSNs ---------------------------------------------------------------------


@pytest.mark.parametrize("ssn", ["123-45-6789", "123 45 6789"])
def test_ssn_is_redacted(ssn: str) -> None:
    assert redact_text(f"ssn {ssn} end") == f"ssn {REDACTED} end"


@pytest.mark.parametrize(
    "not_ssn",
    [
        "000-12-3456",  # area 000 is never issued
        "666-12-3456",  # area 666 is never issued
        "912-12-3456",  # 9xx areas are never issued
        "123-00-4567",  # group 00 is never issued
        "123-45-0000",  # serial 0000 is never issued
        "1234-56-7890",  # wrong shape
        "123-45-67890",  # wrong shape
    ],
)
def test_invalid_ssn_shapes_are_not_redacted(not_ssn: str) -> None:
    assert redact_text(not_ssn) == not_ssn


# --- Payment cards ------------------------------------------------------------


@pytest.mark.parametrize(
    "card",
    [
        "4111111111111111",  # Visa test number
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "5500 0000 0000 0004",  # Mastercard test number
        "378282246310005",  # Amex (15 digits)
    ],
)
def test_luhn_valid_card_is_redacted(card: str) -> None:
    assert redact_text(f"card {card} ok") == f"card {REDACTED} ok"


def test_luhn_invalid_digit_run_is_not_redacted() -> None:
    # Order IDs / timestamps must not be destroyed: Luhn gate avoids false positives.
    assert redact_text("order 1234567890123456") == "order 1234567890123456"


@pytest.mark.parametrize(
    ("digits", "valid"),
    [("4111111111111111", True), ("4111111111111112", False), ("0", True), ("", False)],
)
def test_is_luhn_valid(digits: str, *, valid: bool) -> None:
    assert is_luhn_valid(digits) is valid


# --- Credentials --------------------------------------------------------------


def test_bearer_token_is_redacted_but_scheme_kept() -> None:
    out = redact_text("Authorization: Bearer abc123.def456-ghi")
    assert out == f"Authorization: Bearer {REDACTED}"


def test_jwt_is_redacted() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlX2J5dGVz"
    assert redact_text(f"token={jwt}") == f"token={REDACTED}"


@pytest.mark.parametrize(
    "key",
    [
        "sk-ant-api03-AbCdEf0123456789_-AbCdEf0123456789",
        "sk-proj-AbCdEf0123456789AbCdEf0123456789",
        "sk-AbCdEf0123456789AbCdEf0123456789",
    ],
)
def test_provider_api_keys_are_redacted(key: str) -> None:
    out = redact_text(f"key {key} leaked")
    assert out == f"key {REDACTED} leaked"


# --- Structured values --------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "authorization",
        "Authorization",
        "api_key",
        "X-API-Key",
        "password",
        "client_secret",
        "access_token",
        "refresh-token",
        "cookie",
        "set-cookie",
        "private_key",
    ],
)
def test_sensitive_keys_are_redacted_regardless_of_value(key: str) -> None:
    assert redact_value({key: "harmless-looking"}) == {key: REDACTED}


def test_nested_structures_are_redacted() -> None:
    value = {
        "user": {"email": "jane@example.com", "headers": {"Authorization": "Bearer x"}},
        "items": ["ok", "4111 1111 1111 1111", 42, None, True],
    }
    assert redact_value(value) == {
        "user": {"email": REDACTED, "headers": {"Authorization": REDACTED}},
        "items": ["ok", REDACTED, 42, None, True],
    }


def test_tuples_are_redacted_as_lists() -> None:
    assert redact_value(("jane@example.com",)) == [REDACTED]


def test_excessive_depth_is_cut_off_not_recursed() -> None:
    deep: object = "jane@example.com"
    for _ in range(100):
        deep = {"k": deep}
    out = redact_value(deep, max_depth=5)
    cursor = out
    for _ in range(5):
        assert isinstance(cursor, dict)
        cursor = cursor["k"]
    assert cursor == "[TRUNCATED:depth]"


def test_non_string_scalars_pass_through() -> None:
    assert redact_value(3.5) == 3.5
    assert redact_value(None) is None


def test_unknown_objects_are_stringified_then_redacted() -> None:
    class Thing:
        def __str__(self) -> str:
            return "owner jane@example.com"

    assert redact_value(Thing()) == f"owner {REDACTED}"


# --- Properties ---------------------------------------------------------------

_local = st.text(alphabet=string.ascii_letters + string.digits + "._+-", min_size=1, max_size=20)
_domain = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=1, max_size=15)


@given(local=_local, domain=_domain, prefix=st.text(max_size=30), suffix=st.text(max_size=30))
def test_generated_emails_never_survive(local: str, domain: str, prefix: str, suffix: str) -> None:
    email = f"{local}@{domain}.com"
    assert email not in redact_text(f"{prefix} {email} {suffix}")


@given(st.text(max_size=200))
def test_redaction_is_idempotent(text: str) -> None:
    once = redact_text(text)
    assert redact_text(once) == once
