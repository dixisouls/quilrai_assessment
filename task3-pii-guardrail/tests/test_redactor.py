"""Unit and property tests for the streaming PII redactor."""

from __future__ import annotations

import string
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from task3_pii_guardrail.redactor import MAX_HOLDBACK, REDACTED, StreamRedactor, redact_all


def stream(chunks: list[str]) -> str:
    redactor = StreamRedactor()
    return "".join(redactor.feed(c) for c in chunks) + redactor.flush()


# --- Whole-text detection -------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail jane.doe@example.com now", f"mail {REDACTED} now"),
        ("JANE+tag@Sub.Example.co.uk.", f"{REDACTED}."),
        ("ssn 123-45-6789 ok", f"ssn {REDACTED} ok"),
        ("ssn 123 45 6789 ok", f"ssn {REDACTED} ok"),
        ("card 4111 1111 1111 1111 ok", f"card {REDACTED} ok"),
        ("card 4111-1111-1111-1111 ok", f"card {REDACTED} ok"),
        ("card 4111111111111111 ok", f"card {REDACTED} ok"),
        ("amex 378282246310005", f"amex {REDACTED}"),
        ("card 4111 1111 1111 1111 123 cvv", f"card {REDACTED} 123 cvv"),
        ("two: a@b.io and 5500 0000 0000 0004", f"two: {REDACTED} and {REDACTED}"),
    ],
)
def test_detects_each_pii_type(text: str, expected: str) -> None:
    assert redact_all(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "order 1234567890123456 shipped",  # 16 digits, fails Luhn
        "invoice 12345678901234567890123",  # long digit run: no sub-window guessing
        "ssn-like 000-12-3456 666-12-3456 912-12-3456 123-00-4567 123-45-0000",
        "version 1.2.3 and 10.0.0.1",
        "no at sign here",
        "trailing at@ and @leading",
        "price 1,234.56 USD",
    ],
)
def test_avoids_false_positives(text: str) -> None:
    assert redact_all(text) == text


# --- Streaming: split points ---------------------------------------------------------

SAMPLE = (
    "Hi Jane, your email jane.doe@example.com and SSN 123-45-6789 are on file. "
    "Card 4111 1111 1111 1111 expires soon; backup a_b@x-y.io. Thanks!"
)


def test_pii_split_at_every_possible_point_is_redacted() -> None:
    expected = redact_all(SAMPLE)
    for i in range(len(SAMPLE) + 1):
        assert stream([SAMPLE[:i], SAMPLE[i:]]) == expected, i


def test_character_by_character_stream_matches_whole_text() -> None:
    assert stream(list(SAMPLE)) == redact_all(SAMPLE)


def test_no_raw_pii_ever_leaves_the_redactor_mid_stream() -> None:
    redactor = StreamRedactor()
    emitted = ""
    for ch in SAMPLE:
        emitted += redactor.feed(ch)
        for secret in ("jane.doe", "123-45", "4111 1111", "a_b@"):
            assert secret not in emitted
    emitted += redactor.flush()
    assert emitted == redact_all(SAMPLE)


# --- Streaming: latency and memory ---------------------------------------------------


def test_prose_is_released_as_soon_as_each_word_ends() -> None:
    redactor = StreamRedactor()
    out = redactor.feed("The quick brown fox ")
    assert out == "The quick brown fox "  # nothing held once a boundary arrives
    assert redactor.feed("jum") == ""  # a partial word might still become an email
    assert redactor.feed("ps over") == "jumps "
    assert redactor.flush() == "over"


def test_digits_are_held_only_while_they_could_form_a_card_or_ssn() -> None:
    redactor = StreamRedactor()
    assert redactor.feed("Total: 42") == "Total: "
    assert redactor.feed(" items, ") == "42 items, "


def test_holdback_is_bounded_for_unbroken_input() -> None:
    redactor = StreamRedactor()
    emitted = 0
    for _ in range(1000):  # 1 MB with no boundary at all
        emitted += len(redactor.feed("a" * 1000))
        assert redactor.pending_chars <= MAX_HOLDBACK
    emitted += len(redactor.flush())
    assert emitted == 1_000_000


def test_long_runs_still_redact_pii_near_the_forced_cut() -> None:
    # PII inside a run longer than the holdback must not leak through a forced cut.
    text = "x" * 2000 + " jane@example.com " + "y" * 2000
    chunks = [text[i : i + 7] for i in range(0, len(text), 7)]
    assert "jane@example.com" not in stream(chunks)


def test_redaction_cost_is_linear_in_stream_length() -> None:
    piece = "Contact jane.doe@example.com or 4111 1111 1111 1111 for help. " * 20
    text = piece * 100  # ~120 KB
    start = time.perf_counter()
    out = stream([text[i : i + 4] for i in range(0, len(text), 4)])  # token-sized chunks
    elapsed = time.perf_counter() - start
    assert "jane.doe" not in out
    assert elapsed < 2.0, elapsed


@pytest.mark.parametrize(
    "hostile", ["a" * 50_000, "1 " * 25_000, "@" * 50_000, "a@" * 25_000, "-1" * 25_000]
)
def test_hostile_input_is_fast(hostile: str) -> None:
    start = time.perf_counter()
    stream([hostile[i : i + 16] for i in range(0, len(hostile), 16)])
    assert time.perf_counter() - start < 1.0


def test_flush_is_final() -> None:
    redactor = StreamRedactor()
    redactor.feed("abc")
    assert redactor.flush() == "abc"
    assert redactor.flush() == ""
    with pytest.raises(RuntimeError):
        redactor.feed("more")


# --- Properties -------------------------------------------------------------------------

_fragments = st.one_of(
    st.sampled_from(
        [
            "jane.doe@example.com",
            "a@b.io",
            "123-45-6789",
            "123 45 6789",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "378282246310005",
            "1234567890123456",
            " ",
            ", ",
            ". ",
            "\n",
            "-",
            "@",
        ]
    ),
    st.text(alphabet=string.ascii_letters + string.digits + " .,@-_", min_size=1, max_size=12),
)


@settings(max_examples=300, deadline=None)
@given(
    parts=st.lists(_fragments, min_size=1, max_size=25),
    cuts=st.lists(st.integers(min_value=0, max_value=400), max_size=30),
)
def test_any_chunking_gives_the_same_output_as_whole_text(
    parts: list[str], cuts: list[int]
) -> None:
    text = "".join(parts)
    points = sorted({c % (len(text) + 1) for c in cuts})
    chunks = [text[a:b] for a, b in zip([0, *points], [*points, len(text)], strict=True)]
    assert stream(chunks) == redact_all(text)


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=300))
def test_arbitrary_unicode_never_crashes_and_is_chunk_invariant(text: str) -> None:
    third = len(text) // 3
    assert stream([text[:third], text[third : 2 * third], text[2 * third :]]) == redact_all(text)


def test_redactions_are_counted_exactly() -> None:
    redactor = StreamRedactor()
    out = redactor.feed("a@b.io, 4111 1111 1111 1111, order 1234567890123456, [REDACTED] ")
    out += redactor.flush()
    assert redactor.redactions == 2  # the literal marker and the non-card digits don't count


def test_discard_drops_a_held_partial_value() -> None:
    redactor = StreamRedactor()
    assert redactor.feed("Contact jane.do") == "Contact "
    redactor.discard()
    assert redactor.flush() == ""


# --- Review #4 regressions ----------------------------------------------------------


@pytest.mark.parametrize("pad", [900, 950, 1000])
@pytest.mark.parametrize("size", [1, 4, 64])
def test_forced_cut_never_splits_a_long_email(pad: int, size: int) -> None:
    domain = ".".join("d" * 60 for _ in range(9)) + ".com"
    text = "start " + "x" * pad + "@" + f"victim.secret@{domain}" + "-" + "y" * 1500 + " end"
    assert "victim.secret" not in redact_all(text)
    assert "victim.secret" not in stream([text[i : i + size] for i in range(0, len(text), size)])
