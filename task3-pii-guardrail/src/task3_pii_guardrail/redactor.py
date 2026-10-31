"""Streaming PII redaction with a bounded look-behind buffer.

The problem: provider output arrives as small text deltas, and a sensitive
value can be split across them (``"jane@exa"`` + ``"mple.com"``). The
redactor must never emit text that might still turn out to be part of a match,
and must never hold back text it doesn't need to (latency, memory).

How :class:`StreamRedactor` decides what is safe to emit
----------------------------------------------------------
Every pattern (email, SSN, payment card) matches a contiguous run of
*candidate characters*: ASCII letters, digits and ``._%+@-``, plus a space only
when it sits between digits (a card or SSN separator). So at any moment, only
the **trailing run of candidate characters** can still grow into a match.
Everything before it ends at a boundary character that no match can cross,
which means that prefix can be redacted and emitted right away, with exactly
the result whole-text redaction would give.

Consequences:

* **Latency:** in prose, the held text is the current word. ``"The quick "``
  is released immediately; ``"jum"`` waits for its boundary.
* **Correctness:** for any chunking, the output equals :func:`redact_all` of
  the whole text (property-tested). Boundaries use ASCII semantics
  (``re.ASCII``) so a cut can never change how a pattern's lookarounds or
  ``\\b`` evaluate.
* **Memory:** the hold-back is capped at :data:`MAX_HOLDBACK` characters. A
  longer unbroken run (base64 blob, minified data) is force-emitted in blocks,
  after moving the cut so it never splits a complete match. In that forced
  path a cut may land mid-run, which can only cause *extra* redaction (a
  truncated digit run looking like a card), never a leak.
* **Cost:** each :meth:`feed` scans only the new chunk, and redaction regexes
  run once over each emitted region. Total work is linear in the stream
  length. All quantifiers are bounded and match starts are anchored with
  lookbehinds, so there is no quadratic rescanning on hostile input.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

REDACTED: Final = "[REDACTED]"
MAX_HOLDBACK: Final = 2048
_KEEP_ON_FORCED_CUT: Final = 1024

_CANDIDATE: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+@-"
)
_DIGITS: Final = frozenset("0123456789")

_EMAIL: Final = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
    r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}",
    re.ASCII,
)
# US SSN with '-' or ' ' separators; never-issued areas (000, 666, 9xx), group 00
# and serial 0000 are excluded to cut false positives.
_SSN: Final = re.compile(r"\b(?!000|666|9\d\d)\d{3}([- ])(?!00)\d{2}\1(?!0000)\d{4}\b", re.ASCII)
# 13-19 digits, optionally grouped by single spaces or dashes; Luhn decides.
_CARD_CANDIDATE: Final = re.compile(r"\b\d(?:[ -]?\d){12,18}\b", re.ASCII)
_DIGIT_GROUP: Final = re.compile(r"\d+", re.ASCII)
_CARD_MIN, _CARD_MAX, _CARD_GROUP_MIN = 13, 19, 3


def is_luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:  # noqa: PLR2004 - Luhn digit fold
                d -= 9
        total += d
    return bool(digits) and total % 10 == 0


def _card_sub(match: re.Match[str]) -> str:
    """Redact a Luhn-valid PAN in a candidate, including one followed by a CVV group.

    Unseparated runs are checked whole only: guessing sub-windows of a long
    digit run would flag about 10% of random IDs. Grouped candidates must look
    like a real PAN layout (one separator style, groups of 3 or more digits),
    and are then also checked at group boundaries.
    """
    raw = match.group(0)
    groups = list(_DIGIT_GROUP.finditer(raw))
    if len(groups) > 1 and (
        len(set(raw) - _DIGITS) > 1  # mixed separators: "000-12-3456 666" is not a card
        or any(len(g.group()) < _CARD_GROUP_MIN for g in groups)
    ):
        return raw
    if is_luhn_valid("".join(g.group() for g in groups)):
        return REDACTED
    if len(groups) < 2:  # noqa: PLR2004
        return raw
    for i in range(len(groups)):
        for j in range(len(groups), i, -1):
            digits = "".join(g.group() for g in groups[i:j])
            if _CARD_MIN <= len(digits) <= _CARD_MAX and is_luhn_valid(digits):
                return raw[: groups[i].start()] + REDACTED + raw[groups[j - 1].end() :]
    return raw


_RULES: Final[tuple[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]], ...]] = (
    (_EMAIL, REDACTED),
    (_SSN, REDACTED),
    (_CARD_CANDIDATE, _card_sub),
)


def redact_counted(text: str) -> tuple[str, int]:
    """Redact a complete text; also return how many values were replaced."""
    count = 0
    for pattern, repl in _RULES:
        if pattern is _EMAIL and "@" not in text:
            continue
        redacted = pattern.sub(repl, text)
        # Markers added by this rule. Not subn(): the card rule may "replace" a
        # candidate with itself, and the input may already contain the marker.
        count += redacted.count(REDACTED) - text.count(REDACTED)
        text = redacted
    return text, count


def redact_all(text: str) -> str:
    """Redact a complete text. The reference result streaming must reproduce."""
    return redact_counted(text)[0]


class StreamRedactor:
    """Incremental redactor: ``feed`` deltas, then ``flush`` once at end of stream."""

    def __init__(self) -> None:
        self._pending = ""
        self._closed = False
        self.redactions = 0  # values replaced so far (for audit; never the values)

    @property
    def pending_chars(self) -> int:
        return len(self._pending)

    def feed(self, chunk: str) -> str:
        """Add a delta; return the redacted text that is now safe to emit."""
        if self._closed:
            raise RuntimeError("feed() after flush()")
        if not chunk:
            return ""
        buf = self._pending + chunk
        cut = self._run_start(buf, len(self._pending))
        if len(buf) - cut > MAX_HOLDBACK:
            cut = self._forced_cut(buf)
        self._pending = buf[cut:]
        return self._redact(buf[:cut]) if cut else ""

    def flush(self) -> str:
        """End of stream: redact and return whatever is still held."""
        if self._closed:
            return ""
        self._closed = True
        out, self._pending = self._redact(self._pending), ""
        return out

    def discard(self) -> None:
        """Abort: drop held text *without* emitting it.

        Used when the upstream stream fails mid-way. Held text may be the start
        of a value (``"jane.do"``) that only the rest of the stream would have
        identified, so flushing it would leak a fragment of PII.
        """
        self._closed = True
        self._pending = ""

    def _redact(self, text: str) -> str:
        out, count = redact_counted(text)
        self.redactions += count
        return out

    # --- internals ------------------------------------------------------------------

    @staticmethod
    def _is_candidate(buf: str, i: int) -> bool:
        ch = buf[i]
        if ch in _CANDIDATE:
            return True
        # A space is part of a run only as a separator between digits; at the very
        # end of the buffer it might become one, so it's held.
        return (
            ch == " "
            and i > 0
            and buf[i - 1] in _DIGITS
            and (i + 1 == len(buf) or buf[i + 1] in _DIGITS)
        )

    def _run_start(self, buf: str, old_len: int) -> int:
        """Index where the trailing candidate run begins (== len(buf) if none)."""
        i = len(buf)
        while i > old_len and self._is_candidate(buf, i - 1):
            i -= 1
        if i > old_len:
            return i  # boundary found inside the new chunk
        # The whole chunk extends the held run. The held text was a run, except
        # possibly its last char: a held trailing space is a separator only if
        # the chunk continues with a digit.
        if old_len and not self._is_candidate(buf, old_len - 1):
            return old_len
        return 0

    @staticmethod
    def _forced_cut(buf: str) -> int:
        """Cut an over-long run, never through a complete match."""
        cut = len(buf) - _KEEP_ON_FORCED_CUT
        for pattern, _ in _RULES:
            for m in pattern.finditer(buf, max(0, cut - 400), min(len(buf), cut + 400)):
                if m.start() < cut < m.end():
                    cut = m.start()
        return cut
