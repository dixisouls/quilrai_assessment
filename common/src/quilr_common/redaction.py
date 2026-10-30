"""Sensitive-data redaction for observability data (logs, audit events, error details).

Two complementary mechanisms:

* **Key-based** — values under keys such as ``authorization`` or ``api_key`` are
  always replaced, whatever they look like. This catches secrets that have no
  recognisable shape.
* **Pattern-based** — free text is scanned for credentials (bearer tokens, JWTs,
  provider API keys) and PII (emails, SSNs, Luhn-valid payment card numbers).

Every match is replaced with the same ``[REDACTED]`` marker so the output is
idempotent and cannot be distinguished by type. That matters when logs leave the
trust boundary.

Scope: this module redacts *whole strings*. Redacting a *stream* of partial
chunks needs a bounded look-behind buffer and is built on top of these patterns
by the LLM-gateway guardrail (Task 3).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any, Final

REDACTED: Final = "[REDACTED]"
DEPTH_TRUNCATED: Final = "[TRUNCATED:depth]"

# Key names are normalised (lower-case, '-' -> '_') before lookup.
SENSITIVE_KEYS: Final = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "x_api_key",
        "api_key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "cookie",
        "set_cookie",
        "private_key",
        "session",
    }
)

# --- Credential patterns ------------------------------------------------------
# Order matters: the bearer rule keeps the scheme word, so it runs before the
# bare-JWT rule would swallow the token on its own.
_BEARER = re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9\-._~+/]+=*")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
# Anthropic (sk-ant-...), OpenAI project (sk-proj-...) and legacy (sk-...) keys.
_PROVIDER_KEY = re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}")

# --- PII patterns -------------------------------------------------------------
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# US SSN with '-' or ' ' separators. Areas 000, 666 and 9xx, group 00 and serial
# 0000 are never issued, so excluding them cuts false positives. Unseparated
# 9-digit runs are deliberately not matched: too many collide with IDs.
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}([- ])(?!00)\d{2}\1(?!0000)\d{4}\b")
# 13-19 digits, optionally grouped by single spaces or dashes; the Luhn check
# below decides whether a candidate is really a card number.
_CARD_CANDIDATE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def is_luhn_valid(digits: str) -> bool:
    """Return True if ``digits`` (digits only) passes the Luhn checksum."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:  # noqa: PLR2004 - Luhn digit fold
                d -= 9
        total += d
    return total % 10 == 0


def _card_sub(match: re.Match[str]) -> str:
    raw = match.group(0)
    digits = raw.replace(" ", "").replace("-", "")
    return REDACTED if is_luhn_valid(digits) else raw


_RULES: Final[tuple[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]], ...]] = (
    (_BEARER, rf"\1 {REDACTED}"),
    (_JWT, REDACTED),
    (_PROVIDER_KEY, REDACTED),
    (_EMAIL, REDACTED),
    (_SSN, REDACTED),
    (_CARD_CANDIDATE, _card_sub),
)


def redact_text(text: str) -> str:
    """Replace every credential / PII match in ``text`` with ``[REDACTED]``."""
    for pattern, repl in _RULES:
        text = pattern.sub(repl, text)
    return text


def _is_sensitive_key(key: object) -> bool:
    return isinstance(key, str) and key.strip().lower().replace("-", "_") in SENSITIVE_KEYS


def redact_value(value: Any, *, max_depth: int = 8) -> Any:
    """Recursively redact a JSON-like value.

    Mappings and sequences are rebuilt rather than mutated, and tuples come back
    as lists, as they would through JSON. Nesting beyond ``max_depth`` is
    replaced, so a hostile payload can't blow the stack or the log size.
    Scalars other than ``str`` pass through. Unknown objects are stringified,
    then redacted.
    """
    return _redact(value, max_depth)


def _redact(value: Any, depth: int) -> Any:  # noqa: PLR0911 - flat type dispatch
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if depth <= 0:
        return DEPTH_TRUNCATED
    if isinstance(value, Mapping):
        return {
            str(k): REDACTED if _is_sensitive_key(k) else _redact(v, depth - 1)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_redact(v, depth - 1) for v in value]
    if isinstance(value, bytes | bytearray):
        return redact_text(bytes(value).decode("utf-8", errors="replace"))
    return redact_text(str(value))
