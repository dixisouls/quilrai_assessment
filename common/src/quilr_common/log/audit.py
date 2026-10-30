"""Security audit events and a tamper-evident, hash-chained audit file.

Each security decision (allow, deny, redact, rate-limit, failover) is emitted as
an :class:`AuditEvent`. Events go to two places:

1. The normal JSON log stream (``log_type: "audit"``), so the platform log
   shipper delivers them to the SIEM with everything else.
2. Optionally, an append-only JSON-lines file in which each record includes the
   digest of the previous one. Editing, deleting or reordering any record
   breaks the chain, and :func:`verify_chain` reports the first bad line.

Threat model:

* **Unkeyed (SHA-256):** catches accidental corruption and careless edits. It
  does **not** stop an attacker with write access, who can rewrite the file
  and recompute every hash.
* **Keyed (HMAC-SHA256, ``LOG_AUDIT_HMAC_KEY``):** forging a record requires
  the key. Keep the key off the log host (KMS / secret manager); production
  should always set it. The verifier requires the expected algorithm, so an
  attacker can't downgrade records to plain SHA-256.
* **Tail truncation** (dropping the newest N records) is invisible to any
  chain on its own. Anchor ``ChainVerification.head_hash`` externally, e.g.
  ship it periodically to the SIEM.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from quilr_common.log.context import get_context
from quilr_common.log.fallback import report_logging_failure
from quilr_common.log.settings import ServiceInfo
from quilr_common.redaction import redact_value

AUDIT_LOGGER_NAME: Final = "quilr.audit"
GENESIS_HASH: Final = "0" * 64
_CONTEXT_FIELDS: Final = ("request_id", "tenant_id", "principal")
_TAIL_READ_BLOCK: Final = 4096


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    RATE_LIMITED = "rate_limited"
    FAILOVER = "failover"
    ERROR = "error"


class AuditEvent(BaseModel):
    """One security-relevant decision. Immutable once created.

    ``request_id``, ``tenant_id`` and ``principal`` default to the values bound
    in the current log context, so call sites can't forget them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str = Field(pattern=r"^[a-z0-9_.:-]{1,64}$")
    decision: Decision
    reason: str = Field(min_length=1, max_length=512)
    principal: str | None = Field(default=None, max_length=256)
    tenant_id: str | None = Field(default=None, max_length=256)
    request_id: str | None = Field(default=None, max_length=128)
    resource: str | None = Field(default=None, max_length=256)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _fill_from_context(cls, data: Any) -> Any:
        if isinstance(data, dict):
            ctx = get_context()
            for key in _CONTEXT_FIELDS:
                if data.get(key) is None and ctx.get(key) is not None:
                    data = {**data, key: str(ctx[key])}
        return data

    def to_log(self) -> dict[str, Any]:
        """JSON-safe, redacted payload. Defence in depth: callers shouldn't put PII here."""
        redacted: dict[str, Any] = redact_value(self.model_dump(mode="json"))
        return redacted


def emit_audit(event: AuditEvent) -> None:
    """Emit ``event`` through logging. Audit records bypass the app log level."""
    logging.getLogger(AUDIT_LOGGER_NAME).info(
        "audit %s %s", event.action, event.decision.value, extra={"audit": event.to_log()}
    )


class AuditChainError(RuntimeError):
    """The audit file is corrupted; refusing to extend it (fail closed)."""


def _canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _algorithm(key: bytes | None) -> str:
    return "sha256" if key is None else "hmac-sha256"


def _entry_hash(entry_without_hash: dict[str, Any], key: bytes | None) -> str:
    data = _canonical(entry_without_hash).encode()
    if key is None:
        return hashlib.sha256(data).hexdigest()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _check_entry(  # noqa: PLR0911 - one early return per verification rule
    raw: str, expected_seq: int, expected_prev: str, key: bytes | None
) -> tuple[str | None, str]:
    """Validate one line. Returns (error or None, the line's hash)."""
    try:
        entry = json.loads(raw)
    except json.JSONDecodeError:
        return "not valid JSON", ""
    if not isinstance(entry, dict) or not isinstance(entry.get("hash"), str):
        return "missing hash", ""
    claimed = entry.pop("hash")
    if entry.get("seq") != expected_seq:
        return f"expected seq {expected_seq}, got {entry.get('seq')!r}", claimed
    if entry.get("alg") != _algorithm(key):
        return f"unexpected alg {entry.get('alg')!r}, expected {_algorithm(key)!r}", claimed
    if entry.get("prev_hash") != expected_prev:
        return "prev_hash does not link to previous record", claimed
    if not hmac.compare_digest(_entry_hash(entry, key), claimed):
        return "hash mismatch (record modified)", claimed
    return None, claimed


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    records: int
    head_hash: str
    first_bad_line: int | None = None
    reason: str | None = None


def verify_chain(path: Path, *, key: bytes | None = None) -> ChainVerification:
    """Walk the whole file, re-deriving every digest. Line numbers are 1-based.

    Pass the same ``key`` the writer used. Every record must use the matching
    algorithm, which rules out downgrade attacks.
    """
    prev, count = GENESIS_HASH, 0
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            error, digest = _check_entry(line.rstrip("\n"), count + 1, prev, key)
            if error is not None:
                return ChainVerification(False, count, prev, lineno, error)
            prev, count = digest, count + 1
    return ChainVerification(True, count, prev)


def _read_last_line(fd: int) -> str | None:
    """Return the last line of the file (without its newline), or None if empty."""
    size = os.fstat(fd).st_size
    if size == 0:
        return None
    buf, pos = b"", size
    while pos > 0:
        step = min(_TAIL_READ_BLOCK, pos)
        pos -= step
        buf = os.pread(fd, step, pos) + buf
        # Two newlines bound the last line (the final one terminates it).
        if buf.count(b"\n") >= 2:  # noqa: PLR2004 - two newlines bound one line
            break
    if not buf.endswith(b"\n"):
        raise AuditChainError("audit file does not end with a newline (partial write?)")
    return buf[:-1].rsplit(b"\n", 1)[-1].decode("utf-8", errors="replace")


class HashChainFileHandler(logging.Handler):
    """Append audit records to a hash-chained JSON-lines file.

    Opened with ``O_APPEND`` and mode ``0600``. On start it validates the
    current tail and **refuses** to extend a corrupted chain, because silently
    starting a new one would hide tampering. One writer per file: run one
    handler per service instance and give each instance its own file.
    """

    def __init__(
        self,
        path: Path,
        service: ServiceInfo,
        *,
        fsync: bool = True,
        key: bytes | None = None,
    ) -> None:
        super().__init__(level=logging.INFO)
        self._service = service.name
        self._key = key
        self._fsync = fsync
        self._write_lock = threading.Lock()
        self.failures = 0
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(self._fd, 0o600)  # tighten a pre-existing file too
            self._seq, self._prev = self._recover()
        except BaseException:
            os.close(self._fd)
            raise

    def _recover(self) -> tuple[int, str]:
        last = _read_last_line(self._fd)
        if last is None:
            return 0, GENESIS_HASH
        try:
            entry = json.loads(last)
            seq = int(entry["seq"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AuditChainError("last audit record is unreadable") from exc
        # The tail can't be linked without its predecessor, but its digest (and,
        # when keyed, its authenticity) can be checked before we extend it.
        error, digest = _check_entry(last, seq, str(entry.get("prev_hash")), self._key)
        if error is not None:
            raise AuditChainError(f"last audit record is invalid: {error}")
        return seq, digest

    def emit(self, record: logging.LogRecord) -> None:
        payload = getattr(record, "audit", None)
        if payload is None:
            return
        try:
            with self._write_lock:
                entry: dict[str, Any] = {
                    "seq": self._seq + 1,
                    "ts": datetime.fromtimestamp(record.created, tz=UTC)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                    "service": self._service,
                    "event": payload,
                    "alg": _algorithm(self._key),
                    "prev_hash": self._prev,
                }
                digest = _entry_hash(entry, self._key)
                line = _canonical({**entry, "hash": digest}) + "\n"
                os.write(self._fd, line.encode("utf-8"))
                if self._fsync:
                    os.fsync(self._fd)
                self._seq, self._prev = self._seq + 1, digest
        except Exception:  # noqa: BLE001 - logging handlers must never raise into callers
            self.handleError(record)

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 - stdlib name
        # A lost audit record is a security event in itself, so report it loudly,
        # without the stdlib default of echoing the (unredacted) record to stderr.
        self.failures += 1
        report_logging_failure("audit_chain_file", sys.exc_info()[1], audit=True, seq=self._seq + 1)

    def close(self) -> None:
        with self._write_lock:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1
        super().close()
