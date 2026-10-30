"""Unit tests for audit events and the tamper-evident hash-chained audit file."""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import stat
import threading
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from quilr_common.log.audit import (
    AuditChainError,
    AuditEvent,
    Decision,
    HashChainFileHandler,
    verify_chain,
)
from quilr_common.log.context import bind_context
from quilr_common.log.settings import ServiceInfo
from quilr_common.redaction import REDACTED

SERVICE = ServiceInfo(name="audit-test", version="0.0.1", env="test")


def _record(event: AuditEvent) -> logging.LogRecord:
    return logging.makeLogRecord({"name": "quilr.audit", "msg": "audit", "audit": event.to_log()})


def _event(i: int = 0, **kw: Any) -> AuditEvent:
    base: dict[str, Any] = {
        "action": "tools.call",
        "decision": Decision.DENY,
        "reason": f"role viewer cannot call admin tool #{i}",
    }
    base.update(kw)
    return AuditEvent(**base)


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- AuditEvent ---------------------------------------------------------------


def test_event_picks_up_request_context() -> None:
    with bind_context(request_id="req-9", tenant_id="acme", principal="alice"):
        event = _event()
    assert (event.request_id, event.tenant_id, event.principal) == ("req-9", "acme", "alice")


def test_explicit_fields_override_context() -> None:
    with bind_context(tenant_id="acme"):
        event = _event(tenant_id="other")
    assert event.tenant_id == "other"


def test_event_rejects_unknown_fields_and_bad_action() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(action="x", decision=Decision.ALLOW, reason="r", surprise=1)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        AuditEvent(action="Bad Action!", decision=Decision.ALLOW, reason="r")
    with pytest.raises(ValidationError):
        AuditEvent(action="x", decision="maybe", reason="r")


def test_event_is_immutable() -> None:
    event = _event()
    with pytest.raises(ValidationError):
        event.reason = "changed"  # type: ignore[misc]


def test_event_log_payload_is_redacted() -> None:
    event = _event(reason="refund for jane@example.com", metadata={"api_key": "sk-x"})
    payload = event.to_log()
    assert payload["reason"] == f"refund for {REDACTED}"
    assert payload["metadata"] == {"api_key": REDACTED}


# --- Hash chain ---------------------------------------------------------------


def test_chain_writes_linked_records_and_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    handler = HashChainFileHandler(path, SERVICE, fsync=False)
    for i in range(5):
        handler.handle(_record(_event(i)))
    handler.close()

    rows = _read(path)
    assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5]
    assert rows[0]["prev_hash"] == "0" * 64
    for prev, cur in itertools.pairwise(rows):
        assert cur["prev_hash"] == prev["hash"]
    assert rows[0]["service"] == "audit-test"
    assert rows[0]["event"]["decision"] == "deny"

    result = verify_chain(path)
    assert result.ok and result.records == 5 and result.first_bad_line is None


def test_file_is_created_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    handler = HashChainFileHandler(path, SERVICE, fsync=False)
    handler.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_chain_continues_across_restart(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    h1 = HashChainFileHandler(path, SERVICE, fsync=False)
    h1.handle(_record(_event(1)))
    h1.close()
    h2 = HashChainFileHandler(path, SERVICE, fsync=False)
    h2.handle(_record(_event(2)))
    h2.close()
    assert [r["seq"] for r in _read(path)] == [1, 2]
    assert verify_chain(path).ok


def test_ignores_non_audit_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    handler = HashChainFileHandler(path, SERVICE, fsync=False)
    handler.handle(logging.makeLogRecord({"name": "app", "msg": "not audit"}))
    handler.close()
    assert path.read_text() == ""


def _write_chain(path: Path, n: int) -> None:
    handler = HashChainFileHandler(path, SERVICE, fsync=False)
    for i in range(n):
        handler.handle(_record(_event(i)))
    handler.close()


def test_verify_detects_modified_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 4)
    lines = path.read_text().splitlines()
    tampered = json.loads(lines[2])
    tampered["event"]["decision"] = "allow"
    lines[2] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n")
    result = verify_chain(path)
    assert not result.ok
    assert result.first_bad_line == 3


def test_verify_detects_deleted_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 4)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    result = verify_chain(path)
    assert not result.ok
    assert result.first_bad_line == 2


def test_verify_detects_garbage_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 2)
    with path.open("a") as f:
        f.write("not json\n")
    result = verify_chain(path)
    assert not result.ok
    assert result.first_bad_line == 3


def test_refuses_to_append_to_corrupted_chain(tmp_path: Path) -> None:
    # Fail closed: silently starting a new chain would hide tampering.
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 2)
    with path.open("a") as f:
        f.write('{"seq": 3, "hash": "trunc')
    with pytest.raises(AuditChainError):
        HashChainFileHandler(path, SERVICE, fsync=False)


def test_concurrent_writers_produce_valid_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    handler = HashChainFileHandler(path, SERVICE, fsync=False)

    def work(offset: int) -> None:
        for i in range(50):
            handler.handle(_record(_event(offset + i)))

    threads = [threading.Thread(target=work, args=(t * 100,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    handler.close()
    result = verify_chain(path)
    assert result.ok
    assert result.records == 400


def test_model_validate_accepts_existing_event() -> None:
    event = _event()
    assert AuditEvent.model_validate(event) == event


# --- Verification edge cases --------------------------------------------------


def _rewrite(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_verify_detects_line_without_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 2)
    rows = _read(path)
    del rows[1]["hash"]
    _rewrite(path, rows)
    result = verify_chain(path)
    assert (result.ok, result.first_bad_line, result.reason) == (False, 2, "missing hash")


def test_verify_detects_broken_link_even_with_valid_own_hash(tmp_path: Path) -> None:
    # Attacker splices a self-consistent record whose prev_hash points elsewhere.
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    rows = _read(path)
    forged = {k: v for k, v in rows[1].items() if k != "hash"}
    forged["prev_hash"] = "f" * 64
    forged["hash"] = hashlib.sha256(
        json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    rows[1] = forged
    _rewrite(path, rows)
    result = verify_chain(path)
    assert result.first_bad_line == 2
    assert result.reason == "prev_hash does not link to previous record"


def test_head_hash_matches_last_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    assert verify_chain(path).head_hash == _read(path)[-1]["hash"]


def test_fsync_mode_writes_durably(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    handler = HashChainFileHandler(path, SERVICE, fsync=True)
    handler.handle(_record(_event()))
    handler.close()
    handler.close()  # idempotent
    assert verify_chain(path).records == 1


@pytest.mark.parametrize(
    "tail",
    [
        '{"no_seq": true}\n',
        '{"seq": 1, "prev_hash": "x", "hash": "deadbeef", "alg": "sha256"}\n',
    ],
)
def test_refuses_to_append_after_invalid_tail(tmp_path: Path, tail: str) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(tail)
    with pytest.raises(AuditChainError):
        HashChainFileHandler(path, SERVICE, fsync=False)


def test_tightens_permissions_of_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.touch(mode=0o644)
    path.chmod(0o644)
    HashChainFileHandler(path, SERVICE, fsync=False).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# --- Keyed (HMAC) chain -------------------------------------------------------

KEY = b"k" * 32


def _write_keyed(path: Path, n: int, key: bytes = KEY) -> None:
    handler = HashChainFileHandler(path, SERVICE, fsync=False, key=key)
    for i in range(n):
        handler.handle(_record(_event(i)))
    handler.close()


def _forge_full_rewrite(path: Path) -> None:
    """What an attacker with write access does: flip a decision, recompute everything."""
    rows = _read(path)
    rows[0]["event"]["decision"] = "allow"
    prev = "0" * 64
    for row in rows:
        row.pop("hash")
        row["alg"] = "sha256"
        row["prev_hash"] = prev
        prev = row["hash"] = hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    _rewrite(path, rows)


def test_unkeyed_chain_cannot_stop_a_full_rewrite(tmp_path: Path) -> None:
    # Documents the limitation that motivates LOG_AUDIT_HMAC_KEY.
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    _forge_full_rewrite(path)
    assert verify_chain(path).ok


def test_keyed_chain_verifies_with_key(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_keyed(path, 3)
    assert all(r["alg"] == "hmac-sha256" for r in _read(path))
    assert verify_chain(path, key=KEY).ok


def test_keyed_chain_detects_full_rewrite_and_downgrade(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_keyed(path, 3)
    _forge_full_rewrite(path)
    result = verify_chain(path, key=KEY)
    assert not result.ok
    assert result.first_bad_line == 1
    assert "unexpected alg" in (result.reason or "")


def test_keyed_chain_rejects_wrong_key_and_missing_key(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_keyed(path, 2)
    assert not verify_chain(path, key=b"x" * 32).ok
    assert not verify_chain(path).ok


def test_keyed_writer_refuses_to_extend_with_wrong_key(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_keyed(path, 2)
    with pytest.raises(AuditChainError):
        HashChainFileHandler(path, SERVICE, fsync=False, key=b"x" * 32)


def test_keyed_chain_continues_across_restart(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_keyed(path, 2)
    _write_keyed(path, 2)
    assert verify_chain(path, key=KEY).records == 4
