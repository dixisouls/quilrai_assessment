"""Tests for logging bootstrap: settings, queueing, sinks, and stdout isolation."""

from __future__ import annotations

import io
import json
import logging
import queue
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from quilr_common.log import (
    AuditEvent,
    Decision,
    LoggingSettings,
    ServiceInfo,
    bind_context,
    configure_logging,
    emit_audit,
    get_logger,
    shutdown_logging,
    verify_chain,
)
from quilr_common.log.audit import HashChainFileHandler
from quilr_common.log.setup import StructuredQueueHandler
from quilr_common.redaction import REDACTED

SERVICE = ServiceInfo(name="setup-test", version="0.0.1", env="test")


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    shutdown_logging()


def _json_lines(buf: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


# --- Settings -----------------------------------------------------------------


def test_settings_read_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FORMAT", "console")
    monkeypatch.setenv("LOG_AUDIT_PATH", str(tmp_path / "a.jsonl"))
    s = LoggingSettings()
    assert (s.level, s.format, s.audit_path) == ("DEBUG", "console", tmp_path / "a.jsonl")


def test_settings_reject_invalid_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "LOUD")
    with pytest.raises(ValidationError):
        LoggingSettings()


def test_defaults_are_safe() -> None:
    s = LoggingSettings()
    assert s.stream == "stderr"  # never pollute stdout unless asked
    assert s.format == "json"
    assert s.audit_fsync is True


def test_stdout_reserved_refuses_stdout_stream() -> None:
    with pytest.raises(ValueError, match="stdout is reserved"):
        configure_logging(SERVICE, LoggingSettings(stream="stdout"), stdout_reserved=True)


# --- Runtime behaviour --------------------------------------------------------


def test_logs_flow_through_queue_with_context_and_redaction() -> None:
    buf = io.StringIO()
    configure_logging(SERVICE, LoggingSettings(), stream=buf)
    with bind_context(request_id="req-1"):
        get_logger("app").info("user %s", "jane@example.com")
    shutdown_logging()  # flushes the queue
    [rec] = _json_lines(buf)
    assert rec["msg"] == f"user {REDACTED}"
    # Context must be captured on the *calling* thread, not the listener thread.
    assert rec["request_id"] == "req-1"


def test_exceptions_survive_the_queue() -> None:
    buf = io.StringIO()
    configure_logging(SERVICE, LoggingSettings(), stream=buf)
    try:
        raise KeyError("missing")
    except KeyError:
        get_logger("app").exception("lookup failed")
    shutdown_logging()
    [rec] = _json_lines(buf)
    assert rec["exc"]["type"] == "KeyError"
    assert "Traceback" in rec["exc"]["stack"]


def test_level_filtering() -> None:
    buf = io.StringIO()
    configure_logging(SERVICE, LoggingSettings(level="WARNING"), stream=buf)
    get_logger("app").info("hidden")
    get_logger("app").warning("shown")
    shutdown_logging()
    assert [r["msg"] for r in _json_lines(buf)] == ["shown"]


def test_third_party_loggers_are_captured_and_redacted() -> None:
    buf = io.StringIO()
    configure_logging(SERVICE, LoggingSettings(), stream=buf)
    logging.getLogger("httpx").warning("GET https://x.io/?key=sk-AbCdEf0123456789AbCdEf0123456789")
    shutdown_logging()
    [rec] = _json_lines(buf)
    assert rec["logger"] == "httpx"
    assert "sk-AbCd" not in rec["msg"]


def test_configure_is_idempotent() -> None:
    buf = io.StringIO()
    configure_logging(SERVICE, LoggingSettings(), stream=io.StringIO())
    configure_logging(SERVICE, LoggingSettings(), stream=buf)
    get_logger("app").info("once")
    shutdown_logging()
    assert len(_json_lines(buf)) == 1


def test_audit_goes_to_stream_and_chain_file(tmp_path: Path) -> None:
    buf = io.StringIO()
    path = tmp_path / "audit.jsonl"
    configure_logging(SERVICE, LoggingSettings(audit_path=path, audit_fsync=False), stream=buf)
    with bind_context(request_id="req-7"):
        emit_audit(AuditEvent(action="tools.call", decision=Decision.DENY, reason="no role"))
    get_logger("app").info("plain app log")
    shutdown_logging()

    stream = _json_lines(buf)
    audit_lines = [r for r in stream if r["log_type"] == "audit"]
    assert len(audit_lines) == 1
    assert audit_lines[0]["audit"]["decision"] == "deny"
    assert audit_lines[0]["request_id"] == "req-7"

    assert verify_chain(path).records == 1  # app log did NOT enter the audit chain


# --- Process-level isolation (the stdio-MCP requirement) ----------------------


@pytest.mark.integration
def test_stdout_stays_empty_in_a_real_process() -> None:
    script = textwrap.dedent(
        """
        import logging
        from quilr_common.log import (ServiceInfo, LoggingSettings, configure_logging,
                                      get_logger, shutdown_logging)
        configure_logging(ServiceInfo(name="p", version="0", env="test"), LoggingSettings(),
                          stdout_reserved=True)
        get_logger("app").info("to stderr")
        logging.getLogger("third.party").warning("also stderr")
        try:
            1 / 0
        except ZeroDivisionError:
            get_logger("app").exception("err")
        shutdown_logging()
        """
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, trusted test script
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    msgs = [json.loads(line)["msg"] for line in proc.stderr.splitlines()]
    assert msgs == ["to stderr", "also stderr", "err"]


def test_audit_bypasses_app_log_level(tmp_path: Path) -> None:
    buf = io.StringIO()
    path = tmp_path / "audit.jsonl"
    settings = LoggingSettings(level="ERROR", audit_path=path, audit_fsync=False)
    configure_logging(SERVICE, settings, stream=buf)
    emit_audit(AuditEvent(action="refund", decision=Decision.ALLOW, reason="within limit"))
    shutdown_logging()
    assert [r["log_type"] for r in _json_lines(buf)] == ["audit"]
    assert verify_chain(path).records == 1


# --- Backpressure -------------------------------------------------------------


def _record(**attrs: Any) -> logging.LogRecord:
    return logging.makeLogRecord({"name": "app", "msg": "m", **attrs})


def test_full_queue_drops_and_counts_app_logs() -> None:
    q: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=1)
    handler = StructuredQueueHandler(q)
    handler.handle(_record())
    handler.handle(_record())
    handler.handle(_record())
    assert q.qsize() == 1
    assert handler.dropped == 2


def test_full_queue_never_silently_drops_audit(capsys: pytest.CaptureFixture[str]) -> None:
    q: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=1)
    handler = StructuredQueueHandler(q)
    handler.handle(_record())
    secret_msg = "refund for jane@example.com"
    handler.handle(_record(msg=secret_msg, audit={"action": "x"}))  # blocks ~1s, then reports
    assert handler.dropped == 0  # not counted as a quiet app-log drop
    assert handler.audit_lost == 1
    [line] = capsys.readouterr().err.splitlines()
    report = json.loads(line)
    assert report["level"] == "CRITICAL"
    assert report["log_type"] == "logging_failure"
    assert report["audit"] is True
    assert report["error_type"] == "Full"
    assert "jane@example.com" not in line  # stdlib fallback would have leaked this


def test_audit_file_failure_is_reported_without_leaking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    handler = HashChainFileHandler(tmp_path / "a.jsonl", SERVICE, fsync=False)
    handler.close()  # fd is gone; the next write must fail
    handler.handle(_record(msg="card 4111111111111111", audit={"action": "x"}))
    assert handler.failures == 1
    err = capsys.readouterr().err
    assert json.loads(err)["component"] == "audit_chain_file"
    assert "4111" not in err


def test_runtime_reports_drops_and_shutdown_is_idempotent() -> None:
    runtime = configure_logging(SERVICE, LoggingSettings(), stream=io.StringIO())
    assert runtime.dropped == 0
    runtime.shutdown()
    runtime.shutdown()


def test_root_handlers_are_restored_after_shutdown() -> None:
    root = logging.getLogger()
    before = list(root.handlers)
    configure_logging(SERVICE, LoggingSettings(), stream=io.StringIO())
    assert root.handlers != before
    shutdown_logging()
    assert root.handlers == before


def test_hmac_key_must_be_long_enough() -> None:
    with pytest.raises(ValidationError):
        LoggingSettings(audit_hmac_key="short")


def test_hmac_key_from_settings_signs_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = "s" * 32
    settings = LoggingSettings(audit_path=path, audit_fsync=False, audit_hmac_key=key)
    configure_logging(SERVICE, settings, stream=io.StringIO())
    emit_audit(AuditEvent(action="x", decision=Decision.ALLOW, reason="r"))
    shutdown_logging()
    assert verify_chain(path, key=key.encode()).ok
    assert not verify_chain(path).ok
    assert repr(settings).count(key) == 0  # SecretStr never prints the key
