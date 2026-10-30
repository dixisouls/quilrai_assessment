"""Unit tests for the JSON and console log formatters."""

from __future__ import annotations

import io
import json
import logging
import sys
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import pytest

from quilr_common.log.context import bind_context
from quilr_common.log.formatter import ConsoleFormatter, JsonFormatter
from quilr_common.log.settings import ServiceInfo
from quilr_common.redaction import REDACTED

SERVICE = ServiceInfo(name="test-svc", version="1.2.3", env="test")


@pytest.fixture
def capture() -> Iterator[tuple[logging.Logger, io.StringIO]]:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter(SERVICE, max_field_chars=300))
    logger = logging.getLogger("quilr.test.formatter")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    yield logger, buf
    logger.handlers = []


def _lines(buf: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buf.getvalue().splitlines()]


def test_emits_one_json_object_per_line_with_core_fields(capture: Any) -> None:
    logger, buf = capture
    logger.info("hello %s", "world")
    [rec] = _lines(buf)
    assert rec["msg"] == "hello world"
    assert rec["level"] == "INFO"
    assert rec["logger"] == "quilr.test.formatter"
    assert rec["service"] == {"name": "test-svc", "version": "1.2.3", "env": "test"}
    assert rec["log_type"] == "app"
    ts = datetime.fromisoformat(rec["ts"])
    assert ts.utcoffset() is not None
    assert ts.utcoffset().total_seconds() == 0  # type: ignore[union-attr]  # checked above
    assert rec["ts"].endswith("Z")


def test_includes_bound_context(capture: Any) -> None:
    logger, buf = capture
    with bind_context(request_id="req-1", tenant_id="acme"):
        logger.info("x")
    [rec] = _lines(buf)
    assert rec["request_id"] == "req-1"
    assert rec["tenant_id"] == "acme"


def test_includes_extra_fields(capture: Any) -> None:
    logger, buf = capture
    logger.info("x", extra={"upstream": "anthropic", "latency_ms": 12.5})
    [rec] = _lines(buf)
    assert rec["upstream"] == "anthropic"
    assert rec["latency_ms"] == 12.5


def test_extra_fields_cannot_spoof_reserved_fields(capture: Any) -> None:
    logger, buf = capture
    logger.info("real", extra={"log_type": "audit", "service": "evil", "ts": "1970"})
    [rec] = _lines(buf)
    assert rec["log_type"] == "app"
    assert rec["service"]["name"] == "test-svc"
    assert rec["ts"] != "1970"
    assert rec["extra_log_type"] == "audit"


def test_message_args_are_redacted(capture: Any) -> None:
    logger, buf = capture
    logger.info("user %s paid with %s", "jane@example.com", "4111 1111 1111 1111")
    [rec] = _lines(buf)
    assert rec["msg"] == f"user {REDACTED} paid with {REDACTED}"


def test_sensitive_extra_keys_and_values_are_redacted(capture: Any) -> None:
    logger, buf = capture
    logger.info(
        "x",
        extra={
            "api_key": "abc",
            "headers": {"Authorization": "Bearer t"},
            "note": "ssn 123-45-6789",
        },
    )
    [rec] = _lines(buf)
    assert rec["api_key"] == REDACTED
    assert rec["headers"]["Authorization"] == REDACTED
    assert rec["note"] == f"ssn {REDACTED}"


def test_bound_context_is_redacted_too(capture: Any) -> None:
    logger, buf = capture
    with bind_context(principal="jane@example.com"):
        logger.info("x")
    [rec] = _lines(buf)
    assert rec["principal"] == REDACTED


def test_exception_is_structured_and_redacted(capture: Any) -> None:
    logger, buf = capture
    try:
        raise ValueError("bad card 4111111111111111")
    except ValueError:
        logger.exception("failed")
    [rec] = _lines(buf)
    assert rec["level"] == "ERROR"
    assert rec["exc"]["type"] == "ValueError"
    assert rec["exc"]["message"] == f"bad card {REDACTED}"
    assert "Traceback" in rec["exc"]["stack"]
    assert "4111111111111111" not in rec["exc"]["stack"]


def test_newlines_cannot_forge_extra_log_lines(capture: Any) -> None:
    logger, buf = capture
    logger.info('a\n{"level":"CRITICAL","msg":"forged"}')
    lines = buf.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["level"] == "INFO"


def test_long_fields_are_truncated(capture: Any) -> None:
    logger, buf = capture
    logger.info("x" * 1000, extra={"blob": "y" * 1000})
    [rec] = _lines(buf)
    assert len(rec["msg"]) < 400
    assert rec["msg"].endswith("…[TRUNCATED:700]")
    assert rec["blob"].endswith("…[TRUNCATED:700]")


def test_unserializable_extra_does_not_crash(capture: Any) -> None:
    logger, buf = capture

    class Opaque:
        def __repr__(self) -> str:
            return "<Opaque>"

        __str__ = __repr__

    logger.info("x", extra={"obj": Opaque(), "raw": b"\x00\x01"})
    [rec] = _lines(buf)
    assert rec["obj"] == "<Opaque>"
    assert isinstance(rec["raw"], str)


def test_console_formatter_is_human_readable_and_redacted() -> None:
    record = logging.makeLogRecord(
        {
            "name": "svc",
            "levelno": logging.WARNING,
            "levelname": "WARNING",
            "msg": "user %s",
            "args": ("jane@example.com",),
            "tenant_id": "acme",
        }
    )
    out = ConsoleFormatter(SERVICE).format(record)
    assert "WARNING" in out
    assert f"user {REDACTED}" in out
    assert "tenant_id=acme" in out
    assert "\n" not in out


def test_nested_lists_are_truncated(capture: Any) -> None:
    logger, buf = capture
    logger.info("x", extra={"items": ["z" * 1000]})
    [rec] = _lines(buf)
    assert rec["items"][0].endswith("…[TRUNCATED:700]")


def test_console_formatter_renders_non_strings_and_quoted_strings() -> None:
    record = logging.makeLogRecord(
        {"name": "svc", "msg": "m", "latency_ms": 12, "note": "two words", "tags": ["a"]}
    )
    out = ConsoleFormatter(SERVICE).format(record)
    assert "latency_ms=12" in out
    assert "note='two words'" in out
    assert 'tags=["a"]' in out


def test_console_formatter_appends_redacted_stack() -> None:
    try:
        raise ValueError("leak jane@example.com")
    except ValueError:
        record = logging.makeLogRecord({"name": "svc", "msg": "m", "exc_info": sys.exc_info()})
    out = ConsoleFormatter(SERVICE).format(record)
    _, _, stack = out.partition("\n")
    assert "Traceback" in stack
    assert "jane@example.com" not in out
