"""JSON (production) and console (local dev) log formatters.

Each record goes through the same steps:

1. Collect the message, bound context, ``extra=`` fields, exception and audit payload.
2. **Redact** everything with :mod:`quilr_common.redaction`.
3. **Truncate** long strings. This runs after redaction on purpose: truncating
   first could cut a secret in half so the pattern no longer matches, and the
   remaining half would leak.
4. Serialise to a single line. JSON escaping turns embedded newlines into ``\\n``,
   so a message can't forge extra log lines.
"""

from __future__ import annotations

import json
import logging
import traceback
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Final

from quilr_common.log.context import get_context
from quilr_common.log.settings import ServiceInfo
from quilr_common.redaction import redact_value

# Attributes every LogRecord has; anything else on a record came from `extra=`.
_STD_ATTRS: Final = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
    "taskName",
}
# Attributes we attach ourselves (see setup.StructuredQueueHandler / audit.emit_audit).
_INTERNAL_ATTRS: Final = frozenset({"ctx", "exc_struct", "audit"})
# Top-level keys owned by the formatter; user fields can't overwrite them.
_RESERVED: Final = frozenset(
    {"ts", "level", "logger", "msg", "log_type", "service", "exc", "audit"}
)

type ExcInfo = tuple[type[BaseException], BaseException, TracebackType | None]


def exception_struct(exc_info: ExcInfo) -> dict[str, str]:
    """Render ``exc_info`` into a JSON-friendly dict (not yet redacted)."""
    exc_type, exc, tb = exc_info
    return {
        "type": exc_type.__qualname__,
        "message": str(exc),
        "stack": "".join(traceback.format_exception(exc_type, exc, tb)),
    }


def _truncate(value: Any, limit: int) -> Any:
    if isinstance(value, str):
        if len(value) > limit:
            return f"{value[:limit]}…[TRUNCATED:{len(value) - limit}]"
        return value
    if isinstance(value, dict):
        return {k: _truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v, limit) for v in value]
    return value


def _timestamp(record: logging.LogRecord) -> str:
    dt = datetime.fromtimestamp(record.created, tz=UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _console_pair(key: str, value: Any) -> str:
    if isinstance(value, str):
        # Bare when unambiguous; repr() quotes and escapes newlines/control chars.
        plain = value and value.isprintable() and " " not in value
        return f"{key}={value}" if plain else f"{key}={value!r}"
    return f"{key}={json.dumps(value, ensure_ascii=True, default=str)}"


class _StructuredFormatter(logging.Formatter):
    def __init__(self, service: ServiceInfo, *, max_field_chars: int = 8192) -> None:
        super().__init__()
        self._service = service.model_dump()
        self._limit = max_field_chars

    def _build(self, record: logging.LogRecord) -> dict[str, Any]:
        ctx: dict[str, Any] = getattr(record, "ctx", None) or get_context()
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _STD_ATTRS and k not in _INTERNAL_ATTRS
        }
        fields: dict[str, Any] = {}
        for key, val in {**ctx, **extras}.items():
            fields[f"extra_{key}" if key in _RESERVED else key] = val

        exc: dict[str, str] | None = getattr(record, "exc_struct", None)
        if exc is None and record.exc_info and record.exc_info[0] is not None:
            exc = exception_struct(record.exc_info)

        audit: dict[str, Any] | None = getattr(record, "audit", None)
        out: dict[str, Any] = {
            "ts": _timestamp(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "log_type": "audit" if audit is not None else "app",
            **fields,
        }
        if exc is not None:
            out["exc"] = exc
        if audit is not None:
            out["audit"] = audit
        out = _truncate(redact_value(out, max_depth=10), self._limit)
        out["service"] = self._service  # trusted, set after redaction
        return out


class JsonFormatter(_StructuredFormatter):
    """One redacted JSON object per line, ready for log shippers (Vector, Fluent Bit, ...)."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(self._build(record), ensure_ascii=True, default=str)


class ConsoleFormatter(_StructuredFormatter):
    """Human-readable single-line format for local development. Still redacted."""

    def format(self, record: logging.LogRecord) -> str:
        data = self._build(record)
        head = f"{data.pop('ts')} {data.pop('level'):<8} {data.pop('logger')}: {data.pop('msg')}"
        data.pop("service")
        data.pop("log_type")
        exc = data.pop("exc", None)
        kv = " ".join(_console_pair(k, v) for k, v in data.items())
        line = f"{head} {kv}".rstrip()
        if exc is not None:
            line += "\n" + exc["stack"].rstrip()
        return line
