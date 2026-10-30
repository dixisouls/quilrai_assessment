"""Last-resort reporting for when the logging pipeline itself fails.

The stdlib ``Handler.handleError`` prints the raw record message and arguments
to stderr. Those are *unredacted* and may contain PII or secrets. Our handlers
call :func:`report_logging_failure` instead. It writes one structured JSON line
holding only safe metadata (component, exception type, flags) and never the
record's content.
"""

from __future__ import annotations

import json
import sys
import time


def report_logging_failure(component: str, error: BaseException | None, **flags: object) -> None:
    line = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": "CRITICAL",
        "logger": "quilr.logging",
        "log_type": "logging_failure",
        "msg": "log record lost",
        "component": component,
        "error_type": type(error).__qualname__ if error is not None else None,
        **{k: v for k, v in flags.items() if isinstance(v, bool | int | str)},
    }
    try:
        sys.stderr.write(json.dumps(line, ensure_ascii=True) + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001, S110 - nothing left to report to; never raise from logging
        pass
