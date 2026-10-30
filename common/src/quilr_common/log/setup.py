"""Logging bootstrap: one call per process wires every sink.

Design:

* **Non-blocking.** Log calls only enqueue. A single ``QueueListener`` thread
  does the formatting, redaction and I/O, so a slow disk or a pipe that is
  full can't add latency to request handling.
* **Context captured on the caller's thread.** The stdlib
  ``QueueHandler.prepare`` drops ``exc_info``, and ``contextvars`` don't cross
  threads. :class:`StructuredQueueHandler` snapshots both before enqueueing.
* **Backpressure.** The queue is bounded. App logs are dropped (and counted)
  when it is full. Audit records block briefly instead, because losing them is
  worse than a short stall.
* **Root ownership.** The root logger is configured, so third-party libraries
  (httpx, uvicorn, ...) get the same JSON + redaction treatment. Previous root
  handlers are restored on shutdown.
"""

from __future__ import annotations

import atexit
import copy
import logging
import queue
import sys
from dataclasses import dataclass, field
from logging.handlers import QueueHandler, QueueListener
from typing import Final, TextIO

from quilr_common.log.audit import AUDIT_LOGGER_NAME, HashChainFileHandler
from quilr_common.log.context import get_context
from quilr_common.log.fallback import report_logging_failure
from quilr_common.log.formatter import ConsoleFormatter, JsonFormatter, exception_struct
from quilr_common.log.settings import LoggingSettings, ServiceInfo

_QUEUE_SIZE: Final = 50_000
_AUDIT_ENQUEUE_TIMEOUT_S: Final = 1.0


class StructuredQueueHandler(QueueHandler):
    """Queue handler that keeps context and structured exceptions."""

    def __init__(self, q: queue.Queue[logging.LogRecord]) -> None:
        super().__init__(q)
        self.dropped = 0
        self.audit_lost = 0

    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        record = copy.copy(record)  # other handlers may still see the original
        record.msg = record.getMessage()
        record.args = None
        record.ctx = get_context()
        if record.exc_info and record.exc_info[0] is not None:
            record.exc_struct = exception_struct(record.exc_info)
        # Traceback objects pin frames (and their locals) in memory; drop them.
        record.exc_info = None
        record.exc_text = None
        return record

    def enqueue(self, record: logging.LogRecord) -> None:
        q: queue.Queue[logging.LogRecord] = self.queue  # type: ignore[assignment]  # we construct it
        if getattr(record, "audit", None) is not None:
            # Raises queue.Full after the timeout -> handleError -> structured stderr line.
            q.put(record, timeout=_AUDIT_ENQUEUE_TIMEOUT_S)
            return
        try:
            q.put_nowait(record)
        except queue.Full:
            self.dropped += 1

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 - stdlib name
        is_audit = getattr(record, "audit", None) is not None
        if is_audit:
            self.audit_lost += 1
        report_logging_failure("log_queue", sys.exc_info()[1], audit=is_audit)


@dataclass
class LoggingRuntime:
    queue_handler: StructuredQueueHandler
    listener: QueueListener
    handlers: list[logging.Handler]
    previous_root_handlers: list[logging.Handler]
    previous_root_level: int
    stopped: bool = field(default=False)

    @property
    def dropped(self) -> int:
        return self.queue_handler.dropped

    def shutdown(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        self.listener.stop()  # drains the queue before returning
        root = logging.getLogger()
        root.removeHandler(self.queue_handler)
        for h in self.previous_root_handlers:
            root.addHandler(h)
        root.setLevel(self.previous_root_level)
        for h in self.handlers:
            h.close()
        logging.captureWarnings(False)


_runtime: LoggingRuntime | None = None


def configure_logging(
    service: ServiceInfo,
    settings: LoggingSettings | None = None,
    *,
    stdout_reserved: bool = False,
    stream: TextIO | None = None,
) -> LoggingRuntime:
    """Configure process-wide logging. Calling again replaces the previous setup.

    Args:
        service: identity stamped on every record.
        settings: defaults to :class:`LoggingSettings` read from the environment.
        stdout_reserved: set for stdio protocol servers (MCP). Refuses any
            configuration that would write logs to stdout.
        stream: overrides the target stream (tests).
    """
    global _runtime  # noqa: PLW0603 - logging is process-global by nature
    settings = settings or LoggingSettings()
    target = stream or (sys.stdout if settings.stream == "stdout" else sys.stderr)
    if stdout_reserved and (settings.stream == "stdout" or target is sys.stdout):
        raise ValueError("stdout is reserved for protocol traffic; use LOG_STREAM=stderr")

    shutdown_logging()

    formatter_cls = JsonFormatter if settings.format == "json" else ConsoleFormatter
    stream_handler = logging.StreamHandler(target)
    stream_handler.setFormatter(formatter_cls(service, max_field_chars=settings.max_field_chars))
    handlers: list[logging.Handler] = [stream_handler]
    if settings.audit_path is not None:
        handlers.append(
            HashChainFileHandler(
                settings.audit_path,
                service,
                fsync=settings.audit_fsync,
                key=key.get_secret_value().encode() if (key := settings.audit_hmac_key) else None,
            )
        )

    q: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=_QUEUE_SIZE)
    queue_handler = StructuredQueueHandler(q)
    listener = QueueListener(q, *handlers, respect_handler_level=True)

    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    for h in previous_handlers:
        root.removeHandler(h)
    root.addHandler(queue_handler)
    root.setLevel(settings.level)
    # Audit events are never filtered by the application log level.
    logging.getLogger(AUDIT_LOGGER_NAME).setLevel(logging.INFO)
    logging.captureWarnings(True)

    listener.start()
    _runtime = LoggingRuntime(queue_handler, listener, handlers, previous_handlers, previous_level)
    return _runtime


def shutdown_logging() -> None:
    """Flush and stop the active logging runtime. Safe to call repeatedly."""
    global _runtime  # noqa: PLW0603 - see configure_logging
    if _runtime is not None:
        _runtime.shutdown()
        _runtime = None


def get_logger(name: str) -> logging.Logger:
    """Return a stdlib logger. All structure comes from the configured handlers."""
    return logging.getLogger(name)


atexit.register(shutdown_logging)
