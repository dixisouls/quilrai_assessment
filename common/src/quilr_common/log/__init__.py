"""Structured JSON logging, request context and tamper-evident audit trail.

Typical service bootstrap::

    from quilr_common.log import ServiceInfo, configure_logging, get_logger

    configure_logging(ServiceInfo(name="mcp-gateway", version="1.0.0", env="prod"))
    log = get_logger(__name__)
"""

from quilr_common.log.audit import (
    AuditChainError,
    AuditEvent,
    ChainVerification,
    Decision,
    emit_audit,
    verify_chain,
)
from quilr_common.log.context import (
    bind_context,
    get_context,
    new_request_id,
    sanitize_request_id,
)
from quilr_common.log.settings import LoggingSettings, ServiceInfo
from quilr_common.log.setup import (
    LoggingRuntime,
    configure_logging,
    get_logger,
    shutdown_logging,
)

__all__ = [
    "AuditChainError",
    "AuditEvent",
    "ChainVerification",
    "Decision",
    "LoggingRuntime",
    "LoggingSettings",
    "ServiceInfo",
    "bind_context",
    "configure_logging",
    "emit_audit",
    "get_context",
    "get_logger",
    "new_request_id",
    "sanitize_request_id",
    "shutdown_logging",
    "verify_chain",
]
