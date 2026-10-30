"""Logging configuration and service identity."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServiceInfo(BaseModel):
    """Identity stamped on every log line, so aggregated logs can be filtered by source."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    env: str = Field(min_length=1, max_length=32)


class LoggingSettings(BaseSettings):
    """Logging settings, read from ``LOG_*`` environment variables.

    Defaults are the safe choice: JSON to **stderr**, so stdout stays free for
    protocol traffic such as stdio MCP, and audit records are fsynced.
    """

    model_config = SettingsConfigDict(env_prefix="LOG_", extra="forbid", frozen=True)

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "console"] = "json"
    stream: Literal["stdout", "stderr"] = "stderr"
    # When set, audit events are also appended to this tamper-evident file.
    audit_path: Path | None = None
    audit_fsync: bool = True
    # HMAC key for the audit chain. Without it the chain only detects accidental
    # corruption (see quilr_common.log.audit). Required in production.
    audit_hmac_key: SecretStr | None = Field(default=None, min_length=32)
    # Per-field cap; bounds log volume from hostile or runaway inputs.
    max_field_chars: int = Field(default=8192, ge=256, le=1_000_000)
