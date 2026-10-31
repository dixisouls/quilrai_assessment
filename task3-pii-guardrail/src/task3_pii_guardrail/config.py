"""Gateway configuration (``LLM_GATEWAY_*`` environment variables).

The Anthropic key is read from ``ANTHROPIC_API_KEY`` by the SDK's own
credential resolution; it is never stored in these settings.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LLM_GATEWAY_", extra="forbid", frozen=True)

    # Client API keys accepted by the gateway (JSON list in the environment).
    api_keys: list[Annotated[SecretStr, Field(min_length=16)]] = Field(min_length=1)

    model: str = "claude-opus-5-5"
    default_max_tokens: int = Field(default=4096, ge=1, le=64_000)
    anthropic_base_url: str | None = None  # e.g. the mock provider in tests and demos
    refusal_fallback: bool = True
    provider_timeout_s: float = Field(default=120.0, gt=0, le=900)
    provider_max_retries: int = Field(default=2, ge=0, le=5)

    max_body_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    host: str = "127.0.0.1"
    port: int = Field(default=8090, ge=1, le=65535)
