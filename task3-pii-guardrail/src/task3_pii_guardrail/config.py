"""Gateway configuration: ``LLM_GATEWAY_*`` variables plus ``ANTHROPIC_API_KEY``.

Entrypoints load both with :func:`quilr_common.config.load_settings`, so they
come from the environment or the ``.env`` file. The provider key is its own
settings class: it is required at startup (a missing key stops the process
with a clear message, instead of failing on the first request), and it is
passed to the SDK explicitly.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LLM_GATEWAY_", extra="forbid", frozen=True, dotenv_filtering="match_prefix"
    )

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


class AnthropicCredentials(BaseSettings):
    """``ANTHROPIC_API_KEY``, required.

    ``extra="ignore"`` with ``only_existing``: other ``ANTHROPIC_*`` variables
    belong to Anthropic's tooling, not to this gateway, so they aren't policed here.
    """

    model_config = SettingsConfigDict(
        env_prefix="ANTHROPIC_", extra="ignore", frozen=True, dotenv_filtering="only_existing"
    )

    api_key: SecretStr = Field(min_length=1)
