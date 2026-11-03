"""Router and rate-limit settings: ``LLM_ROUTER_*`` variables plus ``OPENAI_API_KEY``.

Gateway-wide settings (client API keys, primary model, ports) and the
Anthropic key stay in Task 3's settings. Entrypoints load all of them with
:func:`quilr_common.config.load_settings`, so they come from the environment
or the ``.env`` file.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class RouterSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LLM_ROUTER_", extra="forbid", frozen=True, dotenv_filtering="match_prefix"
    )

    # Rate limit: tokens per tenant API key per sliding window.
    tokens_per_minute: int = Field(default=50_000, ge=1)
    window_s: float = Field(default=60.0, gt=0, le=3600)
    db_path: Path = Path("var/ratelimit.sqlite3")

    # Failover: the primary must answer within this or the backup serves.
    primary_timeout_ms: int = Field(default=3000, ge=100, le=60_000)
    backup_timeout_s: float = Field(default=30.0, gt=0, le=600)

    # Backup provider (OpenAI).
    openai_model: str = "gpt-6.1-sol"
    openai_base_url: str | None = None  # e.g. the mock in tests and demos
    # 0: a backup 429 goes straight to the client with its Retry-After. An SDK
    # retry would sleep inside the backup deadline and turn it into a 504.
    backup_max_retries: int = Field(default=0, ge=0, le=5)


class OpenAICredentials(BaseSettings):
    """``OPENAI_API_KEY``, required: the backup must be usable when the primary fails.

    ``extra="ignore"`` with ``only_existing``: other ``OPENAI_*`` variables
    belong to OpenAI's tooling, not to this gateway.
    """

    model_config = SettingsConfigDict(
        env_prefix="OPENAI_", extra="ignore", frozen=True, dotenv_filtering="only_existing"
    )

    api_key: SecretStr = Field(min_length=1)
