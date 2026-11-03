"""Entry point: ``python -m task4_model_router``. The full LLM gateway.

    auth (Task 3) -> token rate limiter (SQLite) -> failover router
    (Anthropic primary, OpenAI backup) -> streaming PII redaction (Task 3)

Configuration: ``LLM_GATEWAY_*`` (Task 3), ``LLM_ROUTER_*`` (this task),
``ANTHROPIC_API_KEY`` and ``OPENAI_API_KEY``. See ``.env.example``.
"""

from __future__ import annotations

import os

import uvicorn

from quilr_common.log import LoggingSettings, ServiceInfo, configure_logging, get_logger
from task3_pii_guardrail.api import create_app
from task3_pii_guardrail.config import GatewaySettings
from task3_pii_guardrail.providers import AnthropicProvider
from task4_model_router.config import RouterSettings
from task4_model_router.openai_provider import OpenAIProvider
from task4_model_router.ratelimit import TokenRateLimiter
from task4_model_router.router import FailoverProvider


def main() -> None:
    configure_logging(
        ServiceInfo(name="llm-gateway", version="0.2.0", env=os.environ.get("APP_ENV", "dev")),
        LoggingSettings(),
    )
    gateway = GatewaySettings()  # LLM_GATEWAY_* from the environment
    router = RouterSettings()  # LLM_ROUTER_* from the environment
    primary = AnthropicProvider(
        api_key=None,  # SDK reads ANTHROPIC_API_KEY
        model=gateway.model,
        default_max_tokens=gateway.default_max_tokens,
        timeout_s=gateway.provider_timeout_s,
        max_retries=0,  # a 429 must fail over now, not be retried inside the 3 s budget
        base_url=gateway.anthropic_base_url,
        refusal_fallback=gateway.refusal_fallback,
    )
    backup = OpenAIProvider(
        api_key=None,  # SDK reads OPENAI_API_KEY
        model=router.openai_model,
        default_max_tokens=gateway.default_max_tokens,
        timeout_s=router.backup_timeout_s,
        max_retries=router.backup_max_retries,
        base_url=router.openai_base_url,
    )
    provider = FailoverProvider(
        primary,
        backup,
        primary_timeout_s=router.primary_timeout_ms / 1000,
        secondary_timeout_s=router.backup_timeout_s,
    )
    limiter = TokenRateLimiter(
        router.db_path, limit=router.tokens_per_minute, window_s=router.window_s
    )
    get_logger("task4_model_router").info(
        "llm gateway starting",
        extra={
            "port": gateway.port,
            "primary": gateway.model,
            "backup": router.openai_model,
            "tokens_per_minute": router.tokens_per_minute,
            "primary_timeout_ms": router.primary_timeout_ms,
        },
    )
    try:
        uvicorn.run(
            create_app(gateway, provider, limiter=limiter),
            host=gateway.host,
            port=gateway.port,
            log_config=None,
            server_header=False,
            proxy_headers=False,
        )
    finally:
        limiter.close()


if __name__ == "__main__":
    main()
