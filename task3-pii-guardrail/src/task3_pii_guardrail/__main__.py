"""Entry point: ``python -m task3_pii_guardrail``.

Configuration: ``LLM_GATEWAY_*`` (see ``.env.example``) and
``ANTHROPIC_API_KEY``, which the Anthropic SDK reads itself.
"""

from __future__ import annotations

import os

import uvicorn

from quilr_common.log import LoggingSettings, ServiceInfo, configure_logging, get_logger
from task3_pii_guardrail.api import create_app
from task3_pii_guardrail.config import GatewaySettings
from task3_pii_guardrail.providers import AnthropicProvider


def main() -> None:
    configure_logging(
        ServiceInfo(name="llm-gateway", version="0.1.0", env=os.environ.get("APP_ENV", "dev")),
        LoggingSettings(),
    )
    settings = GatewaySettings()  # values come from LLM_GATEWAY_* environment variables
    provider = AnthropicProvider(
        api_key=None,  # resolved by the SDK from ANTHROPIC_API_KEY
        model=settings.model,
        default_max_tokens=settings.default_max_tokens,
        timeout_s=settings.provider_timeout_s,
        max_retries=settings.provider_max_retries,
        base_url=settings.anthropic_base_url,
        refusal_fallback=settings.refusal_fallback,
    )
    get_logger("task3_pii_guardrail").info(
        "llm gateway starting",
        extra={"host": settings.host, "port": settings.port, "model": settings.model},
    )
    uvicorn.run(
        create_app(settings, provider),
        host=settings.host,
        port=settings.port,
        log_config=None,
        server_header=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
