"""Entry point: ``python -m task3_pii_guardrail``.

Configuration: ``LLM_GATEWAY_*``, ``ANTHROPIC_API_KEY`` and ``LOG_*``, from the
environment or the ``.env`` file (see ``.env.example``). The process refuses
to start if a required value is missing or invalid.
"""

from __future__ import annotations

import uvicorn

from quilr_common.config import load_settings, service_info
from quilr_common.log import LoggingSettings, configure_logging, get_logger
from task3_pii_guardrail.api import create_app
from task3_pii_guardrail.config import AnthropicCredentials, GatewaySettings
from task3_pii_guardrail.providers import AnthropicProvider


def main() -> None:
    configure_logging(service_info("llm-gateway", "0.1.0"), load_settings(LoggingSettings))
    settings = load_settings(GatewaySettings)
    credentials = load_settings(AnthropicCredentials)
    provider = AnthropicProvider(
        api_key=credentials.api_key.get_secret_value(),
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
