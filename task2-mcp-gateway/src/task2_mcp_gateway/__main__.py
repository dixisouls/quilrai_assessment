"""Entry point: ``python -m task2_mcp_gateway`` (or the ``task2-mcp-gateway`` script).

Configuration: ``GATEWAY_*`` and ``LOG_*``, from the environment or the
``.env`` file (see ``.env.example``). The process refuses to start without a
downstream URL, issuer, audience and a public key or JWKS file.
"""

from __future__ import annotations

import httpx
import uvicorn

from quilr_common.config import ConfigError, load_settings, service_info
from quilr_common.log import LoggingSettings, configure_logging, get_logger
from task2_mcp_gateway.config import GatewaySettings
from task2_mcp_gateway.proxy import create_app


def main() -> None:
    configure_logging(service_info("mcp-gateway", "0.1.0"), load_settings(LoggingSettings))
    settings = load_settings(GatewaySettings)
    try:
        verifier = settings.build_verifier()
    except (OSError, ValueError, TypeError) as exc:
        # Missing or unreadable key file, or a key that isn't valid: no traceback,
        # just what to fix. The key material itself is never printed.
        raise ConfigError(f"configuration error: token verification key: {exc}") from None
    client = httpx.AsyncClient(
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        follow_redirects=False,  # a redirect must never move traffic off the configured host
    )
    app = create_app(settings, verifier, client, close_client_on_shutdown=True)
    get_logger("task2_mcp_gateway").info(
        "gateway starting", extra={"host": settings.host, "port": settings.port}
    )
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,  # uvicorn logs go through our JSON + redaction pipeline
        server_header=False,
        proxy_headers=False,  # don't trust X-Forwarded-* from clients
    )


if __name__ == "__main__":
    main()
