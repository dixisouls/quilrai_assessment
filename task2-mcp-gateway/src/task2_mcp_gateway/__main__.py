"""Entry point: ``python -m task2_mcp_gateway`` (or the ``task2-mcp-gateway`` script).

All configuration comes from ``GATEWAY_*`` and ``LOG_*`` environment
variables (see ``.env.example``). The process refuses to start without a
downstream URL, issuer, audience and a public key or JWKS file.
"""

from __future__ import annotations

import os

import httpx
import uvicorn

from quilr_common.log import LoggingSettings, ServiceInfo, configure_logging, get_logger
from task2_mcp_gateway.config import GatewaySettings
from task2_mcp_gateway.proxy import create_app


def main() -> None:
    configure_logging(
        ServiceInfo(name="mcp-gateway", version="0.1.0", env=os.environ.get("APP_ENV", "dev")),
        LoggingSettings(),
    )
    settings = GatewaySettings()  # values come from GATEWAY_* environment variables
    verifier = settings.build_verifier()
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
