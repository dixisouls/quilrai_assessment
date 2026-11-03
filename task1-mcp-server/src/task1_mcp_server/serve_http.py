"""HTTP entry point: ``python -m task1_mcp_server.serve_http``.

The brief's transport is stdio (``python -m task1_mcp_server``), and that is
still the primary way to run this server. This second entry point serves the
*same* tools over MCP Streamable HTTP, so the MCP security gateway (Task 2) can
sit in front of them::

    agent ──► MCP gateway (Task 2: JWT auth, RBAC) ──► these tools over HTTP

The service, validation and error codes are identical; only the transport
differs.

It has no authentication of its own. It is meant to be reachable only by the
gateway, so it binds to loopback by default. On loopback the SDK also checks
``Host``/``Origin`` headers against DNS rebinding.

Configuration: ``MCP_SERVER_*`` and ``LOG_*``, from the environment or the
``.env`` file (see ``.env.example``).
"""

from __future__ import annotations

import uvicorn
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from quilr_common.config import load_settings, service_info
from quilr_common.log import LoggingSettings, configure_logging, get_logger
from task1_mcp_server.server import SERVER_NAME, SERVER_VERSION, build_server
from task1_mcp_server.service import CustomerToolService
from task1_mcp_server.store import seeded_store


class HttpServerSettings(BaseSettings):
    """Where the HTTP transport listens (``MCP_SERVER_*``)."""

    model_config = SettingsConfigDict(
        env_prefix="MCP_SERVER_", extra="forbid", frozen=True, dotenv_filtering="match_prefix"
    )

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)


def main() -> None:
    configure_logging(service_info(SERVER_NAME, SERVER_VERSION), load_settings(LoggingSettings))
    settings = load_settings(HttpServerSettings)
    app = build_server(CustomerToolService(seeded_store())).streamable_http_app(host=settings.host)
    get_logger("task1_mcp_server").info(
        "serving MCP over Streamable HTTP", extra={"host": settings.host, "port": settings.port}
    )
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,  # uvicorn logs go through the JSON + redaction pipeline
        server_header=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
