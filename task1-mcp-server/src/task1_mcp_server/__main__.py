"""Entry point: ``python -m task1_mcp_server`` (or the ``task1-mcp-server`` script).

Logging is configured with ``stdout_reserved=True`` *before* anything else
runs, so no log record can ever be written to stdout, the JSON-RPC channel.
"""

from __future__ import annotations

import contextlib
import os

import anyio

from quilr_common.log import LoggingSettings, ServiceInfo, configure_logging, get_logger
from task1_mcp_server.server import SERVER_NAME, SERVER_VERSION, build_server
from task1_mcp_server.service import CustomerToolService
from task1_mcp_server.store import CustomerStore, seeded_store
from task1_mcp_server.transport import serve_stdio


def run(store: CustomerStore | None = None) -> None:
    configure_logging(
        ServiceInfo(name=SERVER_NAME, version=SERVER_VERSION, env=os.environ.get("APP_ENV", "dev")),
        LoggingSettings(),
        stdout_reserved=True,
    )
    log = get_logger("task1_mcp_server")
    server = build_server(CustomerToolService(store or seeded_store()))
    log.info("serving MCP over stdio")
    with contextlib.suppress(KeyboardInterrupt):  # Ctrl-C in a terminal is a normal stop
        anyio.run(serve_stdio, server)
    log.info("stdin closed; shutting down")


def main() -> None:
    run()


if __name__ == "__main__":
    main()
