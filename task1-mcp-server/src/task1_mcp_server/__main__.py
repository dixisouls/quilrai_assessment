"""Entry point: ``python -m task1_mcp_server`` (or the ``task1-mcp-server`` script).

Order matters: logging is configured first (to stderr, with
``stdout_reserved=True``), then stdout is reserved for the protocol so every
later write in the process goes to stderr, then the server is built and served.
Logging can't come second: once ``sys.stdout`` *is* stderr, the logging
guard can't tell them apart and refuses to start.
"""

from __future__ import annotations

import contextlib
import os

import anyio

from quilr_common.log import LoggingSettings, ServiceInfo, configure_logging, get_logger
from task1_mcp_server.server import SERVER_NAME, SERVER_VERSION, build_server
from task1_mcp_server.service import CustomerToolService
from task1_mcp_server.store import CustomerStore, seeded_store
from task1_mcp_server.transport import reserve_stdout, serve_stdio


def run(store: CustomerStore | None = None) -> None:
    configure_logging(
        ServiceInfo(name=SERVER_NAME, version=SERVER_VERSION, env=os.environ.get("APP_ENV", "dev")),
        LoggingSettings(),
        stdout_reserved=True,
    )
    wire = reserve_stdout()
    log = get_logger("task1_mcp_server")
    server = build_server(CustomerToolService(store or seeded_store()))
    log.info("serving MCP over stdio")
    with contextlib.suppress(KeyboardInterrupt):  # Ctrl-C in a terminal is a normal stop
        anyio.run(serve_stdio, server, wire)
    log.info("stdin closed; shutting down")


def main() -> None:
    run()


if __name__ == "__main__":
    main()
