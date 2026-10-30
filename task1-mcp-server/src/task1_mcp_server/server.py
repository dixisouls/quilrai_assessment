"""Wires :class:`CustomerToolService` into the MCP SDK's low-level ``Server``.

The low-level ``Server`` is used rather than ``MCPServer`` (the v2 successor to
``FastMCP``) because ``MCPServer`` turns argument-validation failures into
``is_error`` tool results. The assessment requires JSON-RPC error codes, and
the low-level API lets :class:`CustomerToolService` decide the error class
before any business logic runs.
"""

from __future__ import annotations

from importlib.metadata import version
from typing import Any, Final

import mcp_types as types
from mcp.server import Server, ServerRequestContext

from task1_mcp_server.service import CustomerToolService

SERVER_NAME: Final = "quilr-customer-tools"
SERVER_VERSION: Final = version("task1-mcp-server")


def build_server(service: CustomerToolService) -> Server[Any]:
    async def list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=service.list_tools())

    async def call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await service.call(params.name, params.arguments)

    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        instructions=(
            "Customer support tools. Customer ids look like CUST-00042. trigger_refund moves "
            "money: confirm amount and reason before calling it."
        ),
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
