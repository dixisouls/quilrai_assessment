"""Mock downstream MCP server (official SDK, Streamable HTTP) for the gateway to protect.

Tools: two any-role tools and two ``admin_*`` tools. Every executed call is
logged as ``downstream tool executed`` with the tool name, so tests and demos
can prove a denied call never arrived.

Run: ``python -m task2_mcp_gateway.mock_downstream --port 9000``
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Final

import mcp_types as types
import uvicorn
from mcp.server import Server, ServerRequestContext
from mcp.shared.exceptions import MCPError

from quilr_common.log import LoggingSettings, ServiceInfo, configure_logging, get_logger

log = get_logger("mock_downstream")

_OBJECT: Final = {"type": "object", "properties": {}, "additionalProperties": False}
TOOLS: Final = (
    types.Tool(name="get_status", description="Service health summary.", input_schema=_OBJECT),
    types.Tool(name="list_users", description="List user ids.", input_schema=_OBJECT),
    types.Tool(
        name="admin_reset_key",
        description="Rotate a user's API key (admin only).",
        input_schema={
            "type": "object",
            "properties": {"user_id": {"type": "string"}},
            "required": ["user_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin_delete_user", description="Delete a user (admin only).", input_schema=_OBJECT
    ),
)
_NAMES: Final = {t.name for t in TOOLS}


def build_mock_server() -> Server[Any]:
    async def list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=list(TOOLS))

    async def call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        if params.name not in _NAMES:
            raise MCPError(types.INVALID_PARAMS, "Unknown tool")
        log.info("downstream tool executed", extra={"tool": params.name})
        result = {"tool": params.name, "status": "executed"}
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(result))], structured_content=result
        )

    return Server(
        "mock-downstream", version="0.1.0", on_list_tools=list_tools, on_call_tool=call_tool
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    configure_logging(
        ServiceInfo(name="mock-downstream", version="0.1.0", env="dev"), LoggingSettings()
    )
    app = build_mock_server().streamable_http_app(host=args.host)
    uvicorn.run(app, host=args.host, port=args.port, log_config=None, server_header=False)


if __name__ == "__main__":
    main()
