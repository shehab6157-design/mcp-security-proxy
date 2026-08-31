"""A tiny real MCP server used to exercise the proxy end-to-end in dev/tests.

Exposes a few toy tools so the proxy has something genuine to forward calls to
without needing a third-party MCP server on hand.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import anyio
from mcp import types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

TOOLS = [
    types.Tool(
        name="echo",
        description="Echo back the given text.",
        inputSchema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    ),
    types.Tool(
        name="get_time",
        description="Return the current UTC time.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="read_file",
        description="Read a file from disk.",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
]


async def handle_list_tools(
    _ctx: ServerRequestContext[Any, Any],
    _params: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:
    return types.ListToolsResult(tools=TOOLS)


async def handle_call_tool(
    _ctx: ServerRequestContext[Any, Any],
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    args = params.arguments or {}

    if params.name == "echo":
        text = args.get("text", "")
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    if params.name == "get_time":
        now = datetime.now(timezone.utc).isoformat()
        return types.CallToolResult(content=[types.TextContent(type="text", text=now)])

    if params.name == "read_file":
        path = args.get("path", "")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = f.read()
            return types.CallToolResult(content=[types.TextContent(type="text", text=data)])
        except OSError as e:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(e))], is_error=True
            )

    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"unknown tool: {params.name}")],
        is_error=True,
    )


async def main() -> None:
    server = Server(
        name="mock-downstream-server",
        version="0.1.0",
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
    )
    init_options = server.create_initialization_options()
    async with stdio_server() as (read, write):
        await server.run(read, write, init_options)


if __name__ == "__main__":
    anyio.run(main)
