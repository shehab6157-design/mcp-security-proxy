"""Dev-only smoke test: acts as the AI agent, drives the proxy over stdio,
and calls each mock tool a few times so we can inspect the resulting audit log.

Not a unit test suite (Phase 1 has none yet) - just an end-to-end sanity check.
"""

from __future__ import annotations

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> None:
    params = StdioServerParameters(
        command="python3",
        args=["-m", "proxy.server", "--config", "config/proxy_config.yaml"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("tools:", [t.name for t in tools.tools])

            r1 = await session.call_tool("echo", {"text": "hello from test_client"})
            print("echo ->", r1.content)

            r2 = await session.call_tool("get_time", {})
            print("get_time ->", r2.content)

            r3 = await session.call_tool(
                "read_file",
                {"path": "PROJECT_SPEC.md"},
                meta={"reasoning": "smoke-testing the proxy's read_file forwarding"},
            )
            print("read_file (first 60 chars) ->", r3.content[0].text[:60])

            r4 = await session.call_tool("read_file", {"path": "/no/such/file"})
            print("read_file missing ->", r4.content, "is_error=", r4.is_error)


if __name__ == "__main__":
    anyio.run(main)
