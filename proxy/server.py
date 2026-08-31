"""MCP Security Proxy — Phase 1.

Sits between an AI agent (MCP client) and a real downstream MCP server. The
agent is configured to launch this proxy instead of the real server; this
proxy launches the real server itself as a subprocess, forwards every request
to it, and writes a hash-chained audit log entry for every tool call.

Usage:
    python -m proxy.server --config config/proxy_config.yaml
"""

from __future__ import annotations

import argparse
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import yaml
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from proxy.audit_log import HashChainAuditLog
from proxy.extract import extract_reasoning_summary, extract_target_resource, payload_size

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s proxy %(levelname)s %(message)s",
    stream=sys.stderr,  # stdout is reserved for the MCP stdio transport
)
log = logging.getLogger("mcp_security_proxy")


def load_config(config_path: str | Path) -> dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


async def run_proxy(config: dict[str, Any]) -> None:
    agent_id = config["agent_id"]
    downstream_cfg = config["downstream"]
    audit_log = HashChainAuditLog(config.get("log_path", "logs/calls.jsonl"))

    downstream_params = StdioServerParameters(
        command=downstream_cfg["command"],
        args=downstream_cfg.get("args", []),
        env=downstream_cfg.get("env"),
    )

    @asynccontextmanager
    async def lifespan(_server: Server[ClientSession]):
        log.info(
            "starting downstream server: %s %s",
            downstream_cfg["command"],
            " ".join(downstream_cfg.get("args", [])),
        )
        async with stdio_client(downstream_params) as (down_read, down_write):
            async with ClientSession(down_read, down_write) as session:
                await session.initialize()
                log.info("downstream server initialized")
                yield session

    async def handle_list_tools(
        ctx: ServerRequestContext[ClientSession, Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        return await ctx.lifespan_context.list_tools(params=params)

    async def handle_call_tool(
        ctx: ServerRequestContext[ClientSession, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult | types.InputRequiredResult:
        arguments = params.arguments or {}
        meta = dict(params.meta) if params.meta else None

        entry = audit_log.append(
            agent_id=agent_id,
            tool_name=params.name,
            target_resource=extract_target_resource(params.name, arguments),
            payload_size=payload_size(arguments),
            reasoning_summary=extract_reasoning_summary(params.name, arguments, meta),
        )
        log.info(
            "trace=%s tool=%s target=%s size=%dB",
            entry.trace_id,
            params.name,
            entry.target_resource,
            entry.payload_size,
        )

        result = await ctx.lifespan_context.call_tool(params.name, arguments)
        if isinstance(result, (types.CallToolResult, types.InputRequiredResult)):
            return result
        raise RuntimeError(
            f"unexpected downstream result type for tool {params.name!r}: {type(result)!r}"
        )

    server: Server[ClientSession] = Server(
        name="mcp-security-proxy",
        version="0.1.0",
        instructions="Audit-logging proxy in front of a downstream MCP server.",
        lifespan=lifespan,
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
    )

    init_options = server.create_initialization_options()
    async with stdio_server() as (agent_read, agent_write):
        await server.run(agent_read, agent_write, init_options)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Security Proxy")
    parser.add_argument(
        "--config",
        default="config/proxy_config.yaml",
        help="Path to the proxy YAML config file",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    anyio.run(run_proxy, config)


if __name__ == "__main__":
    main()
