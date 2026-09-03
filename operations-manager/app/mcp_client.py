"""Thin helpers for talking to downstream MCP servers over Streamable HTTP -
the same client machinery a real MCP-aware agent would use, just wrapped so
the operations manager can call it on the caller's behalf after authorization."""
import json
import logging

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

logger = logging.getLogger("operations-manager.mcp_client")


async def list_tools(mcp_url: str) -> list[dict]:
    """Return [{name, description, input_schema}, ...] for one MCP server."""
    async with streamablehttp_client(mcp_url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "input_schema": t.inputSchema or {},
                }
                for t in result.tools
            ]


async def call_tool(mcp_url: str, tool_name: str, arguments: dict) -> dict:
    """Invoke one tool on one MCP server and return its structured result
    (falling back to the first text content block if a tool has no
    structured output)."""
    async with streamablehttp_client(mcp_url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)
            if result.isError:
                text = result.content[0].text if result.content else "tool call failed"
                raise RuntimeError(text)
            if result.structuredContent is not None:
                return result.structuredContent
            if result.content:
                text = getattr(result.content[0], "text", str(result.content[0]))
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    return {"text": text}
            return {}
