"""An MCP server built on the official Python SDK, with one tool: echo.

Used by tests/integration/test_sdk_handshake.py. The SDK validates the handshake the way
real servers do, which the hand-rolled fixtures in this directory do not (issue #27).
Needs the `mcp` package. SDK 2.x names the server class MCPServer and SDK 1.x names it
FastMCP, so the import tries both.
"""

from __future__ import annotations

try:
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:
    from mcp.server.fastmcp import FastMCP as _Server

server = _Server("sdk")


@server.tool()
def echo(text: str) -> str:
    """Return the text it was given."""
    return text


if __name__ == "__main__":
    server.run()
