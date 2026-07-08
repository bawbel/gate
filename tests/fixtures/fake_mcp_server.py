"""Minimal stdlib-only stdio MCP-like server for integration tests.

Speaks the same newline-delimited JSON-RPC transport as mux/transport.py.
Implements just enough of MCP to exercise the gate's request loop:
initialize, tools/list, tools/call. No third-party dependencies, no network.

Tool surface (fixed, matches tests/fixtures/proxy_test.cap.yaml):
  get_file   -- granted 'allow' in the test manifest
  send_email -- granted 'approve' in the test manifest
  delete_all -- unmatched, resolves to 'deny' via the wildcard grant

tools/call echoes its arguments back in the response so tests can assert on
exactly what the gate forwarded upstream.
"""

from __future__ import annotations

import json
import sys

_TOOLS = [
    {"name": "get_file", "description": "Read a file.", "inputSchema": {"type": "object"}},
    {"name": "send_email", "description": "Send an email.", "inputSchema": {"type": "object"}},
    {"name": "delete_all", "description": "Delete everything.", "inputSchema": {"type": "object"}},
]


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        message = json.loads(line)
        response = _handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


def _handle(message: dict) -> dict | None:
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "fake-mcp-server", "version": "0.0.1"},
                "capabilities": {"tools": {}},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _TOOLS}}

    if method == "tools/call":
        params = message.get("params", {})
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {"type": "text", "text": json.dumps(params, separators=(",", ":"))}
                ]
            },
        }

    if request_id is None:
        return None  # notification, no response expected

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


if __name__ == "__main__":
    main()
