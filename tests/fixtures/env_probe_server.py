"""Minimal stdlib-only stdio MCP-like server that reports which environment variables it has.

Tool surface (matches tests/fixtures/env_probe_*.cap.yaml):
  probe -- tools/call returns the sorted names of this process's environment variables

Only names are returned, never values. No third-party dependencies, no network.
"""

from __future__ import annotations

import json
import os
import sys

_TOOLS = [{"name": "probe", "description": "List env names.", "inputSchema": {"type": "object"}}]


def _handle(message: dict) -> dict | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "env-probe", "version": "0.0.1"},
            "capabilities": {"tools": {}},
        }}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _TOOLS}}
    if method == "tools/call":
        names = sorted(os.environ)
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "content": [{"type": "text", "text": json.dumps(names)}],
        }}
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response = _handle(json.loads(line))
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
