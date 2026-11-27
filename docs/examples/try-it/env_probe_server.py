"""A stub MCP server that reports one environment variable. Standard library only, no network.

Used by docs/TRY-IT.md to show what an upstream server inherits from the gate.
"""

import json
import os
import sys

TOOLS = [{"name": "show_env", "description": "Report whether TRY_IT_TOKEN is set in this process.",
          "inputSchema": {"type": "object", "properties": {}}}]


def say(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


for raw in sys.stdin:
    if not raw.strip():
        continue
    message = json.loads(raw)
    method, request_id = message.get("method"), message.get("id")
    if request_id is None:
        continue
    if method == "initialize":
        say({"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "try-it-env", "version": "0.0.1"}}})
    elif method == "tools/list":
        say({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        text = "TRY_IT_TOKEN=" + str(os.environ.get("TRY_IT_TOKEN"))
        content = [{"type": "text", "text": text}]
        say({"jsonrpc": "2.0", "id": request_id, "result": {"content": content}})
    else:
        error = {"code": -32601, "message": "no such method"}
        say({"jsonrpc": "2.0", "id": request_id, "error": error})
