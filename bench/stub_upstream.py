"""A stub MCP upstream for the benchmark. Standard library only.

    python stub_upstream.py [--mode normal|stall] [--response-bytes N]

Tools: `get_file` (allowed in bench/manifest.cap.yaml) and `needs_ok` (approve).
`tools/call` answers with a text of --response-bytes bytes. In `stall` mode it
never answers a `tools/call`.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

TOOLS = [
    {"name": "get_file", "description": "Read a file.", "inputSchema": {"type": "object"}},
    {
        "name": "needs_ok",
        "description": "A tool that needs approval.",
        "inputSchema": {"type": "object"},
    },
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["normal", "stall"], default="normal")
    parser.add_argument("--response-bytes", type=int, default=16)
    args = parser.parse_args()
    text = "x" * args.response_bytes
    out = sys.stdout
    for line in sys.stdin:
        message = json.loads(line)
        method, request_id = message.get("method"), message.get("id")
        if request_id is None:
            continue
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "bench-stub", "version": "0"},
                "capabilities": {"tools": {}},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            if args.mode == "stall":
                time.sleep(3600)
                continue
            result = {"content": [{"type": "text", "text": text}]}
        else:
            out.write(
                json.dumps(
                    {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "no"}}
                )
                + "\n"
            )
            out.flush()
            continue
        out.write(
            json.dumps(
                {"jsonrpc": "2.0", "id": request_id, "result": result}, separators=(",", ":")
            )
            + "\n"
        )
        out.flush()


if __name__ == "__main__":
    main()
