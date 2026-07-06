"""Stdio MCP transport: read/write newline-delimited JSON-RPC over stdin/stdout.

Each message is a single JSON object terminated by a newline (\\n).
The gate uses this both to talk to the host (downstream) and to upstream
MCP servers it spawns as subprocesses.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import IO, Any, Iterator

from bawbel_gate._const import REASON_PARSE_ERROR
from bawbel_gate._types import JsonRpcMessage


def read_messages(stream: IO[str]) -> Iterator[JsonRpcMessage]:
    """Yield decoded JSON-RPC messages from a line-delimited stream.

    Lines that are not valid JSON are skipped with a stderr warning.
    EOF terminates the iterator.
    """
    for raw in stream:
        raw = raw.strip()
        if not raw:
            continue
        try:
            yield json.loads(raw)
        except json.JSONDecodeError as exc:
            _warn(f"{REASON_PARSE_ERROR}: {exc}")


def write_message(stream: IO[str], message: JsonRpcMessage) -> None:
    """Write a single JSON-RPC message to stream, terminated by newline."""
    stream.write(json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n")
    stream.flush()


def deny_response(request_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> JsonRpcMessage:
    """Build a JSON-RPC error response."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def spawn_server(command: str, args: list[str]) -> subprocess.Popen:
    """Spawn an upstream MCP server subprocess with stdio transport."""
    return subprocess.Popen(  # nosec B603 # noqa: S603 -- command + args come from operator-controlled gate.yaml, not user input
        [command, *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )


def _warn(msg: str) -> None:
    print(f"bawbel-gate: warning: {msg}", file=sys.stderr, flush=True)
