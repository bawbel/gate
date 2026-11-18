"""Stdlib-only stdio upstream that checks the MCP handshake and records what it received.

Used by tests/test_mux_handshake.py. The other fixtures in this directory ignore the
handshake. This one behaves the way a server built on the official MCP SDK does.

    python handshake_probe_server.py MODE LOG_PATH

MODE
  strict     accepts a well-formed handshake. It answers -32602 to an `initialize` whose
             params lack protocolVersion, capabilities or clientInfo, and to `tools/list`
             before `notifications/initialized`.
  reject     answers every `initialize` with an error carrying REJECT_TEXT, and every other
             request normally. A gate that ignores the error would still see the tool.
  malformed  answers `initialize` with a result that is not an object.

LOG_PATH receives one JSON object per line:
  {"recv": <message>}   every message received, in order
  {"early": <message>}  a message that arrived while the server was still holding back its
                        `initialize` response, so it was sent before the response was read
  {"sent": "initialize"}  the `initialize` response was written
"""

from __future__ import annotations

import json
import queue
import sys
import threading
import time

REJECT_TEXT = "UPSTREAM-ERROR-TEXT-MUST-NOT-REACH-THE-HOST"
# Long enough for an early message to reach the pipe, short enough to keep the tests fast.
HOLD_SECONDS = 0.2
TOOLS = [{"name": "echo", "description": "Return the text.", "inputSchema": {"type": "object"}}]


def main() -> None:
    mode, log_path = sys.argv[1], sys.argv[2]
    incoming: queue.Queue = queue.Queue()
    threading.Thread(target=_read_stdin, args=(incoming,), daemon=True).start()

    with open(log_path, "a", encoding="utf-8") as log:
        initialized = False
        while True:
            message = incoming.get()
            if message is None:
                return
            _log(log, {"recv": message})
            method, request_id = message.get("method"), message.get("id")

            if method == "initialize":
                time.sleep(HOLD_SECONDS)
                for queued in list(incoming.queue):
                    if queued is not None:
                        _log(log, {"early": queued})
                _send(_initialize_response(mode, message))
                _log(log, {"sent": "initialize"})
            elif method == "notifications/initialized":
                initialized = True
            elif request_id is None:
                continue
            elif method == "tools/list":
                if mode == "strict" and not initialized:
                    _send(_error(request_id, -32602, "Request before initialization was complete"))
                else:
                    _send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
            elif method == "tools/call":
                text = message.get("params", {}).get("arguments", {}).get("text", "")
                _send({"jsonrpc": "2.0", "id": request_id,
                       "result": {"content": [{"type": "text", "text": text}]}})
            else:
                _send(_error(request_id, -32601, "Method not found"))


def _initialize_response(mode: str, message: dict) -> dict:
    request_id = message["id"]
    if mode == "reject":
        return _error(request_id, -32602, REJECT_TEXT)
    if mode == "malformed":
        return {"jsonrpc": "2.0", "id": request_id, "result": "not an object"}
    if not _well_formed(message.get("params")):
        return _error(request_id, -32602, "Invalid request parameters")
    return {
        "jsonrpc": "2.0", "id": request_id,
        "result": {
            "protocolVersion": message["params"]["protocolVersion"],
            "serverInfo": {"name": "handshake-probe", "version": "0.0.1"},
            "capabilities": {"tools": {}},
        },
    }


def _well_formed(params) -> bool:
    if not isinstance(params, dict):
        return False
    info = params.get("clientInfo")
    return (
        isinstance(params.get("protocolVersion"), str) and params["protocolVersion"] != ""
        and isinstance(params.get("capabilities"), dict)
        and isinstance(info, dict)
        and all(isinstance(info.get(key), str) and info[key] != "" for key in ("name", "version"))
    )


def _error(request_id, code: int, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": text}}


def _read_stdin(incoming: queue.Queue) -> None:
    for line in sys.stdin:
        line = line.strip()
        if line:
            incoming.put(json.loads(line))
    incoming.put(None)


def _send(message: dict) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _log(log, entry: dict) -> None:
    log.write(json.dumps(entry) + "\n")
    log.flush()


if __name__ == "__main__":
    main()
