"""DEMO driver: plays an MCP client by sending fixed JSON-RPC lines to a command.

Standard library only. No network. Nothing here is generated: the sessions are fixed lists, so
two runs send the same lines.

usage: python3 driver.py a | control | b | direct | events FILE | records FILE [N]
  a        session A: four calls to the notes stub, with a description change after the third
  control  the outbox alone, to show the same tool is allowed when nothing else came first
  b        session B: the three legs in a row, then the client's next request at once
  direct   ask the notes stub itself for its tool list, bypassing the gate
  events   count the audit events of each type in FILE
  records  print the last N records of FILE, one line each (default 6)

The gate command is `bawbel-gate` unless DEMO_GATE says otherwise.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import shlex
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
WAIT_SECONDS = 15.0  # how long a request is waited for
PROBE_SECONDS = 2.0  # how long the request that follows a piped one is waited for

# A step is (label, message, mode). "wait": send, then read the answer. "pipe": send and do not
# wait, as a client does when its next request is ready.
Step = tuple


def _request(request_id: int, method: str, params: dict | None = None) -> dict:
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def _call(request_id: int, tool: str, **arguments) -> dict:
    return _request(request_id, "tools/call", {"name": tool, "arguments": arguments})


def _start() -> list[Step]:
    initialize = _request(1, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "demo-driver", "version": "0"}})
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    return [("initialize", initialize, "wait"), ("initialized", initialized, "wait"),
            ("tools/list", _request(2, "tools/list"), "wait")]


def session_a_steps() -> list[Step]:
    """Three calls, a list, a fourth call. The stub changes a description after the third."""
    return _start() + [
        ("call 1  notes__read_notes", _call(3, "notes__read_notes"), "wait"),
        ("call 2  notes__read_notes", _call(4, "notes__read_notes"), "wait"),
        ("call 3  notes__read_notes", _call(5, "notes__read_notes"), "wait"),
        ("tools/list (again)", _request(6, "tools/list"), "wait"),
        ("call 4  notes__read_notes", _call(7, "notes__read_notes"), "wait"),
    ]


def session_control_steps() -> list[Step]:
    return _start() + [
        ("outbox__send_report", _call(3, "outbox__send_report", body="weekly summary (demo)"),
         "wait"),
    ]


def session_b_steps() -> list[Step]:
    """Private data, then untrusted text, then the send. The next request follows at once."""
    return _start() + [
        ("call 1  notes__read_notes", _call(3, "notes__read_notes"), "wait"),
        ("call 2  web__fetch_page", _call(4, "web__fetch_page", name="news"), "wait"),
        ("call 3  outbox__send_report",
         _call(5, "outbox__send_report", body="the user's notes (demo)"), "pipe"),
        ("the client's next request", _request(9, "tools/list"), "wait"),
    ]


def describe(response: dict | None) -> str:
    if response is None:
        return "no answer"
    if "error" in response:
        error = response["error"]
        reason = error.get("data", {}).get("reason")
        return f"denied ({error['code']}) reason={reason}" if reason else f"error ({error['code']})"
    result = response.get("result", {})
    if "tools" in result:
        names = ", ".join(tool["name"] for tool in result["tools"]) or "none"
        return f"{len(result['tools'])} tool(s): {names}"
    content = result.get("content")
    if content:
        return "allowed: " + content[0].get("text", "")[:60]
    return "ok"


@dataclass
class SessionResult:
    responses: dict = field(default_factory=dict)
    exit_code: int | str = 0
    stderr: str = ""
    stdout_banner: list = field(default_factory=list)


def run_session(command: list[str], steps: list[Step], cwd: Path, out=print) -> SessionResult:
    """Start `command` in `cwd`, send the steps, print one line per step, close its input."""
    proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    lines: queue.Queue = queue.Queue()
    errors: list[str] = []
    threading.Thread(target=lambda: [lines.put(line) for line in proc.stdout], daemon=True).start()
    threading.Thread(target=lambda: errors.extend(proc.stderr), daemon=True).start()
    result = SessionResult()

    def next_json(timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                return None
            if line.lstrip().startswith("{"):
                message = json.loads(line)
                result.responses[message.get("id")] = message
                return message
            result.stdout_banner.append(line.rstrip())

    previous_mode = "wait"
    sent: dict = {}
    for label, message, mode in steps:
        try:
            proc.stdin.write(json.dumps(message) + "\n")
            proc.stdin.flush()
        except BrokenPipeError:
            out(f"  {label:<30} the gate has exited")
            break
        if "id" in message:
            sent[message["id"]] = label
        if "id" in message and mode == "wait":
            patience = PROBE_SECONDS if previous_mode == "pipe" else WAIT_SECONDS
            answer = next_json(patience)
            while answer is not None and answer.get("id") != message["id"]:
                earlier = sent.get(answer.get("id"), f"id {answer.get('id')}")
                out(f"  {'answer to: ' + earlier:<30} {describe(answer)}")
                answer = next_json(patience)
            out(f"  {label:<30} {describe(answer)}")
        elif "id" in message:
            out(f"  {label:<30} (sent; the next request follows at once)")
        previous_mode = mode
    while (late := next_json(0.3)) is not None:
        out(f"  {'answer to: ' + sent.get(late.get('id'), '?'):<30} {describe(late)}")
    with contextlib.suppress(BrokenPipeError):
        proc.stdin.close()
    try:
        result.exit_code = proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        result.exit_code = "killed"
    time.sleep(0.2)
    result.stderr = "".join(errors)
    for banner in result.stdout_banner:
        out(f"  (gate stdout, not JSON-RPC)    {banner}")
    return result


def direct_description(cwd: Path, python: str = "python3") -> str:
    """The notes stub's own description of read_notes, asked for without the gate."""
    command = [python, "stub_server.py", "--role", "notes", "--state", "state.json"]
    proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    try:
        proc.stdin.write(json.dumps(_request(1, "tools/list")) + "\n")
        proc.stdin.flush()
        reply = json.loads(proc.stdout.readline())
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    return next(t["description"] for t in reply["result"]["tools"] if t["name"] == "read_notes")


def gate_command(*arguments: str) -> list[str]:
    return shlex.split(os.environ.get("DEMO_GATE", "bawbel-gate")) + list(arguments)


def print_stderr(result: SessionResult) -> None:
    print(f"  gate exit code: {result.exit_code}")
    for line in result.stderr.splitlines():
        if line.strip() and not line.startswith("="):
            print(f"  gate stderr: {line.rstrip()}")


def format_record(record: dict) -> str:
    parts = [f"seq {record.get('seq'):<3}", f"{record.get('event', ''):<14}"]
    if record.get("event") == "CALL_DECIDED":
        taint = ",".join(record.get("taint", [])) or "-"
        parts += [f"{record.get('server')}/{record.get('tool')}", f"{record.get('effect')}",
                  f"reason={record.get('reason')}", f"taint={taint}"]
    return "  " + "  ".join(parts)


def print_records(path: Path, count: int) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    for row in rows[-count:]:
        print(format_record(row))


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    action = argv[0]
    cwd = Path.cwd()
    if action == "a":
        result = run_session(gate_command("serve", "-c", "gate.a.yaml"), session_a_steps(), cwd)
        print_stderr(result)
        print()
        print("  the same tool, asked for straight from the stub, without the gate:")
        print(f"    read_notes: {direct_description(cwd)}")
        listed = result.responses.get(6, {}).get("result", {}).get("tools", [{}])[0]
        print("  the same tool, as the gate listed it after call 3:")
        print(f"    {listed.get('name')}: {listed.get('description')}")
    elif action in ("control", "b"):
        steps = session_control_steps() if action == "control" else session_b_steps()
        print_stderr(run_session(gate_command("serve", "-c", "gate.b.yaml"), steps, cwd))
    elif action == "direct":
        print(direct_description(cwd))
    elif action == "events":
        counts = Counter(json.loads(line)["event"] for line in
                         Path(argv[1]).read_text(encoding="utf-8").splitlines() if line.strip())
        for event in ("SESSION_START", "CALL_DECIDED", "DRIFT_DETECTED", "SESSION_END"):
            print(f"  {event:<15} {counts.get(event, 0)}")
    elif action == "records":
        count = int(argv[2]) if len(argv) > 2 else 6
        print_records(Path(argv[1]), count)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
