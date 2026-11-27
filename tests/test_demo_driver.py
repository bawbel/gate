"""Tests for examples/demo: the driver, the stub MCP server, and the demo through the real gate.

Written before the driver and the stub. They pin what the demo claims, so a change in the
gate's behaviour (for example, detecting a description change during a session) fails here and
the demo text has to be updated with it. No network is used.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "demo"
GATE = [sys.executable, "-c", "from bawbel_gate.cli import main; main()"]

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="the demo is a shell demo")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"demo_{name}", DEMO / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def driver():
    return _load("driver")


# ---------------------------------------------------------------------------
# The driver: fixed JSON-RPC lines, nothing generated
# ---------------------------------------------------------------------------

SESSIONS = ("session_a_steps", "session_control_steps", "session_b_steps")


@pytest.mark.parametrize("name", SESSIONS)
def test_every_session_is_fixed_valid_json_rpc_with_unique_increasing_ids(driver, name):
    steps = getattr(driver, name)()
    messages = [message for _, message, _ in steps]
    assert messages[0]["method"] == "initialize"
    assert messages[1]["method"] == "notifications/initialized"
    ids = [message["id"] for message in messages if "id" in message]
    assert ids == sorted(set(ids)), "request ids must be unique and increasing"
    for message in messages:
        assert message["jsonrpc"] == "2.0"
        assert json.loads(json.dumps(message)) == message
    assert getattr(driver, name)() == steps, "the same lines every time"


def test_session_a_is_four_calls_with_a_list_before_and_after_the_third(driver):
    methods = [message["method"] for _, message, _ in driver.session_a_steps()]
    assert methods == [
        "initialize", "notifications/initialized", "tools/list",
        "tools/call", "tools/call", "tools/call",
        "tools/list", "tools/call",
    ]
    calls = [m["params"]["name"] for _, m, _ in driver.session_a_steps()
             if m["method"] == "tools/call"]
    assert calls == ["notes__read_notes"] * 4


def test_session_b_is_the_three_legs_and_then_the_next_request_at_once(driver):
    steps = driver.session_b_steps()
    called = [m["params"]["name"] for _, m, _ in steps if m["method"] == "tools/call"]
    assert called == ["notes__read_notes", "web__fetch_page", "outbox__send_report"]
    modes = [mode for _, _, mode in steps]
    assert modes[-2:] == ["pipe", "wait"], "the call that needs approval is not waited for"
    assert steps[-1][1]["method"] == "tools/list"


def test_the_control_session_calls_only_the_outbox(driver):
    called = [m["params"]["name"] for _, m, _ in driver.session_control_steps()
              if m["method"] == "tools/call"]
    assert called == ["outbox__send_report"]


def test_describe_names_the_outcome_and_the_reason(driver):
    allowed = {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "hi"}]}}
    error = {"code": -32031, "message": "bawbel-gate: denied",
             "data": {"reason": "approval_denied", "ave": []}}
    denied = {"jsonrpc": "2.0", "id": 4, "error": error}
    assert driver.describe(allowed) == "allowed: hi"
    assert driver.describe(denied) == "denied (-32031) reason=approval_denied"
    assert driver.describe(None) == "no answer"


def test_a_decided_record_is_one_compact_line(driver):
    record = {"seq": 13, "event": "CALL_DECIDED", "server": "outbox", "tool": "send_report",
              "effect": "deny", "reason": "approval_denied",
              "taint": ["tool.response.notes", "tool.response.web"]}
    line = driver.format_record(record)
    assert line.split() == ["seq", "13", "CALL_DECIDED", "outbox/send_report", "deny",
                            "reason=approval_denied",
                            "taint=tool.response.notes,tool.response.web"]
    assert driver.format_record({"seq": 1, "event": "SESSION_START"}).split() == [
        "seq", "1", "SESSION_START"]


# ---------------------------------------------------------------------------
# No network anywhere in the demo
# ---------------------------------------------------------------------------

NETWORK_MODULES = {"socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx", "ftplib",
                   "smtplib", "telnetlib", "asyncio", "socketserver", "xmlrpc", "websockets"}


@pytest.mark.parametrize("name", ["driver.py", "stub_server.py"])
def test_the_demo_python_imports_no_network_module(name):
    tree = ast.parse((DEMO / name).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & NETWORK_MODULES, sorted(imported & NETWORK_MODULES)


def test_demo_sh_calls_no_network_tool():
    script = (DEMO / "demo.sh").read_text(encoding="utf-8")
    for tool in ("curl", "wget", " nc ", "ssh ", "pip install", "git clone"):
        assert tool not in script, f"demo.sh must not use {tool.strip()!r}"


# ---------------------------------------------------------------------------
# The stub server: deterministic, role-scoped
# ---------------------------------------------------------------------------

def _stub(tmp_path: Path, role: str = "notes"):
    work = tmp_path / "work"
    if not work.exists():
        shutil.copytree(DEMO, work)
    command = [sys.executable, "stub_server.py", "--role", role, "--state", "state.json",
               "--sink", "sink.txt"]
    proc = subprocess.Popen(command, cwd=work, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)

    def ask(message: dict):
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()
        while True:  # a notification has no id: skip it and read the answer
            reply = json.loads(proc.stdout.readline())
            if "id" in reply:
                return reply

    return proc, ask, work


def _description(ask, request_id: int, tool: str = "read_notes") -> str:
    tools = ask({"jsonrpc": "2.0", "id": request_id, "method": "tools/list"})["result"]["tools"]
    return next(t["description"] for t in tools if t["name"] == tool)


@posix_only
def test_the_stub_changes_one_description_after_the_third_call_and_not_before(tmp_path):
    proc, ask, _ = _stub(tmp_path)
    try:
        before = _description(ask, 1)
        for i in (2, 3, 4):
            reply = ask({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                         "params": {"name": "read_notes", "arguments": {}}})
            assert "result" in reply
            if i < 4:
                assert _description(ask, 10 + i) == before, f"unchanged after call {i - 1}"
        after = _description(ask, 20)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    assert after != before
    assert before == json.loads((DEMO / "stub-server.json").read_text())["servers"]["notes"][
        "tools"][0]["description"], "before the change it serves the reviewed text"


@posix_only
def test_a_second_stub_instance_sees_the_change_through_the_shared_state(tmp_path):
    first, ask_first, work = _stub(tmp_path)
    try:
        original = _description(ask_first, 1)
        for i in (2, 3, 4):
            ask_first({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                       "params": {"name": "read_notes", "arguments": {}}})
    finally:
        first.stdin.close()
        first.wait(timeout=10)
    second, ask_second, _ = _stub(tmp_path)
    try:
        assert _description(ask_second, 1) != original
    finally:
        second.stdin.close()
        second.wait(timeout=10)


@posix_only
def test_each_role_serves_only_its_own_tools(tmp_path):
    expected = {"notes": {"read_notes"}, "web": {"fetch_page"}, "outbox": {"send_report"}}
    for role, names in expected.items():
        proc, ask, _ = _stub(tmp_path / role, role)
        try:
            tools = ask({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        finally:
            proc.stdin.close()
            proc.wait(timeout=10)
        assert {t["name"] for t in tools} == names


@posix_only
def test_the_outbox_writes_only_to_a_local_file(tmp_path):
    proc, ask, work = _stub(tmp_path, "outbox")
    try:
        ask({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "send_report", "arguments": {"body": "weekly summary"}}})
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    assert (work / "sink.txt").read_text().strip() == "weekly summary"


# ---------------------------------------------------------------------------
# The demo through the real gate
# ---------------------------------------------------------------------------

def _prepare(tmp_path: Path) -> Path:
    work = tmp_path / "demo"
    shutil.copytree(DEMO, work)
    for config in work.glob("gate.*.yaml"):
        config.write_text(config.read_text().replace("command: python3",
                                                     f"command: {sys.executable}"))
    return work


def _audit(work: Path) -> list[dict]:
    path = work / "gate.audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@posix_only
def test_a_description_change_during_a_session_is_not_noticed_by_the_gate(driver, tmp_path):
    work = _prepare(tmp_path)
    original = json.loads((work / "stub-server.json").read_text())["servers"]["notes"][
        "tools"][0]["description"]
    result = driver.run_session(GATE + ["serve", "-c", "gate.a.yaml"],
                                driver.session_a_steps(), cwd=work)
    assert result.exit_code == 0
    for request_id in (3, 4, 5, 7):
        assert result.responses[request_id]["result"], f"call {request_id} was forwarded"
    listed = {r["id"]: r for r in result.responses.values()
              if "result" in r and "tools" in r["result"]}
    assert listed[2]["result"]["tools"][0]["description"] == original
    assert listed[6]["result"]["tools"][0]["description"] == original, (
        "the gate answers tools/list from the list it took at session start")
    direct = driver.direct_description(work, python=sys.executable)
    assert direct != original, "a host connected straight to the stub would see the new text"
    events = [record["event"] for record in _audit(work)]
    assert "DRIFT_DETECTED" not in events
    decided = [r for r in _audit(work) if r["event"] == "CALL_DECIDED"]
    assert [r["effect"] for r in decided] == ["allow"] * 4


@posix_only
def test_the_outbox_alone_is_allowed_and_the_three_legs_in_a_row_are_not(driver, tmp_path):
    work = _prepare(tmp_path)
    control = driver.run_session(GATE + ["serve", "-c", "gate.b.yaml"],
                                 driver.session_control_steps(), cwd=work)
    send_id = max(i for i in control.responses if i >= 3)
    assert "result" in control.responses[send_id]
    assert (work / "sink.txt").exists()
    (work / "sink.txt").unlink()

    blocked = driver.run_session(GATE + ["serve", "-c", "gate.b.yaml"],
                                 driver.session_b_steps(), cwd=work)
    errors = [r["error"]["data"]["reason"] for r in blocked.responses.values() if "error" in r]
    assert errors == ["approval_denied"]
    assert not (work / "sink.txt").exists(), "the report was never sent"
    assert 9 not in blocked.responses, "the client's next request was consumed as the answer"
    last = [r for r in _audit(work) if r["event"] == "CALL_DECIDED"][-1]
    assert (last["tool"], last["effect"], last["reason"]) == (
        "send_report", "deny", "approval_denied")
    assert set(last["taint"]) == {"tool.response.notes", "tool.response.web"}

    verify = subprocess.run(GATE + ["audit", "verify", "gate.audit.jsonl"], cwd=work,
                            capture_output=True, text=True)
    assert verify.returncode == 0, verify.stdout + verify.stderr
    assert verify.stdout.startswith("ok: ")
