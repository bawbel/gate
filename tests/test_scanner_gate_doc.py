"""docs/SCANNER-AND-GATE.md and its example files stay true.

The tool list is compared with the fixture server it describes, the JSON-RPC lines in the document
are parsed, and the gate commands in it are run against the fixture. The scanner is not needed.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "SCANNER-AND-GATE.md"
EXAMPLE = REPO_ROOT / "docs" / "examples" / "scanner-and-gate"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
GATE = [sys.executable, "-c", "from bawbel_gate.cli import main; main()"]


def _doc_json_lines() -> list[dict]:
    text = DOC.read_text(encoding="utf-8")
    return [json.loads(m) for m in re.findall(r"^\s+'(\{.*\})' \\$", text, flags=re.MULTILINE)]


def test_tools_json_is_the_fixture_servers_tool_list():
    path = FIXTURES / "fake_mcp_server.py"
    spec = importlib.util.spec_from_file_location("fake_mcp_server", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert json.loads((EXAMPLE / "tools.json").read_text(encoding="utf-8")) == module._TOOLS


def test_gate_yaml_names_files_the_document_tells_the_reader_to_copy():
    config = yaml.safe_load((EXAMPLE / "gate.yaml").read_text(encoding="utf-8"))
    server = config["servers"][0]
    copied = {Path(server["args"][0]).name, Path(server["manifest"]).name}
    assert copied == {"fake_mcp_server.py", "proxy_test.cap.yaml"}
    for name in copied:
        assert (FIXTURES / name).exists()
        assert name in DOC.read_text(encoding="utf-8")
    assert not Path(config["audit_log"]).is_absolute(), "no absolute path in a committed file"


def test_the_json_rpc_lines_in_the_document_are_valid_and_in_order():
    lines = _doc_json_lines()
    assert [line.get("id") for line in lines] == [1, None, 2, 3, 4]
    assert [line["method"] for line in lines] == [
        "initialize", "notifications/initialized", "tools/list", "tools/call", "tools/call"]
    assert [line["params"]["name"] for line in lines if line["method"] == "tools/call"] == [
        "files__get_file", "files__delete_all"]


@pytest.mark.skipif(sys.platform == "win32", reason="the document's commands are shell commands")
def test_the_gate_commands_in_the_document_give_the_documented_result(tmp_path):
    work = tmp_path / "scanner-and-gate-try"
    work.mkdir()
    for name in ("fake_mcp_server.py", "proxy_test.cap.yaml"):
        shutil.copy(FIXTURES / name, work / name)
    for name in ("tools.json", "gate.yaml"):
        shutil.copy(EXAMPLE / name, work / name)
    config = (work / "gate.yaml").read_text()
    config = config.replace("command: python3", f"command: {sys.executable}")
    (work / "gate.yaml").write_text(config)

    stdin = "".join(json.dumps(line) + "\n" for line in _doc_json_lines())
    served = subprocess.run(GATE + ["serve", "-c", "gate.yaml"], cwd=work, input=stdin,
                            capture_output=True, text=True, timeout=60)
    assert served.returncode == 0, served.stderr
    answers = {m["id"]: m for m in (json.loads(l) for l in served.stdout.splitlines()
                                    if l.startswith("{"))}
    listed = [tool["name"] for tool in answers[2]["result"]["tools"]]
    assert listed == ["files__get_file", "files__send_email"], "delete_all is not listed"
    assert "result" in answers[3]
    assert answers[4]["error"]["data"]["reason"] == "resolved"

    verified = subprocess.run(GATE + ["audit", "verify", "gate.audit.jsonl"], cwd=work,
                              capture_output=True, text=True, timeout=60)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert verified.stdout.startswith("ok: 4 records, chain intact")
