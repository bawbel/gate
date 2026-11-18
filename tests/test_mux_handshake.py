"""The gate's handshake with each upstream server. See DESIGN.md 3.3 "Gate to upstream", issue #27.

Drives run_enforce() against tests/fixtures/handshake_probe_server.py, a stdlib-only
upstream that behaves like a server built on the official MCP SDK and records every
message it receives. No third-party package and no network are needed. The same handshake
against a real SDK server is tests/integration/test_sdk_handshake.py.
"""

from __future__ import annotations

import json
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

from bawbel_gate._const import JSONRPC_DENY_CODE
from bawbel_gate.mux.config import ApprovalConfig, GateConfig, ServerConfig
from tests.fixtures.handshake_probe_server import REJECT_TEXT
from tests.proxy_harness import run_enforce_session

FIXTURES = Path(__file__).parent / "fixtures"
PROBE = FIXTURES / "handshake_probe_server.py"
MANIFEST = FIXTURES / "handshake_probe.cap.yaml"  # grants `echo: allow`, denies the rest


def _cfg(tmp_path: Path, servers: list[tuple[str, str]]) -> GateConfig:
    """One probe upstream per (name, mode). Each logs to tmp_path/<name>.log."""
    return GateConfig(
        audit_log=tmp_path / "audit.jsonl",
        servers=[
            ServerConfig(
                name=name, command=sys.executable,
                args=[str(PROBE), mode, str(tmp_path / f"{name}.log")], manifest=MANIFEST,
            )
            for name, mode in servers
        ],
        approval=ApprovalConfig(channel="terminal", timeout_seconds=5),
    )


def _session(tmp_path: Path, servers: list[tuple[str, str]]) -> dict[int, dict]:
    """Run a host session: initialize, tools/list, then tools/call on every server's echo."""
    calls = [
        {"jsonrpc": "2.0", "id": 10 + index, "method": "tools/call",
         "params": {"name": f"{name}__echo", "arguments": {"text": f"to {name}"}}}
        for index, (name, _mode) in enumerate(servers)
    ]
    sent = run_enforce_session(_cfg(tmp_path, servers), [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        *calls,
    ])
    return {message["id"]: message for message in sent}


def _events(tmp_path: Path, name: str) -> list[tuple[str, str]]:
    """What the upstream saw, in order.

    Entries are ("recv", method), ("sent", "initialize") and ("early", method).
    """
    events = []
    for line in (tmp_path / f"{name}.log").read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        kind, value = next(iter(entry.items()))
        events.append((kind, value["method"] if isinstance(value, dict) else value))
    return events


def _received(tmp_path: Path, name: str) -> list[dict]:
    lines = (tmp_path / f"{name}.log").read_text(encoding="utf-8").splitlines()
    return [json.loads(line)["recv"] for line in lines if "recv" in json.loads(line)]


def _tool_names(responses: dict[int, dict]) -> list[str]:
    return [tool["name"] for tool in responses[2]["result"]["tools"]]


class TestInitializeRequest:
    def test_params_carry_protocol_version_capabilities_and_client_info(self, tmp_path):
        responses = _session(tmp_path, [("probe", "strict")])

        initialize = _received(tmp_path, "probe")[0]
        assert initialize["method"] == "initialize"
        params = initialize["params"]
        assert params["protocolVersion"] == responses[1]["result"]["protocolVersion"], (
            "the gate advertises one protocol version, to the host and to the upstream"
        )
        assert params["capabilities"] == {}
        assert params["clientInfo"] == {"name": "bawbel-gate", "version": version("bawbel-gate")}

    def test_a_server_that_validates_the_handshake_exposes_its_tools(self, tmp_path):
        responses = _session(tmp_path, [("probe", "strict")])

        assert _tool_names(responses) == ["probe__echo"]
        assert responses[10]["result"]["content"][0]["text"] == "to probe"


class TestInitializedNotification:
    def test_sent_once_after_the_initialize_response_and_before_tools_list(self, tmp_path):
        _session(tmp_path, [("probe", "strict")])

        assert _events(tmp_path, "probe") == [
            ("recv", "initialize"),
            ("sent", "initialize"),
            ("recv", "notifications/initialized"),
            ("recv", "tools/list"),
            ("recv", "tools/call"),
        ], (
            "an ('early', ...) entry means a message reached the upstream before the gate "
            "had read its initialize response"
        )

    def test_is_a_notification_without_an_id(self, tmp_path):
        _session(tmp_path, [("probe", "strict")])

        notification = _received(tmp_path, "probe")[1]
        assert notification == {"jsonrpc": "2.0", "method": "notifications/initialized"}


@pytest.mark.parametrize("mode", ["reject", "malformed"])
class TestInitializeFailure:
    def test_server_is_suspended_and_nothing_more_is_sent_to_it(self, tmp_path, mode):
        responses = _session(tmp_path, [("bad", mode)])

        assert _tool_names(responses) == []
        assert _events(tmp_path, "bad") == [("recv", "initialize"), ("sent", "initialize")], (
            "after a failed initialize the upstream must receive no notifications/initialized, "
            "no tools/list and no tools/call"
        )

    def test_a_call_to_the_suspended_server_is_denied(self, tmp_path, mode):
        responses = _session(tmp_path, [("bad", mode)])

        assert responses[10]["error"]["code"] == JSONRPC_DENY_CODE
        assert "result" not in responses[10]

    def test_one_stderr_line_names_the_server_and_no_upstream_text_is_repeated(
        self, tmp_path, capfd, mode,
    ):
        responses = _session(tmp_path, [("bad", mode)])

        captured = capfd.readouterr()
        naming = [line for line in captured.err.splitlines() if "upstream bad" in line]
        assert len(naming) == 1, captured.err
        everything = captured.out + captured.err + json.dumps(list(responses.values()))
        assert REJECT_TEXT not in everything
        assert "not an object" not in everything


class TestOneFailingServerDoesNotAffectTheOthers:
    def test_the_healthy_server_keeps_its_tools(self, tmp_path):
        responses = _session(tmp_path, [("good", "strict"), ("bad", "reject")])

        assert _tool_names(responses) == ["good__echo"]
        assert responses[10]["result"]["content"][0]["text"] == "to good"
        assert responses[11]["error"]["code"] == JSONRPC_DENY_CODE
