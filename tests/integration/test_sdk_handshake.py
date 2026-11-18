"""The gate in front of a server built on the official MCP Python SDK. See DESIGN.md 3.3, issue #27.

The SDK rejects an `initialize` without protocolVersion, capabilities and clientInfo, and
a `tools/list` before `notifications/initialized`. Before the fix the gate sent neither,
so it exposed zero tools from such a server. Skipped when the `mcp` package is not
installed (the `dev` extra installs it).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from bawbel_gate.mux.config import ApprovalConfig, GateConfig, ServerConfig
from tests.proxy_harness import run_enforce_session

FIXTURES = Path(__file__).parent.parent / "fixtures"
SDK_SERVER = FIXTURES / "sdk_echo_server.py"
MANIFEST = FIXTURES / "handshake_probe.cap.yaml"  # grants `echo: allow`, denies the rest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("mcp") is None,
    reason="the `mcp` package is not installed; pip install -e '.[dev]' installs it",
)


def _cfg(audit_log: Path) -> GateConfig:
    server = ServerConfig(
        name="sdk", command=sys.executable, args=[str(SDK_SERVER)], manifest=MANIFEST,
    )
    return GateConfig(
        audit_log=audit_log, servers=[server],
        approval=ApprovalConfig(channel="terminal", timeout_seconds=5),
    )


class TestSdkServerThroughTheGate:
    def test_tools_list_and_tools_call_work(self, tmp_path):
        sent = run_enforce_session(_cfg(tmp_path / "audit.jsonl"), [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "sdk__echo", "arguments": {"text": "hello from the host"}}},
        ])
        responses = {message["id"]: message for message in sent}

        names = [tool["name"] for tool in responses[2]["result"]["tools"]]
        assert names == ["sdk__echo"], (
            "the gate must expose the SDK server's tool, namespaced; an empty list means "
            "the upstream handshake was rejected"
        )

        assert "error" not in responses[3], responses[3]
        content = responses[3]["result"]["content"]
        assert content[0]["text"] == "hello from the host"
