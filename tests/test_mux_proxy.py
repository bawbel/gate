"""Integration test for the mux request loop (mux/proxy.py). See DESIGN.md 3.3, 6.2.

Drives run_enforce() end-to-end against a real subprocess (tests/fixtures/
fake_mcp_server.py) with in-memory host_in/host_out and an injected approval
input function, so no TTY or real MCP server is required. The property tests in
tests/property/ already cover resolve()'s algebraic invariants (I1-I5); this file
covers the orchestration seam that calls resolve(), forwards on allow/approve,
and never forwards on deny -- code that did not exist before mux/proxy.py.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from bawbel_gate._const import (
    JSONRPC_DENY_CODE,
    REASON_APPROVAL_DENIED,
)
from bawbel_gate.audit.writer import verify_chain
from bawbel_gate.console.state import ConsoleState
from bawbel_gate.mux.config import ApprovalConfig, GateConfig, ServerConfig
from bawbel_gate.mux.proxy import run_enforce

FIXTURES = Path(__file__).parent / "fixtures"
FAKE_SERVER = FIXTURES / "fake_mcp_server.py"
MANIFEST = FIXTURES / "proxy_test.cap.yaml"


def _cfg(audit_log: Path, timeout_seconds: int = 5) -> GateConfig:
    server = ServerConfig(
        name="files", command=sys.executable, args=[str(FAKE_SERVER)], manifest=MANIFEST,
    )
    return GateConfig(
        audit_log=audit_log,
        servers=[server],
        approval=ApprovalConfig(channel="terminal", timeout_seconds=timeout_seconds),
    )


def _run(cfg: GateConfig, messages: list[dict], *, console_state=None, approval_input_fn=None):
    host_in = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    host_out = io.StringIO()
    run_enforce(
        cfg,
        console_state=console_state,
        host_in=host_in,
        host_out=host_out,
        approval_input_fn=approval_input_fn,
    )
    responses = {}
    for line in host_out.getvalue().splitlines():
        obj = json.loads(line)
        responses[obj["id"]] = obj
    return responses


class TestToolsListMergeAndNamespacing:
    def test_merged_list_is_namespaced_and_omits_denied_tool(self, tmp_path):
        cfg = _cfg(tmp_path / "audit.jsonl")
        responses = _run(cfg, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ])
        names = {t["name"] for t in responses[2]["result"]["tools"]}
        assert names == {"files__get_file", "files__send_email"}, (
            "tools/list must namespace every tool and omit files__delete_all, "
            "whose only matching grant is the wildcard deny"
        )


class TestDeniedCallNeverForwards:
    def test_unmatched_effect_deny_returns_error_without_forwarding(self, tmp_path):
        cfg = _cfg(tmp_path / "audit.jsonl")
        responses = _run(cfg, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "files__delete_all", "arguments": {"path": "/"}},
            },
        ])
        err = responses[2]["error"]
        assert err["code"] == JSONRPC_DENY_CODE
        # No "result" key: if this had been forwarded, the fake server would have
        # echoed the arguments back in result.content instead of erroring.
        assert "result" not in responses[2]


class TestAllowedCallForwardsAndTaints:
    def test_allow_forwards_bare_tool_name_and_updates_taint(self, tmp_path):
        cfg = _cfg(tmp_path / "audit.jsonl")
        state = ConsoleState(
            sessions={}, manifests={}, audit_log=cfg.audit_log,
            started_at="2026-01-01T00:00:00Z", config_sha256="sha256:" + "0" * 64,
        )
        responses = _run(cfg, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "files__get_file", "arguments": {"path": "a.txt"}},
            },
        ], console_state=state)

        result = responses[2]["result"]
        echoed = json.loads(result["content"][0]["text"])
        assert echoed == {"name": "get_file", "arguments": {"path": "a.txt"}}, (
            "the upstream must receive the bare tool name, not the namespaced one"
        )

        assert len(state.sessions) == 1
        session = next(iter(state.sessions.values()))
        assert "tool.response.files" in session.tainted_by
        assert session.untrusted_seen is True
        assert session.private_touched is True


class TestApprovalGate:
    def test_approval_denied_blocks_forward(self, tmp_path):
        cfg = _cfg(tmp_path / "audit.jsonl")
        responses = _run(cfg, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "files__send_email", "arguments": {"to": "x@example.com"}},
            },
        ], approval_input_fn=lambda: "n")

        err = responses[2]["error"]
        assert err["code"] == JSONRPC_DENY_CODE
        assert err["data"]["reason"] == REASON_APPROVAL_DENIED
        assert "result" not in responses[2]

    def test_approval_granted_forwards(self, tmp_path):
        cfg = _cfg(tmp_path / "audit.jsonl")
        responses = _run(cfg, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "files__send_email", "arguments": {"to": "x@example.com"}},
            },
        ], approval_input_fn=lambda: "y")

        assert "result" in responses[2], "a granted approval must forward the call"


class TestAuditChain:
    def test_chain_verifies_after_a_session(self, tmp_path):
        audit_log = tmp_path / "audit.jsonl"
        cfg = _cfg(audit_log)
        _run(cfg, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "files__get_file", "arguments": {}},
            },
            {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "files__delete_all", "arguments": {}},
            },
        ])
        result = verify_chain(audit_log)
        assert result.ok, result.error
        assert result.records >= 3  # SESSION_START + 2 x CALL_DECIDED (at least)


class TestUnknownNamespacedTool:
    def test_malformed_tool_name_is_denied(self, tmp_path):
        cfg = _cfg(tmp_path / "audit.jsonl")
        responses = _run(cfg, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "not_namespaced", "arguments": {}},
            },
        ])
        assert responses[2]["error"]["code"] == JSONRPC_DENY_CODE
