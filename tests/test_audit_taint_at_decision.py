"""GATE-36: a CALL_DECIDED record carries the taint the decision was made against.

`_forward_and_tag` adds the called server's provenance class to the session, and the record used
to be written after that, so a first call to a `tool.response.files` server was decided against an
empty taint set and recorded with `["tool.response.files"]`. The record, and the decision span,
now carry the taint as it was when the gate decided. These tests were committed failing, before
the fix.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from bawbel_gate.mux import proxy
from bawbel_gate.mux.config import ApprovalConfig, GateConfig, ServerConfig
from tests.proxy_harness import run_enforce_session

FIXTURES = Path(__file__).parent / "fixtures"
FAKE_SERVER = FIXTURES / "fake_mcp_server.py"
MANIFEST = FIXTURES / "proxy_test.cap.yaml"  # provenance_class tool.response.files
CLASS = "tool.response.files"


def _cfg(tmp_path: Path) -> GateConfig:
    server = ServerConfig(
        name="files", command=sys.executable, args=[str(FAKE_SERVER)], manifest=MANIFEST,
    )
    return GateConfig(
        audit_log=tmp_path / "audit.jsonl", servers=[server],
        approval=ApprovalConfig(channel="terminal", timeout_seconds=5),
    )


def _call(request_id: int, tool: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": f"files__{tool}", "arguments": {"path": "/x"}}}


def _run(tmp_path: Path, calls: list[dict], approval_answer: str = "y") -> list[dict]:
    cfg = _cfg(tmp_path)
    run_enforce_session(
        cfg,
        [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, *calls],
        approval_input_fn=lambda: approval_answer,
    )
    lines = cfg.audit_log.read_text(encoding="utf-8").splitlines()
    return [r for r in map(json.loads, lines) if r["event"] == "CALL_DECIDED"]


class TestTheRecordHoldsTheTaintAtDecisionTime:
    def test_the_first_allowed_call_is_recorded_with_the_taint_at_decision(self, tmp_path):
        records = _run(tmp_path, [_call(2, "get_file")])
        assert records[0]["effect"] == "allow"
        assert records[0]["taint"] == []

    def test_the_second_call_is_recorded_with_the_taint_the_first_added(self, tmp_path):
        records = _run(tmp_path, [_call(2, "get_file"), _call(3, "get_file")])
        assert [r["taint"] for r in records] == [[], [CLASS]]

    def test_an_approved_call_is_recorded_with_the_taint_it_was_decided_against(self, tmp_path):
        records = _run(tmp_path, [_call(2, "send_email")], approval_answer="y")
        assert records[0]["effect"] == "approve"
        assert records[0]["taint"] == []

    def test_a_denied_call_is_recorded_with_the_current_taint(self, tmp_path):
        """A control: a denied call is not forwarded, so nothing is added after it."""
        records = _run(tmp_path, [_call(2, "get_file"), _call(3, "delete_all")])
        assert records[1]["effect"] == "deny"
        assert records[1]["taint"] == [CLASS]

    def test_a_refused_approval_is_recorded_with_the_taint_at_the_decision(self, tmp_path):
        calls = [_call(2, "get_file"), _call(3, "send_email")]
        records = _run(tmp_path, calls, approval_answer="n")
        assert records[1]["effect"] == "deny"
        assert records[1]["taint"] == [CLASS]


class TestTheSpanHoldsItToo:
    def test_the_decision_span_gets_the_taint_at_decision_time(self, tmp_path, monkeypatch):
        seen: list[list[str]] = []

        def capture(tool, server, decision, taint_classes, latency_ms):
            seen.append(list(taint_classes))

        monkeypatch.setattr(proxy, "record_decision_span", capture)
        _run(tmp_path, [_call(2, "get_file"), _call(3, "get_file")])
        assert seen == [[], [CLASS]]

    def test_the_session_still_ends_with_the_taint_the_calls_added(self, tmp_path):
        """The fix records an earlier snapshot. It does not change what the session holds."""
        from tests.proxy_harness import empty_console_state

        cfg = _cfg(tmp_path)
        state = empty_console_state(cfg)
        run_enforce_session(
            cfg,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                _call(2, "get_file"),
            ],
            console_state=state,
        )
        (session,) = state.sessions.values()
        assert CLASS in session.tainted_by
