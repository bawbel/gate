"""M6: Embedded console + Console API.

See DESIGN.md 13.1 and IMPLEMENTATION_PLAN.md M6.

P0 deliverables tested here:
  - Bearer token minting and auth
  - GET /v1/state snapshot
  - GET /v1/events SSE stream
  - POST /v1/approvals/{id}
  - Read-only guarantee: no endpoint can mutate manifests, taint, or tool calls
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

import pytest

from bawbel_gate.console.auth import mint_token, verify_token, TOKEN_BYTE_LENGTH
from bawbel_gate.console.state import ConsoleState, serialize_state
from bawbel_gate.console.approvals import ApprovalRegistry, ApprovalDecision
from bawbel_gate.mux.session import SessionState


# ---------------------------------------------------------------------------
# Bearer token auth (DESIGN.md 13.1)
# ---------------------------------------------------------------------------

class TestBearerToken:
    def test_mint_returns_hex_string(self):
        token = mint_token()
        assert isinstance(token, str)
        assert all(c in "0123456789abcdef" for c in token)

    def test_token_length_sufficient(self):
        token = mint_token()
        assert len(token) == TOKEN_BYTE_LENGTH * 2  # hex-encoded

    def test_two_tokens_are_different(self):
        assert mint_token() != mint_token()

    def test_verify_correct_token(self):
        token = mint_token()
        assert verify_token(token, token) is True

    def test_verify_wrong_token(self):
        token = mint_token()
        assert verify_token("wrong", token) is False

    def test_verify_empty_token_rejected(self):
        token = mint_token()
        assert verify_token("", token) is False

    def test_verify_is_constant_time(self):
        """verify_token uses hmac.compare_digest or equivalent to resist timing attacks."""
        token = mint_token()
        # Ensure implementation uses compare_digest (property, not timing test)
        from bawbel_gate.console.auth import verify_token as vt
        import inspect
        src = inspect.getsource(vt)
        assert "compare_digest" in src or "hmac" in src


# ---------------------------------------------------------------------------
# State snapshot serializer (DESIGN.md 13.1 GET /v1/state)
# ---------------------------------------------------------------------------

class TestStateSerializer:
    def _make_state(self, tmp_path: Path) -> ConsoleState:
        audit_log = tmp_path / "audit.jsonl"
        audit_log.write_text("", encoding="utf-8")
        return ConsoleState(
            sessions={"s1": SessionState()},
            manifests={},
            audit_log=audit_log,
            started_at="2026-07-06T00:00:00Z",
            config_sha256="sha256:" + "0" * 64,
        )

    def test_serialize_returns_dict(self, tmp_path):
        state = self._make_state(tmp_path)
        result = serialize_state(state)
        assert isinstance(result, dict)

    def test_top_level_keys_present(self, tmp_path):
        state = self._make_state(tmp_path)
        result = serialize_state(state)
        assert "gate" in result
        assert "sessions" in result
        assert "audit" in result

    def test_gate_section(self, tmp_path):
        state = self._make_state(tmp_path)
        result = serialize_state(state)
        assert result["gate"]["started_at"] == state.started_at
        assert result["gate"]["config_sha256"] == state.config_sha256

    def test_session_fields(self, tmp_path):
        state = self._make_state(tmp_path)
        session = state.sessions["s1"]
        session.add_taint("tool.response.github")
        session.mark_private_touched()
        result = serialize_state(state)
        assert result["sessions"]
        s = result["sessions"][0]
        assert "session_id" in s
        assert "tainted_by" in s
        assert "private_touched" in s
        assert s["private_touched"] is True

    def test_serialize_does_not_mutate_state(self, tmp_path):
        state = self._make_state(tmp_path)
        before = len(state.sessions)
        serialize_state(state)
        assert len(state.sessions) == before

    def test_audit_section_has_head_hash(self, tmp_path):
        from bawbel_gate.audit.writer import AuditWriter
        from bawbel_gate._const import EVENT_SESSION_START
        log = tmp_path / "audit.jsonl"
        writer = AuditWriter(log)
        writer.append({"event": EVENT_SESSION_START, "session": "s1", "ts": "2026-07-06T00:00:00Z"})
        state = ConsoleState(
            sessions={},
            manifests={},
            audit_log=log,
            started_at="2026-07-06T00:00:00Z",
            config_sha256="sha256:" + "0" * 64,
        )
        result = serialize_state(state)
        assert result["audit"]["records"] == 1
        assert result["audit"]["head_hash"].startswith("sha256:")

    def test_json_serializable(self, tmp_path):
        state = self._make_state(tmp_path)
        result = serialize_state(state)
        json.dumps(result)  # must not raise


# ---------------------------------------------------------------------------
# Approval registry — race semantics (DESIGN.md 13.1 POST /v1/approvals/{id})
# ---------------------------------------------------------------------------

class TestApprovalRegistry:
    def test_register_and_retrieve(self):
        reg = ApprovalRegistry()
        ap_id = reg.register(session="s1", server="github", tool="create_pull_request",
                             cause="trifecta_third_leg")
        assert reg.get(ap_id) is not None

    def test_first_decision_wins(self):
        reg = ApprovalRegistry()
        ap_id = reg.register(session="s1", server="github", tool="t", cause="c")
        ok1 = reg.decide(ap_id, ApprovalDecision.GRANT)
        ok2 = reg.decide(ap_id, ApprovalDecision.DENY)
        assert ok1 is True
        assert ok2 is False  # 409 semantics: second writer loses

    def test_decide_unknown_id_returns_none(self):
        reg = ApprovalRegistry()
        result = reg.decide("nonexistent", ApprovalDecision.GRANT)
        assert result is None  # 404 semantics

    def test_concurrent_race_first_wins(self):
        """Thread-safety: exactly one thread wins when two decide concurrently."""
        reg = ApprovalRegistry()
        ap_id = reg.register(session="s", server="s", tool="t", cause="c")
        results = []

        def do_decide(decision):
            results.append(reg.decide(ap_id, decision))

        t1 = threading.Thread(target=do_decide, args=(ApprovalDecision.GRANT,))
        t2 = threading.Thread(target=do_decide, args=(ApprovalDecision.DENY,))
        t1.start(); t2.start()
        t1.join(); t2.join()

        wins = [r for r in results if r is True]
        losses = [r for r in results if r is False]
        assert len(wins) == 1
        assert len(losses) == 1

    def test_expired_approval_not_retrievable(self):
        reg = ApprovalRegistry()
        ap_id = reg.register(
            session="s", server="s", tool="t", cause="c", expires_in_s=0.001
        )
        time.sleep(0.01)
        assert reg.get(ap_id) is None  # expired

    def test_approval_id_format(self):
        reg = ApprovalRegistry()
        ap_id = reg.register(session="s", server="s", tool="t", cause="c")
        assert ap_id.startswith("ap_")


# ---------------------------------------------------------------------------
# Console HTTP server integration
# ---------------------------------------------------------------------------

def _start_console(tmp_path: Path) -> tuple[str, str, "ConsoleServer"]:
    """Start a console server on a random loopback port. Returns (base_url, token, server)."""
    from bawbel_gate.console.server import ConsoleServer
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    state = ConsoleState(
        sessions={},
        manifests={},
        audit_log=log,
        started_at="2026-07-06T00:00:00Z",
        config_sha256="sha256:" + "0" * 64,
    )
    server = ConsoleServer(state=state, host="127.0.0.1", port=0)
    server.start_background()
    token = server.token
    port = server.port
    return f"http://127.0.0.1:{port}", token, server


class TestConsoleServer:
    def test_state_endpoint_ok(self, tmp_path):
        base, token, server = _start_console(tmp_path)
        try:
            req = urllib.request.Request(
                f"{base}/v1/state",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                data = json.loads(resp.read())
                assert "gate" in data
        finally:
            server.stop()

    def test_state_endpoint_401_without_token(self, tmp_path):
        base, token, server = _start_console(tmp_path)
        try:
            req = urllib.request.Request(f"{base}/v1/state")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 401
        finally:
            server.stop()

    def test_state_endpoint_401_wrong_token(self, tmp_path):
        base, token, server = _start_console(tmp_path)
        try:
            req = urllib.request.Request(
                f"{base}/v1/state",
                headers={"Authorization": "Bearer wrongtoken"},
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 401
        finally:
            server.stop()

    def test_events_endpoint_ok(self, tmp_path):
        base, token, server = _start_console(tmp_path)
        try:
            req = urllib.request.Request(
                f"{base}/v1/events",
                headers={"Authorization": f"Bearer {token}", "Accept": "text/event-stream"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                assert resp.status == 200
                ct = resp.headers.get("Content-Type", "")
                assert "text/event-stream" in ct
        finally:
            server.stop()

    def test_approval_post_404_unknown(self, tmp_path):
        base, token, server = _start_console(tmp_path)
        try:
            body = json.dumps({"decision": "grant"}).encode()
            req = urllib.request.Request(
                f"{base}/v1/approvals/nonexistent",
                data=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 404
        finally:
            server.stop()

    def test_unknown_path_returns_404(self, tmp_path):
        base, token, server = _start_console(tmp_path)
        try:
            req = urllib.request.Request(
                f"{base}/v1/nonexistent",
                headers={"Authorization": f"Bearer {token}"},
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 404
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# Read-only guarantee (DESIGN.md 13.1 security property)
# ---------------------------------------------------------------------------

class TestReadOnlyGuarantee:
    """No console endpoint may mutate manifests, taint, or issue tool calls."""

    def test_state_endpoint_is_get_only(self, tmp_path):
        """POST to /v1/state must be rejected."""
        base, token, server = _start_console(tmp_path)
        try:
            body = b"{}"
            req = urllib.request.Request(
                f"{base}/v1/state",
                data=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code in (404, 405)
        finally:
            server.stop()

    def test_no_tool_call_endpoint_exists(self, tmp_path):
        """There is no /v1/tools/call or similar endpoint."""
        base, token, server = _start_console(tmp_path)
        try:
            for path in ["/v1/tools/call", "/v1/execute", "/v1/run"]:
                req = urllib.request.Request(
                    f"{base}{path}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with pytest.raises(urllib.error.HTTPError) as exc_info:
                    urllib.request.urlopen(req, timeout=5)
                assert exc_info.value.code == 404, f"Expected 404 for {path}"
        finally:
            server.stop()

    def test_no_manifest_mutation_endpoint(self, tmp_path):
        """There is no endpoint to PUT/PATCH manifests."""
        base, token, server = _start_console(tmp_path)
        try:
            body = b"{}"
            for path in ["/v1/manifests/github", "/v1/policy"]:
                req = urllib.request.Request(
                    f"{base}{path}",
                    data=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    method="PUT",
                )
                with pytest.raises(urllib.error.HTTPError) as exc_info:
                    urllib.request.urlopen(req, timeout=5)
                assert exc_info.value.code == 404, f"Expected 404 for PUT {path}"
        finally:
            server.stop()

    def test_session_clear_not_accessible_via_console(self, tmp_path):
        """SESSION_CLEAR is CLI-only; no POST /v1/sessions/{id}/clear endpoint."""
        base, token, server = _start_console(tmp_path)
        try:
            body = b"{}"
            req = urllib.request.Request(
                f"{base}/v1/sessions/s1/clear",
                data=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 404
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestConsoleCLI:
    def test_serve_console_flag_exists(self):
        from click.testing import CliRunner
        from bawbel_gate.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert "console" in result.output.lower()
