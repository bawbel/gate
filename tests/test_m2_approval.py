"""Unit tests for the terminal approval channel and SESSION_CLEAR CLI."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from bawbel_gate.cli import main
from bawbel_gate.policy.approval import (
    request_approval,
    _redact_args,
    _format_prompt,
    _REDACTED,
)
from bawbel_gate._const import REASON_APPROVAL_DENIED, REASON_APPROVAL_TIMEOUT
from bawbel_gate.audit.writer import verify_chain, AuditWriter


# ---------------------------------------------------------------------------
# Arg redaction
# ---------------------------------------------------------------------------

class TestRedactArgs:
    def test_aws_key_redacted(self):
        out = _redact_args({"key": "AKIAIOSFODNN7EXAMPLE"})
        assert out["key"] == _REDACTED

    def test_nested_dict_redacted(self):
        out = _redact_args({"outer": {"token": "AKIAIOSFODNN7EXAMPLE"}})
        assert out["outer"]["token"] == _REDACTED

    def test_list_redacted(self):
        out = _redact_args(["AKIAIOSFODNN7EXAMPLE", "normal"])
        assert out[0] == _REDACTED
        assert out[1] == "normal"

    def test_normal_string_unchanged(self):
        out = _redact_args({"repo": "myorg/myrepo"})
        assert out["repo"] == "myorg/myrepo"

    def test_non_string_unchanged(self):
        out = _redact_args({"count": 42, "flag": True})
        assert out["count"] == 42
        assert out["flag"] is True

    def test_pem_redacted(self):
        out = _redact_args({"key_pem": "-----BEGIN RSA PRIVATE KEY-----"})
        assert out["key_pem"] == _REDACTED


# ---------------------------------------------------------------------------
# Prompt format
# ---------------------------------------------------------------------------

class TestFormatPrompt:
    def test_prompt_contains_tool(self):
        p = _format_prompt("create_pull_request", {}, set(), "trifecta_third_leg", [], 120)
        assert "create_pull_request" in p

    def test_prompt_contains_reason(self):
        p = _format_prompt("t", {}, set(), "trifecta_third_leg", [], 120)
        assert "trifecta_third_leg" in p

    def test_prompt_contains_ave_id(self):
        p = _format_prompt("t", {}, set(), "r", ["AVE-2026-00038"], 120)
        assert "AVE-2026-00038" in p

    def test_prompt_contains_taint_class(self):
        p = _format_prompt("t", {}, {"tool.response.github"}, "r", [], 120)
        assert "tool.response.github" in p

    def test_prompt_contains_timeout(self):
        p = _format_prompt("t", {}, set(), "r", [], 90)
        assert "90" in p


# ---------------------------------------------------------------------------
# request_approval (with injected input_fn)
# ---------------------------------------------------------------------------

class TestRequestApproval:
    def _approve(self) -> str:
        return "y"

    def _deny(self) -> str:
        return "n"

    def _empty(self) -> str:
        return ""

    def test_y_grants(self):
        output = []
        result = request_approval(
            "create_pull_request", {}, set(), "trifecta_third_leg", [],
            output_fn=output.append, input_fn=self._approve,
        )
        assert result == ""  # granted

    def test_yes_grants(self):
        result = request_approval(
            "create_pull_request", {}, set(), "trifecta_third_leg", [],
            output_fn=lambda _: None, input_fn=lambda: "yes",
        )
        assert result == ""

    def test_Y_grants(self):
        result = request_approval(
            "create_pull_request", {}, set(), "trifecta_third_leg", [],
            output_fn=lambda _: None, input_fn=lambda: "Y",
        )
        assert result == ""

    def test_n_denies(self):
        result = request_approval(
            "create_pull_request", {}, set(), "trifecta_third_leg", [],
            output_fn=lambda _: None, input_fn=self._deny,
        )
        assert result == REASON_APPROVAL_DENIED

    def test_empty_denies(self):
        result = request_approval(
            "create_pull_request", {}, set(), "trifecta_third_leg", [],
            output_fn=lambda _: None, input_fn=self._empty,
        )
        assert result == REASON_APPROVAL_DENIED

    def test_garbage_denies(self):
        result = request_approval(
            "t", {}, set(), "r", [],
            output_fn=lambda _: None, input_fn=lambda: "maybe",
        )
        assert result == REASON_APPROVAL_DENIED

    def test_prompt_shown_before_input(self):
        output = []
        request_approval(
            "create_pull_request", {}, {"tool.response.github"}, "trifecta_third_leg",
            ["AVE-2026-00038"],
            output_fn=output.append, input_fn=lambda: "y",
        )
        prompt = "".join(output)
        assert "create_pull_request" in prompt
        assert "trifecta_third_leg" in prompt
        assert "AVE-2026-00038" in prompt
        assert "tool.response.github" in prompt

    def test_secret_not_shown_in_prompt(self):
        output = []
        request_approval(
            "create_or_update_file",
            {"content": "AKIAIOSFODNN7EXAMPLE"},
            set(), "guard:secret_scan", [],
            output_fn=output.append, input_fn=lambda: "n",
        )
        prompt = "".join(output)
        assert "AKIAIOSFODNN7EXAMPLE" not in prompt
        assert _REDACTED in prompt


# ---------------------------------------------------------------------------
# SESSION_CLEAR CLI
# ---------------------------------------------------------------------------

class TestSessionClear:
    def test_clear_requires_confirm_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["clear", "--session", "abc-123"])
        assert result.exit_code != 0

    def test_clear_writes_audit_record(self, tmp_path):
        audit_log = tmp_path / "audit.jsonl"
        runner = CliRunner()
        result = runner.invoke(main, [
            "clear",
            "--session", "test-session-001",
            "--confirm",
            "--audit-log", str(audit_log),
        ])
        assert result.exit_code == 0
        assert "SESSION_CLEAR" in result.output
        assert audit_log.exists()

        # Verify the audit chain is intact
        verify = verify_chain(audit_log)
        assert verify.ok
        assert verify.records == 1

    def test_clear_audit_record_has_correct_fields(self, tmp_path):
        import json
        audit_log = tmp_path / "audit.jsonl"
        runner = CliRunner()
        runner.invoke(main, [
            "clear",
            "--session", "my-session-id",
            "--confirm",
            "--audit-log", str(audit_log),
        ])
        record = json.loads(audit_log.read_text(encoding="utf-8").strip())
        assert record["event"] == "SESSION_CLEAR"
        assert record["session"] == "my-session-id"
        assert record["operator"] == "cli"
        assert "ts" in record
        assert "hash" in record
        assert "prev" in record

    def test_clear_continues_existing_chain(self, tmp_path):
        audit_log = tmp_path / "audit.jsonl"
        # Pre-populate with one record
        writer = AuditWriter(audit_log)
        writer.append({"event": "SESSION_START", "session": "s1", "ts": "2026-01-01T00:00:00.000Z"})
        assert writer.seq == 1

        runner = CliRunner()
        runner.invoke(main, [
            "clear",
            "--session", "s1",
            "--confirm",
            "--audit-log", str(audit_log),
        ])
        # Chain should have 2 records and both valid
        verify = verify_chain(audit_log)
        assert verify.ok
        assert verify.records == 2

    def test_clear_hash_in_output(self, tmp_path):
        audit_log = tmp_path / "audit.jsonl"
        runner = CliRunner()
        result = runner.invoke(main, [
            "clear",
            "--session", "sess-xyz",
            "--confirm",
            "--audit-log", str(audit_log),
        ])
        assert "sha256:" in result.output
