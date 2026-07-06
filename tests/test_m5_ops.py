"""M5: Operations layer — OTel spans, CEF/syslog export, posture report.

See DESIGN.md 8.5 (SIEM and OTel export) and IMPLEMENTATION_PLAN.md M5.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Alertable event constants (DESIGN.md 8.5)
# ---------------------------------------------------------------------------

class TestAlertableEventConstants:
    def test_all_six_event_classes_defined(self):
        from bawbel_gate._const import (
            ALERT_DRIFT_DETECTED,
            ALERT_TRIFECTA_TRIP,
            ALERT_DENY_BURST,
            ALERT_SECRET_SCAN_HIT,
            ALERT_APPROVAL_TIMEOUT,
            ALERT_CHAIN_GAP,
        )
        classes = {
            ALERT_DRIFT_DETECTED,
            ALERT_TRIFECTA_TRIP,
            ALERT_DENY_BURST,
            ALERT_SECRET_SCAN_HIT,
            ALERT_APPROVAL_TIMEOUT,
            ALERT_CHAIN_GAP,
        }
        assert len(classes) == 6

    def test_event_class_names_use_dot_notation(self):
        from bawbel_gate._const import ALERT_DRIFT_DETECTED
        assert "." in ALERT_DRIFT_DETECTED

    def test_severities_defined(self):
        from bawbel_gate._const import (
            ALERT_SEV_CRITICAL,
            ALERT_SEV_HIGH,
            ALERT_SEV_MEDIUM,
            ALERT_SEV_LOW,
        )
        assert ALERT_SEV_CRITICAL
        assert ALERT_SEV_HIGH
        assert ALERT_SEV_MEDIUM
        assert ALERT_SEV_LOW

    def test_drift_detected_severity_is_high(self):
        from bawbel_gate._const import (
            ALERT_DRIFT_DETECTED,
            ALERT_SEV_HIGH,
            ALERT_DEFAULT_SEVERITIES,
        )
        assert ALERT_DEFAULT_SEVERITIES[ALERT_DRIFT_DETECTED] == ALERT_SEV_HIGH

    def test_chain_gap_severity_is_critical(self):
        from bawbel_gate._const import (
            ALERT_CHAIN_GAP,
            ALERT_SEV_CRITICAL,
            ALERT_DEFAULT_SEVERITIES,
        )
        assert ALERT_DEFAULT_SEVERITIES[ALERT_CHAIN_GAP] == ALERT_SEV_CRITICAL

    def test_approval_timeout_severity_is_low(self):
        from bawbel_gate._const import (
            ALERT_APPROVAL_TIMEOUT,
            ALERT_SEV_LOW,
            ALERT_DEFAULT_SEVERITIES,
        )
        assert ALERT_DEFAULT_SEVERITIES[ALERT_APPROVAL_TIMEOUT] == ALERT_SEV_LOW


# ---------------------------------------------------------------------------
# CEF/syslog formatter (DESIGN.md 8.5 — SIEMs without OTel ingestion)
# ---------------------------------------------------------------------------

class TestCEFFormatter:
    def _format(self, event_class, attrs=None):
        from bawbel_gate.ops.syslog_cef import format_cef_record
        return format_cef_record(event_class, attrs or {})

    def test_output_starts_with_cef_prefix(self):
        from bawbel_gate._const import ALERT_DRIFT_DETECTED
        record = self._format(ALERT_DRIFT_DETECTED)
        assert record.startswith("CEF:0|")

    def test_vendor_and_product_in_header(self):
        from bawbel_gate._const import ALERT_TRIFECTA_TRIP
        record = self._format(ALERT_TRIFECTA_TRIP)
        assert "bawbel" in record.lower()
        assert "gate" in record.lower()

    def test_severity_numeric_in_header(self):
        from bawbel_gate._const import ALERT_CHAIN_GAP
        # CEF severity: 10 = highest; chain gap is critical
        record = self._format(ALERT_CHAIN_GAP)
        parts = record.split("|")
        assert len(parts) >= 7
        sev = int(parts[6])
        assert sev >= 8  # critical -> 8-10 in CEF

    def test_extension_attributes_present(self):
        from bawbel_gate._const import ALERT_SECRET_SCAN_HIT
        record = self._format(ALERT_SECRET_SCAN_HIT, {"tool": "write_file", "server": "fs"})
        assert "tool=write_file" in record
        assert "server=fs" in record

    def test_pipe_in_attr_value_is_escaped(self):
        from bawbel_gate._const import ALERT_DENY_BURST
        record = self._format(ALERT_DENY_BURST, {"detail": "a|b"})
        assert "a\\|b" in record
        assert "a|b" not in record.split("|")[-1]

    def test_equals_in_attr_value_is_escaped(self):
        from bawbel_gate._const import ALERT_DENY_BURST
        record = self._format(ALERT_DENY_BURST, {"expr": "x=1"})
        assert "x\\=1" in record

    def test_all_six_event_classes_format_without_error(self):
        from bawbel_gate._const import (
            ALERT_DRIFT_DETECTED, ALERT_TRIFECTA_TRIP, ALERT_DENY_BURST,
            ALERT_SECRET_SCAN_HIT, ALERT_APPROVAL_TIMEOUT, ALERT_CHAIN_GAP,
        )
        from bawbel_gate.ops.syslog_cef import format_cef_record
        for ec in (
            ALERT_DRIFT_DETECTED, ALERT_TRIFECTA_TRIP, ALERT_DENY_BURST,
            ALERT_SECRET_SCAN_HIT, ALERT_APPROVAL_TIMEOUT, ALERT_CHAIN_GAP,
        ):
            record = format_cef_record(ec, {"server": "test"})
            assert record.startswith("CEF:0|"), f"Bad CEF for {ec!r}"

    def test_newline_in_value_replaced(self):
        from bawbel_gate._const import ALERT_TRIFECTA_TRIP
        record = self._format(ALERT_TRIFECTA_TRIP, {"msg": "line1\nline2"})
        assert "\n" not in record

    def test_cef_record_is_single_line(self):
        from bawbel_gate._const import ALERT_DRIFT_DETECTED
        record = self._format(ALERT_DRIFT_DETECTED, {"k": "v"})
        assert "\n" not in record


# ---------------------------------------------------------------------------
# Posture report — computation
# ---------------------------------------------------------------------------

def _write_audit_log(tmp_path: Path, records: list[dict]) -> Path:
    p = tmp_path / "audit.jsonl"
    p.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )
    return p


class TestPostureComputation:
    def test_empty_log_zero_counts(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture
        log = _write_audit_log(tmp_path, [])
        stats = compute_posture(log)
        assert stats.allow_count == 0
        assert stats.approve_count == 0
        assert stats.deny_count == 0
        assert stats.trifecta_trips == 0
        assert stats.drift_events == 0
        assert stats.secret_scan_hits == 0
        assert stats.approval_timeouts == 0
        assert stats.chain_gaps == 0

    def test_allow_approve_deny_counted(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture
        from bawbel_gate._const import (
            EVENT_CALL_DECIDED, EFFECT_ALLOW, EFFECT_APPROVE, EFFECT_DENY,
        )
        records = [
            {"event": EVENT_CALL_DECIDED, "effect": EFFECT_ALLOW},
            {"event": EVENT_CALL_DECIDED, "effect": EFFECT_ALLOW},
            {"event": EVENT_CALL_DECIDED, "effect": EFFECT_APPROVE},
            {"event": EVENT_CALL_DECIDED, "effect": EFFECT_DENY},
        ]
        log = _write_audit_log(tmp_path, records)
        stats = compute_posture(log)
        assert stats.allow_count == 2
        assert stats.approve_count == 1
        assert stats.deny_count == 1

    def test_trifecta_trip_counted(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture
        from bawbel_gate._const import (
            EVENT_CALL_DECIDED, EFFECT_APPROVE, REASON_TRIFECTA_THIRD_LEG,
        )
        records = [
            {
                "event": EVENT_CALL_DECIDED,
                "effect": EFFECT_APPROVE,
                "reason": REASON_TRIFECTA_THIRD_LEG,
            },
        ]
        log = _write_audit_log(tmp_path, records)
        stats = compute_posture(log)
        assert stats.trifecta_trips == 1

    def test_drift_event_counted(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture
        from bawbel_gate._const import EVENT_DRIFT_DETECTED
        records = [
            {"event": EVENT_DRIFT_DETECTED, "server": "github"},
        ]
        log = _write_audit_log(tmp_path, records)
        stats = compute_posture(log)
        assert stats.drift_events == 1

    def test_secret_scan_hit_counted(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture
        from bawbel_gate._const import (
            EVENT_CALL_DECIDED, EFFECT_DENY, REASON_GUARD_SECRET_SCAN,
        )
        records = [
            {
                "event": EVENT_CALL_DECIDED,
                "effect": EFFECT_DENY,
                "reason": REASON_GUARD_SECRET_SCAN,
            },
        ]
        log = _write_audit_log(tmp_path, records)
        stats = compute_posture(log)
        assert stats.secret_scan_hits == 1

    def test_approval_timeout_counted(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture
        from bawbel_gate._const import EVENT_APPROVAL_TIMEOUT
        records = [
            {"event": EVENT_APPROVAL_TIMEOUT, "session": "s1"},
        ]
        log = _write_audit_log(tmp_path, records)
        stats = compute_posture(log)
        assert stats.approval_timeouts == 1

    def test_missing_log_raises(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture, PostureError
        with pytest.raises(PostureError, match="not found"):
            compute_posture(tmp_path / "missing.jsonl")

    def test_non_decision_events_ignored(self, tmp_path):
        from bawbel_gate.ops.posture import compute_posture
        from bawbel_gate._const import EVENT_SESSION_START, EVENT_SESSION_END
        records = [
            {"event": EVENT_SESSION_START},
            {"event": EVENT_SESSION_END},
        ]
        log = _write_audit_log(tmp_path, records)
        stats = compute_posture(log)
        assert stats.allow_count == 0
        assert stats.deny_count == 0


# ---------------------------------------------------------------------------
# Posture report — rendering
# ---------------------------------------------------------------------------

class TestPostureReport:
    def _make_stats(self, **kwargs):
        from bawbel_gate.ops.posture import PostureStats
        defaults = dict(
            allow_count=10, approve_count=2, deny_count=5,
            trifecta_trips=1, drift_events=0, secret_scan_hits=0,
            approval_timeouts=1, chain_gaps=0, session_count=3,
        )
        defaults.update(kwargs)
        return PostureStats(**defaults)

    def test_render_is_non_empty(self):
        from bawbel_gate.ops.posture import render_posture_report
        stats = self._make_stats()
        report = render_posture_report(stats)
        assert report.strip()

    def test_render_includes_decision_counts(self):
        from bawbel_gate.ops.posture import render_posture_report
        stats = self._make_stats(allow_count=42, deny_count=7)
        report = render_posture_report(stats)
        assert "42" in report
        assert "7" in report

    def test_render_includes_security_events(self):
        from bawbel_gate.ops.posture import render_posture_report
        stats = self._make_stats(trifecta_trips=3, secret_scan_hits=1)
        report = render_posture_report(stats)
        assert "3" in report
        assert "1" in report

    def test_render_no_em_dashes(self):
        from bawbel_gate.ops.posture import render_posture_report
        stats = self._make_stats()
        report = render_posture_report(stats)
        assert "—" not in report  # em dash banned by CLAUDE.md

    def test_json_render_is_valid(self):
        from bawbel_gate.ops.posture import render_posture_report
        stats = self._make_stats()
        report_json = render_posture_report(stats, fmt="json")
        parsed = json.loads(report_json)
        assert parsed["allow_count"] == stats.allow_count
        assert parsed["trifecta_trips"] == stats.trifecta_trips


# ---------------------------------------------------------------------------
# OTel — noop when SDK not installed
# ---------------------------------------------------------------------------

class TestOTelNoOp:
    def test_record_decision_span_no_exception(self):
        """record_decision_span must not raise even if opentelemetry is absent."""
        from bawbel_gate.ops.otel import record_decision_span
        from bawbel_gate.policy.engine import resolve
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        from bawbel_gate.mux.session import SessionState
        from bawbel_gate._const import EFFECT_ALLOW

        manifest = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            trifecta={"private_data": False, "untrusted_content": False, "external_comms": False},
            grants=[ToolGrant(name="get_issue", effect=EFFECT_ALLOW)],
        )
        session = SessionState()
        decision = resolve("get_issue", {"issue_number": 1}, manifest, session)
        record_decision_span(
            tool="get_issue",
            server="github",
            decision=decision,
            taint_classes=list(session.tainted_by),
            latency_ms=0.5,
        )

    def test_emit_alert_event_no_exception(self):
        """emit_alert_event must not raise even if opentelemetry is absent."""
        from bawbel_gate.ops.otel import emit_alert_event
        from bawbel_gate._const import ALERT_DRIFT_DETECTED
        emit_alert_event(ALERT_DRIFT_DETECTED, {"server": "github"})

    def test_otel_available_flag_is_bool(self):
        from bawbel_gate.ops import otel
        assert isinstance(otel.OTEL_AVAILABLE, bool)

    def test_setup_otel_returns_noop_without_sdk(self):
        """setup_otel must not raise when OTel SDK is absent."""
        from bawbel_gate.ops.otel import setup_otel
        setup_otel(endpoint=None)  # no endpoint -> no provider to configure


# ---------------------------------------------------------------------------
# CLI: posture command
# ---------------------------------------------------------------------------

class TestPostureCLI:
    def test_posture_command_exists(self):
        from click.testing import CliRunner
        from bawbel_gate.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["posture", "--help"])
        assert result.exit_code == 0
        assert "audit" in result.output.lower() or "posture" in result.output.lower()

    def test_posture_command_runs_on_empty_log(self, tmp_path):
        from click.testing import CliRunner
        from bawbel_gate.cli import main
        log = tmp_path / "audit.jsonl"
        log.write_text("", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["posture", "--audit-log", str(log)])
        assert result.exit_code == 0

    def test_posture_command_json_flag(self, tmp_path):
        from click.testing import CliRunner
        from bawbel_gate.cli import main
        log = tmp_path / "audit.jsonl"
        log.write_text(
            json.dumps({"event": "CALL_DECIDED", "effect": "allow"}) + "\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["posture", "--audit-log", str(log), "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "allow_count" in parsed
