"""Unit tests for M3: integrity pinning, harden, and verify CLI."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
import pytest
from click.testing import CliRunner

from bawbel_gate.cli import main
from bawbel_gate.integrity.pinning import pin_tool_schema, check_pin, detect_drift, DriftResult
from bawbel_gate.integrity.harden import (
    apply_harden, merge_stanza, load_stanza, HardenError,
)

CORPUS_MANIFESTS = Path(__file__).parent / "corpus" / "manifests"
MITIGATIONS_FILE = Path(__file__).parent.parent / "mitigations" / "ave-mitigations.json"

_TOOLS = [
    {"name": "get_issue", "description": "Get a GitHub issue."},
    {"name": "create_pull_request", "description": "Create a pull request."},
]


# ---------------------------------------------------------------------------
# Pinning
# ---------------------------------------------------------------------------

class TestPinning:
    def test_pin_deterministic(self):
        assert pin_tool_schema(_TOOLS) == pin_tool_schema(_TOOLS)

    def test_check_pin_match(self):
        assert check_pin(_TOOLS, pin_tool_schema(_TOOLS)) is True

    def test_check_pin_mismatch(self):
        pin = pin_tool_schema(_TOOLS)
        other = [{"name": "other", "description": "x"}]
        assert check_pin(other, pin) is False

    def test_detect_drift_clean(self):
        pin = pin_tool_schema(_TOOLS)
        r = detect_drift(_TOOLS, pin)
        assert isinstance(r, DriftResult)
        assert r.drifted is False
        assert r.current_hash == pin

    def test_detect_drift_mutated(self):
        pin = pin_tool_schema(_TOOLS)
        poisoned = [_TOOLS[0], {"name": "create_pull_request", "description": "INJECTED"}]
        r = detect_drift(poisoned, pin)
        assert r.drifted is True
        assert r.stored_hash == pin
        assert r.current_hash != pin

    def test_tool_order_normalised(self):
        tools_a = [_TOOLS[0], _TOOLS[1]]
        tools_b = [_TOOLS[1], _TOOLS[0]]
        assert pin_tool_schema(tools_a) == pin_tool_schema(tools_b)

    def test_empty_tools_pin(self):
        pin = pin_tool_schema([])
        assert pin.startswith("sha256:")
        assert check_pin([], pin) is True


# ---------------------------------------------------------------------------
# Harden — stanza load and merge
# ---------------------------------------------------------------------------

class TestHardenStanzaLoad:
    def test_load_reviewed_stanza(self):
        stanza = load_stanza("AVE-2026-00041", MITIGATIONS_FILE, allow_unreviewed=False)
        assert "taint_rules" in stanza or "integrity_watch" in stanza

    def test_load_missing_ave_raises(self, tmp_path):
        mf = tmp_path / "m.json"
        mf.write_text('{"schema": "bawbel/ave-mitigations/v1", "mitigations": {}}', encoding="utf-8")
        with pytest.raises(HardenError, match="not found"):
            load_stanza("AVE-2026-99999", mf, allow_unreviewed=False)

    def test_load_unreviewed_blocked(self, tmp_path):
        mf = tmp_path / "m.json"
        mf.write_text(json.dumps({
            "schema": "bawbel/ave-mitigations/v1",
            "mitigations": {
                "AVE-2026-00099": {
                    "review_status": "llm_drafted",
                    "manifest_stanza": {"integrity_watch": []},
                },
            },
        }), encoding="utf-8")
        with pytest.raises(HardenError, match="allow-unreviewed"):
            load_stanza("AVE-2026-00099", mf, allow_unreviewed=False)

    def test_load_unreviewed_allowed_with_flag(self, tmp_path):
        mf = tmp_path / "m.json"
        mf.write_text(json.dumps({
            "schema": "bawbel/ave-mitigations/v1",
            "mitigations": {
                "AVE-2026-00099": {
                    "review_status": "unreviewed",
                    "manifest_stanza": {"integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}]},
                },
            },
        }), encoding="utf-8")
        stanza = load_stanza("AVE-2026-00099", mf, allow_unreviewed=True)
        assert stanza["integrity_watch"]


class TestMergeStanza:
    def _base_manifest(self) -> dict:
        return {
            "schema": "bawbel/capability-manifest/v1",
            "subject": {"kind": "mcp-server", "name": "github"},
            "provenance_class": "tool.response.github",
            "instruction_authority": "none",
            "trifecta": {
                "private_data": True, "untrusted_content": True, "external_comms": True
            },
            "grants": {"tools": [{"name": "*", "effect": "deny"}]},
        }

    def test_taint_rules_appended(self):
        stanza = {"taint_rules": [{"when": {"tainted_by_any": ["web.fetched"]}, "then": []}]}
        merged = merge_stanza(self._base_manifest(), stanza)
        assert merged["taint_rules"] == stanza["taint_rules"]

    def test_taint_rules_deduplicated(self):
        rule = {"when": {"tainted_by_any": ["web.fetched"]}, "then": []}
        manifest = {**self._base_manifest(), "taint_rules": [rule]}
        stanza = {"taint_rules": [rule]}  # same rule
        merged = merge_stanza(manifest, stanza)
        assert len(merged["taint_rules"]) == 1

    def test_integrity_watch_appended(self):
        stanza = {"integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}]}
        merged = merge_stanza(self._base_manifest(), stanza)
        assert merged["integrity_watch"] == stanza["integrity_watch"]

    def test_argument_guards_appended(self):
        stanza = {"argument_guards": [{"applies_to": "*", "outbound_secret_scan": True}]}
        merged = merge_stanza(self._base_manifest(), stanza)
        assert merged["grants"]["argument_guards"] == stanza["argument_guards"]

    def test_merge_is_nondestructive(self):
        original = self._base_manifest()
        stanza = {"taint_rules": [{"when": {}, "then": []}]}
        merged = merge_stanza(original, stanza)
        assert "taint_rules" not in original  # original unchanged

    def test_apply_harden_full_flow(self, tmp_path):
        manifest_file = tmp_path / "test.cap.yaml"
        manifest_file.write_text(
            yaml.dump(self._base_manifest(), default_flow_style=False),
            encoding="utf-8",
        )
        result = apply_harden(
            ave_id="AVE-2026-00041",
            manifest_path=manifest_file,
            mitigations_path=MITIGATIONS_FILE,
            allow_unreviewed=False,
            write=False,
        )
        assert result.ave_id == "AVE-2026-00041"
        assert result.review_status == "reviewed"
        assert result.applied is False
        assert "integrity_watch" in result.diff or "taint_rules" in result.diff

    def test_apply_harden_write(self, tmp_path):
        manifest_file = tmp_path / "test.cap.yaml"
        manifest_file.write_text(
            yaml.dump(self._base_manifest(), default_flow_style=False),
            encoding="utf-8",
        )
        result = apply_harden(
            ave_id="AVE-2026-00041",
            manifest_path=manifest_file,
            mitigations_path=MITIGATIONS_FILE,
            allow_unreviewed=False,
            write=True,
        )
        assert result.applied is True
        written = yaml.safe_load(manifest_file.read_text(encoding="utf-8"))
        assert "integrity_watch" in written or "taint_rules" in written


# ---------------------------------------------------------------------------
# CLI: verify
# ---------------------------------------------------------------------------

class TestVerifyCLI:
    def _tools_json(self, tmp_path, tools=None) -> Path:
        tools = tools or _TOOLS
        p = tmp_path / "tools.json"
        p.write_text(json.dumps(tools), encoding="utf-8")
        return p

    def _manifest_with_pin(self, tmp_path, pin=None, tools=None) -> Path:
        tools = tools or _TOOLS
        p = tmp_path / "test.cap.yaml"
        raw = {
            "schema": "bawbel/capability-manifest/v1",
            "subject": {"kind": "mcp-server", "name": "test"},
            "provenance_class": "tool.response.test",
            "instruction_authority": "none",
            "trifecta": {"private_data": False, "untrusted_content": False, "external_comms": False},
            "grants": {"tools": [{"name": "*", "effect": "deny"}]},
            "tool_schema_integrity": pin or pin_tool_schema(tools),
        }
        p.write_text(yaml.dump(raw, default_flow_style=False), encoding="utf-8")
        return p

    def test_verify_clean_ok(self, tmp_path):
        tools_file = self._tools_json(tmp_path)
        manifest = self._manifest_with_pin(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["verify", str(tools_file), str(manifest)])
        assert result.exit_code == 0
        assert "no drift" in result.output

    def test_verify_drift_exits_1(self, tmp_path):
        tools_file = self._tools_json(tmp_path)
        # Use wrong pin
        manifest = self._manifest_with_pin(tmp_path, pin="sha256:" + "a" * 64)
        runner = CliRunner()
        result = runner.invoke(main, ["verify", str(tools_file), str(manifest)])
        assert result.exit_code == 1

    def test_verify_accept_updates_pin(self, tmp_path):
        tools_file = self._tools_json(tmp_path)
        manifest = self._manifest_with_pin(tmp_path, pin="sha256:" + "a" * 64)
        runner = CliRunner()
        result = runner.invoke(main, ["verify", str(tools_file), str(manifest), "--accept"])
        assert result.exit_code == 0
        written = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        assert written["tool_schema_integrity"] == pin_tool_schema(_TOOLS)

    def test_verify_no_pin_stored_reports(self, tmp_path):
        tools_file = self._tools_json(tmp_path)
        p = tmp_path / "no-pin.cap.yaml"
        p.write_text(
            yaml.dump({
                "schema": "bawbel/capability-manifest/v1",
                "subject": {"kind": "mcp-server", "name": "test"},
                "provenance_class": "tool.response.test",
                "instruction_authority": "none",
                "trifecta": {"private_data": False, "untrusted_content": False, "external_comms": False},
                "grants": {"tools": [{"name": "*", "effect": "deny"}]},
            }, default_flow_style=False),
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["verify", str(tools_file), str(p)])
        assert result.exit_code == 0
        assert "no pin" in result.output


# ---------------------------------------------------------------------------
# CLI: harden
# ---------------------------------------------------------------------------

class TestHardenCLI:
    def _manifest_file(self, tmp_path) -> Path:
        p = tmp_path / "test.cap.yaml"
        p.write_text(
            yaml.dump({
                "schema": "bawbel/capability-manifest/v1",
                "subject": {"kind": "mcp-server", "name": "github"},
                "provenance_class": "tool.response.github",
                "instruction_authority": "none",
                "trifecta": {
                    "private_data": True, "untrusted_content": True, "external_comms": True
                },
                "grants": {"tools": [{"name": "*", "effect": "deny"}]},
            }, default_flow_style=False),
            encoding="utf-8",
        )
        return p

    def test_harden_shows_diff(self, tmp_path):
        manifest = self._manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "harden", "--ave", "AVE-2026-00041",
            "--manifest", str(manifest),
            "--mitigations", str(MITIGATIONS_FILE),
        ])
        assert result.exit_code == 0
        assert "AVE-2026-00041" in result.output

    def test_harden_write_applies_stanza(self, tmp_path):
        manifest = self._manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "harden", "--ave", "AVE-2026-00041",
            "--manifest", str(manifest),
            "--mitigations", str(MITIGATIONS_FILE),
            "--write",
        ])
        assert result.exit_code == 0
        written = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        assert "integrity_watch" in written or "taint_rules" in written

    def test_harden_missing_ave_exits_1(self, tmp_path):
        manifest = self._manifest_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "harden", "--ave", "AVE-2026-99999",
            "--manifest", str(manifest),
            "--mitigations", str(MITIGATIONS_FILE),
        ])
        assert result.exit_code == 1

    def test_harden_unreviewed_blocked_by_default(self, tmp_path):
        manifest = self._manifest_file(tmp_path)
        mf = tmp_path / "m.json"
        mf.write_text(json.dumps({
            "schema": "bawbel/ave-mitigations/v1",
            "mitigations": {
                "AVE-2026-00099": {
                    "review_status": "llm_drafted",
                    "manifest_stanza": {"integrity_watch": []},
                },
            },
        }), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "harden", "--ave", "AVE-2026-00099",
            "--manifest", str(manifest),
            "--mitigations", str(mf),
        ])
        assert result.exit_code == 1
        assert "allow-unreviewed" in result.output or "allow-unreviewed" in (result.stderr or "")

    def test_harden_unreviewed_allowed_with_flag(self, tmp_path):
        manifest = self._manifest_file(tmp_path)
        mf = tmp_path / "m.json"
        mf.write_text(json.dumps({
            "schema": "bawbel/ave-mitigations/v1",
            "mitigations": {
                "AVE-2026-00099": {
                    "review_status": "unreviewed",
                    "manifest_stanza": {"integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}]},
                },
            },
        }), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "harden", "--ave", "AVE-2026-00099",
            "--manifest", str(manifest),
            "--mitigations", str(mf),
            "--allow-unreviewed",
        ])
        assert result.exit_code == 0
