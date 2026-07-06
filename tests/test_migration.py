"""Tests for scripts/migrate_ave_v1_2.py.

Covers: null-insert, idempotency, triage.provenance insertion, validation,
--force flag, --dry-run, error handling on bad JSON.
"""

import json
import shutil
from pathlib import Path

import jsonschema
from click.testing import CliRunner

from scripts.migrate_ave_v1_2 import migrate, migrate_record, validate_record

REPO_ROOT  = Path(__file__).parent.parent
AVE_V1_1   = REPO_ROOT / "tests" / "corpus" / "ave" / "v1_1"
SCHEMA_DIR = REPO_ROOT / "schemas"


# ---------------------------------------------------------------------------
# migrate_record unit tests
# ---------------------------------------------------------------------------

class TestMigrateRecord:
    def _base_v1_1(self) -> dict:
        return {
            "schema_version": "1.1",
            "id": "AVE-2026-00099",
            "title": "Test",
            "description": "Test record.",
            "aivss": {"version": "0.8", "base_score": 5.0},
            "triage": {"status": "reviewed"},
            "mitigation": {"strategy": ["deny_by_default"]},
        }

    def test_bumps_schema_version(self):
        out, changed = migrate_record(self._base_v1_1())
        assert out["schema_version"] == "1.2"
        assert changed is True

    def test_adds_three_null_fields(self):
        out, _ = migrate_record(self._base_v1_1())
        assert out["provenance_vector"] is None
        assert out["trifecta_profile"] is None
        assert out["capability_mitigation"] is None

    def test_adds_triage_provenance_unclassified(self):
        out, _ = migrate_record(self._base_v1_1())
        assert out["triage"]["provenance"] == "unclassified"

    def test_preserves_existing_triage_provenance(self):
        record = self._base_v1_1()
        record["triage"]["provenance"] = "classified"
        out, _ = migrate_record(record)
        assert out["triage"]["provenance"] == "classified"

    def test_preserves_existing_fields(self):
        record = self._base_v1_1()
        out, _ = migrate_record(record)
        assert out["id"] == record["id"]
        assert out["title"] == record["title"]
        assert out["mitigation"] == record["mitigation"]

    def test_idempotent_on_already_migrated(self):
        record = self._base_v1_1()
        out1, changed1 = migrate_record(record)
        assert changed1 is True
        out2, changed2 = migrate_record(out1)
        assert changed2 is False
        assert out1 == out2

    def test_force_can_reprocess_already_migrated(self):
        """migrate_record itself is stateless; the CLI --force flag controls skipping."""
        record = self._base_v1_1()
        out1, _ = migrate_record(record)
        out2, changed = migrate_record(out1)
        assert changed is False  # idempotent at the record level
        assert out2["schema_version"] == "1.2"

    def test_does_not_overwrite_existing_null_fields(self):
        record = self._base_v1_1()
        record["schema_version"] = "1.2"
        record["provenance_vector"] = None
        record["trifecta_profile"] = None
        record["capability_mitigation"] = None
        record["triage"]["provenance"] = "unclassified"
        out, changed = migrate_record(record)
        assert changed is False


# ---------------------------------------------------------------------------
# validate_record unit tests
# ---------------------------------------------------------------------------

class TestValidateRecord:
    def test_valid_null_insert_record_passes(self, ave_12_schema):
        record = {
            "schema_version": "1.2",
            "id": "AVE-2026-00099",
            "title": "Test",
            "description": "Test.",
            "aivss": {"version": "0.8", "base_score": 5.0},
            "triage": {"status": "reviewed", "provenance": "unclassified"},
            "mitigation": {"strategy": ["deny_by_default"]},
            "provenance_vector": None,
            "trifecta_profile": None,
            "capability_mitigation": None,
        }
        validate_record(record, ave_12_schema)  # must not raise

    def test_invalid_record_raises(self, ave_12_schema):
        record = {"schema_version": "1.2"}  # missing required fields
        try:
            validate_record(record, ave_12_schema)
            raise AssertionError("expected ValidationError")
        except jsonschema.ValidationError:
            pass


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------

class TestMigrateCLI:
    def _runner(self):
        return CliRunner()

    def test_migrates_v1_1_files(self, ave_12_schema, tmp_path):
        shutil.copytree(AVE_V1_1, tmp_path / "in")
        out_dir = tmp_path / "out"
        result = self._runner().invoke(
            migrate,
            [
                "--in", str(tmp_path / "in"),
                "--out", str(out_dir),
                "--schema", str(SCHEMA_DIR / "ave-1.2.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        outputs = list(out_dir.glob("*.json"))
        assert len(outputs) == len(list((tmp_path / "in").glob("*.json")))
        for f in outputs:
            rec = json.loads(f.read_text())
            assert rec["schema_version"] == "1.2"
            validate_record(rec, ave_12_schema)

    def test_idempotent_in_place(self, ave_12_schema, tmp_path):
        shutil.copytree(AVE_V1_1, tmp_path / "records")
        rec_dir = tmp_path / "records"
        schema = str(SCHEMA_DIR / "ave-1.2.json")
        args = ["--in", str(rec_dir), "--out", str(rec_dir), "--schema", schema]
        r1 = self._runner().invoke(migrate, args)
        assert r1.exit_code == 0
        r2 = self._runner().invoke(migrate, args)
        assert r2.exit_code == 0
        assert "skip" in r2.output

    def test_force_remigrates_already_12(self, tmp_path):
        shutil.copytree(AVE_V1_1, tmp_path / "in")
        out_dir = tmp_path / "out"
        schema = str(SCHEMA_DIR / "ave-1.2.json")
        args = ["--in", str(tmp_path / "in"), "--out", str(out_dir), "--schema", schema]
        self._runner().invoke(migrate, args)
        r2 = self._runner().invoke(migrate, ["--in", str(out_dir), "--out", str(out_dir), "--schema", schema, "--force"])
        assert r2.exit_code == 0
        # per-file "skip" prefix must not appear; "0 skipped" in summary is fine
        assert not any(line.startswith("skip ") for line in r2.output.splitlines())

    def test_dry_run_writes_no_files(self, tmp_path):
        shutil.copytree(AVE_V1_1, tmp_path / "in")
        out_dir = tmp_path / "out"
        result = self._runner().invoke(
            migrate,
            [
                "--in", str(tmp_path / "in"),
                "--out", str(out_dir),
                "--schema", str(SCHEMA_DIR / "ave-1.2.json"),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert not out_dir.exists() or not list(out_dir.glob("*.json"))

    def test_invalid_json_reports_error(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        result = self._runner().invoke(
            migrate,
            [
                "--in", str(tmp_path),
                "--out", str(tmp_path / "out"),
                "--schema", str(SCHEMA_DIR / "ave-1.2.json"),
            ],
        )
        assert result.exit_code == 1
        assert "invalid JSON" in result.output or "invalid JSON" in (result.exception and str(result.exception) or "")

    def test_empty_directory_warns(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = self._runner().invoke(
            migrate,
            ["--in", str(empty), "--out", str(tmp_path / "out"), "--schema", str(SCHEMA_DIR / "ave-1.2.json")],
        )
        assert result.exit_code == 0
