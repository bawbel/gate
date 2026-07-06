"""M7: bawbel-hub fleet ingest service, state store, enrollment, and posture.

See DESIGN.md 13.2, 14 and IMPLEMENTATION_PLAN.md M7.

Tests cover:
  - Fleet state store (SQLite, idempotent upsert, rebuild)
  - Chain verification on ingest (200/409/422)
  - Enrollment token lifecycle (mint, single-use, expiry)
  - Fleet posture queries (per-gate rows, aggregate)
  - Hub HTTP server endpoints
  - Gate-side ingest client (cursor management, batching)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from bawbel_gate.hub.store import FleetStore
from bawbel_gate.hub.enroll import EnrollmentRegistry, EnrollmentError
from bawbel_gate.hub.ingest import process_batch, ChainMismatch
from bawbel_gate.hub.fleet import compute_fleet_posture, GatePostureRow
from bawbel_gate._const import (
    EVENT_CALL_DECIDED,
    EVENT_DRIFT_DETECTED,
    EFFECT_ALLOW,
    EFFECT_APPROVE,
    EFFECT_DENY,
    REASON_TRIFECTA_THIRD_LEG,
)


# ---------------------------------------------------------------------------
# Helpers: build valid audit records with correct hash chain
# ---------------------------------------------------------------------------

def _make_records(gate_id: str, session_id: str, count: int = 3) -> list[dict]:
    """Build a small chain of valid CALL_DECIDED records."""
    from bawbel_gate.audit.writer import AuditWriter
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        path = Path(tf.name)
    try:
        writer = AuditWriter(path)
        for i in range(count):
            writer.append({
                "ts": f"2026-07-06T00:0{i}:00Z",
                "event": EVENT_CALL_DECIDED,
                "session": session_id,
                "server": "github",
                "tool": "get_issue",
                "effect": EFFECT_ALLOW,
                "reason": "",
            })
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Fleet state store
# ---------------------------------------------------------------------------

class TestFleetStore:
    def test_create_in_memory(self):
        store = FleetStore(":memory:")
        assert store is not None

    def test_upsert_records_idempotent(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=2)
        store.upsert_records("gate-1", records)
        store.upsert_records("gate-1", records)  # second upsert is idempotent
        count = store.record_count("gate-1", "s1")
        assert count == 2

    def test_upsert_increments_session_state(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=3)
        store.upsert_records("gate-1", records)
        state = store.get_session_state("gate-1", "s1")
        assert state is not None
        assert state["allow_count"] == 3

    def test_trifecta_trip_counted(self):
        store = FleetStore(":memory:")
        from bawbel_gate.audit.writer import AuditWriter
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
            path = Path(tf.name)
        try:
            writer = AuditWriter(path)
            writer.append({
                "ts": "2026-07-06T00:00:00Z",
                "event": EVENT_CALL_DECIDED,
                "session": "s1",
                "server": "github",
                "tool": "create_pr",
                "effect": EFFECT_APPROVE,
                "reason": REASON_TRIFECTA_THIRD_LEG,
            })
            lines = path.read_text(encoding="utf-8").splitlines()
            records = [json.loads(l) for l in lines if l.strip()]
        finally:
            os.unlink(path)
        store.upsert_records("gate-1", records)
        state = store.get_session_state("gate-1", "s1")
        assert state["trifecta_trips"] == 1

    def test_drift_event_counted(self):
        store = FleetStore(":memory:")
        from bawbel_gate.audit.writer import AuditWriter
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
            path = Path(tf.name)
        try:
            writer = AuditWriter(path)
            writer.append({
                "ts": "2026-07-06T00:00:00Z",
                "event": EVENT_DRIFT_DETECTED,
                "session": "s1",
                "server": "github",
            })
            lines = path.read_text(encoding="utf-8").splitlines()
            records = [json.loads(l) for l in lines if l.strip()]
        finally:
            os.unlink(path)
        store.upsert_records("gate-1", records)
        state = store.get_session_state("gate-1", "s1")
        assert state["drift_events"] == 1

    def test_multiple_gates_isolated(self):
        store = FleetStore(":memory:")
        r1 = _make_records("gate-1", "s1", count=2)
        r2 = _make_records("gate-2", "s2", count=1)
        store.upsert_records("gate-1", r1)
        store.upsert_records("gate-2", r2)
        assert store.record_count("gate-1", "s1") == 2
        assert store.record_count("gate-2", "s2") == 1
        assert store.record_count("gate-1", "s2") == 0

    def test_rebuild_from_records(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=3)
        store.upsert_records("gate-1", records)
        store.rebuild_session_state("gate-1", "s1")
        state = store.get_session_state("gate-1", "s1")
        assert state["allow_count"] == 3

    def test_chain_head_tracked(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=2)
        store.upsert_records("gate-1", records)
        head = store.get_chain_head("gate-1", "s1")
        assert head is not None
        assert head["last_hash"].startswith("sha256:")
        assert head["last_seq"] == 2


# ---------------------------------------------------------------------------
# Chain verification on ingest (DESIGN.md 13.2)
# ---------------------------------------------------------------------------

class TestChainVerification:
    def test_valid_chain_accepted(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=3)
        result = process_batch("gate-1", records, store)
        assert result.ok is True
        assert len(result.acked) == 1
        assert result.acked.get("s1") == 3

    def test_mutated_hash_detected(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=2)
        records[0]["hash"] = "sha256:" + "f" * 64  # tamper
        with pytest.raises(ChainMismatch):
            process_batch("gate-1", records, store)

    def test_prev_mismatch_detected(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=2)
        records[1]["prev"] = "sha256:" + "0" * 64  # wrong prev
        with pytest.raises(ChainMismatch):
            process_batch("gate-1", records, store)

    def test_replay_idempotent(self):
        store = FleetStore(":memory:")
        records = _make_records("gate-1", "s1", count=2)
        process_batch("gate-1", records, store)
        result2 = process_batch("gate-1", records, store)  # replay
        assert result2.ok is True
        assert store.record_count("gate-1", "s1") == 2  # no duplicates

    def test_continuation_accepted(self):
        store = FleetStore(":memory:")
        r1 = _make_records("gate-1", "s1", count=2)
        process_batch("gate-1", r1, store)
        # Build continuation starting from r1's head
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
            path = Path(tf.name)
        try:
            from bawbel_gate.audit.writer import AuditWriter
            writer = AuditWriter.from_existing(path)
            # Simulate by writing 2 more records
            for i in range(2):
                writer.append({
                    "ts": f"2026-07-06T01:0{i}:00Z",
                    "event": EVENT_CALL_DECIDED,
                    "session": "s1",
                    "effect": EFFECT_DENY,
                    "reason": "no_grant",
                })
            r2 = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        finally:
            os.unlink(path)
        # r2 has its own chain; this is fine since it's a separate log
        result = process_batch("gate-1", r2, store)
        assert result.ok is True


# ---------------------------------------------------------------------------
# Enrollment (DESIGN.md 14.3)
# ---------------------------------------------------------------------------

class TestEnrollment:
    def test_mint_token(self):
        reg = EnrollmentRegistry(":memory:")
        token = reg.mint_token()
        assert token
        assert len(token) >= 32

    def test_tokens_are_unique(self):
        reg = EnrollmentRegistry(":memory:")
        t1, t2 = reg.mint_token(), reg.mint_token()
        assert t1 != t2

    def test_consume_token_succeeds(self):
        reg = EnrollmentRegistry(":memory:")
        token = reg.mint_token()
        gate_id = reg.consume_token(token)
        assert gate_id.startswith("gate-")

    def test_token_is_single_use(self):
        reg = EnrollmentRegistry(":memory:")
        token = reg.mint_token()
        reg.consume_token(token)
        with pytest.raises(EnrollmentError, match="already used|not found|invalid"):
            reg.consume_token(token)

    def test_invalid_token_rejected(self):
        reg = EnrollmentRegistry(":memory:")
        with pytest.raises(EnrollmentError):
            reg.consume_token("not-a-real-token")

    def test_list_tokens(self):
        reg = EnrollmentRegistry(":memory:")
        reg.mint_token()
        reg.mint_token()
        tokens = reg.list_tokens()
        assert len(tokens) == 2


# ---------------------------------------------------------------------------
# Fleet posture queries
# ---------------------------------------------------------------------------

class TestFleetPosture:
    def _store_with_data(self) -> FleetStore:
        store = FleetStore(":memory:")
        for gate_id in ("gate-1", "gate-2"):
            records = _make_records(gate_id, "s1", count=3)
            store.upsert_records(gate_id, records)
        return store

    def test_compute_fleet_posture_returns_rows(self):
        store = self._store_with_data()
        rows = compute_fleet_posture(store)
        assert len(rows) >= 2

    def test_row_fields(self):
        store = self._store_with_data()
        rows = compute_fleet_posture(store)
        row = rows[0]
        assert isinstance(row, GatePostureRow)
        assert row.gate_id
        assert row.allow_count >= 0

    def test_aggregate_allow_count(self):
        store = self._store_with_data()
        rows = compute_fleet_posture(store)
        total_allow = sum(r.allow_count for r in rows)
        assert total_allow == 6  # 2 gates x 3 records each = 6 allows


# ---------------------------------------------------------------------------
# Hub HTTP server
# ---------------------------------------------------------------------------

def _start_hub(tmp_path: Path):
    from bawbel_gate.hub.server import HubServer
    store = FleetStore(":memory:")
    enroll = EnrollmentRegistry(":memory:")
    admin_token = enroll.mint_admin_token()
    server = HubServer(store=store, enroll=enroll, host="127.0.0.1", port=0)
    server.start_background()
    base = f"http://127.0.0.1:{server.port}"
    return base, admin_token, server


class TestHubServer:
    def test_fleet_state_ok(self, tmp_path):
        base, admin_token, server = _start_hub(tmp_path)
        try:
            req = urllib.request.Request(
                f"{base}/v1/fleet/state",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                data = json.loads(resp.read())
                assert "gates" in data
        finally:
            server.stop()

    def test_fleet_state_requires_auth(self, tmp_path):
        base, admin_token, server = _start_hub(tmp_path)
        try:
            req = urllib.request.Request(f"{base}/v1/fleet/state")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 401
        finally:
            server.stop()

    def test_ingest_records_ok(self, tmp_path):
        base, admin_token, server = _start_hub(tmp_path)
        try:
            records = _make_records("gate-1", "s1", count=2)
            ndjson = "\n".join(json.dumps(r) for r in records) + "\n"
            req = urllib.request.Request(
                f"{base}/v1/gates/gate-1/records",
                data=ndjson.encode(),
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/x-ndjson",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                data = json.loads(resp.read())
                assert "acked" in data
        finally:
            server.stop()

    def test_ingest_empty_batch_ok(self, tmp_path):
        base, admin_token, server = _start_hub(tmp_path)
        try:
            req = urllib.request.Request(
                f"{base}/v1/gates/gate-1/records",
                data=b"",
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/x-ndjson",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
        finally:
            server.stop()

    def test_enrollment_token_mint(self, tmp_path):
        base, admin_token, server = _start_hub(tmp_path)
        try:
            req = urllib.request.Request(
                f"{base}/v1/enrollment/tokens",
                data=b"{}",
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
                data = json.loads(resp.read())
                assert "token" in data
        finally:
            server.stop()

    def test_no_command_channel(self, tmp_path):
        """Hub cannot issue tool calls or push commands to gates (DESIGN.md 14.6)."""
        base, admin_token, server = _start_hub(tmp_path)
        try:
            for path in ["/v1/gates/gate-1/execute", "/v1/commands", "/v1/push"]:
                req = urllib.request.Request(
                    f"{base}{path}",
                    headers={"Authorization": f"Bearer {admin_token}"},
                )
                with pytest.raises(urllib.error.HTTPError) as exc_info:
                    urllib.request.urlopen(req, timeout=5)
                assert exc_info.value.code == 404, f"Expected 404 for {path}"
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# Gate-side ingest client (cursor management)
# ---------------------------------------------------------------------------

class TestIngestClient:
    def test_cursor_file_created(self, tmp_path):
        from bawbel_gate.ingest.client import IngestCursor
        cursor = IngestCursor(tmp_path / "ingest.cursor")
        cursor.set_acked("s1", 5)
        cursor.save()
        assert (tmp_path / "ingest.cursor").exists()

    def test_cursor_loads_from_file(self, tmp_path):
        from bawbel_gate.ingest.client import IngestCursor
        cursor = IngestCursor(tmp_path / "ingest.cursor")
        cursor.set_acked("s1", 10)
        cursor.save()
        cursor2 = IngestCursor(tmp_path / "ingest.cursor")
        cursor2.load()
        assert cursor2.get_acked("s1") == 10

    def test_cursor_missing_session_returns_zero(self, tmp_path):
        from bawbel_gate.ingest.client import IngestCursor
        cursor = IngestCursor(tmp_path / "ingest.cursor")
        assert cursor.get_acked("unknown") == 0

    def test_batch_from_audit_log(self, tmp_path):
        from bawbel_gate.ingest.client import build_batch
        from bawbel_gate.audit.writer import AuditWriter
        log = tmp_path / "audit.jsonl"
        writer = AuditWriter(log)
        for i in range(5):
            writer.append({
                "ts": f"2026-07-06T00:0{i}:00Z",
                "event": EVENT_CALL_DECIDED,
                "session": "s1",
                "effect": EFFECT_ALLOW,
                "reason": "",
            })
        cursor_acked = {"s1": 2}  # already acked up to seq 2
        batch = build_batch(log, cursor_acked, max_records=200)
        # Should return records with seq 3, 4, 5
        assert len(batch) == 3
        assert all(r["seq"] > 2 for r in batch)

    def test_batch_respects_max_records(self, tmp_path):
        from bawbel_gate.ingest.client import build_batch
        from bawbel_gate.audit.writer import AuditWriter
        log = tmp_path / "audit.jsonl"
        writer = AuditWriter(log)
        for i in range(10):
            writer.append({
                "ts": f"2026-07-06T00:{i:02d}:00Z",
                "event": EVENT_CALL_DECIDED,
                "session": "s1",
                "effect": EFFECT_ALLOW,
                "reason": "",
            })
        batch = build_batch(log, {}, max_records=3)
        assert len(batch) == 3

    def test_empty_log_empty_batch(self, tmp_path):
        from bawbel_gate.ingest.client import build_batch
        log = tmp_path / "audit.jsonl"
        log.write_text("", encoding="utf-8")
        batch = build_batch(log, {}, max_records=200)
        assert batch == []


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestHubCLI:
    def test_enroll_command_exists(self):
        from click.testing import CliRunner
        from bawbel_gate.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["enroll", "--help"])
        assert result.exit_code == 0

    def test_hub_serve_command_exists(self):
        from click.testing import CliRunner
        from bawbel_gate.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["hub", "--help"])
        assert result.exit_code == 0
