"""Tests for audit canonical JSON, writer, and chain verifier (invariants I6, I7)."""

import json
from pathlib import Path

from bawbel_gate.audit.canonical import canonical_bytes, canonical_str
from bawbel_gate.audit.writer import AuditWriter, verify_chain
from bawbel_gate._const import AUDIT_CHAIN_GENESIS, AUDIT_HASH_PREFIX


class TestCanonical:
    def test_sorted_keys(self):
        obj = {"b": 1, "a": 2}
        result = canonical_str(obj)
        assert result.index('"a"') < result.index('"b"')

    def test_compact_no_whitespace(self):
        result = canonical_str({"k": "v"})
        assert " " not in result

    def test_byte_stable_across_calls(self):
        obj = {"z": [3, 1, 2], "a": {"nested": True}}
        assert canonical_bytes(obj) == canonical_bytes(obj)

    def test_arrays_order_preserved(self):
        obj = {"items": [3, 1, 2]}
        result = canonical_str(obj)
        assert "[3,1,2]" in result

    def test_utf8_encoding(self):
        obj = {"key": "こんにちは"}
        b = canonical_bytes(obj)
        assert isinstance(b, bytes)
        assert "こんにちは".encode("utf-8") in b

    def test_i6_no_sort_keys_elsewhere(self):
        """I6: ensure no other module calls json.dumps with sort_keys=True."""
        import subprocess
        result = subprocess.run(  # nosec B603 B607 # noqa: S603 S607
            ["grep", "-rn", "sort_keys=True", "src/"],
            capture_output=True, text=True
        )
        hits = [
            line for line in result.stdout.splitlines()
            if "canonical.py" not in line
        ]
        assert not hits, "sort_keys=True found outside canonical.py:\n" + "\n".join(hits)


class TestAuditWriter:
    def test_first_record_prev_is_genesis(self, tmp_path):
        writer = AuditWriter(tmp_path / "audit.jsonl")
        writer.append({"event": "TEST"})
        line = (tmp_path / "audit.jsonl").read_text().splitlines()[0]
        record = json.loads(line)
        assert record["prev"] == AUDIT_CHAIN_GENESIS

    def test_seq_increments(self, tmp_path):
        writer = AuditWriter(tmp_path / "audit.jsonl")
        writer.append({"event": "A"})
        writer.append({"event": "B"})
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert json.loads(lines[0])["seq"] == 1
        assert json.loads(lines[1])["seq"] == 2

    def test_prev_chaining(self, tmp_path):
        writer = AuditWriter(tmp_path / "audit.jsonl")
        h1 = writer.append({"event": "A"})
        writer.append({"event": "B"})
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert json.loads(lines[1])["prev"] == h1

    def test_hash_starts_with_prefix(self, tmp_path):
        writer = AuditWriter(tmp_path / "audit.jsonl")
        h = writer.append({"event": "X"})
        assert h.startswith(AUDIT_HASH_PREFIX)

    def test_head_matches_last_hash(self, tmp_path):
        writer = AuditWriter(tmp_path / "audit.jsonl")
        writer.append({"event": "A"})
        h = writer.append({"event": "B"})
        assert writer.head == h

    def test_file_appended_not_overwritten(self, tmp_path):
        p = tmp_path / "audit.jsonl"
        w1 = AuditWriter(p)
        w1.append({"event": "A"})
        w2 = AuditWriter(p)
        w2.append({"event": "B"})
        lines = p.read_text().splitlines()
        assert len(lines) == 2


class TestVerifyChain:
    def _write_chain(self, tmp_path, n: int) -> Path:
        p = tmp_path / "chain.jsonl"
        writer = AuditWriter(p)
        for i in range(n):
            writer.append({"event": f"E{i}", "data": i})
        return p

    def test_valid_chain_passes(self, tmp_path):
        p = self._write_chain(tmp_path, 5)
        result = verify_chain(p)
        assert result.ok
        assert result.records == 5

    def test_single_byte_mutation_detected(self, tmp_path):
        p = self._write_chain(tmp_path, 3)
        lines = p.read_text().splitlines()
        # Corrupt one character in the middle record's data
        corrupted = lines[1].replace('"E1"', '"X1"')
        p.write_text("\n".join([lines[0], corrupted, lines[2]]) + "\n", encoding="utf-8")
        result = verify_chain(p)
        assert not result.ok

    def test_truncated_last_record_detected(self, tmp_path):
        p = self._write_chain(tmp_path, 3)
        content = p.read_text()
        # Truncate the last line mid-record
        p.write_text(content[:-20], encoding="utf-8")
        result = verify_chain(p)
        assert not result.ok

    def test_empty_file_ok(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        result = verify_chain(p)
        assert result.ok
        assert result.records == 0

    def test_i7_prev_mismatch_detected(self, tmp_path):
        p = self._write_chain(tmp_path, 2)
        lines = p.read_text().splitlines()
        r1 = json.loads(lines[0])
        r2 = json.loads(lines[1])
        r2["prev"] = "sha256:" + "f" * 64
        p.write_text(lines[0] + "\n" + json.dumps(r2) + "\n", encoding="utf-8")
        result = verify_chain(p)
        assert not result.ok
        assert "prev mismatch" in (result.error or "")


class TestSessionState:
    def test_taint_is_monotone(self):
        from bawbel_gate.mux.session import SessionState
        s = SessionState()
        s.add_taint("tool.response.github")
        s.add_taint("web.fetched")
        assert "tool.response.github" in s.tainted_by
        assert "web.fetched" in s.tainted_by

    def test_with_taint_does_not_mutate_original(self):
        from bawbel_gate.mux.session import SessionState
        s = SessionState()
        s2 = s.with_taint({"tool.response.github"})
        assert "tool.response.github" not in s.tainted_by
        assert "tool.response.github" in s2.tainted_by

    def test_trifecta_third_leg_requires_all_three(self):
        from bawbel_gate.mux.session import SessionState
        s = SessionState()
        assert not s.trifecta_third_leg(external_comms=True)
        s.mark_private_touched()
        assert not s.trifecta_third_leg(external_comms=True)
        s.mark_untrusted_seen()
        assert s.trifecta_third_leg(external_comms=True)
        assert not s.trifecta_third_leg(external_comms=False)

    def test_snapshot_is_serialisable(self):
        from bawbel_gate.mux.session import SessionState
        s = SessionState()
        s.add_taint("tool.response.github")
        snap = s.snapshot()
        assert json.dumps(snap)  # must not raise


class TestNamespace:
    def test_round_trip(self):
        from bawbel_gate.mux.namespace import to_namespaced, from_namespaced
        ns = to_namespaced("github", "create_pull_request")
        server, tool = from_namespaced(ns)
        assert server == "github"
        assert tool == "create_pull_request"

    def test_invalid_raises(self):
        from bawbel_gate.mux.namespace import from_namespaced
        try:
            from_namespaced("no_separator_here")
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

    def test_is_namespaced(self):
        from bawbel_gate.mux.namespace import is_namespaced
        assert is_namespaced("github__tool")
        assert not is_namespaced("bare_tool")


class TestConfig:
    def test_load_valid_config(self, tmp_path):
        from bawbel_gate.mux.config import load_config
        manifest = tmp_path / "github-mcp.cap.yaml"
        manifest.write_text("schema: bawbel/capability-manifest/v1\n", encoding="utf-8")
        cfg_file = tmp_path / "gate.yaml"
        cfg_file.write_text(
            f"schema: bawbel/gate-config/v1\n"
            f"audit_log: /tmp/gate.jsonl\n"
            f"servers:\n"
            f"  - name: github\n"
            f"    command: github-mcp\n"
            f"    args: []\n"
            f"    manifest: {manifest}\n",
            encoding="utf-8",
        )
        cfg = load_config(cfg_file)
        assert len(cfg.servers) == 1
        assert cfg.servers[0].name == "github"

    def test_wrong_schema_raises(self, tmp_path):
        from bawbel_gate.mux.config import load_config, ConfigError
        cfg_file = tmp_path / "gate.yaml"
        cfg_file.write_text("schema: wrong/schema\nservers: []\naudit_log: x\n", encoding="utf-8")
        try:
            load_config(cfg_file)
            raise AssertionError("expected ConfigError")
        except ConfigError:
            pass

    def test_fail_open_timeout_rejected(self):
        from bawbel_gate.mux.config import ApprovalConfig, ConfigError
        try:
            ApprovalConfig(on_timeout="allow")
            raise AssertionError("expected ConfigError")
        except ConfigError:
            pass

    def test_duplicate_server_names_rejected(self, tmp_path):
        from bawbel_gate.mux.config import load_config, ConfigError
        m = tmp_path / "m.yaml"
        m.write_text("schema: bawbel/capability-manifest/v1\n", encoding="utf-8")
        cfg_file = tmp_path / "gate.yaml"
        cfg_file.write_text(
            f"schema: bawbel/gate-config/v1\naudit_log: x.jsonl\n"
            f"servers:\n"
            f"  - name: dup\n    command: cmd\n    args: []\n    manifest: {m}\n"
            f"  - name: dup\n    command: cmd\n    args: []\n    manifest: {m}\n",
            encoding="utf-8",
        )
        try:
            load_config(cfg_file)
            raise AssertionError("expected ConfigError")
        except ConfigError:
            pass


class TestLearnRecorder:
    def test_records_calls(self):
        from bawbel_gate.learn.recorder import LearnRecorder
        r = LearnRecorder()
        r.record_call("github", "get_issue", {"owner": "myorg", "repo": "myrepo", "number": 42})
        obs = r.all_observations()
        assert len(obs) == 1
        assert obs[0].call_count == 1
        assert obs[0].server == "github"
        assert obs[0].tool == "get_issue"

    def test_call_count_accumulates(self):
        from bawbel_gate.learn.recorder import LearnRecorder
        r = LearnRecorder()
        for _ in range(5):
            r.record_call("github", "get_issue", {"number": 1})
        assert r.all_observations()[0].call_count == 5

    def test_flush_writes_jsonl(self, tmp_path):
        from bawbel_gate.learn.recorder import LearnRecorder
        r = LearnRecorder()
        r.record_call("github", "get_issue", {"number": 1})
        p = tmp_path / "obs.jsonl"
        r.flush(p)
        lines = p.read_text().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["server"] == "github"
        assert rec["tool"] == "get_issue"


class TestLearnSynthesize:
    def test_generates_manifest_per_server(self, tmp_path):
        from bawbel_gate.learn.recorder import LearnRecorder
        from bawbel_gate.learn.synthesize import synthesize_manifests
        r = LearnRecorder()
        r.record_call("github", "get_issue", {"number": 1})
        r.record_call("github", "create_pull_request", {"title": "feat", "base": "main"})
        obs_path = tmp_path / "obs.jsonl"
        r.flush(obs_path)
        out_dir = tmp_path / "manifests"
        written = synthesize_manifests(obs_path, out_dir)
        assert len(written) == 1
        assert (out_dir / "github.cap.yaml").exists()

    def test_write_tools_get_approve(self, tmp_path):
        from bawbel_gate.learn.recorder import LearnRecorder
        from bawbel_gate.learn.synthesize import synthesize_manifests
        import yaml
        r = LearnRecorder()
        r.record_call("github", "create_pull_request", {"title": "x"})
        r.record_call("github", "get_issue", {"number": 1})
        obs_path = tmp_path / "obs.jsonl"
        r.flush(obs_path)
        written = synthesize_manifests(obs_path, tmp_path / "out")
        content = written[0].read_text()
        manifest = yaml.safe_load(content.split("\n\n", 1)[1])
        grants = {g["name"]: g["effect"] for g in manifest["grants"]["tools"]}
        assert grants["create_pull_request"] == "approve"
        assert grants["get_issue"] == "allow"
        assert grants["*"] == "deny"

    def test_wildcard_deny_always_present(self, tmp_path):
        from bawbel_gate.learn.recorder import LearnRecorder
        from bawbel_gate.learn.synthesize import synthesize_manifests
        import yaml
        r = LearnRecorder()
        r.record_call("fs", "read_file", {"path": "/work/README.md"})
        obs_path = tmp_path / "obs.jsonl"
        r.flush(obs_path)
        written = synthesize_manifests(obs_path, tmp_path / "out")
        content = written[0].read_text()
        manifest = yaml.safe_load(content.split("\n\n", 1)[1])
        tool_names = [g["name"] for g in manifest["grants"]["tools"]]
        assert "*" in tool_names
        wildcard_effect = next(g["effect"] for g in manifest["grants"]["tools"] if g["name"] == "*")
        assert wildcard_effect == "deny"
