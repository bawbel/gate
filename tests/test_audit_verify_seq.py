"""GATE-32: `audit verify` checks that seq is 1, 2, 3 ... with no gap and no repeat.

See DESIGN.md 8.6 (the rule is stated in the companion draft). The chain's prev and hash links
say a record was not edited and not removed from the middle. They do not say that seq is
contiguous, and a chain with correct links and a skipped seq used to verify
(docs/hub/ACCOUNTABILITY-LIMITS.md, experiment E2). These tests were committed failing, before
the fix.

A restart is not an exception in one file. `serve` resumes the chain and the seq from the
audit_log on each run (`AuditWriter.from_existing`), so the second run's SESSION_START carries
the next seq. A file in which seq starts again at 1 is a different chain and its first record
carries the genesis prev, so it is a new file, not a restart.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from hypothesis import given
from hypothesis import strategies as st

from bawbel_gate._const import AUDIT_CHAIN_GENESIS, EVENT_CALL_DECIDED, EVENT_SESSION_START
from bawbel_gate.audit.writer import AuditWriter, _compute_hash, verify_chain
from bawbel_gate.cli import main


def _event(session: str, i: int) -> dict:
    return {
        "ts": f"2026-11-26T00:00:{i % 60:02d}.000Z",
        "session": session,
        "event": EVENT_CALL_DECIDED,
        "server": "github",
        "tool": "get_issue",
        "effect": "allow",
        "reason": "resolved",
    }


def _log_with_seqs(path: Path, seqs: list) -> Path:
    """A log whose prev and hash links are all correct and whose seq values are as given."""
    prev, lines = AUDIT_CHAIN_GENESIS, []
    for i, seq in enumerate(seqs):
        record = {"seq": seq, **_event("s1", i), "prev": prev}
        record["hash"] = _compute_hash({k: v for k, v in record.items() if k != "hash"}, prev)
        prev = record["hash"]
        lines.append(json.dumps(record))
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


class TestSeqIsChecked:
    def test_a_contiguous_log_verifies(self, tmp_path):
        result = verify_chain(_log_with_seqs(tmp_path / "a.jsonl", [1, 2, 3, 4]))
        assert result.ok and result.records == 4

    def test_a_gap_in_the_middle_fails_at_the_first_record_after_it(self, tmp_path):
        """E2: seq 1, 2, 5, 6 printed `ok: 4 records, chain intact`."""
        result = verify_chain(_log_with_seqs(tmp_path / "a.jsonl", [1, 2, 5, 6]))
        assert not result.ok
        assert result.records == 2
        assert result.error_seq == 5
        assert "expected seq 3" in (result.error or "")

    def test_a_log_that_starts_high_fails_at_its_first_record(self, tmp_path):
        """E2: seq 7, 8, 9 verified."""
        result = verify_chain(_log_with_seqs(tmp_path / "a.jsonl", [7, 8, 9]))
        assert not result.ok
        assert result.records == 0
        assert "expected seq 1" in (result.error or "")

    def test_a_repeated_seq_fails(self, tmp_path):
        """E2: seq 1, 2, 2, 3 verified with this tool and was refused by the Hub."""
        result = verify_chain(_log_with_seqs(tmp_path / "a.jsonl", [1, 2, 2, 3]))
        assert not result.ok
        assert result.records == 2
        assert "expected seq 3" in (result.error or "")

    @pytest.mark.parametrize("bad", [None, "2", 2.0, True, 0, -1])
    def test_a_seq_that_is_missing_or_not_a_positive_integer_fails(self, tmp_path, bad):
        path = _log_with_seqs(tmp_path / "a.jsonl", [1, 2, 3])
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[1])
        if bad is None:
            record.pop("seq")
        else:
            record["seq"] = bad
        # re-link, so that only seq is wrong and the chain links are valid
        prev = json.loads(lines[0])["hash"]
        record["prev"] = prev
        record.pop("hash", None)
        record["hash"] = _compute_hash(record, prev)
        third = json.loads(lines[2])
        third["prev"] = record["hash"]
        third.pop("hash")
        third["hash"] = _compute_hash(third, record["hash"])
        path.write_text(
            "\n".join([lines[0], json.dumps(record), json.dumps(third)]) + "\n", encoding="utf-8"
        )
        assert not verify_chain(path).ok

    def test_the_old_messages_for_a_broken_link_are_unchanged(self, tmp_path):
        path = _log_with_seqs(tmp_path / "a.jsonl", [1, 2, 3])
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[1]  # a removal from the middle: seq 1, 3 and a prev that no longer links
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = verify_chain(path)
        assert not result.ok
        assert "prev mismatch" in (result.error or "")

    def test_an_empty_file_still_verifies_as_zero_records(self, tmp_path):
        path = tmp_path / "a.jsonl"
        path.write_text("", encoding="utf-8")
        result = verify_chain(path)
        assert result.ok and result.records == 0


class TestARestartIsNotAGap:
    def test_a_file_written_by_two_serve_runs_verifies(self, tmp_path):
        """AuditWriter.from_existing resumes the chain and the seq, so the second run's
        SESSION_START has the next seq."""
        path = tmp_path / "two-runs.jsonl"
        first = AuditWriter(path)
        first.append({"ts": "t", "session": "s1", "event": EVENT_SESSION_START})
        first.append(_event("s1", 1))
        second = AuditWriter.from_existing(path)
        second.append({"ts": "t", "session": "s2", "event": EVENT_SESSION_START})
        second.append(_event("s2", 2))
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert [r["seq"] for r in records] == [1, 2, 3, 4]
        assert [r["session"] for r in records] == ["s1", "s1", "s2", "s2"]
        result = verify_chain(path)
        assert result.ok and result.records == 4

    def test_a_second_run_that_restarts_seq_at_one_in_the_same_file_fails(self, tmp_path):
        """What would happen if a writer did not resume the seq: the chain links are valid and
        seq starts again. There is no restart exception, because the writer never does this."""
        path = _log_with_seqs(tmp_path / "a.jsonl", [1, 2, 3, 1, 2])
        result = verify_chain(path)
        assert not result.ok
        assert result.error_seq == 1


class TestProperty:
    @given(seqs=st.lists(st.integers(min_value=-2, max_value=12), min_size=1, max_size=8))
    def test_a_log_verifies_exactly_when_seq_runs_one_to_n(self, tmp_path_factory, seqs):
        path = _log_with_seqs(tmp_path_factory.mktemp("p") / "a.jsonl", seqs)
        assert verify_chain(path).ok == (seqs == list(range(1, len(seqs) + 1)))


class TestCommand:
    def test_audit_verify_exits_1_and_names_the_record_on_a_gap(self, tmp_path):
        path = _log_with_seqs(tmp_path / "a.jsonl", [1, 2, 5, 6])
        result = CliRunner().invoke(main, ["audit", "verify", str(path)])
        assert result.exit_code == 1
        assert "FAIL" in result.output and "seq 5" in result.output
        assert "expected seq 3" in result.output

    def test_audit_verify_still_exits_0_on_a_contiguous_log(self, tmp_path):
        path = _log_with_seqs(tmp_path / "a.jsonl", [1, 2, 3])
        result = CliRunner().invoke(main, ["audit", "verify", str(path)])
        assert result.exit_code == 0
        assert "ok: 3 records, chain intact" in result.output
