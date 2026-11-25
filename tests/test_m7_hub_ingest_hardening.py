"""HUB-R12a: Hub ingest refuses what DESIGN.md 13.2 says it verifies.

Each test is one of the reproductions in docs/hub/THREAT-MODEL.md (cases H3, H4, H6),
turned into an assertion. They were committed failing, before the fix.

The rule these tests pin down (the one design choice in HUB-R12a): a record is accepted
only if it is one of

  (a) a replay: the Hub already holds that (gate, session, seq) with identical content;
  (b) the next record of a session the Hub holds: seq is the held head's seq plus one,
      prev is the held head's hash, and the hash recomputes;
  (c) the first record of a session: seq 1, prev is the genesis value, hash recomputes;
  (d) a restart: the first record of a session the Hub does not hold, written as
      SESSION_START, whose prev is the hash of a record the Hub holds for the same gate
      that no held record already follows, whose seq is that record's seq plus one, and
      whose hash recomputes.

Anything else is refused whole and nothing is stored: 409 for a chain, gap or rewrite
problem, 422 for a record that is not shaped like an audit record.
"""

from __future__ import annotations

import json
import signal
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from bawbel_gate._const import (
    AUDIT_CHAIN_GENESIS,
    EFFECT_ALLOW,
    EFFECT_DENY,
    EVENT_CALL_DECIDED,
    EVENT_SESSION_START,
)
from bawbel_gate.audit.writer import AuditWriter, _compute_hash
from bawbel_gate.hub.enroll import EnrollmentRegistry
from bawbel_gate.hub.ingest import ChainMismatch, process_batch
from bawbel_gate.hub.store import FleetStore

try:  # the schema error is new in HUB-R12a
    from bawbel_gate.hub.ingest import IngestSchemaError
except ImportError:  # pragma: no cover - before the fix, so the tests fail as "did not raise"
    class IngestSchemaError(Exception):  # type: ignore[no-redef]
        index = -1


@pytest.fixture(autouse=True)
def _no_hang():
    """A server that blocks on a stalled client also blocks `stop()`. Fail the test instead of
    hanging the run. SIGALRM does not exist on Windows, where the test simply has no guard."""
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _boom(signum, frame):
        raise TimeoutError("test took longer than 12 s")

    previous = signal.signal(signal.SIGALRM, _boom)
    signal.alarm(12)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


# ---------------------------------------------------------------------------
# Builders. Every chain is written by the gate's own writer, so it is a real one.
# ---------------------------------------------------------------------------

def _decided(session: str, effect: str = EFFECT_ALLOW, i: int = 0) -> dict:
    return {
        "ts": f"2026-11-25T00:00:{i:02d}.000Z",
        "session": session,
        "event": EVENT_CALL_DECIDED,
        "server": "github",
        "tool": "get_issue",
        "effect": effect,
        "reason": "resolved",
    }


def _started(session: str) -> dict:
    return {
        "ts": "2026-11-25T00:00:00.000Z",
        "session": session,
        "event": EVENT_SESSION_START,
        "manifest_hashes": {},
    }


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _chain(tmp_path: Path, session: str, count: int, effect: str = EFFECT_ALLOW,
           name: str = "log.jsonl") -> list[dict]:
    path = tmp_path / name
    writer = AuditWriter(path)
    for i in range(count):
        writer.append(_decided(session, effect, i))
    return _read(path)


def _two_runs(tmp_path: Path, first: int = 2, second: int = 2) -> tuple[list[dict], list[dict]]:
    """What `serve` writes when run twice on one audit_log: one chain, two sessions."""
    path = tmp_path / "two-runs.jsonl"
    w1 = AuditWriter(path)
    w1.append(_started("s1"))
    for i in range(first - 1):
        w1.append(_decided("s1", EFFECT_ALLOW, i))
    w2 = AuditWriter.from_existing(path)
    w2.append(_started("s2"))
    for i in range(second - 1):
        w2.append(_decided("s2", EFFECT_DENY, i))
    records = _read(path)
    return ([r for r in records if r["session"] == "s1"], [r for r in records if r["session"] == "s2"])


def _rehash(record: dict, prev: str) -> dict:
    """Give a record another prev and recompute its hash. The hash rule is public (DESIGN.md 8.6),
    so a rewritten chain can always be made consistent."""
    body = {k: v for k, v in record.items() if k != "hash"}
    body["prev"] = prev
    body["hash"] = _compute_hash(body, prev)
    return body


# ---------------------------------------------------------------------------
# Helpers for the HTTP cases
# ---------------------------------------------------------------------------

def _start_hub(**kwargs):
    from bawbel_gate.hub.server import HubServer

    store = FleetStore(":memory:")
    enroll = EnrollmentRegistry(":memory:")
    server = HubServer(store=store, enroll=enroll, host="127.0.0.1", port=0, **kwargs)
    server.start_background()
    return f"http://127.0.0.1:{server.port}", server.admin_token, server, store


def _post(base: str, token: str, gate: str, records: list[dict]) -> tuple[int, dict]:
    body = "".join(json.dumps(r) + "\n" for r in records).encode()
    req = urllib.request.Request(
        f"{base}/v1/gates/{gate}/records", data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/x-ndjson"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _get_state(base: str, token: str, timeout: float = 5.0) -> int:
    req = urllib.request.Request(f"{base}/v1/fleet/state", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def _raw(port: int, payload: bytes) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(payload)
    return sock


# ---------------------------------------------------------------------------
# H3. The chain check can be bypassed (C3.7 to C3.10)
# ---------------------------------------------------------------------------

class TestRecordsThatAreNotAuditRecords:
    def test_hash_without_prev_and_a_huge_seq_is_refused_and_moves_nothing(self):
        """C3.7 and C3.8: it returned 200 and set the stored head for the session to 1000000."""
        store = FleetStore(":memory:")
        bogus = {"seq": 1000000, "session": "s1", "event": EVENT_CALL_DECIDED,
                 "effect": EFFECT_DENY, "hash": "sha256:" + "ab" * 32}
        with pytest.raises(IngestSchemaError):
            process_batch("gate-a", [bogus], store)
        assert store.get_chain_head("gate-a", "s1") is None
        assert store.record_count("gate-a", "s1") == 0

    def test_after_the_bypass_attempt_a_wrong_record_is_still_refused(self, tmp_path):
        """C3.9 and C3.10: a record 4 with a wrong prev and a wrong hash was stored and counted."""
        store = FleetStore(":memory:")
        records = _chain(tmp_path, "s1", 3, EFFECT_DENY)
        process_batch("gate-a", records, store)
        bogus = {"seq": 1000000, "session": "s1", "event": EVENT_CALL_DECIDED, "hash": "sha256:" + "ab" * 32}
        with pytest.raises(IngestSchemaError):
            process_batch("gate-a", [bogus], store)
        forged = dict(_decided("s1", EFFECT_DENY, 3), seq=4, prev="sha256:" + "11" * 32, hash="sha256:" + "22" * 32)
        with pytest.raises(ChainMismatch):
            process_batch("gate-a", [forged], store)
        assert store.record_count("gate-a", "s1") == 3
        assert store.get_aggregate_state("gate-a")["deny_count"] == 3

    @pytest.mark.parametrize("change", [
        {"hash": None}, {"prev": None}, {"seq": None}, {"seq": "2"}, {"seq": 0}, {"seq": -1},
        {"seq": True}, {"seq": 1.5}, {"session": ["s1"]}, {"session": 7}, {"hash": 7}, {"prev": ""},
    ])
    def test_a_record_with_a_missing_or_mistyped_member_is_refused(self, tmp_path, change):
        """C6.6 and C6.8: a seq that is a string or null, a session that is a list. They raised
        AttributeError, TypeError or ValueError, and the connection closed with no answer."""
        store = FleetStore(":memory:")
        record = _chain(tmp_path, "s1", 1)[0]
        for key, value in change.items():
            if value is None:
                record.pop(key, None)
            else:
                record[key] = value
        with pytest.raises(IngestSchemaError) as exc:
            process_batch("gate-a", [record], store)
        assert exc.value.index == 0
        assert store.record_count("gate-a", "s1") == 0

    def test_a_json_value_that_is_not_an_object_is_refused(self):
        store = FleetStore(":memory:")
        with pytest.raises(IngestSchemaError):
            process_batch("gate-a", ["a string", 5, ["list"]], store)  # type: ignore[list-item]

    def test_one_bad_record_refuses_the_whole_batch(self, tmp_path):
        store = FleetStore(":memory:")
        records = _chain(tmp_path, "s1", 3)
        bad = dict(records[2])
        bad.pop("prev")
        with pytest.raises(IngestSchemaError) as exc:
            process_batch("gate-a", records[:2] + [bad], store)
        assert exc.value.index == 2
        assert store.record_count("gate-a", "s1") == 0

    def test_over_http_the_bypass_gets_422_and_the_chain_still_ingests(self, tmp_path):
        base, token, server, store = _start_hub()
        try:
            bogus = {"seq": 1000000, "session": "s1", "event": EVENT_CALL_DECIDED, "hash": "sha256:" + "ab" * 32}
            status, body = _post(base, token, "gate-a", [bogus])
            assert (status, body["error"], body["index"]) == (422, "schema", 0)
            status, body = _post(base, token, "gate-a", _chain(tmp_path, "s1", 3))
            assert (status, body) == (200, {"acked": {"s1": 3}})
        finally:
            server.stop()

    def test_over_http_a_mistyped_member_gets_an_answer_and_the_server_stays_up(self, tmp_path):
        base, token, server, store = _start_hub()
        try:
            record = _chain(tmp_path, "s1", 1)[0]
            record["seq"] = "2"
            status, body = _post(base, token, "gate-a", [record])
            assert (status, body["error"]) == (422, "schema")
            assert _get_state(base, token) == 200
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# H3. A rewrite of records the Hub already holds (C3.2)
# ---------------------------------------------------------------------------

class TestRewrite:
    def test_a_valid_rewrite_of_held_records_is_refused(self, tmp_path):
        """C3.2: records 5 and 6 replaced, with a valid chain from record 4, returned 200."""
        store = FleetStore(":memory:")
        original = _chain(tmp_path, "s1", 6)
        process_batch("gate-a", original, store)
        r5 = _rehash(_decided("s1", EFFECT_DENY, 4) | {"seq": 5}, original[3]["hash"])
        r6 = _rehash(_decided("s1", EFFECT_DENY, 5) | {"seq": 6}, r5["hash"])
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", [r5, r6], store)
        assert exc.value.reason == "rewrite"
        assert exc.value.session_id == "s1"
        held = store.get_chain_head("gate-a", "s1")
        assert (held["last_seq"], held["last_hash"]) == (6, original[5]["hash"])
        assert store.get_aggregate_state("gate-a")["deny_count"] == 0

    def test_a_rewrite_with_the_held_hash_but_other_content_is_refused(self, tmp_path):
        store = FleetStore(":memory:")
        original = _chain(tmp_path, "s1", 3)
        process_batch("gate-a", original, store)
        forged = dict(original[1], effect=EFFECT_DENY)  # hash member left as it was
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", [forged], store)
        assert exc.value.reason == "rewrite"

    def test_over_http_a_rewrite_gets_409_with_a_reason_and_nothing_changes(self, tmp_path):
        base, token, server, store = _start_hub()
        try:
            original = _chain(tmp_path, "s1", 4)
            assert _post(base, token, "gate-a", original)[0] == 200
            r4 = _rehash(_decided("s1", EFFECT_DENY, 3) | {"seq": 4}, original[2]["hash"])
            status, body = _post(base, token, "gate-a", [r4])
            assert status == 409
            assert (body["error"], body["reason"], body["session"]) == ("chain_mismatch", "rewrite", "s1")
            assert store.get_chain_head("gate-a", "s1")["last_hash"] == original[3]["hash"]
        finally:
            server.stop()

    def test_an_identical_replay_and_a_truncated_prefix_are_still_accepted(self, tmp_path):
        """C4.1 and C3.4. Re-sending records the Hub holds, unchanged, is what a cursor does after
        a crash (DESIGN.md 13.2). It is not a rewrite and must not change a counter."""
        store = FleetStore(":memory:")
        original = _chain(tmp_path, "s1", 6, EFFECT_DENY)
        process_batch("gate-a", original, store)
        again = process_batch("gate-a", original[:3], store)
        assert again.acked == {"s1": 3}
        assert store.record_count("gate-a", "s1") == 6
        assert store.get_aggregate_state("gate-a")["deny_count"] == 6

    def test_a_real_continuation_is_the_next_seq_with_the_held_head_as_prev(self, tmp_path):
        """tests/test_m7_hub.py::test_continuation_accepted shipped a second, separate chain under
        the same session id and the same seq numbers and asserted 200. That is C3.2, a rewrite."""
        store = FleetStore(":memory:")
        path = tmp_path / "log.jsonl"
        w = AuditWriter(path)
        for i in range(2):
            w.append(_decided("s1", EFFECT_ALLOW, i))
        process_batch("gate-a", _read(path), store)
        w2 = AuditWriter.from_existing(path)
        for i in range(2, 4):
            w2.append(_decided("s1", EFFECT_DENY, i))
        result = process_batch("gate-a", _read(path)[2:], store)
        assert result.acked == {"s1": 4}
        assert store.record_count("gate-a", "s1") == 4


# ---------------------------------------------------------------------------
# A gap in seq (docs/hub/ACCOUNTABILITY-LIMITS.md, experiment E2)
# ---------------------------------------------------------------------------

def _chain_with_seqs(seqs: list[int], session: str = "s1") -> list[dict]:
    """A chain whose prev and hash links are all correct and whose seq values are as given."""
    out, prev = [], AUDIT_CHAIN_GENESIS
    for i, seq in enumerate(seqs):
        record = {"seq": seq, **_decided(session, EFFECT_ALLOW, i), "prev": prev}
        record["hash"] = _compute_hash({k: v for k, v in record.items() if k != "hash"}, prev)
        prev = record["hash"]
        out.append(record)
    return out


class TestSeqGap:
    def test_a_gap_in_the_middle_of_a_batch_is_refused(self):
        store = FleetStore(":memory:")
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", _chain_with_seqs([1, 2, 5, 6]), store)
        assert (exc.value.reason, exc.value.expected_seq) == ("seq_gap", 3)
        assert store.record_count("gate-a", "s1") == 0

    def test_a_session_that_starts_high_is_refused(self):
        store = FleetStore(":memory:")
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", _chain_with_seqs([7, 8, 9]), store)
        assert (exc.value.reason, exc.value.expected_seq) == ("seq_gap", 1)

    def test_a_repeated_seq_is_refused(self):
        store = FleetStore(":memory:")
        with pytest.raises(ChainMismatch):
            process_batch("gate-a", _chain_with_seqs([1, 2, 2, 3]), store)
        assert store.record_count("gate-a", "s1") == 0

    def test_a_gap_after_held_records_is_refused_and_names_the_seq_to_resend_from(self, tmp_path):
        store = FleetStore(":memory:")
        records = _chain(tmp_path, "s1", 6)
        process_batch("gate-a", records[:3], store)
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", records[4:], store)
        assert (exc.value.reason, exc.value.expected_seq) == ("seq_gap", 4)
        assert exc.value.expected_prev == records[2]["hash"]
        assert store.record_count("gate-a", "s1") == 3

    def test_records_out_of_order_in_one_batch_are_refused(self, tmp_path):
        """C4.2: records 2, 1, 3 got 409."""
        store = FleetStore(":memory:")
        r = _chain(tmp_path, "s1", 3)
        with pytest.raises(ChainMismatch):
            process_batch("gate-a", [r[1], r[0], r[2]], store)

    def test_a_contiguous_chain_is_accepted(self):
        store = FleetStore(":memory:")
        assert process_batch("gate-a", _chain_with_seqs([1, 2, 3, 4]), store).acked == {"s1": 4}

    def test_over_http_a_gap_gets_409_with_the_seq_to_resend_from(self):
        base, token, server, store = _start_hub()
        try:
            status, body = _post(base, token, "gate-a", _chain_with_seqs([1, 2, 5, 6]))
            assert status == 409
            assert (body["error"], body["reason"], body["expected_seq"]) == ("chain_mismatch", "seq_gap", 3)
            assert store.record_count("gate-a", "s1") == 0
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# The one exception: a restart that the gate signals (SESSION_START)
# ---------------------------------------------------------------------------

class TestRestart:
    def test_a_file_that_holds_two_runs_is_accepted(self, tmp_path):
        """The shape of #159: `serve` run twice on one audit_log is one chain across two sessions,
        and the second session's seq continues. Its first record is the SESSION_START the gate
        wrote at the restart."""
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path, first=3, second=3)
        assert process_batch("gate-a", s1 + s2, store).acked == {"s1": 3, "s2": 6}
        assert store.record_count("gate-a", "s2") == 3
        assert store.get_aggregate_state("gate-a")["deny_count"] == 2

    def test_the_two_runs_can_arrive_in_two_batches(self, tmp_path):
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path)
        process_batch("gate-a", s1, store)
        assert process_batch("gate-a", s2, store).acked == {"s2": 4}

    def test_the_order_of_sessions_inside_one_batch_does_not_matter(self, tmp_path):
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path)
        assert process_batch("gate-a", s2 + s1, store).acked == {"s1": 2, "s2": 4}

    def test_a_restart_whose_predecessor_the_hub_does_not_hold_is_refused(self, tmp_path):
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path, first=3)
        process_batch("gate-a", s1[:2], store)  # the Hub lacks s1 seq 3
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", s2, store)
        assert exc.value.reason == "prev"
        assert store.get_chain_head("gate-a", "s2") is None

    def test_a_first_record_that_is_not_a_session_start_is_not_a_restart(self, tmp_path):
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path)
        process_batch("gate-a", s1, store)
        with pytest.raises(ChainMismatch):
            process_batch("gate-a", s2[1:], store)  # drops the SESSION_START

    def test_a_restart_with_the_wrong_seq_is_refused(self, tmp_path):
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path)
        process_batch("gate-a", s1, store)
        skipped = _rehash(dict(s2[0], seq=s2[0]["seq"] + 3), s1[-1]["hash"])
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", [skipped], store)
        assert exc.value.reason == "seq_gap"

    def test_a_second_restart_from_the_same_predecessor_is_a_fork_and_is_refused(self, tmp_path):
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path)
        process_batch("gate-a", s1 + s2, store)
        fork = _rehash(dict(s2[0], session="s3"), s1[-1]["hash"])
        with pytest.raises(ChainMismatch) as exc:
            process_batch("gate-a", [fork], store)
        assert exc.value.reason == "fork"
        assert store.get_chain_head("gate-a", "s3") is None

    def test_a_restart_may_not_borrow_another_gates_records(self, tmp_path):
        store = FleetStore(":memory:")
        s1, s2 = _two_runs(tmp_path)
        process_batch("gate-b", s1, store)
        with pytest.raises(ChainMismatch):
            process_batch("gate-a", s2, store)

    def test_a_new_chain_from_genesis_with_a_new_session_is_still_a_first_record(self, tmp_path):
        """A rotated log starts again at seq 1 with the genesis value (DESIGN.md 13.2, retention)."""
        store = FleetStore(":memory:")
        process_batch("gate-a", _chain(tmp_path, "s1", 3, name="old.jsonl"), store)
        assert process_batch("gate-a", _chain(tmp_path, "s9", 2, name="new.jsonl"), store).acked == {"s9": 2}


# ---------------------------------------------------------------------------
# H6. Size and stalls
# ---------------------------------------------------------------------------

class TestBodyCap:
    def test_a_body_over_the_cap_gets_413_and_is_not_read_or_stored(self, tmp_path):
        base, token, server, store = _start_hub(max_body_bytes=2048)
        try:
            records = _chain(tmp_path, "s1", 40)
            status, body = _post(base, token, "gate-a", records)
            assert status == 413
            assert body["error"] == "too_large"
            assert store.record_count("gate-a", "s1") == 0
            assert _get_state(base, token) == 200
        finally:
            server.stop()

    def test_a_body_at_or_under_the_cap_is_accepted(self, tmp_path):
        base, token, server, store = _start_hub(max_body_bytes=4096)
        try:
            records = _chain(tmp_path, "s1", 3)
            assert len("".join(json.dumps(r) + "\n" for r in records).encode()) < 4096
            assert _post(base, token, "gate-a", records)[0] == 200
        finally:
            server.stop()

    def test_the_cap_has_a_default_so_a_60_mib_body_is_refused(self, tmp_path):
        """C6.3: a 60 MiB body returned 200."""
        base, token, server, store = _start_hub()
        try:
            # The body is never sent: the answer must not wait for it.
            sock = _raw(server.port, (f"POST /v1/gates/gate-a/records HTTP/1.1\r\nHost: x\r\n"
                                      f"Authorization: Bearer {token}\r\n"
                                      f"Content-Length: {60 * 1024 * 1024}\r\n\r\n").encode())
            first = sock.recv(256).split(b"\r\n", 1)[0]
            sock.close()
            assert b" 413 " in first, first
        finally:
            server.stop()

    @pytest.mark.parametrize("length", ["abc", "-1", "1e3", " "])
    def test_a_content_length_that_is_not_a_number_gets_400(self, length):
        """C6.5: `abc` closed the connection with no answer, and -1 read to the end of the stream."""
        base, token, server, store = _start_hub()
        try:
            sock = _raw(server.port, (f"POST /v1/gates/gate-a/records HTTP/1.1\r\nHost: x\r\n"
                                      f"Authorization: Bearer {token}\r\nContent-Length: {length}\r\n\r\n").encode())
            first = sock.recv(256).split(b"\r\n", 1)[0]
            sock.close()
            assert b" 400 " in first, first
            assert _get_state(base, token) == 200
        finally:
            server.stop()

    def test_a_chunked_body_is_not_silently_read_as_empty(self):
        base, token, server, store = _start_hub()
        try:
            sock = _raw(server.port, (f"POST /v1/gates/gate-a/records HTTP/1.1\r\nHost: x\r\n"
                                      f"Authorization: Bearer {token}\r\nTransfer-Encoding: chunked\r\n\r\n"
                                      f"0\r\n\r\n").encode())
            first = sock.recv(256).split(b"\r\n", 1)[0]
            sock.close()
            assert b" 411 " in first or b" 501 " in first, first
        finally:
            server.stop()


class TestStalledClients:
    def test_a_client_that_never_finishes_its_headers_does_not_block_another(self):
        """C6.1, first line."""
        base, token, server, store = _start_hub(request_timeout_s=3.0)
        stalled = _raw(server.port, b"GET /v1/fleet/state HTTP/1.1\r\nHost: x\r\n")
        try:
            started = time.monotonic()
            assert _get_state(base, token, timeout=2.0) == 200
            assert time.monotonic() - started < 2.0
        finally:
            stalled.close()
            server.stop()

    def test_an_authenticated_post_that_promises_a_body_and_sends_none_does_not_block_another(self):
        """C6.1, second line: it promised 100 bytes and sent none."""
        base, token, server, store = _start_hub(request_timeout_s=3.0)
        stalled = _raw(server.port, (f"POST /v1/gates/gate-a/records HTTP/1.1\r\nHost: x\r\n"
                                     f"Authorization: Bearer {token}\r\nContent-Length: 100\r\n\r\n").encode())
        try:
            started = time.monotonic()
            assert _get_state(base, token, timeout=2.0) == 200
            assert time.monotonic() - started < 2.0
        finally:
            stalled.close()
            server.stop()

    def test_a_stalled_connection_is_closed_by_the_server_after_the_timeout(self):
        base, token, server, store = _start_hub(request_timeout_s=0.5)
        stalled = _raw(server.port, (f"POST /v1/gates/gate-a/records HTTP/1.1\r\nHost: x\r\n"
                                     f"Authorization: Bearer {token}\r\nContent-Length: 100\r\n\r\n").encode())
        try:
            stalled.settimeout(4.0)
            data = b""
            while True:
                chunk = stalled.recv(4096)  # a socket timeout here means the server never closed it
                if not chunk:
                    break
                data += chunk
            assert data == b"" or b" 408 " in data.split(b"\r\n", 1)[0]
        finally:
            stalled.close()
            server.stop()

    def test_a_body_that_trickles_in_is_cut_off_at_the_total_deadline(self):
        """One byte now and then keeps a per-read timeout alive for ever. The deadline is for the
        whole body."""
        base, token, server, store = _start_hub(request_timeout_s=1.0)
        sock = _raw(server.port, (f"POST /v1/gates/gate-a/records HTTP/1.1\r\nHost: x\r\n"
                                  f"Authorization: Bearer {token}\r\nContent-Length: 100\r\n\r\n").encode())
        try:
            started = time.monotonic()
            closed_at = None
            sock.settimeout(0.3)
            while time.monotonic() - started < 5.0:
                try:
                    sock.sendall(b" ")
                    data = sock.recv(256)
                    if data == b"" or b" 408 " in data:
                        closed_at = time.monotonic() - started
                        break
                except socket.timeout:
                    pass
                except (BrokenPipeError, ConnectionResetError):
                    closed_at = time.monotonic() - started
                    break
                time.sleep(0.2)
            assert closed_at is not None and closed_at < 4.0
        finally:
            sock.close()
            server.stop()

    def test_two_batches_at_the_same_time_cannot_both_extend_the_same_head(self, tmp_path):
        """With one thread per connection the verify-then-store step must be one step, or two
        batches can both be checked against the same head. The store makes both threads read the
        head before either writes, if the code lets them."""
        import threading

        class _RacyStore(FleetStore):
            armed = False

            def get_chain_head(self, gate_id, session_id):
                head = super().get_chain_head(gate_id, session_id)
                if self.armed:
                    try:
                        self.barrier.wait()
                    except threading.BrokenBarrierError:
                        pass
                return head

        store = _RacyStore(":memory:")
        store.barrier = threading.Barrier(2, timeout=0.5)
        base = _chain(tmp_path, "s1", 2)
        process_batch("gate-a", base, store)
        store.armed = True
        a = _rehash(_decided("s1", EFFECT_ALLOW, 2) | {"seq": 3}, base[1]["hash"])
        b = _rehash(_decided("s1", EFFECT_DENY, 2) | {"seq": 3}, base[1]["hash"])
        outcomes: list[str] = []

        def run(rec: dict) -> None:
            try:
                process_batch("gate-a", [rec], store)
                outcomes.append("ok")
            except ChainMismatch:
                outcomes.append("refused")

        threads = [threading.Thread(target=run, args=(r,)) for r in (a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(outcomes) == ["ok", "refused"]
        assert store.record_count("gate-a", "s1") == 3


class TestServerOptions:
    def test_each_server_keeps_its_own_store(self):
        """Handler settings were class attributes, so a second HubServer in one process replaced
        the first one's store."""
        base1, tok1, s1, store1 = _start_hub()
        base2, tok2, s2, store2 = _start_hub()
        try:
            records = _chain_with_seqs([1, 2])
            assert _post(base1, tok1, "gate-a", records)[0] == 200
            assert store1.record_count("gate-a", "s1") == 2
            assert store2.record_count("gate-a", "s1") == 0
        finally:
            s1.stop()
            s2.stop()

    def test_the_cli_exposes_the_two_limits_with_environment_bindings(self):
        from click.testing import CliRunner

        from bawbel_gate.cli import main

        out = CliRunner().invoke(main, ["hub", "serve", "--help"]).output
        assert "--max-body-bytes" in out and "BAWBEL_HUB_MAX_BODY_BYTES" in out
        assert "--request-timeout" in out and "BAWBEL_HUB_REQUEST_TIMEOUT_S" in out

    @pytest.mark.parametrize("flag,value", [("--max-body-bytes", "0"), ("--max-body-bytes", "-5"),
                                             ("--request-timeout", "0"), ("--request-timeout", "abc")])
    def test_a_bad_limit_is_refused_by_the_cli(self, flag, value):
        from click.testing import CliRunner

        from bawbel_gate.cli import main

        result = CliRunner().invoke(main, ["hub", "serve", "--db", ":memory:", "--port", "0", flag, value])
        assert result.exit_code == 2
        assert "Invalid value" in result.output  # not "No such option"
