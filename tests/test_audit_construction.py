"""Pins the audit chain construction. See DESIGN.md 8.6, docs/adr/0001.

Golden values, not a second implementation: a change to audit/canonical.py or
audit/writer.py that alters one hashed byte fails here. Changing the construction
takes a new ADR and an audit-format version, not a new golden value.
"""

from __future__ import annotations

import hashlib
import json

from bawbel_gate._const import AUDIT_CHAIN_GENESIS
from bawbel_gate.audit.canonical import canonical_bytes
from bawbel_gate.audit.writer import AuditWriter, verify_chain

GENESIS = "sha256:" + "0" * 64
FIRST_EVENT = {"ts": "2026-01-01T00:00:00.000Z", "session": "s1", "event": "SESSION_START"}
SECOND_EVENT = {"ts": "2026-01-01T00:00:01.000Z", "session": "s1", "event": "SESSION_END"}

# canonical(record minus hash) for the first record. prev stays inside the hashed content.
FIRST_CANONICAL = (
    b'{"event":"SESSION_START",'
    b'"prev":"sha256:0000000000000000000000000000000000000000000000000000000000000000",'
    b'"seq":1,"session":"s1","ts":"2026-01-01T00:00:00.000Z"}'
)
FIRST_HASH = "sha256:8c8f68d01ee2c813b6be624856c2d13517581358052cf5d0d3cd5ef81a606ad6"
SECOND_HASH = "sha256:abe9429014222c57ef26762dc5c5ecc576ae6d5d39ebee7c7fc7e2cbfd265ceb"


def _write_two_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.append(dict(FIRST_EVENT))
    writer.append(dict(SECOND_EVENT))
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return path, records


class TestChainConstruction:
    def test_first_prev_is_the_prefixed_zero_digest(self):
        assert AUDIT_CHAIN_GENESIS == GENESIS

    def test_hashed_content_keeps_prev(self, tmp_path):
        _, records = _write_two_records(tmp_path)
        first = records[0]
        assert first["prev"] == GENESIS
        without_hash = {k: v for k, v in first.items() if k != "hash"}
        assert canonical_bytes(without_hash) == FIRST_CANONICAL

    def test_prev_is_concatenated_as_its_utf8_text(self, tmp_path):
        _, records = _write_two_records(tmp_path)
        # 71 bytes of "sha256:<hex>", not the raw 32-byte digest.
        concatenated = GENESIS.encode("utf-8")
        assert len(concatenated) == 71
        expected = "sha256:" + hashlib.sha256(FIRST_CANONICAL + concatenated).hexdigest()
        assert records[0]["hash"] == expected == FIRST_HASH

    def test_second_record_chains_to_the_first(self, tmp_path):
        path, records = _write_two_records(tmp_path)
        assert records[1]["prev"] == FIRST_HASH
        assert records[1]["hash"] == SECOND_HASH
        result = verify_chain(path)
        assert result.ok, result.error
        assert result.records == 2

    def test_hash_is_prefixed_lowercase_hex(self, tmp_path):
        _, records = _write_two_records(tmp_path)
        for record in records:
            prefix, _, digest = record["hash"].partition(":")
            assert prefix == "sha256"
            assert len(digest) == 64
            assert digest == digest.lower()
            int(digest, 16)


class TestCanonicalFormIsNotJcs:
    """Deliberate differences from RFC 8785 (docs/adr/0001).

    Each assertion fails if canonical.py moves toward JCS without a new ADR.
    """

    def test_keys_sorted_compact_and_utf8(self):
        expected = '{"a":[2,3],"b":1,"é":"ü"}'.encode("utf-8")
        assert canonical_bytes({"b": 1, "a": [2, 3], "é": "ü"}) == expected

    def test_non_integer_numbers_use_python_json_form(self):
        assert canonical_bytes(1.0) == b"1.0"  # JCS: 1
        assert canonical_bytes(1e-7) == b"1e-07"  # JCS: 1e-7

    def test_integers_above_2_to_the_53_stay_exact(self):
        assert canonical_bytes(2**53 + 1) == b"9007199254740993"  # JCS: 9007199254740992

    def test_keys_sort_by_code_point_not_utf16_unit(self):
        # U+FB01 sorts before U+1F600 by code point. JCS compares UTF-16 units, and
        # U+1F600 encodes as D83D DE00, so JCS puts it first.
        expected = '{"ﬁ":2,"\U0001f600":1}'.encode("utf-8")
        assert canonical_bytes({"\U0001f600": 1, "ﬁ": 2}) == expected
