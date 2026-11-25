"""Fleet ingest protocol handler. See DESIGN.md 13.2.

Verifies hash chains per (gate_id, session_id) before accepting records. A batch is
accepted whole or refused whole: nothing is stored from a batch that has one record the
Hub cannot place. A refusal is not a sync error: it is tamper evidence, and the caller
maps it to a 409 and emits gate.chain.gap (DESIGN.md 13.2).

A record is accepted only as one of these, checked in this order:

  replay    the Hub already holds this (gate_id, session, seq) and the record is identical
            to the held one. Nothing is stored and no counter moves.
  next      the session is held, seq is the held head's seq plus one, prev is the held
            head's hash, and the hash recomputes.
  first     the session is not held, seq is 1, prev is the genesis value, and the hash
            recomputes.
  restart   the session is not held, the record is a SESSION_START, its prev is the hash
            of a record the Hub holds for this gate that no held record already follows,
            its seq is that record's seq plus one, and the hash recomputes. The gate
            resumes the hash chain from the existing audit_log on each `serve` run
            (audit/writer.py, from_existing), so a restart continues the chain and the
            seq under a new session id.

Anything else is refused with a reason: `prev` (does not link), `hash` (does not
recompute), `seq_gap` (seq is not the next one), `rewrite` (a held seq with other content)
or `fork` (a restart from a record that is already followed). A record that is not shaped
like an audit record is refused with IngestSchemaError.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bawbel_gate._const import AUDIT_CHAIN_GENESIS, EVENT_SESSION_START
from bawbel_gate.audit.writer import _compute_hash

# Why a batch was refused with a 409. The 409 body keeps DESIGN.md 13.2's
# `error: chain_mismatch` and adds the reason.
REFUSED_PREV = "prev"
REFUSED_HASH = "hash"
REFUSED_SEQ_GAP = "seq_gap"
REFUSED_REWRITE = "rewrite"
REFUSED_FORK = "fork"

# Why a record was refused with a 422. Fixed strings: nothing from the record is echoed.
SCHEMA_NOT_OBJECT = "not_object"
SCHEMA_SESSION = "session"
SCHEMA_SEQ = "seq"
SCHEMA_HASH = "hash"
SCHEMA_PREV = "prev"

# seq is stored as a SQLite INTEGER, which is a signed 64-bit value.
_MAX_SEQ = 2**63 - 1


class ChainMismatch(ValueError):
    """Raised when a record does not fit the chain the Hub holds for its session.

    `expected_prev` and `expected_seq` say what the Hub would accept next for that
    session, so a gate can resend from there (DESIGN.md 13.2).
    """

    def __init__(
        self,
        session_id: str,
        expected_prev: str,
        got_prev: str,
        *,
        reason: str = REFUSED_PREV,
        expected_seq: int | None = None,
    ) -> None:
        self.session_id = session_id
        self.expected_prev = expected_prev
        self.got_prev = got_prev
        self.reason = reason
        self.expected_seq = expected_seq
        super().__init__(
            f"chain mismatch for session {session_id!r} ({reason}): "
            f"expected prev={expected_prev!r}, got {got_prev!r}"
        )


class IngestSchemaError(ValueError):
    """Raised when a record is not shaped like an audit record. `index` is its position in the batch."""

    def __init__(self, index: int, reason: str) -> None:
        self.index = index
        self.reason = reason
        super().__init__(f"record {index} is not an audit record ({reason})")


@dataclass
class IngestResult:
    ok:     bool
    acked:  dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def process_batch(
    gate_id: str,
    records: list[dict[str, Any]],
    store: Any,
) -> IngestResult:
    """Verify and store a batch of audit records, whole or not at all.

    Raises IngestSchemaError for a record that is not an audit record (the caller maps
    this to 422) and ChainMismatch for a record the Hub cannot place (409). Neither
    leaves anything stored.

    `acked` maps each session in the batch to the highest seq in this batch that was
    verified, either stored now or already held identically. It is not the Hub's head: a
    gate that resends an old prefix is told about that prefix only.
    """
    if not records:
        return IngestResult(ok=True)

    _check_shape(records)

    # Verify and store as one step, so two batches cannot both be checked against the same head.
    with store.ingest_lock:
        new_records, acked = _verify(gate_id, records, store)
        store.upsert_records(gate_id, new_records)
    return IngestResult(ok=True, acked=acked)


def _check_shape(records: list[Any]) -> None:
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise IngestSchemaError(index, SCHEMA_NOT_OBJECT)
        session = record.get("session", "default")
        if not isinstance(session, str) or not session:
            raise IngestSchemaError(index, SCHEMA_SESSION)
        seq = record.get("seq")
        if type(seq) is not int or not 1 <= seq <= _MAX_SEQ:
            raise IngestSchemaError(index, SCHEMA_SEQ)
        for member, reason in (("hash", SCHEMA_HASH), ("prev", SCHEMA_PREV)):
            value = record.get(member)
            if not isinstance(value, str) or not value:
                raise IngestSchemaError(index, reason)


class _Batch:
    """What one batch has accepted so far, laid over what the store holds."""

    def __init__(self, gate_id: str, store: Any) -> None:
        self._gate_id = gate_id
        self._store = store
        self._heads: dict[str, tuple[int, str] | None] = {}
        self._accepted: dict[tuple[str, int], dict[str, Any]] = {}
        self._by_hash: dict[str, tuple[str, int]] = {}
        self._followed: set[str] = set()
        self.new: list[dict[str, Any]] = []

    def head(self, session: str) -> tuple[int, str] | None:
        if session not in self._heads:
            held = self._store.get_chain_head(self._gate_id, session)
            self._heads[session] = (held["last_seq"], held["last_hash"]) if held else None
        return self._heads[session]

    def held(self, session: str, seq: int) -> dict[str, Any] | None:
        mine = self._accepted.get((session, seq))
        if mine is not None:
            return mine
        return self._store.get_record(self._gate_id, session, seq)

    def seq_of(self, record_hash: str) -> int | None:
        """The seq of a record this gate holds, or has had accepted in this batch, with this hash."""
        mine = self._by_hash.get(record_hash)
        if mine is not None:
            return mine[1]
        return self._store.find_seq_by_hash(self._gate_id, record_hash)

    def is_followed(self, record_hash: str) -> bool:
        return record_hash in self._followed or self._store.has_successor(self._gate_id, record_hash)

    def accept(self, session: str, record: dict[str, Any]) -> None:
        self._heads[session] = (record["seq"], record["hash"])
        self._accepted[(session, record["seq"])] = record
        self._by_hash[record["hash"]] = (session, record["seq"])
        self._followed.add(record["prev"])
        self.new.append(record)


def _verify(
    gate_id: str, records: list[dict[str, Any]], store: Any
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    by_session: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_session.setdefault(record.get("session", "default"), []).append(record)

    # A restart is explained by the records before it, so a session that starts earlier
    # in the seq order is checked first, whatever order the batch lists the sessions in.
    order = sorted(by_session, key=lambda sid: by_session[sid][0]["seq"])

    batch = _Batch(gate_id, store)
    acked: dict[str, int] = {}
    for session in order:
        for record in by_session[session]:
            _verify_one(session, record, batch)
            acked[session] = max(acked.get(session, 0), record["seq"])
    return batch.new, acked


def _verify_one(session: str, record: dict[str, Any], batch: _Batch) -> None:
    """Check one record against the chain and add it to the batch if it is new.

    An identical replay passes and adds nothing. Anything the Hub cannot place raises.
    """
    seq, prev, stored_hash = record["seq"], record["prev"], record["hash"]
    head = batch.head(session)

    if head is not None and seq <= head[0]:
        if batch.held(session, seq) == record:
            return
        raise ChainMismatch(session, head[1], prev, reason=REFUSED_REWRITE, expected_seq=head[0] + 1)

    if head is not None:
        expected_seq, expected_prev = head[0] + 1, head[1]
        if seq != expected_seq:
            raise ChainMismatch(session, expected_prev, prev, reason=REFUSED_SEQ_GAP, expected_seq=expected_seq)
        if prev != expected_prev:
            raise ChainMismatch(session, expected_prev, prev, reason=REFUSED_PREV, expected_seq=expected_seq)
    else:
        expected_prev = _first_record_prev(session, record, batch)

    body = {k: v for k, v in record.items() if k != "hash"}
    if stored_hash != _compute_hash(body, expected_prev):
        raise ChainMismatch(
            session, expected_prev, prev, reason=REFUSED_HASH, expected_seq=seq
        )

    batch.accept(session, record)


def _first_record_prev(session: str, record: dict[str, Any], batch: _Batch) -> str:
    """The prev a first record of a session must carry, or raise. See the module docstring."""
    seq, prev = record["seq"], record["prev"]

    if prev == AUDIT_CHAIN_GENESIS:
        if seq != 1:
            raise ChainMismatch(
                session, AUDIT_CHAIN_GENESIS, prev, reason=REFUSED_SEQ_GAP, expected_seq=1
            )
        return AUDIT_CHAIN_GENESIS

    if record.get("event") == EVENT_SESSION_START:
        predecessor_seq = batch.seq_of(prev)
        if predecessor_seq is not None:
            if seq != predecessor_seq + 1:
                raise ChainMismatch(
                    session, prev, prev, reason=REFUSED_SEQ_GAP, expected_seq=predecessor_seq + 1
                )
            if batch.is_followed(prev):
                raise ChainMismatch(
                    session, prev, prev, reason=REFUSED_FORK, expected_seq=predecessor_seq + 1
                )
            return prev

    raise ChainMismatch(session, AUDIT_CHAIN_GENESIS, prev, reason=REFUSED_PREV, expected_seq=1)
