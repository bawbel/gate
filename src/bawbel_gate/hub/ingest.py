"""Fleet ingest protocol handler. See DESIGN.md 13.2.

Verifies hash chains per (gate_id, session_id) before accepting records.
A chain mismatch is not a sync error: it raises gate.chain.gap (critical).
Replays (same gate_id, session_id, seq) are idempotent and accepted silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bawbel_gate._const import AUDIT_CHAIN_GENESIS, ALERT_CHAIN_GAP
from bawbel_gate.audit.writer import _compute_hash


class ChainMismatch(ValueError):
    """Raised when a record's hash or prev does not match the known chain head."""

    def __init__(self, session_id: str, expected_prev: str, got_prev: str) -> None:
        self.session_id = session_id
        self.expected_prev = expected_prev
        self.got_prev = got_prev
        super().__init__(
            f"chain mismatch for session {session_id!r}: "
            f"expected prev={expected_prev!r}, got {got_prev!r}"
        )


@dataclass
class IngestResult:
    ok:     bool
    acked:  dict[str, int] = field(default_factory=dict)
    errors: list[str]      = field(default_factory=list)


def process_batch(
    gate_id: str,
    records: list[dict[str, Any]],
    store: Any,
) -> IngestResult:
    """Verify and store a batch of audit records.

    Raises ChainMismatch on tamper evidence (caller maps this to a 409 response
    and emits gate.chain.gap). Schema errors (missing hash/prev) are logged and
    skipped (caller maps to 422 for that record index).

    Returns IngestResult with per-session acked seq numbers.
    """
    if not records:
        return IngestResult(ok=True)

    # Group by session_id; verify chain continuity within each session
    by_session: dict[str, list[dict]] = {}
    for r in records:
        sid = r.get("session", "default")
        by_session.setdefault(sid, []).append(r)

    acked: dict[str, int] = {}
    errors: list[str] = []

    for session_id, session_records in by_session.items():
        # Get the known chain head for this (gate_id, session_id)
        head = store.get_chain_head(gate_id, session_id)
        known_prev = head["last_hash"] if head else AUDIT_CHAIN_GENESIS
        known_seq = head["last_seq"] if head else 0

        for record in session_records:
            seq = record.get("seq", 0)
            stored_hash = record.get("hash", "")
            stored_prev = record.get("prev", "")

            # Idempotent: already-stored records pass without re-verification
            if seq <= known_seq:
                continue

            if not stored_hash or not stored_prev:
                errors.append(f"session {session_id} seq {seq}: missing hash or prev")
                continue

            # Verify prev linkage
            if stored_prev != known_prev:
                raise ChainMismatch(session_id, known_prev, stored_prev)

            # Verify hash
            record_without_hash = {k: v for k, v in record.items() if k != "hash"}
            expected = _compute_hash(record_without_hash, known_prev)
            if stored_hash != expected:
                raise ChainMismatch(session_id, known_prev, stored_prev)

            known_prev = stored_hash
            known_seq = seq

        acked[session_id] = known_seq

    # Persist after all sessions verified successfully
    store.upsert_records(gate_id, records)
    return IngestResult(ok=True, acked=acked, errors=errors)
