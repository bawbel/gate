"""Hash-chained audit log writer and chain verifier.

Record format and chain invariant per DESIGN.md 8.6 and invariants I6, I7.
Each record: hash = sha256(canonical_bytes(record_without_hash) || prev_hash_bytes).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bawbel_gate._const import AUDIT_CHAIN_GENESIS, AUDIT_HASH_PREFIX
from bawbel_gate.audit.canonical import canonical_bytes


@dataclass
class ChainState:
    prev: str = AUDIT_CHAIN_GENESIS
    seq: int = 0


class AuditWriter:
    """Append-only, hash-chained JSONL audit log.

    Thread-safe: a single lock guards both the chain state and the file write,
    so concurrent decisions produce a consistent, non-interleaved chain.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._chain = ChainState()
        path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_existing(cls, path: Path) -> "AuditWriter":
        """Resume writing to an existing audit log, continuing the chain from its head."""
        writer = cls.__new__(cls)
        writer._path = path
        writer._lock = threading.Lock()
        writer._chain = _load_chain_head(path)
        return writer

    def append(self, event: dict[str, Any]) -> str:
        """Write one audit record, return its hash."""
        with self._lock:
            self._chain.seq += 1
            record: dict[str, Any] = {"seq": self._chain.seq, **event}
            record_without_hash = {k: v for k, v in record.items() if k != "hash"}
            record_without_hash["prev"] = self._chain.prev
            digest = _compute_hash(record_without_hash, self._chain.prev)
            record["prev"] = self._chain.prev
            record["hash"] = digest
            line = json.dumps(record, sort_keys=False, separators=(",", ":"), ensure_ascii=False)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._chain.prev = digest
            return digest

    @property
    def head(self) -> str:
        with self._lock:
            return self._chain.prev

    @property
    def seq(self) -> int:
        with self._lock:
            return self._chain.seq


def _load_chain_head(path: Path) -> ChainState:
    """Read the existing JSONL log and return its final chain state."""
    if not path.exists():
        return ChainState()
    prev = AUDIT_CHAIN_GENESIS
    seq = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            record = json.loads(line)
            h = record.get("hash", "")
            if h:
                prev = h
            seq = record.get("seq", seq)
    return ChainState(prev=prev, seq=seq)


def _compute_hash(record_without_hash: dict[str, Any], prev: str) -> str:
    """sha256(canonical(record_without_hash) || utf8(prev)) -> 'sha256:<hex>'."""
    payload = canonical_bytes(record_without_hash) + prev.encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"{AUDIT_HASH_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Chain verifier
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    ok: bool
    records: int
    error: str | None = None
    error_seq: int | None = None


def verify_chain(path: Path) -> VerifyResult:
    """Replay a JSONL audit file and verify hash linkage.

    Returns VerifyResult with ok=True if the chain is intact, or ok=False
    with details about the first broken link. Truncated final records are
    detected as a JSON parse error on the last line.
    """
    prev = AUDIT_CHAIN_GENESIS
    count = 0
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return VerifyResult(ok=False, records=count, error=f"line {i}: {exc}", error_seq=i)

        stored_hash = record.get("hash", "")
        stored_prev = record.get("prev", "")

        record_without_hash = {k: v for k, v in record.items() if k != "hash"}
        expected = _compute_hash(record_without_hash, prev)

        if stored_prev != prev:
            return VerifyResult(
                ok=False, records=count,
                error=(
                    f"seq {record.get('seq')}: prev mismatch"
                    f" (expected {prev!r}, got {stored_prev!r})"
                ),
                error_seq=record.get("seq"),
            )
        if stored_hash != expected:
            return VerifyResult(
                ok=False, records=count,
                error=f"seq {record.get('seq')}: hash mismatch",
                error_seq=record.get("seq"),
            )
        prev = stored_hash
        count += 1

    return VerifyResult(ok=True, records=count)
