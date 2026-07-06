"""Gate-side fleet ingest client. See DESIGN.md 13.2.

IngestCursor tracks the last acked seq per session_id, persisted to a JSON file
at ~/.bawbel/ingest.cursor. build_batch() reads the audit JSONL and returns only
records past the acked cursor (up to max_records).

Records are durable in the local JSONL before any send; the JSONL is the outbound
buffer. Replays are harmless because (gate_id, session_id, seq) is the dedup key.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class IngestCursor:
    """Persists the last-acked seq per session_id to a JSON cursor file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._data: dict[str, int] = {}

    def load(self) -> None:
        """Load cursor state from disk. No-op if file does not exist."""
        if not self._path.exists():
            return
        try:
            self._data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self._data = {}

    def save(self) -> None:
        """Persist cursor state to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data), encoding="utf-8")

    def get_acked(self, session_id: str) -> int:
        """Return the last acked seq for a session_id (0 if not seen)."""
        return self._data.get(session_id, 0)

    def set_acked(self, session_id: str, seq: int) -> None:
        """Update the acked seq for a session_id."""
        self._data[session_id] = seq


def build_batch(
    audit_log: Path,
    cursor_acked: dict[str, int],
    max_records: int = 200,
) -> list[dict[str, Any]]:
    """Return records from audit_log not yet acked (past cursor), up to max_records.

    cursor_acked maps session_id -> last acked seq (0 means nothing acked yet).
    """
    if not audit_log.exists():
        return []

    batch: list[dict[str, Any]] = []
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        if len(batch) >= max_records:
            break
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        session_id = record.get("session", "default")
        seq = record.get("seq", 0)
        last_acked = cursor_acked.get(session_id, 0)
        if seq > last_acked:
            batch.append(record)

    return batch
