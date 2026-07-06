"""Fleet state store backed by SQLite (sqlite3 from stdlib).

See DESIGN.md 14.4 -- state is a pure replay of verified chains.
Idempotent upsert by (gate_id, session_id, seq): replays are harmless.
Rebuildable from raw records at any time via rebuild_session_state().
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from bawbel_gate._const import (
    EFFECT_ALLOW,
    EFFECT_APPROVE,
    EFFECT_DENY,
    EVENT_CALL_DECIDED,
    EVENT_DRIFT_DETECTED,
    REASON_TRIFECTA_THIRD_LEG,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS gates (
    gate_id      TEXT PRIMARY KEY,
    enrolled_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_records (
    gate_id      TEXT    NOT NULL,
    session_id   TEXT    NOT NULL,
    seq          INTEGER NOT NULL,
    event        TEXT,
    effect       TEXT,
    reason       TEXT,
    server       TEXT,
    tool         TEXT,
    hash         TEXT,
    prev         TEXT,
    record_json  TEXT    NOT NULL,
    PRIMARY KEY (gate_id, session_id, seq)
);

CREATE TABLE IF NOT EXISTS chain_heads (
    gate_id    TEXT    NOT NULL,
    session_id TEXT    NOT NULL,
    last_hash  TEXT    NOT NULL,
    last_seq   INTEGER NOT NULL,
    PRIMARY KEY (gate_id, session_id)
);

CREATE TABLE IF NOT EXISTS session_state (
    gate_id       TEXT    NOT NULL,
    session_id    TEXT    NOT NULL,
    allow_count   INTEGER DEFAULT 0,
    approve_count INTEGER DEFAULT 0,
    deny_count    INTEGER DEFAULT 0,
    trifecta_trips INTEGER DEFAULT 0,
    drift_events  INTEGER DEFAULT 0,
    PRIMARY KEY (gate_id, session_id)
);

CREATE TABLE IF NOT EXISTS quarantine (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    gate_id      TEXT,
    session_id   TEXT,
    reason       TEXT,
    record_json  TEXT,
    quarantined_at TEXT
);
"""


class StoreError(RuntimeError):
    """Raised on unrecoverable store operations."""


class FleetStore:
    """Thread-safe SQLite-backed fleet state store."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # --- Records ---

    def upsert_records(self, gate_id: str, records: list[dict[str, Any]]) -> None:
        """Insert records, ignoring duplicates (idempotent by (gate_id, session_id, seq))."""
        with self._lock:
            for record in records:
                session_id = record.get("session", "default")
                seq = record.get("seq", 0)
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO audit_records
                        (gate_id, session_id, seq, event, effect, reason,
                         server, tool, hash, prev, record_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        gate_id,
                        session_id,
                        seq,
                        record.get("event"),
                        record.get("effect"),
                        record.get("reason"),
                        record.get("server"),
                        record.get("tool"),
                        record.get("hash"),
                        record.get("prev"),
                        json.dumps(record),
                    ),
                )
                self._upsert_chain_head(gate_id, session_id, record, cursor=None)
                self._increment_session_state(gate_id, session_id, record)

            self._conn.execute(
                "INSERT OR IGNORE INTO gates (gate_id, enrolled_at) VALUES (?, datetime('now'))",
                (gate_id,),
            )
            self._conn.commit()

    def _upsert_chain_head(
        self, gate_id: str, session_id: str, record: dict, cursor: Any
    ) -> None:
        h = record.get("hash", "")
        seq = record.get("seq", 0)
        if not h:
            return
        self._conn.execute(
            """
            INSERT INTO chain_heads (gate_id, session_id, last_hash, last_seq)
            VALUES (?,?,?,?)
            ON CONFLICT(gate_id, session_id) DO UPDATE SET
                last_hash = excluded.last_hash,
                last_seq  = excluded.last_seq
            WHERE excluded.last_seq > chain_heads.last_seq
            """,
            (gate_id, session_id, h, seq),
        )

    def _increment_session_state(
        self, gate_id: str, session_id: str, record: dict
    ) -> None:
        event = record.get("event", "")
        effect = record.get("effect", "")
        reason = record.get("reason", "")

        self._conn.execute(
            "INSERT OR IGNORE INTO session_state (gate_id, session_id) VALUES (?,?)",
            (gate_id, session_id),
        )

        if event == EVENT_CALL_DECIDED:
            if effect == EFFECT_ALLOW:
                self._conn.execute(
                    "UPDATE session_state SET allow_count = allow_count + 1 "
                    "WHERE gate_id=? AND session_id=?",
                    (gate_id, session_id),
                )
            elif effect == EFFECT_APPROVE:
                self._conn.execute(
                    "UPDATE session_state SET approve_count = approve_count + 1 "
                    "WHERE gate_id=? AND session_id=?",
                    (gate_id, session_id),
                )
                if reason == REASON_TRIFECTA_THIRD_LEG:
                    self._conn.execute(
                        "UPDATE session_state SET trifecta_trips = trifecta_trips + 1 "
                        "WHERE gate_id=? AND session_id=?",
                        (gate_id, session_id),
                    )
            elif effect == EFFECT_DENY:
                self._conn.execute(
                    "UPDATE session_state SET deny_count = deny_count + 1 "
                    "WHERE gate_id=? AND session_id=?",
                    (gate_id, session_id),
                )
        elif event == EVENT_DRIFT_DETECTED:
            self._conn.execute(
                "UPDATE session_state SET drift_events = drift_events + 1 "
                "WHERE gate_id=? AND session_id=?",
                (gate_id, session_id),
            )

    # --- Queries ---

    def record_count(self, gate_id: str, session_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM audit_records WHERE gate_id=? AND session_id=?",
                (gate_id, session_id),
            ).fetchone()
        return row[0] if row else 0

    def get_session_state(self, gate_id: str, session_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM session_state WHERE gate_id=? AND session_id=?",
                (gate_id, session_id),
            ).fetchone()
        if not row:
            return None
        return dict(row)

    def get_chain_head(self, gate_id: str, session_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM chain_heads WHERE gate_id=? AND session_id=?",
                (gate_id, session_id),
            ).fetchone()
        return dict(row) if row else None

    def list_gates(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute("SELECT gate_id FROM gates").fetchall()
        return [r[0] for r in rows]

    def get_aggregate_state(self, gate_id: str) -> dict:
        """Sum session_state for a given gate_id."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT
                    SUM(allow_count)    as allow_count,
                    SUM(approve_count)  as approve_count,
                    SUM(deny_count)     as deny_count,
                    SUM(trifecta_trips) as trifecta_trips,
                    SUM(drift_events)   as drift_events,
                    COUNT(*)            as session_count
                FROM session_state WHERE gate_id=?
                """,
                (gate_id,),
            ).fetchone()
        if not row:
            return {}
        return {
            "allow_count":    row[0] or 0,
            "approve_count":  row[1] or 0,
            "deny_count":     row[2] or 0,
            "trifecta_trips": row[3] or 0,
            "drift_events":   row[4] or 0,
            "session_count":  row[5] or 0,
        }

    def rebuild_session_state(self, gate_id: str, session_id: str) -> None:
        """Rebuild session_state from raw records (for after DB repair or migration)."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT event, effect, reason FROM audit_records
                WHERE gate_id=? AND session_id=? ORDER BY seq
                """,
                (gate_id, session_id),
            ).fetchall()

            allow_count = approve_count = deny_count = 0
            trifecta_trips = drift_events = 0

            for row in rows:
                event, effect, reason = row
                if event == EVENT_CALL_DECIDED:
                    if effect == EFFECT_ALLOW:
                        allow_count += 1
                    elif effect == EFFECT_APPROVE:
                        approve_count += 1
                        if reason == REASON_TRIFECTA_THIRD_LEG:
                            trifecta_trips += 1
                    elif effect == EFFECT_DENY:
                        deny_count += 1
                elif event == EVENT_DRIFT_DETECTED:
                    drift_events += 1

            self._conn.execute(
                """
                INSERT INTO session_state
                    (gate_id, session_id, allow_count, approve_count, deny_count,
                     trifecta_trips, drift_events)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(gate_id, session_id) DO UPDATE SET
                    allow_count    = excluded.allow_count,
                    approve_count  = excluded.approve_count,
                    deny_count     = excluded.deny_count,
                    trifecta_trips = excluded.trifecta_trips,
                    drift_events   = excluded.drift_events
                """,
                (gate_id, session_id, allow_count, approve_count,
                 deny_count, trifecta_trips, drift_events),
            )
            self._conn.commit()

    def quarantine(
        self, gate_id: str, session_id: str, reason: str, record: dict
    ) -> None:
        import datetime
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO quarantine (gate_id, session_id, reason, record_json, quarantined_at)
                VALUES (?,?,?,?,?)
                """,
                (
                    gate_id, session_id, reason,
                    json.dumps(record),
                    datetime.datetime.now(datetime.timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
