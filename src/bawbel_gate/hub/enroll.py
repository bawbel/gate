"""Enrollment token registry. See DESIGN.md 14.3.

Tokens are single-use: consuming a token mints a gate_id and marks the token
used. A second consume attempt raises EnrollmentError.

Backed by SQLite (same db as FleetStore can use, or in-memory for tests).
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token      TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    used_at    TEXT,
    gate_id    TEXT
);

CREATE TABLE IF NOT EXISTS admin_tokens (
    token TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class EnrollmentError(ValueError):
    """Raised when enrollment fails (invalid token, already used, etc.)."""


class EnrollmentRegistry:
    """Thread-safe registry of single-use enrollment tokens."""

    TOKEN_LENGTH = 16  # 128-bit tokens

    def __init__(self, db_path: str) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def mint_admin_token(self) -> str:
        """Mint an admin bearer token (not single-use; survives restarts in DB)."""
        token = secrets.token_hex(self.TOKEN_LENGTH)
        with self._lock:
            self._conn.execute(
                "INSERT INTO admin_tokens (token) VALUES (?)", (token,)
            )
            self._conn.commit()
        return token

    def is_admin_token(self, token: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM admin_tokens WHERE token=?", (token,)
            ).fetchone()
        return row is not None

    def mint_token(self) -> str:
        """Mint a new single-use enrollment token."""
        token = secrets.token_hex(self.TOKEN_LENGTH)
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrollment_tokens (token) VALUES (?)", (token,)
            )
            self._conn.commit()
        return token

    def consume_token(self, token: str) -> str:
        """Consume a token and return the minted gate_id. Raises EnrollmentError if invalid."""
        with self._lock:
            row = self._conn.execute(
                "SELECT token, used_at FROM enrollment_tokens WHERE token=?",
                (token,),
            ).fetchone()
            if row is None:
                raise EnrollmentError(f"token not found: {token!r}")
            if row[1] is not None:
                raise EnrollmentError("token already used")

            gate_id = "gate-" + secrets.token_hex(6)
            self._conn.execute(
                "UPDATE enrollment_tokens SET used_at=datetime('now'), gate_id=? WHERE token=?",
                (gate_id, token),
            )
            self._conn.commit()
        return gate_id

    def list_tokens(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT token, created_at, used_at, gate_id FROM enrollment_tokens"
            ).fetchall()
        return [
            {"token": r[0], "created_at": r[1], "used_at": r[2], "gate_id": r[3]}
            for r in rows
        ]
