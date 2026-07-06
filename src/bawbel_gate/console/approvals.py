"""Approval registry for the console approval channel.

See DESIGN.md 13.1 POST /v1/approvals/{id}.

Race semantics: first writer wins; the second writer gets False (-> 409).
Thread-safe via a per-ID lock + decided flag.
Approvals expire per their timeout; get() returns None for expired entries (-> 404).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum

import secrets


class ApprovalDecision(Enum):
    GRANT = "grant"
    DENY = "deny"


@dataclass
class PendingApproval:
    session:    str
    server:     str
    tool:       str
    cause:      str
    expires_at: str
    _expire_ts: float = field(repr=False)
    _decided:   bool = field(default=False, repr=False)
    _lock:      threading.Lock = field(default_factory=threading.Lock, repr=False)

    def is_expired(self) -> bool:
        return time.monotonic() > self._expire_ts

    def try_decide(self, decision: ApprovalDecision) -> bool:
        """Atomically mark as decided. Returns True if this caller won the race."""
        with self._lock:
            if self._decided or self.is_expired():
                return False
            self._decided = True
            self.decision = decision
            return True


class ApprovalRegistry:
    """Thread-safe registry of pending console approvals."""

    def __init__(self) -> None:
        self._approvals: dict[str, PendingApproval] = {}
        self._lock = threading.Lock()

    def register(
        self,
        session: str,
        server: str,
        tool: str,
        cause: str,
        expires_in_s: float = 120.0,
    ) -> str:
        """Register a new pending approval. Returns its ID."""
        ap_id = "ap_" + secrets.token_hex(8)
        import datetime
        expires_at = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=expires_in_s)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        ap = PendingApproval(
            session=session,
            server=server,
            tool=tool,
            cause=cause,
            expires_at=expires_at,
            _expire_ts=time.monotonic() + expires_in_s,
        )
        with self._lock:
            self._approvals[ap_id] = ap
        return ap_id

    def get(self, ap_id: str) -> PendingApproval | None:
        """Return the PendingApproval or None if unknown / expired."""
        with self._lock:
            ap = self._approvals.get(ap_id)
        if ap is None or ap.is_expired():
            return None
        return ap

    def decide(self, ap_id: str, decision: ApprovalDecision) -> bool | None:
        """Apply a decision. Returns True (won), False (lost race / 409), None (404)."""
        ap = self.get(ap_id)
        if ap is None:
            return None
        return ap.try_decide(decision)
