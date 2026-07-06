"""SessionState: monotone session state per DESIGN.md 6.1.

tainted_by, private_touched, untrusted_seen only grow. The only reset is
SESSION_CLEAR (operator CLI, confirmed, audited). No method on this class
clears state.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from bawbel_gate._types import ProvenanceClass


@dataclass
class SessionState:
    """Mutable monotone session state. See DESIGN.md 6.1."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    manifest_hashes: dict[str, str] = field(default_factory=dict)
    tainted_by: set[ProvenanceClass] = field(default_factory=set)
    private_touched: bool = False
    untrusted_seen: bool = False
    suspended: set[str] = field(default_factory=set)  # server names
    seq: int = 0

    def add_taint(self, provenance_class: ProvenanceClass) -> None:
        """Monotonically add a provenance class to the taint set."""
        self.tainted_by.add(provenance_class)

    def mark_private_touched(self) -> None:
        self.private_touched = True

    def mark_untrusted_seen(self) -> None:
        self.untrusted_seen = True

    def suspend_server(self, server_name: str) -> None:
        self.suspended.add(server_name)

    def is_suspended(self, server_name: str) -> bool:
        return server_name in self.suspended

    def trifecta_third_leg(self, external_comms: bool) -> bool:
        """True if this call would be the third trifecta leg (DESIGN.md 5.2 step 6)."""
        return self.private_touched and self.untrusted_seen and external_comms

    def with_taint(self, extra: set[ProvenanceClass]) -> "SessionState":
        """Return a new SessionState with additional taint classes (for property tests)."""
        copy = SessionState(
            session_id=self.session_id,
            manifest_hashes=dict(self.manifest_hashes),
            tainted_by=set(self.tainted_by) | extra,
            private_touched=self.private_touched,
            untrusted_seen=self.untrusted_seen,
            suspended=set(self.suspended),
            seq=self.seq,
        )
        return copy

    def snapshot(self) -> dict:
        """Serialisable snapshot for audit records and console API."""
        return {
            "session_id": self.session_id,
            "tainted_by": sorted(self.tainted_by),
            "private_touched": self.private_touched,
            "untrusted_seen": self.untrusted_seen,
            "suspended": sorted(self.suspended),
            "seq": self.seq,
        }
