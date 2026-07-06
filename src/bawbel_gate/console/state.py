"""ConsoleState: in-memory projection of gate state for the console API.

See DESIGN.md 13.1 GET /v1/state.

ConsoleState is the shared data structure the HTTP server reads; it is never
mutated by the server. Session and manifest state are updated by the mux layer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bawbel_gate._const import AUDIT_CHAIN_GENESIS


@dataclass
class ConsoleState:
    sessions:      dict[str, Any]  # session_id -> SessionState
    manifests:     dict[str, Any]  # server name -> Manifest
    audit_log:     Path
    started_at:    str
    config_sha256: str
    approvals:     dict[str, Any] = field(default_factory=dict)  # approval_id -> PendingApproval


def _audit_summary(audit_log: Path) -> dict[str, Any]:
    """Return {head_hash, records} from the audit log without loading it all into memory."""
    if not audit_log.exists():
        return {"head_hash": AUDIT_CHAIN_GENESIS, "records": 0}

    count = 0
    head_hash = AUDIT_CHAIN_GENESIS
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            h = record.get("hash", "")
            if h:
                head_hash = h
            count += 1
        except json.JSONDecodeError:
            continue

    return {"head_hash": head_hash, "records": count}


def _serialize_session(session_id: str, session: Any) -> dict[str, Any]:
    """Serialize a SessionState to the console API shape."""
    return {
        "session_id":       session_id,
        "tainted_by":       sorted(session.tainted_by),
        "private_touched":  session.private_touched,
        "untrusted_seen":   session.untrusted_seen,
        "suspended_servers": sorted(session.suspended),
    }


def serialize_state(state: ConsoleState) -> dict[str, Any]:
    """Return the full state snapshot for GET /v1/state. Never mutates state."""
    sessions = [
        _serialize_session(sid, s)
        for sid, s in state.sessions.items()
    ]

    servers = []
    for name, manifest in state.manifests.items():
        servers.append({
            "name":            name,
            "manifest_sha256": getattr(manifest, "manifest_sha256", None),
            "trifecta":        getattr(manifest, "trifecta", {}),
        })

    pending_approvals = []
    for ap_id, ap in state.approvals.items():
        if not ap.is_expired():
            pending_approvals.append({
                "approval_id": ap_id,
                "session_id":  ap.session,
                "server":      ap.server,
                "tool":        ap.tool,
                "cause":       ap.cause,
                "expires_at":  ap.expires_at,
            })

    return {
        "gate": {
            "started_at":    state.started_at,
            "config_sha256": state.config_sha256,
        },
        "sessions":  sessions,
        "servers":   servers,
        "approvals": pending_approvals,
        "audit":     _audit_summary(state.audit_log),
    }
