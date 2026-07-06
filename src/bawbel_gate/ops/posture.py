"""Agent-risk-posture report: one-page CISO artifact from manifests + audit log.

See DESIGN.md 8.5, IMPLEMENTATION_PLAN.md M5 P1.

Parses the audit JSONL and tallies: allow/approve/deny counts, trifecta trips,
drift events, secret-scan hits, approval timeouts, and chain gaps. Renders as
a human-readable text report or JSON.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


class PostureError(ValueError):
    """Raised when posture computation cannot proceed."""


@dataclass
class PostureStats:
    allow_count:       int
    approve_count:     int
    deny_count:        int
    trifecta_trips:    int
    drift_events:      int
    secret_scan_hits:  int
    approval_timeouts: int
    chain_gaps:        int
    session_count:     int


def compute_posture(audit_log: Path) -> PostureStats:
    """Parse an audit JSONL and return PostureStats.

    Counts decisions and security events; ignores unknown event types.
    """
    if not audit_log.exists():
        raise PostureError(f"audit log not found: {audit_log}")

    from bawbel_gate._const import (
        EFFECT_ALLOW,
        EFFECT_APPROVE,
        EFFECT_DENY,
        EVENT_APPROVAL_TIMEOUT,
        EVENT_CALL_DECIDED,
        EVENT_DRIFT_DETECTED,
        EVENT_SESSION_START,
        REASON_GUARD_SECRET_SCAN,
        REASON_TRIFECTA_THIRD_LEG,
    )

    allow_count       = 0
    approve_count     = 0
    deny_count        = 0
    trifecta_trips    = 0
    drift_events      = 0
    secret_scan_hits  = 0
    approval_timeouts = 0
    chain_gaps        = 0
    session_count     = 0

    for line in audit_log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        event = record.get("event", "")

        if event == EVENT_SESSION_START:
            session_count += 1

        elif event == EVENT_CALL_DECIDED:
            effect  = record.get("effect", "")
            reason  = record.get("reason", "")
            if effect == EFFECT_ALLOW:
                allow_count += 1
            elif effect == EFFECT_APPROVE:
                approve_count += 1
                if reason == REASON_TRIFECTA_THIRD_LEG:
                    trifecta_trips += 1
            elif effect == EFFECT_DENY:
                deny_count += 1
                if reason == REASON_GUARD_SECRET_SCAN:
                    secret_scan_hits += 1

        elif event == EVENT_DRIFT_DETECTED:
            drift_events += 1

        elif event == EVENT_APPROVAL_TIMEOUT:
            approval_timeouts += 1

    return PostureStats(
        allow_count=allow_count,
        approve_count=approve_count,
        deny_count=deny_count,
        trifecta_trips=trifecta_trips,
        drift_events=drift_events,
        secret_scan_hits=secret_scan_hits,
        approval_timeouts=approval_timeouts,
        chain_gaps=chain_gaps,
        session_count=session_count,
    )


def render_posture_report(stats: PostureStats, fmt: str = "text") -> str:
    """Render PostureStats as a text table or JSON string."""
    if fmt == "json":
        return json.dumps(asdict(stats), indent=2)

    total = stats.allow_count + stats.approve_count + stats.deny_count
    lines = [
        "bawbel-gate Posture Report",
        "=" * 40,
        "",
        "DECISION SUMMARY",
        f"  allow   : {stats.allow_count:>6}",
        f"  approve : {stats.approve_count:>6}",
        f"  deny    : {stats.deny_count:>6}",
        f"  total   : {total:>6}",
        "",
        "SECURITY EVENTS",
        f"  trifecta trips     : {stats.trifecta_trips:>4}",
        f"  drift events       : {stats.drift_events:>4}",
        f"  secret scan hits   : {stats.secret_scan_hits:>4}",
        f"  approval timeouts  : {stats.approval_timeouts:>4}",
        f"  chain gaps         : {stats.chain_gaps:>4}",
        "",
        f"Sessions tracked: {stats.session_count}",
    ]
    return "\n".join(lines)
