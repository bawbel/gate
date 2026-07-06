"""Fleet posture queries. See DESIGN.md 14.4.

Fleet state is a pure replay of verified chains. This module provides
per-gate posture rows and aggregate stats for the fleet console.
"""

from __future__ import annotations

from dataclasses import dataclass

from bawbel_gate.hub.store import FleetStore


@dataclass
class GatePostureRow:
    gate_id:       str
    allow_count:   int
    approve_count: int
    deny_count:    int
    trifecta_trips: int
    drift_events:  int
    session_count: int


def compute_fleet_posture(store: FleetStore) -> list[GatePostureRow]:
    """Return one posture row per enrolled gate."""
    rows = []
    for gate_id in store.list_gates():
        agg = store.get_aggregate_state(gate_id)
        rows.append(GatePostureRow(
            gate_id=gate_id,
            allow_count=agg.get("allow_count", 0),
            approve_count=agg.get("approve_count", 0),
            deny_count=agg.get("deny_count", 0),
            trifecta_trips=agg.get("trifecta_trips", 0),
            drift_events=agg.get("drift_events", 0),
            session_count=agg.get("session_count", 0),
        ))
    return rows
