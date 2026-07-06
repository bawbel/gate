"""Policy engine: grant resolution algorithm per DESIGN.md 5.2.

The resolution order is exactly:
  1. Match grant (exact > wildcard > None -> deny)
  2. No match -> deny
  3. Conditions -> deny if any fails
  4. Argument guards -> deny if any fires
  5. Taint rules (lattice_min)
  6. Trifecta invariant (non-configurable, lattice_min with approve)

No step can raise an effect. lattice_min guarantees monotone descent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bawbel_gate._const import (
    EFFECT_ALLOW,
    EFFECT_APPROVE,
    EFFECT_DENY,
    EFFECT_ORDER,
    JSONRPC_DENY_CODE,
    REASON_CONDITION_FAILED,
    REASON_GUARD_BYTE_CAP,
    REASON_GUARD_SECRET_SCAN,
    REASON_NO_GRANT,
    REASON_TRIFECTA_THIRD_LEG,
)
from bawbel_gate._types import AveId, Effect

# Exported for property tests (invariant I2, I5)
PERMISSIVENESS = EFFECT_ORDER


@dataclass
class Decision:
    effect: Effect
    reason: str
    ave: list[AveId] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)

    def to_jsonrpc_error(self, request_id: Any) -> dict:
        """Build a -32031 JSON-RPC error for denied calls (DESIGN.md 6.2)."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": JSONRPC_DENY_CODE,
                "message": "bawbel-gate: denied",
                "data": {
                    "reason": self.reason,
                    "ave": self.ave,
                },
            },
        }


def lattice_min(a: Effect, b: Effect) -> Effect:
    """Return the less permissive of two effects (I5: deny absorbs all)."""
    return a if EFFECT_ORDER[a] <= EFFECT_ORDER[b] else b


def resolve(
    tool: str,
    args: dict[str, Any],
    manifest: "Manifest",  # type: ignore[name-defined]  # noqa: F821
    session: "SessionState",  # type: ignore[name-defined]  # noqa: F821
) -> Decision:
    """Run the full grant resolution pipeline per DESIGN.md 5.2."""
    from bawbel_gate.policy.manifest import Manifest
    from bawbel_gate.mux.session import SessionState

    # Step 1-2: match grant; no match -> deny
    grant = manifest.match_grant(tool)
    if grant is None:
        return Decision(effect=EFFECT_DENY, reason=REASON_NO_GRANT)

    effect: Effect = grant.effect

    # Step 3: conditions — fail -> deny, never fallthrough
    if grant.conditions and not grant.conditions_ok(args):
        return Decision(effect=EFFECT_DENY, reason=REASON_CONDITION_FAILED)

    # Step 4: argument guards — hit -> deny
    violation = manifest.guard_violation(tool, args)
    if violation == "secret_scan":
        return Decision(effect=EFFECT_DENY, reason=REASON_GUARD_SECRET_SCAN)
    if violation == "byte_cap":
        return Decision(effect=EFFECT_DENY, reason=REASON_GUARD_BYTE_CAP)

    # Step 5: taint rules (lattice_min only — cannot raise effect)
    for rule in manifest.taint_rules:
        if rule.matches_session(session.tainted_by):
            rule_effect = rule.effect_for(tool, manifest.trifecta)
            if rule_effect is not None:
                effect = lattice_min(effect, rule_effect)

    # Step 6: trifecta invariant — non-configurable, cannot be disabled
    if session.trifecta_third_leg(manifest.trifecta.get("external_comms", False)):
        effect = lattice_min(effect, EFFECT_APPROVE)
        if effect == EFFECT_APPROVE:
            return Decision(effect=effect, reason=REASON_TRIFECTA_THIRD_LEG)

    return Decision(effect=effect, reason="resolved")
