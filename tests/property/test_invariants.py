"""Property tests for invariants I1-I5 (DESIGN.md 5, references/invariants.md).

Written BEFORE the implementation per gate-implementation skill workflow.
These tests define what correct behaviour means; the implementation must
make them pass.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

effects = st.sampled_from(["allow", "approve", "deny"])
prov_classes = st.sampled_from([
    "tool.response.github", "tool.response.fs", "web.fetched",
    "tool.response.slack", "model.generated",
])
tool_names = st.text(min_size=1, max_size=32, alphabet=st.characters(
    whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_"
))


# ---------------------------------------------------------------------------
# I5 - lattice_min algebraic laws (before engine exists)
# ---------------------------------------------------------------------------

class TestLatticeMin:
    """I5: lattice_min is associative, commutative, idempotent; deny absorbs."""

    def test_deny_absorbs_allow(self):
        from bawbel_gate.policy.engine import lattice_min
        assert lattice_min("deny", "allow") == "deny"
        assert lattice_min("allow", "deny") == "deny"

    def test_deny_absorbs_approve(self):
        from bawbel_gate.policy.engine import lattice_min
        assert lattice_min("deny", "approve") == "deny"
        assert lattice_min("approve", "deny") == "deny"

    def test_approve_beats_allow(self):
        from bawbel_gate.policy.engine import lattice_min
        assert lattice_min("allow", "approve") == "approve"

    def test_idempotent(self):
        from bawbel_gate.policy.engine import lattice_min
        for e in ("allow", "approve", "deny"):
            assert lattice_min(e, e) == e

    @given(a=effects, b=effects)
    def test_commutative(self, a, b):
        from bawbel_gate.policy.engine import lattice_min
        assert lattice_min(a, b) == lattice_min(b, a)

    @given(a=effects, b=effects, c=effects)
    def test_associative(self, a, b, c):
        from bawbel_gate.policy.engine import lattice_min
        assert lattice_min(lattice_min(a, b), c) == lattice_min(a, lattice_min(b, c))

    @given(effects_list=st.lists(effects, min_size=1, max_size=8))
    def test_fold_order_independent(self, effects_list):
        from bawbel_gate.policy.engine import lattice_min
        from functools import reduce
        result = reduce(lattice_min, effects_list)
        for perm in [effects_list, list(reversed(effects_list))]:
            assert reduce(lattice_min, perm) == result


# ---------------------------------------------------------------------------
# I1 - Default deny
# ---------------------------------------------------------------------------

class TestDefaultDeny:
    def test_no_match_is_deny(self):
        from bawbel_gate.policy.engine import resolve
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        from bawbel_gate.mux.session import SessionState

        manifest = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": True},
            grants=[ToolGrant(name="*", effect="deny")],
        )
        session = SessionState()
        decision = resolve("nonexistent_tool", {}, manifest, session)
        assert decision.effect == "deny"

    @given(tool=tool_names)
    def test_unmatched_tool_always_deny(self, tool):
        """I1: any call with no matching grant resolves to deny."""
        from bawbel_gate.policy.engine import resolve
        from bawbel_gate.policy.manifest import Manifest
        from bawbel_gate.mux.session import SessionState

        # Empty grants (no wildcard) — default deny
        manifest = Manifest(
            server="s",
            provenance_class="tool.response.s",
            instruction_authority="none",
            trifecta={"private_data": False, "untrusted_content": False, "external_comms": False},
            grants=[],
        )
        decision = resolve(tool, {}, manifest, session=SessionState())
        assert decision.effect == "deny"

    def test_failed_condition_is_deny_not_fallthrough(self):
        """I1: a matched grant whose conditions fail resolves to deny, never next grant."""
        from bawbel_gate.policy.engine import resolve
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        from bawbel_gate.mux.session import SessionState

        from bawbel_gate.policy.manifest import Condition
        manifest = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": True},
            grants=[
                ToolGrant(
                    name="create_pull_request", effect="allow",
                    conditions=[Condition(arg_path="base_repo", pattern="myorg/*")],
                ),
                ToolGrant(name="*", effect="allow"),  # must never be reached
            ],
        )
        session = SessionState()
        # condition fails: base_repo does not match myorg/*
        decision = resolve("create_pull_request", {"base_repo": "other/repo"}, manifest, session)
        assert decision.effect == "deny"
        assert decision.reason == "condition_failed"


# ---------------------------------------------------------------------------
# I2 - Monotonicity
# ---------------------------------------------------------------------------

class TestMonotonicity:
    @given(
        base_taint=st.sets(prov_classes, max_size=3),
        extra=st.sets(prov_classes, min_size=1, max_size=3),
    )
    @settings(max_examples=200)
    def test_taint_never_raises_effect(self, base_taint, extra):
        """I2: adding taint can never produce a MORE permissive effect."""
        from bawbel_gate.policy.engine import resolve, PERMISSIVENESS
        from bawbel_gate.policy.manifest import Manifest, ToolGrant, TaintRule
        from bawbel_gate.mux.session import SessionState

        manifest = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": True},
            grants=[
                ToolGrant(name="create_pull_request", effect="allow"),
                ToolGrant(name="*", effect="deny"),
            ],
            taint_rules=[
                TaintRule(
                    tainted_by_any=["tool.response.*"],
                    actions=[{"tools_with": "external_comms", "effect": "approve"}],
                )
            ],
        )
        session_base = SessionState()
        for cls in base_taint:
            session_base.add_taint(cls)

        session_extra = session_base.with_taint(extra)

        before = resolve("create_pull_request", {}, manifest, session_base).effect
        after = resolve("create_pull_request", {}, manifest, session_extra).effect
        assert PERMISSIVENESS[after] <= PERMISSIVENESS[before]


# ---------------------------------------------------------------------------
# I4 - Trifecta invariant is unconditional
# ---------------------------------------------------------------------------

class TestTrifectaInvariant:
    def test_trifecta_third_leg_forces_approve_minimum(self):
        """I4: private+untrusted+external_comms -> effect >= approve, regardless of grants."""
        from bawbel_gate.policy.engine import resolve
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        from bawbel_gate.mux.session import SessionState

        # Manifest allows the tool freely — trifecta must downgrade to approve
        manifest = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": True},
            grants=[ToolGrant(name="create_pull_request", effect="allow")],
        )
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()

        decision = resolve("create_pull_request", {}, manifest, session)
        assert decision.effect in ("approve", "deny")
        assert decision.effect != "allow"

    @given(
        grant_effect=effects,
        private_touched=st.booleans(),
        untrusted_seen=st.booleans(),
    )
    def test_trifecta_never_allow_when_complete(
        self, grant_effect, private_touched, untrusted_seen
    ):
        """I4: for any manifest with external_comms, complete trifecta -> never allow."""
        from bawbel_gate.policy.engine import resolve
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        from bawbel_gate.mux.session import SessionState

        manifest = Manifest(
            server="s",
            provenance_class="tool.response.s",
            instruction_authority="none",
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": True},
            grants=[ToolGrant(name="some_tool", effect=grant_effect)],
        )
        session = SessionState()
        if private_touched:
            session.mark_private_touched()
        if untrusted_seen:
            session.mark_untrusted_seen()

        decision = resolve("some_tool", {}, manifest, session)

        if private_touched and untrusted_seen:
            # trifecta complete + external_comms: must never be allow
            assert decision.effect != "allow", (
                f"trifecta complete but got effect={decision.effect!r} "
                f"(grant={grant_effect!r})"
            )

    def test_no_manifest_config_can_disable_trifecta(self):
        """I4: the trifecta step is non-configurable — no manifest field bypasses it."""
        from bawbel_gate.policy.engine import resolve
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        from bawbel_gate.mux.session import SessionState

        # Worst case: all taint rules explicitly grant allow for this tool
        manifest = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": True},
            grants=[ToolGrant(name="exfil_tool", effect="allow")],
        )
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()
        session.add_taint("tool.response.github")

        result = resolve("exfil_tool", {}, manifest, session)
        assert result.effect in ("approve", "deny")
        assert result.effect != "allow"
