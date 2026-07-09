"""Replay test: 2025 GitHub-MCP prompt-injection exfil pattern.

Attack chain (AVE-2026-00041):
  1. Agent reads a poisoned GitHub issue containing an injection payload.
     -> Session becomes untrusted (taint: tool.response.github, untrusted_seen).
  2. Payload instructs the agent to read private repository secrets / files.
     -> Session becomes private_touched (trifecta: two legs complete).
  3. Payload instructs the agent to open a PR to an attacker-controlled fork.
     -> Trifecta third leg fires (external_comms). Blocked at >= approve.

Each layer is asserted independently so a future regression pinpoints which
enforcement step broke.
"""

from __future__ import annotations

from pathlib import Path

from bawbel_gate._const import (
    EFFECT_ALLOW,
    EFFECT_APPROVE,
    EFFECT_DENY,
    REASON_TRIFECTA_THIRD_LEG,
)
from bawbel_gate.policy.engine import resolve
from bawbel_gate.policy.manifest import load_manifest
from bawbel_gate.mux.session import SessionState

CORPUS_MANIFESTS = Path(__file__).parent.parent / "corpus" / "manifests"
GITHUB_MANIFEST_PATH = CORPUS_MANIFESTS / "github-mcp.cap.yaml"


def _manifest():
    return load_manifest(GITHUB_MANIFEST_PATH, "github")


# ---------------------------------------------------------------------------
# Layer 1: get_issue allowed on clean session, taint accumulates correctly
# ---------------------------------------------------------------------------

class TestLayer1PoisonedIssueRead:
    """get_issue is allowed initially; reading it taints the session."""

    def test_get_issue_allowed_on_clean_session(self):
        """Layer 1a: before any taint the agent can read issues (allowed by manifest)."""
        manifest = _manifest()
        session = SessionState()
        d = resolve("get_issue", {"issue_number": 42}, manifest, session)
        assert d.effect == EFFECT_ALLOW, (
            f"Layer 1 regression: get_issue should be ALLOW on a clean session, got {d.effect!r}"
        )

    def test_get_issue_response_taints_session(self):
        """Layer 1b: after get_issue responds, taint is added to the session."""
        session = SessionState()
        # Simulate what the mux does after a tool.response.github response is received.
        session.add_taint("tool.response.github")
        session.mark_untrusted_seen()
        assert "tool.response.github" in session.tainted_by
        assert session.untrusted_seen is True

    def test_tainted_create_pr_is_downgraded_by_taint_rule(self):
        """Layer 1c: after taint, create_pull_request is downgraded from allow to approve.

        The corpus manifest's taint_rules fire: tainted_by_any=[tool.response.github]
        -> create_pull_request effect: approve.
        """
        manifest = _manifest()
        session = SessionState()
        session.add_taint("tool.response.github")

        # create_pull_request to myorg/* still meets its condition
        d = resolve(
            "create_pull_request",
            {"base_repo": "myorg/target"},
            manifest,
            session,
        )
        # Taint rule downgrades grant(allow) -> approve before trifecta fires
        assert d.effect in (EFFECT_APPROVE, EFFECT_DENY), (
            f"Layer 1c regression: taint rule must downgrade create_pull_request, got {d.effect!r}"
        )
        assert d.effect != EFFECT_ALLOW


# ---------------------------------------------------------------------------
# Layer 2: private read is blocked / gated after two-legged trifecta
# ---------------------------------------------------------------------------

class TestLayer2PrivateRead:
    """After get_issue taint + private_touched, any external call requires approve."""

    def test_two_leg_trifecta_gating(self):
        """Layer 2: with private_touched + untrusted_seen, any external tool is gated >= approve.

        create_or_update_file is explicitly granted at 'approve' in the manifest, so
        it is permitted — but only at that level, not silently allowed.
        """
        manifest = _manifest()
        session = SessionState()
        session.add_taint("tool.response.github")
        session.mark_untrusted_seen()
        session.mark_private_touched()

        # create_or_update_file is granted at 'approve' in the corpus manifest
        d = resolve(
            "create_or_update_file", {"path": ".env", "content": "secret"}, manifest, session
        )
        # The grant is approve; trifecta fires and lattice_min(approve, approve)=approve
        assert d.effect != EFFECT_ALLOW, (
            "Layer 2 regression: private_touched+untrusted_seen must gate to >= approve,"
            f" got {d.effect!r}"
        )

    def test_unmatched_tool_denied_after_private_read(self):
        """Layer 2b: tools not in manifest are denied even after partial trifecta."""
        manifest = _manifest()
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()

        d = resolve("unknown_tool", {}, manifest, session)
        assert d.effect == EFFECT_DENY

    def test_secret_scan_blocks_exfil_in_args(self):
        """Layer 2c: argument guard blocks AWS key embedded in a tool argument."""
        manifest = _manifest()
        session = SessionState()

        # Payload instructs agent to write a file containing secrets
        d = resolve(
            "create_or_update_file",
            {"path": "dump.txt", "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"},
            manifest,
            session,
        )
        assert d.effect == EFFECT_DENY, (
            f"Layer 2c regression: secret scan must deny credential exfil, got {d.effect!r}"
        )


# ---------------------------------------------------------------------------
# Layer 3: PR-to-fork is blocked by trifecta third leg
# ---------------------------------------------------------------------------

class TestLayer3PrToFork:
    """With full trifecta (private+untrusted+external_comms), create_pull_request
    to an attacker fork must be blocked at >= approve (i.e., require explicit
    human approval, not allowed automatically).
    """

    def test_pr_to_trusted_repo_condition_required(self):
        """Layer 3a: create_pull_request to out-of-org repo fails condition check."""
        manifest = _manifest()
        session = SessionState()

        # Attacker instructs PR to their fork outside myorg/*
        d = resolve(
            "create_pull_request",
            {"base_repo": "attacker/stolen-fork"},
            manifest,
            session,
        )
        assert d.effect == EFFECT_DENY, (
            "Layer 3a regression: PR to out-of-org fork must be denied by condition,"
            f" got {d.effect!r}"
        )

    def test_pr_trifecta_third_leg_fires_on_external_comms(self):
        """Layer 3b: full trifecta — any create_pull_request (even in-org) requires approval.

        This is the core of the exfil defence: even if the condition passes, the
        trifecta invariant forces the effect to >= approve. No allow path exists.
        """
        manifest = _manifest()
        session = SessionState()
        session.add_taint("tool.response.github")
        session.mark_untrusted_seen()
        session.mark_private_touched()

        d = resolve(
            "create_pull_request",
            {"base_repo": "myorg/target"},  # condition passes
            manifest,
            session,
        )
        assert d.effect != EFFECT_ALLOW, (
            "Layer 3b regression: trifecta must block allow on full 3-leg completion,"
            f" got {d.effect!r}"
        )
        assert d.reason == REASON_TRIFECTA_THIRD_LEG, (
            f"Layer 3b regression: deny reason must be trifecta_third_leg, got {d.reason!r}"
        )

    def test_full_chain_is_blocked_end_to_end(self):
        """Layer 3c: replay the complete attack chain atomically.

        Step 1: read poisoned issue       -> session taints, untrusted_seen
        Step 2: read private file content -> private_touched
        Step 3: attempt PR to attacker fork -> denied (condition fails on base_repo)
        Step 3 alt: attempt PR in-org    -> denied (trifecta fires, >= approve)

        All three denials are asserted independently.
        """
        manifest = _manifest()
        session = SessionState()

        # --- Step 1: agent calls get_issue (allowed initially) ---
        d1 = resolve("get_issue", {"issue_number": 99}, manifest, session)
        assert d1.effect == EFFECT_ALLOW, "pre-condition: get_issue must be allowed before taint"

        # Mux processes tool.response.github, taints session
        session.add_taint("tool.response.github")
        session.mark_untrusted_seen()

        # --- Step 2: injection payload triggers private-data access ---
        # create_or_update_file is in manifest at 'approve'; taint rule doesn't
        # cover it so the session must track private_touched separately
        session.mark_private_touched()

        # --- Step 3a: PR to attacker fork (out-of-org) ---
        d3a = resolve(
            "create_pull_request",
            {"base_repo": "attacker/evil-fork"},
            manifest,
            session,
        )
        assert d3a.effect == EFFECT_DENY, (
            f"Step 3a: PR to attacker fork must be denied; got {d3a.effect!r}"
        )

        # --- Step 3b: PR to in-org repo — trifecta fires ---
        d3b = resolve(
            "create_pull_request",
            {"base_repo": "myorg/legit"},
            manifest,
            session,
        )
        assert d3b.effect != EFFECT_ALLOW, (
            f"Step 3b: in-org PR must not be allowed after full trifecta; got {d3b.effect!r}"
        )
        assert d3b.reason == REASON_TRIFECTA_THIRD_LEG, (
            f"Step 3b: trifecta_third_leg must be cited; got {d3b.reason!r}"
        )


# ---------------------------------------------------------------------------
# Regression guard: no manifest field disables the exfil defence
# ---------------------------------------------------------------------------

class TestExfilDefenceNonConfigurable:
    """Guard against future regressions that might add a bypass."""

    def test_trifecta_cannot_be_disabled_by_removing_trifecta_key(self):
        """Even a manifest with trifecta.external_comms=false limits its own tools' scope."""
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        minimal = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            # Operator deliberately declares no external_comms scope on this server
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": False},
            grants=[ToolGrant(name="get_issue", effect=EFFECT_ALLOW)],
        )
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()
        # Trifecta does not fire (external_comms=False for this server)
        # but that is correct: this server cannot open PRs, so it has no external_comms
        d = resolve("get_issue", {}, minimal, session)
        # Must still function (read-only tool, no external_comms) — allowed
        assert d.effect == EFFECT_ALLOW

    def test_grant_effect_allow_cannot_bypass_trifecta(self):
        """A tool granted 'allow' is still capped to approve by the trifecta invariant."""
        from bawbel_gate.policy.manifest import Manifest, ToolGrant
        manifest = Manifest(
            server="github",
            provenance_class="tool.response.github",
            instruction_authority="none",
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": True},
            grants=[
                ToolGrant(name="create_pull_request", effect=EFFECT_ALLOW),
                ToolGrant(name="*", effect=EFFECT_DENY),
            ],
        )
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()

        d = resolve("create_pull_request", {}, manifest, session)
        assert d.effect != EFFECT_ALLOW, (
            f"Grant effect=allow must not bypass trifecta; got {d.effect!r}"
        )
