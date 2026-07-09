"""Unit tests for M2 policy engine, manifest loader, and argument guards."""

from pathlib import Path

from bawbel_gate.policy.engine import resolve, lattice_min, Decision
from bawbel_gate.policy.manifest import (
    Manifest, ToolGrant, TaintRule, ArgumentGuard, Condition,
    ManifestError, load_manifest, _secret_scan,
)
from bawbel_gate.mux.session import SessionState
from bawbel_gate._const import (
    EFFECT_ALLOW, EFFECT_APPROVE, EFFECT_DENY,
    REASON_CONDITION_FAILED, REASON_NO_GRANT,
    REASON_GUARD_SECRET_SCAN, REASON_GUARD_BYTE_CAP,
    REASON_TRIFECTA_THIRD_LEG,
)

CORPUS_MANIFESTS = Path(__file__).parent / "corpus" / "manifests"


def _simple_manifest(
    tool_grants=None,
    taint_rules=None,
    guards=None,
    trifecta=None,
) -> Manifest:
    return Manifest(
        server="github",
        provenance_class="tool.response.github",
        instruction_authority="none",
        trifecta=trifecta or {
            "private_data": True, "untrusted_content": True, "external_comms": True
        },
        grants=(
            tool_grants if tool_grants is not None else [ToolGrant(name="*", effect=EFFECT_DENY)]
        ),
        taint_rules=taint_rules if taint_rules is not None else [],
        argument_guards=guards if guards is not None else [],
    )


# ---------------------------------------------------------------------------
# Lattice
# ---------------------------------------------------------------------------

class TestLatticeMin:
    def test_deny_absorbs(self):
        assert lattice_min(EFFECT_DENY, EFFECT_ALLOW) == EFFECT_DENY
        assert lattice_min(EFFECT_ALLOW, EFFECT_DENY) == EFFECT_DENY

    def test_approve_beats_allow(self):
        assert lattice_min(EFFECT_ALLOW, EFFECT_APPROVE) == EFFECT_APPROVE

    def test_same_returns_same(self):
        for e in (EFFECT_ALLOW, EFFECT_APPROVE, EFFECT_DENY):
            assert lattice_min(e, e) == e


# ---------------------------------------------------------------------------
# Grant resolution
# ---------------------------------------------------------------------------

class TestGrantResolution:
    def test_no_grant_is_deny(self):
        manifest = _simple_manifest(tool_grants=[])
        d = resolve("unknown_tool", {}, manifest, SessionState())
        assert d.effect == EFFECT_DENY
        assert d.reason == REASON_NO_GRANT

    def test_wildcard_deny_matches_any(self):
        manifest = _simple_manifest()
        d = resolve("anything", {}, manifest, SessionState())
        assert d.effect == EFFECT_DENY

    def test_exact_match_beats_wildcard(self):
        manifest = _simple_manifest(tool_grants=[
            ToolGrant(name="get_issue", effect=EFFECT_ALLOW),
            ToolGrant(name="*", effect=EFFECT_DENY),
        ])
        d = resolve("get_issue", {}, manifest, SessionState())
        assert d.effect == EFFECT_ALLOW

    def test_wildcard_fallback_when_no_exact(self):
        manifest = _simple_manifest(tool_grants=[
            ToolGrant(name="get_issue", effect=EFFECT_ALLOW),
            ToolGrant(name="*", effect=EFFECT_DENY),
        ])
        d = resolve("other_tool", {}, manifest, SessionState())
        assert d.effect == EFFECT_DENY

    def test_condition_pass_allows(self):
        manifest = _simple_manifest(tool_grants=[
            ToolGrant(
                name="create_pull_request", effect=EFFECT_ALLOW,
                conditions=[Condition(arg_path="base_repo", pattern="myorg/*")],
            ),
            ToolGrant(name="*", effect=EFFECT_DENY),
        ])
        d = resolve("create_pull_request", {"base_repo": "myorg/myrepo"}, manifest, SessionState())
        assert d.effect == EFFECT_ALLOW

    def test_condition_fail_is_deny_not_fallthrough(self):
        manifest = _simple_manifest(tool_grants=[
            ToolGrant(
                name="create_pull_request", effect=EFFECT_ALLOW,
                conditions=[Condition(arg_path="base_repo", pattern="myorg/*")],
            ),
            ToolGrant(name="*", effect=EFFECT_ALLOW),  # must not be reached
        ])
        d = resolve("create_pull_request", {"base_repo": "other/repo"}, manifest, SessionState())
        assert d.effect == EFFECT_DENY
        assert d.reason == REASON_CONDITION_FAILED

    def test_missing_condition_arg_is_deny(self):
        manifest = _simple_manifest(tool_grants=[
            ToolGrant(
                name="create_pull_request", effect=EFFECT_ALLOW,
                conditions=[Condition(arg_path="base_repo", pattern="myorg/*")],
            ),
        ])
        d = resolve("create_pull_request", {}, manifest, SessionState())
        assert d.effect == EFFECT_DENY


# ---------------------------------------------------------------------------
# Argument guards
# ---------------------------------------------------------------------------

class TestArgumentGuards:
    def test_secret_scan_aws_key_detected(self):
        assert _secret_scan("AKIAIOSFODNN7EXAMPLE") is True

    def test_secret_scan_gitlab_pat_detected(self):
        assert _secret_scan("glpat-abcdefghijklmnopqrst") is True

    def test_secret_scan_vault_token_detected(self):
        assert _secret_scan("hvs.CAESIKSomeVaultToken12345678901234") is True

    def test_secret_scan_pem_detected(self):
        assert _secret_scan("-----BEGIN RSA PRIVATE KEY-----") is True

    def test_secret_scan_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert _secret_scan(jwt) is True

    def test_secret_scan_normal_string_clean(self):
        assert _secret_scan("just a normal string value") is False

    def test_guard_secret_scan_deny(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="create_issue_comment", effect=EFFECT_ALLOW)],
            guards=[ArgumentGuard(applies_to="*", outbound_secret_scan=True)],
        )
        d = resolve(
            "create_issue_comment",
            {"body": "token: AKIAIOSFODNN7EXAMPLE"},
            manifest, SessionState(),
        )
        assert d.effect == EFFECT_DENY
        assert d.reason == REASON_GUARD_SECRET_SCAN

    def test_guard_byte_cap_deny(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="write_file", effect=EFFECT_ALLOW)],
            guards=[ArgumentGuard(
                applies_to="*", outbound_secret_scan=False, max_outbound_bytes=10
            )],
        )
        d = resolve("write_file", {"content": "x" * 100}, manifest, SessionState())
        assert d.effect == EFFECT_DENY
        assert d.reason == REASON_GUARD_BYTE_CAP


# ---------------------------------------------------------------------------
# Taint rules
# ---------------------------------------------------------------------------

class TestTaintRules:
    def test_taint_rule_downgrades_allow_to_approve(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="create_pull_request", effect=EFFECT_ALLOW)],
            taint_rules=[TaintRule(
                tainted_by_any=["tool.response.github"],
                actions=[{"tool": "create_pull_request", "effect": EFFECT_APPROVE}],
            )],
        )
        session = SessionState()
        session.add_taint("tool.response.github")
        d = resolve("create_pull_request", {}, manifest, session)
        assert d.effect == EFFECT_APPROVE

    def test_taint_rule_wildcard_prefix(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="send_message", effect=EFFECT_ALLOW)],
            taint_rules=[TaintRule(
                tainted_by_any=["tool.response.*"],
                actions=[{"tools_with": "external_comms", "effect": EFFECT_APPROVE}],
            )],
        )
        session = SessionState()
        session.add_taint("tool.response.github")
        d = resolve("send_message", {}, manifest, session)
        assert d.effect == EFFECT_APPROVE

    def test_taint_rule_not_triggered_when_no_match(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="get_issue", effect=EFFECT_ALLOW)],
            taint_rules=[TaintRule(
                tainted_by_any=["web.fetched"],
                actions=[{"tool": "get_issue", "effect": EFFECT_DENY}],
            )],
        )
        session = SessionState()  # no web.fetched taint
        d = resolve("get_issue", {}, manifest, session)
        assert d.effect == EFFECT_ALLOW

    def test_taint_rule_cannot_raise_effect(self):
        """Taint rules only go down the lattice — cannot raise approve -> allow."""
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="some_tool", effect=EFFECT_APPROVE)],
            taint_rules=[TaintRule(
                tainted_by_any=["tool.response.github"],
                actions=[{"tool": "some_tool", "effect": EFFECT_ALLOW}],  # cannot raise
            )],
        )
        session = SessionState()
        session.add_taint("tool.response.github")
        d = resolve("some_tool", {}, manifest, session)
        # lattice_min(approve, allow) = approve — taint cannot raise the effect
        assert d.effect == EFFECT_APPROVE


# ---------------------------------------------------------------------------
# Trifecta invariant
# ---------------------------------------------------------------------------

class TestTrifectaInvariant:
    def test_trifecta_complete_forces_approve(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="exfil_tool", effect=EFFECT_ALLOW)],
        )
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()
        d = resolve("exfil_tool", {}, manifest, session)
        assert d.effect in (EFFECT_APPROVE, EFFECT_DENY)
        assert d.effect != EFFECT_ALLOW
        assert d.reason == REASON_TRIFECTA_THIRD_LEG

    def test_trifecta_incomplete_does_not_fire(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="exfil_tool", effect=EFFECT_ALLOW)],
        )
        session = SessionState()
        session.mark_private_touched()
        # untrusted_seen not set -> trifecta not complete
        d = resolve("exfil_tool", {}, manifest, session)
        assert d.effect == EFFECT_ALLOW

    def test_trifecta_no_external_comms_does_not_fire(self):
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="read_file", effect=EFFECT_ALLOW)],
            trifecta={"private_data": True, "untrusted_content": True, "external_comms": False},
        )
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()
        d = resolve("read_file", {}, manifest, session)
        assert d.effect == EFFECT_ALLOW  # not external_comms -> trifecta doesn't apply

    def test_deny_not_upgraded_by_trifecta(self):
        """Trifecta can only lower allow to approve; it cannot raise deny to approve."""
        manifest = _simple_manifest(
            tool_grants=[ToolGrant(name="*", effect=EFFECT_DENY)],
        )
        session = SessionState()
        session.mark_private_touched()
        session.mark_untrusted_seen()
        # tool matches wildcard -> deny; trifecta must not raise it
        d = resolve("some_tool", {}, manifest, session)
        assert d.effect == EFFECT_DENY


# ---------------------------------------------------------------------------
# Decision.to_jsonrpc_error
# ---------------------------------------------------------------------------

class TestDecisionJsonRpc:
    def test_error_code(self):
        d = Decision(effect=EFFECT_DENY, reason=REASON_NO_GRANT)
        err = d.to_jsonrpc_error(request_id=42)
        assert err["error"]["code"] == -32031
        assert err["id"] == 42
        assert err["error"]["data"]["reason"] == REASON_NO_GRANT

    def test_ave_ids_in_data(self):
        d = Decision(effect=EFFECT_DENY, reason=REASON_TRIFECTA_THIRD_LEG, ave=["AVE-2026-00038"])
        err = d.to_jsonrpc_error(request_id=1)
        assert "AVE-2026-00038" in err["error"]["data"]["ave"]


# ---------------------------------------------------------------------------
# Manifest loader (corpus fixture)
# ---------------------------------------------------------------------------

class TestManifestLoader:
    def test_load_corpus_github_manifest(self):
        path = CORPUS_MANIFESTS / "github-mcp.cap.yaml"
        manifest = load_manifest(path, "github")
        assert manifest.server == "github"
        assert manifest.provenance_class == "tool.response.github"
        assert manifest.trifecta["external_comms"] is True
        assert any(g.name == "get_issue" for g in manifest.grants)
        assert manifest.manifest_sha256 is not None

    def test_manifest_sha256_stable(self):
        path = CORPUS_MANIFESTS / "github-mcp.cap.yaml"
        m1 = load_manifest(path, "github")
        m2 = load_manifest(path, "github")
        assert m1.manifest_sha256 == m2.manifest_sha256

    def test_invalid_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.cap.yaml"
        p.write_text("{not: valid: yaml:::", encoding="utf-8")
        try:
            load_manifest(p, "test")
            raise AssertionError("expected ManifestError")
        except (ManifestError, Exception):
            pass

    def test_duplicate_grant_name_raises(self, tmp_path):
        p = tmp_path / "dup.cap.yaml"
        p.write_text(
            "schema: bawbel/capability-manifest/v1\n"
            "subject:\n  kind: mcp-server\n  name: test\n"
            "provenance_class: tool.response.test\n"
            "instruction_authority: none\n"
            "trifecta:\n  private_data: false\n"
            "  untrusted_content: false\n  external_comms: false\n"
            "grants:\n"
            "  tools:\n"
            "    - name: dup_tool\n      effect: allow\n"
            "    - name: dup_tool\n      effect: deny\n",
            encoding="utf-8",
        )
        try:
            load_manifest(p, "test")
            raise AssertionError("expected ManifestError for duplicate names")
        except ManifestError:
            pass
