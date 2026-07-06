"""M4: benign-workload corpus replay — approval budget and latency gates.

Exit criteria from IMPLEMENTATION_PLAN.md M4:
- p95 = 0 approval prompts on benign corpus sessions
- p99 <= 1 approval prompt on benign corpus sessions
- p95 decision latency <= 5ms per DESIGN.md 11.2

Approval prompts are counted by examining Decision.effect:
  approve -> would require human approval
  allow   -> no prompt needed
  deny    -> no prompt needed (silent to human)

A benign corpus should produce zero approve-effects at p95.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from bawbel_gate._const import (
    EFFECT_APPROVE, LATENCY_P95_MAX_MS, APPROVAL_BUDGET_P95, APPROVAL_BUDGET_P99,
)
from bawbel_gate.policy.engine import resolve
from bawbel_gate.policy.manifest import load_manifest
from bawbel_gate.mux.session import SessionState

CORPUS_SESSIONS = Path(__file__).parent / "corpus" / "sessions"
CORPUS_MANIFESTS = Path(__file__).parent / "corpus" / "manifests"

_MANIFEST_MAP = {
    "github": CORPUS_MANIFESTS / "github-mcp.cap.yaml",
}


def _load_corpus(path: Path) -> list[dict]:
    """Load a JSONL session corpus file."""
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _replay_session(records: list[dict]) -> tuple[list[str], list[float]]:
    """Replay a session's calls through the policy engine.

    Returns (effects, latencies_ms).
    """
    sessions: dict[str, SessionState] = {}
    manifests: dict[str, object] = {}
    effects: list[str] = []
    latencies: list[float] = []

    for record in records:
        session_id = record.get("session_id", "default")
        server = record.get("server", "github")
        tool = record.get("tool", "")
        args = record.get("args", {})

        if session_id not in sessions:
            sessions[session_id] = SessionState()
        if server not in manifests:
            manifest_path = _MANIFEST_MAP.get(server)
            if manifest_path is None or not manifest_path.exists():
                continue
            manifests[server] = load_manifest(manifest_path, server)

        session = sessions[session_id]
        manifest = manifests[server]

        t0 = time.perf_counter()
        decision = resolve(tool, args, manifest, session)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        effects.append(decision.effect)
        latencies.append(elapsed_ms)

    return effects, latencies


def _session_approval_count(effects: list[str]) -> int:
    """Count calls that would trigger an approval prompt."""
    return sum(1 for e in effects if e == EFFECT_APPROVE)


class TestApprovalBudget:
    """DESIGN.md 7.5 / IMPLEMENTATION_PLAN.md M4: p95=0 prompts, p99<=1 on benign corpus."""

    def _run_corpus(self) -> list[int]:
        """Run all corpus sessions and return per-session approval counts."""
        approval_counts: list[int] = []
        for corpus_file in sorted(CORPUS_SESSIONS.glob("*.jsonl")):
            records = _load_corpus(corpus_file)
            sessions_seen: dict[str, list[dict]] = {}
            for r in records:
                sid = r.get("session_id", "default")
                sessions_seen.setdefault(sid, []).append(r)
            for sid, session_records in sessions_seen.items():
                effects, _ = _replay_session(session_records)
                approval_counts.append(_session_approval_count(effects))
        return approval_counts

    def test_corpus_exists(self):
        """Corpus directory must contain at least one session file."""
        files = list(CORPUS_SESSIONS.glob("*.jsonl"))
        assert files, f"No .jsonl session files found in {CORPUS_SESSIONS}"

    def test_p95_zero_approval_prompts(self):
        """p95 of sessions must produce zero approval prompts on benign corpus."""
        counts = self._run_corpus()
        assert counts, "No sessions in corpus"
        counts_sorted = sorted(counts)
        p95_idx = max(0, int(len(counts_sorted) * 0.95) - 1)
        p95 = counts_sorted[p95_idx]
        assert p95 <= APPROVAL_BUDGET_P95, (
            f"Approval budget regression: p95={p95} > {APPROVAL_BUDGET_P95}. "
            f"Session counts: {counts_sorted}"
        )

    def test_p99_at_most_one_approval_prompt(self):
        """p99 of sessions must produce at most one approval prompt on benign corpus."""
        counts = self._run_corpus()
        assert counts, "No sessions in corpus"
        counts_sorted = sorted(counts)
        p99_idx = max(0, int(len(counts_sorted) * 0.99) - 1)
        p99 = counts_sorted[p99_idx]
        assert p99 <= APPROVAL_BUDGET_P99, (
            f"Approval budget regression: p99={p99} > {APPROVAL_BUDGET_P99}. "
            f"Session counts: {counts_sorted}"
        )


class TestDecisionLatency:
    """DESIGN.md 11.2 / IMPLEMENTATION_PLAN.md M4: p95 <= 5ms decision overhead."""

    def test_p95_latency_within_budget(self):
        """p95 decision latency must be <= LATENCY_P95_MAX_MS (5ms)."""
        all_latencies: list[float] = []
        for corpus_file in sorted(CORPUS_SESSIONS.glob("*.jsonl")):
            records = _load_corpus(corpus_file)
            _, latencies = _replay_session(records)
            all_latencies.extend(latencies)

        if not all_latencies:
            return  # no corpus yet; skip

        all_latencies.sort()
        p95_idx = max(0, int(len(all_latencies) * 0.95) - 1)
        p95_ms = all_latencies[p95_idx]
        assert p95_ms <= LATENCY_P95_MAX_MS, (
            f"Latency regression: p95={p95_ms:.2f}ms > {LATENCY_P95_MAX_MS}ms. "
            f"Worst 5: {all_latencies[-5:]}"
        )

    def test_single_decision_under_threshold(self):
        """A single resolve() call must complete within the latency budget."""
        manifest = load_manifest(CORPUS_MANIFESTS / "github-mcp.cap.yaml", "github")
        session = SessionState()
        samples = []
        for _ in range(100):
            t0 = time.perf_counter()
            resolve("get_issue", {"issue_number": 1}, manifest, session)
            samples.append((time.perf_counter() - t0) * 1000.0)
        samples.sort()
        p95 = samples[int(len(samples) * 0.95)]
        assert p95 <= LATENCY_P95_MAX_MS, (
            f"Single-decision latency p95={p95:.3f}ms exceeds {LATENCY_P95_MAX_MS}ms budget"
        )


class TestSecurityReview:
    """Threat model re-check per IMPLEMENTATION_PLAN.md M4.

    These tests assert the static security properties of the implementation.
    """

    def test_no_fail_open_path_in_engine(self):
        """The engine must always return a Decision; no path raises or returns None."""
        from bawbel_gate.policy.manifest import Manifest
        manifest = Manifest(
            server="s", provenance_class="tool.response.s",
            instruction_authority="none",
            trifecta={"private_data": False, "untrusted_content": False, "external_comms": False},
            grants=[],
        )
        session = SessionState()
        d = resolve("any_tool", {}, manifest, session)
        assert d is not None
        assert d.effect in ("allow", "approve", "deny")

    def test_approval_timeout_constant_is_deny(self):
        """APPROVAL_ON_TIMEOUT must be 'deny' — fail closed."""
        from bawbel_gate._const import APPROVAL_ON_TIMEOUT, EFFECT_DENY
        assert APPROVAL_ON_TIMEOUT == EFFECT_DENY

    def test_no_inline_sort_keys_outside_canonical(self):
        """I6: no json.dumps(sort_keys=True) outside audit/canonical.py."""
        import subprocess
        result = subprocess.run(  # nosec B603 B607 # noqa: S603 S607
            ["grep", "-rn", "sort_keys=True", "src/"],
            capture_output=True, text=True,
        )
        hits = [
            line for line in result.stdout.splitlines()
            if "canonical.py" not in line
        ]
        assert not hits, "sort_keys=True found outside canonical.py:\n" + "\n".join(hits)

    def test_trifecta_invariant_in_engine_code(self):
        """The engine must reference trifecta_third_leg in its source (invariant is present)."""
        engine_src = (
            Path(__file__).parent.parent / "src" / "bawbel_gate" / "policy" / "engine.py"
        ).read_text(encoding="utf-8")
        assert "trifecta_third_leg" in engine_src, "trifecta check missing from engine"

    def test_deny_is_default_in_all_error_paths(self):
        """Manifest with no grants resolves all tools to deny."""
        from bawbel_gate.policy.manifest import Manifest
        manifest = Manifest(
            server="s", provenance_class="tool.response.s",
            instruction_authority="none",
            trifecta={"private_data": False, "untrusted_content": False, "external_comms": False},
            grants=[],
        )
        for tool in ("", "a", "some_tool", "tools/list"):
            d = resolve(tool, {}, manifest, SessionState())
            assert d.effect == "deny", f"Expected deny for unmatched {tool!r}, got {d.effect!r}"
