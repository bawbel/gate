"""GATE-30: an upstream server starts with an explicit environment, not the gate's whole one.

See DESIGN.md 3.4 and 4.2 (the draft in #232). The environment an upstream process starts
with is a short baseline plus each name in the manifest's `environment.allow` that is set in
the gate's own environment. Nothing else is passed. These tests were committed failing,
before the implementation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bawbel_gate.mux.config import ApprovalConfig, GateConfig, ServerConfig
from bawbel_gate.policy.manifest import ManifestError, load_manifest
from tests.proxy_harness import run_enforce_session

FIXTURES = Path(__file__).parent / "fixtures"
PROBE_SERVER = FIXTURES / "env_probe_server.py"
NONE_MANIFEST = FIXTURES / "env_probe_none.cap.yaml"
DECLARED_MANIFEST = FIXTURES / "env_probe_declared.cap.yaml"

try:  # the module is new in GATE-30
    from bawbel_gate._const import UPSTREAM_ENV_BASELINE_POSIX, UPSTREAM_ENV_BASELINE_WINDOWS
    from bawbel_gate.mux.environment import build_upstream_env
except ImportError:  # pragma: no cover - before the implementation, so tests fail as "not built"
    UPSTREAM_ENV_BASELINE_POSIX = ()  # type: ignore[assignment]
    UPSTREAM_ENV_BASELINE_WINDOWS = ()  # type: ignore[assignment]

    def build_upstream_env(*args, **kwargs):  # type: ignore[no-redef]
        raise NotImplementedError("bawbel_gate.mux.environment is not built yet")


# ---------------------------------------------------------------------------
# build_upstream_env: the rule
# ---------------------------------------------------------------------------

class TestBuildUpstreamEnv:
    def test_a_variable_that_is_neither_baseline_nor_declared_is_not_passed(self):
        environ = {"PATH": "/usr/bin", "OTHER_SERVICE_TOKEN": "s3cret", "GITHUB_TOKEN": "g"}
        built = build_upstream_env(["GITHUB_TOKEN"], environ, windows=False)
        assert "OTHER_SERVICE_TOKEN" not in built.env
        assert built.env == {"PATH": "/usr/bin", "GITHUB_TOKEN": "g"}

    def test_a_declared_variable_that_is_set_is_passed_with_the_gates_value(self):
        built = build_upstream_env(["GITHUB_TOKEN"], {"GITHUB_TOKEN": "value-1"}, windows=False)
        assert built.env["GITHUB_TOKEN"] == "value-1"
        assert built.missing == ()

    def test_a_declared_variable_that_is_not_set_is_absent_and_listed(self):
        built = build_upstream_env(["GITHUB_TOKEN", "OTHER"], {"OTHER": "x"}, windows=False)
        assert "GITHUB_TOKEN" not in built.env
        assert built.missing == ("GITHUB_TOKEN",)

    def test_nothing_declared_gives_only_the_baseline(self):
        environ = {"PATH": "/usr/bin", "HOME": "/home/u", "AWS_SECRET_ACCESS_KEY": "k"}
        built = build_upstream_env([], environ, windows=False)
        assert set(built.env) == {"PATH", "HOME"}

    def test_posix_names_match_exactly(self):
        built = build_upstream_env(["github_token"], {"GITHUB_TOKEN": "g"}, windows=False)
        assert "GITHUB_TOKEN" not in built.env
        assert built.missing == ("github_token",)

    def test_windows_names_match_without_regard_to_case(self):
        built = build_upstream_env(["github_token"], {"GITHUB_TOKEN": "g"}, windows=True)
        assert built.env == {"GITHUB_TOKEN": "g"}
        assert built.missing == ()

    def test_the_baseline_is_short_and_has_no_credential_like_name(self):
        for name in (*UPSTREAM_ENV_BASELINE_POSIX, *UPSTREAM_ENV_BASELINE_WINDOWS):
            assert not any(word in name.upper() for word in ("TOKEN", "KEY", "SECRET", "PASS"))
        assert 0 < len(UPSTREAM_ENV_BASELINE_POSIX) <= 8
        assert 0 < len(UPSTREAM_ENV_BASELINE_WINDOWS) <= 10

    @given(
        environ=st.dictionaries(
            st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789", min_size=1, max_size=12),
            st.text(max_size=10), max_size=12,
        ),
        allow=st.lists(
            st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789", min_size=1, max_size=12),
            max_size=6,
        ),
    )
    def test_property_nothing_outside_the_baseline_and_the_declared_names_gets_through(
        self, environ, allow
    ):
        built = build_upstream_env(allow, environ, windows=False)
        permitted = set(UPSTREAM_ENV_BASELINE_POSIX) | set(allow)
        assert set(built.env) <= permitted
        assert all(built.env[k] == environ[k] for k in built.env)
        assert set(built.missing) == {n for n in allow if n not in environ}
        assert not set(built.env) & set(built.missing)


# ---------------------------------------------------------------------------
# The manifest member
# ---------------------------------------------------------------------------

def _manifest_text(environment: str) -> str:
    return NONE_MANIFEST.read_text(encoding="utf-8") + environment


def _control(tmp_path: Path) -> None:
    """A well-formed environment member loads. Without this, a bad one is refused for the wrong
    reason, because the member does not exist yet."""
    path = tmp_path / "good.cap.yaml"
    path.write_text(_manifest_text("\nenvironment:\n  allow: [GOOD_NAME]\n"), encoding="utf-8")
    assert load_manifest(path, "probe").environment_allow == ("GOOD_NAME",)


class TestManifestMember:
    def test_a_manifest_without_the_member_declares_nothing(self):
        manifest = load_manifest(NONE_MANIFEST, "probe")
        assert manifest.environment_allow == ()

    def test_the_declared_names_are_read_in_order(self):
        manifest = load_manifest(DECLARED_MANIFEST, "probe")
        assert manifest.environment_allow == ("BAWBEL_TEST_DECLARED", "BAWBEL_TEST_MISSING")

    def test_the_names_are_part_of_the_manifest_hash(self):
        plain = load_manifest(NONE_MANIFEST, "probe")
        declared = load_manifest(DECLARED_MANIFEST, "probe")
        assert plain.manifest_sha256 != declared.manifest_sha256

    @pytest.mark.parametrize("names", [
        '["A=B"]', '[""]', '["*"]', '["A", "A"]', '[1]', '["has space"]', '["1STARTS_WITH_DIGIT"]',
    ])
    def test_the_schema_rejects_a_bad_name(self, tmp_path, names):
        _control(tmp_path)
        path = tmp_path / "m.cap.yaml"
        path.write_text(_manifest_text(f"\nenvironment:\n  allow: {names}\n"), encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(path, "probe")

    def test_the_schema_rejects_an_unknown_member_of_environment(self, tmp_path):
        _control(tmp_path)
        path = tmp_path / "m.cap.yaml"
        path.write_text(_manifest_text("\nenvironment:\n  inherit_all: true\n"), encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(path, "probe")

    def test_the_schema_has_no_way_to_set_a_value(self, tmp_path):
        _control(tmp_path)
        path = tmp_path / "m.cap.yaml"
        path.write_text(_manifest_text("\nenvironment:\n  set: {A: b}\n"), encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(path, "probe")


# ---------------------------------------------------------------------------
# spawn_server and the request loop, against a real child
# ---------------------------------------------------------------------------

def _cfg(tmp_path: Path, manifest: Path) -> GateConfig:
    server = ServerConfig(
        name="probe", command=sys.executable, args=[str(PROBE_SERVER)], manifest=manifest,
    )
    return GateConfig(
        audit_log=tmp_path / "audit.jsonl", servers=[server],
        approval=ApprovalConfig(channel="terminal", timeout_seconds=5),
    )


def _probe(tmp_path: Path, manifest: Path) -> list[str]:
    responses = run_enforce_session(_cfg(tmp_path, manifest), [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "probe__probe", "arguments": {}}},
    ])
    by_id = {m["id"]: m for m in responses if "id" in m}
    return json.loads(by_id[3]["result"]["content"][0]["text"])


class TestSpawnAndServe:
    def test_spawn_server_gives_the_child_exactly_the_environment_it_is_given(self):
        from bawbel_gate.mux.transport import spawn_server

        code = "import os, json; print(json.dumps(sorted(os.environ)))"
        proc = spawn_server(sys.executable, ["-I", "-c", code], {"ONLY_THIS": "1"})
        out, _ = proc.communicate(timeout=20)
        names = json.loads(out)
        assert "ONLY_THIS" in names
        assert "BAWBEL_TEST_SECRET" not in names

    def test_an_undeclared_credential_in_the_gates_environment_does_not_reach_the_upstream(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("BAWBEL_TEST_SECRET", "s3cret")
        monkeypatch.setenv("BAWBEL_TEST_DECLARED", "d")
        names = _probe(tmp_path, NONE_MANIFEST)
        assert "BAWBEL_TEST_SECRET" not in names
        assert "BAWBEL_TEST_DECLARED" not in names

    def test_a_declared_variable_reaches_only_the_upstream_that_declares_it(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("BAWBEL_TEST_SECRET", "s3cret")
        monkeypatch.setenv("BAWBEL_TEST_DECLARED", "d")
        names = _probe(tmp_path, DECLARED_MANIFEST)
        assert "BAWBEL_TEST_DECLARED" in names
        assert "BAWBEL_TEST_SECRET" not in names

    def test_a_declared_variable_that_is_not_set_is_named_on_stderr_and_no_value_is(
        self, tmp_path, monkeypatch, capfd
    ):
        monkeypatch.setenv("BAWBEL_TEST_DECLARED", "value-that-must-not-be-printed")
        monkeypatch.delenv("BAWBEL_TEST_MISSING", raising=False)
        names = _probe(tmp_path, DECLARED_MANIFEST)
        err = capfd.readouterr().err
        assert "BAWBEL_TEST_MISSING" in err
        assert "value-that-must-not-be-printed" not in err
        assert "BAWBEL_TEST_MISSING" not in names

    def test_the_audit_log_holds_no_value(self, tmp_path, monkeypatch):
        monkeypatch.setenv("BAWBEL_TEST_DECLARED", "value-that-must-not-be-logged")
        _probe(tmp_path, DECLARED_MANIFEST)
        log = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert "value-that-must-not-be-logged" not in log

    def test_the_probe_runs_in_a_subprocess_so_the_test_environment_is_not_the_answer(self):
        """A control: the test process itself does see the variable it just set."""
        env = {"BAWBEL_TEST_SECRET": "x"}
        out = subprocess.run(
            [sys.executable, "-I", "-c", "import os; print('BAWBEL_TEST_SECRET' in os.environ)"],
            env=env, capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert out == "True"
