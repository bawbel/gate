"""bawbel-gate lint warns about declarations the gate does not enforce.

See DESIGN.md 2.2 and 11.5, issue #42. The warning code is W-UNENFORCED. It is a warning
only: the exit code does not change.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from bawbel_gate.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "lint_unenforced"
CORPUS_MANIFESTS = Path(__file__).parent / "corpus" / "manifests"
CODE = "W-UNENFORCED"

# fixture file -> the text the warning must contain to name the declared field
DECLARATIONS = {
    "binary_integrity.cap.yaml": "subject.binary_integrity",
    "watch_binary.cap.yaml": "integrity_watch[0]",
    "watch_remote_resource.cap.yaml": "integrity_watch[0]",
}


def _lint(directory: Path, *extra: str):
    return CliRunner().invoke(main, ["lint", str(directory), *extra])


def _only(tmp_path: Path, fixture: str) -> Path:
    """A directory that holds a single manifest, so the output is about that manifest."""
    directory = tmp_path / fixture.removesuffix(".cap.yaml")
    directory.mkdir()
    shutil.copy(FIXTURES / fixture, directory / fixture)
    return directory


def _warnings(output: str) -> list[str]:
    return [line for line in output.splitlines() if CODE in line]


class TestWarnsOnDeclaredButUnenforced:
    @pytest.mark.parametrize("fixture", sorted(DECLARATIONS))
    def test_each_field_produces_exactly_one_warning(self, tmp_path, fixture):
        result = _lint(_only(tmp_path, fixture))
        found = _warnings(result.output)
        assert len(found) == 1, result.output
        assert fixture in found[0]

    @pytest.mark.parametrize("fixture", sorted(DECLARATIONS))
    def test_the_warning_names_the_field_and_the_issue(self, tmp_path, fixture):
        found = _warnings(_lint(_only(tmp_path, fixture)).output)[0]
        assert DECLARATIONS[fixture] in found
        assert "#42" in found

    def test_the_kind_is_named_for_a_watch(self, tmp_path):
        # Look only at the text after the code: the fixture file names contain the kinds too.
        remote = _warnings(_lint(_only(tmp_path, "watch_remote_resource.cap.yaml")).output)[0]
        binary = _warnings(_lint(_only(tmp_path, "watch_binary.cap.yaml")).output)[0]
        assert "remote_resource" in remote.split(CODE, 1)[1]
        assert "binary" in binary.split(CODE, 1)[1]

    def test_one_warning_per_declaration(self, tmp_path):
        manifest = yaml.safe_load((FIXTURES / "tool_schema_only.cap.yaml").read_text())
        manifest["subject"]["binary_integrity"] = "sha256:" + "b" * 64
        manifest["integrity_watch"] = [
            {"kind": "remote_resource", "on_drift": "suspend"},
            {"kind": "tool_schema", "on_drift": "suspend"},
            {"kind": "remote_resource", "on_drift": "deny"},
            {"kind": "binary", "on_drift": "suspend"},
        ]
        (tmp_path / "many.cap.yaml").write_text(yaml.safe_dump(manifest))
        found = _warnings(_lint(tmp_path).output)
        assert len(found) == 4, found
        assert sum("integrity_watch[0]" in w for w in found) == 1
        assert sum("integrity_watch[2]" in w for w in found) == 1
        assert sum("integrity_watch[3]" in w for w in found) == 1
        assert sum("subject.binary_integrity" in w for w in found) == 1
        assert not any("integrity_watch[1]" in w for w in found)  # the tool_schema entry


class TestNoWarningWhenNothingIsDeclared:
    def test_a_manifest_with_only_a_tool_schema_watch_has_no_warning(self, tmp_path):
        result = _lint(_only(tmp_path, "tool_schema_only.cap.yaml"))
        assert _warnings(result.output) == []
        assert result.exit_code == 0

    def test_the_corpus_manifests_have_no_warning(self):
        result = _lint(CORPUS_MANIFESTS)
        assert _warnings(result.output) == []
        assert result.exit_code == 0


class TestExitCodeAndOkLineAreUnchanged:
    @pytest.mark.parametrize("fixture", sorted(DECLARATIONS))
    def test_the_ok_line_is_still_printed(self, tmp_path, fixture):
        result = _lint(_only(tmp_path, fixture))
        assert f"ok   {fixture}" in result.output.splitlines()

    @pytest.mark.parametrize("fixture", sorted(DECLARATIONS))
    def test_the_exit_code_is_the_same_as_without_the_field(self, tmp_path, fixture):
        with_field = _lint(_only(tmp_path, fixture))
        without = _lint(_only(tmp_path, "tool_schema_only.cap.yaml"))
        assert with_field.exit_code == without.exit_code == 0

    @pytest.mark.parametrize("fixture", sorted(DECLARATIONS))
    def test_a_forbid_effect_failure_still_exits_1(self, tmp_path, fixture):
        # Every fixture grants get_item with effect allow, so this fails with or without
        # the declared field. The warning must not change that result.
        with_field = _lint(_only(tmp_path, fixture), "--forbid-effect", "allow")
        without = _lint(_only(tmp_path, "tool_schema_only.cap.yaml"), "--forbid-effect", "allow")
        assert with_field.exit_code == without.exit_code == 1
        assert "forbidden effect 'allow'" in with_field.output

    def test_a_schema_error_still_exits_1(self, tmp_path):
        manifest = yaml.safe_load((FIXTURES / "binary_integrity.cap.yaml").read_text())
        manifest["subject"]["binary_integrity"] = "not-a-sha256"
        (tmp_path / "bad.cap.yaml").write_text(yaml.safe_dump(manifest))
        result = _lint(tmp_path)
        assert result.exit_code == 1
        assert "FAIL bad.cap.yaml" in result.output
