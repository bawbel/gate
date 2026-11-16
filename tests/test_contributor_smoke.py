"""Tests for scripts/contributor_smoke.sh in its --list mode.

--list prints the commands the script would run, read from CONTRIBUTING.md, without
installing or running anything, so these tests need no network. The full run is the weekly
`contributor-smoke` workflow.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "contributor_smoke.sh"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None, reason="the script needs bash"
)


def _run(*args: str, document: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if document is not None:
        env["CONTRIBUTING_FILE"] = str(document)
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell
        ["bash", str(SCRIPT), *args],  # noqa: S607
        capture_output=True, text=True, env=env, timeout=60, check=False,
    )


def _documented_commands(text: str, section: str) -> list[str]:
    """The commands in the fenced blocks of `## <section>`, found without the script's awk."""
    body = re.search(rf"^## {re.escape(section)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    assert body, f"no '## {section}' in the document"
    commands: list[str] = []
    for block in re.findall(r"```[a-z]*\n(.*?)```", body.group(1), re.S):
        for line in block.splitlines():
            line = re.sub(r"\s+#.*$", "", line)
            if line.strip() and not line.lstrip().startswith("#"):
                commands.append(line.strip())
    return commands


class TestListMode:
    def test_it_lists_the_documented_commands_in_order(self):
        result = _run("--list")
        assert result.returncode == 0, result.stderr
        text = CONTRIBUTING.read_text(encoding="utf-8")
        expected = _documented_commands(text, "Setup") + _documented_commands(
            text, "Development loop"
        )
        listed = [re.sub(r"^step \d+ \[[^\]]+\] ", "", line) for line in result.stdout.splitlines()]
        assert listed == expected
        assert len(expected) >= 5

    def test_the_steps_are_numbered_and_tagged_with_their_section(self):
        lines = _run("--list").stdout.splitlines()
        assert re.fullmatch(r"step 1 \[Setup\] git clone \S+", lines[0])
        numbers = [int(re.match(r"step (\d+) ", line).group(1)) for line in lines]
        assert numbers == list(range(1, len(lines) + 1))
        assert any("[Development loop] pytest" in line for line in lines)

    def test_the_documented_lint_directory_exists(self):
        """CONTRIBUTING.md once named a manifests/ directory that the repository does not have."""
        text = CONTRIBUTING.read_text(encoding="utf-8")
        lint = [c for c in _documented_commands(text, "Development loop") if " lint " in c]
        assert lint, "the development loop documents no `bawbel-gate lint` command"
        for command in lint:
            directory = command.split(" lint ", 1)[1].split()[0]
            assert (REPO_ROOT / directory).is_dir(), f"`{command}`: {directory} does not exist"


class TestBrokenDocuments:
    def _doc(self, tmp_path: Path, text: str) -> Path:
        path = tmp_path / "CONTRIBUTING.md"
        path.write_text(text, encoding="utf-8")
        return path

    GOOD_SETUP = "## Setup\n\n```bash\ngit clone https://example.invalid/x.git\ncd x\n```\n\n"

    def test_a_missing_section_fails_and_names_it(self, tmp_path):
        result = _run("--list", document=self._doc(tmp_path, self.GOOD_SETUP))
        assert result.returncode == 1
        assert "Development loop" in result.stderr

    def test_a_section_with_no_fenced_block_fails(self, tmp_path):
        text = self.GOOD_SETUP + "## Development loop\n\nRun the tests.\n"
        result = _run("--list", document=self._doc(tmp_path, text))
        assert result.returncode == 1
        assert "Development loop" in result.stderr

    def test_a_section_whose_block_is_only_comments_fails(self, tmp_path):
        text = self.GOOD_SETUP + "## Development loop\n\n```bash\n# run the tests\n```\n"
        result = _run("--list", document=self._doc(tmp_path, text))
        assert result.returncode == 1

    def test_comments_and_blank_lines_are_dropped_and_commands_are_kept_verbatim(self, tmp_path):
        text = (
            self.GOOD_SETUP
            + "## Development loop\n\n```bash\n# a comment\n\npytest -q   # trailing note\n"
            + "pre-commit run --all-files\n```\n"
        )
        result = _run("--list", document=self._doc(tmp_path, text))
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines()[-2:] == [
            "step 3 [Development loop] pytest -q",
            "step 4 [Development loop] pre-commit run --all-files",
        ]

    def test_a_renamed_command_is_listed_as_written(self, tmp_path):
        """The run then fails at that step; --list shows the step it will fail on."""
        text = self.GOOD_SETUP + "## Development loop\n\n```bash\npytestt tests/replay/\n```\n"
        result = _run("--list", document=self._doc(tmp_path, text))
        assert "step 3 [Development loop] pytestt tests/replay/" in result.stdout

    def test_a_missing_document_fails(self, tmp_path):
        result = _run("--list", document=tmp_path / "nope.md")
        assert result.returncode == 1
        assert "cannot read" in result.stderr

    def test_an_unknown_argument_fails(self):
        result = _run("--frobnicate")
        assert result.returncode == 1
        assert "unknown argument" in result.stderr
