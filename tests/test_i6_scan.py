"""Tests for the I6 scan in tests/i6_scan.py, on temporary trees laid out like src/.

The scan is what test_i6_no_sort_keys_elsewhere and
test_no_inline_sort_keys_outside_canonical call, so these tests show that it fails when it
should, on every platform, from any working directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.i6_scan import CANONICAL, SRC_ROOT, assert_no_hits, find_hits

VIOLATION = "def f(x):\n    return json.dumps(x, sort_keys=True)\n"


def _tree(root: Path, files: dict[str, str | bytes]) -> Path:
    """Write files under root/src and return root/src. canonical.py is always present."""
    src = root / "src"
    files = {CANONICAL: "CANON = 'sort_keys=True is allowed here'\n", **files}
    for rel, content in files.items():
        target = src / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return src


class TestI6ScanFindsViolations:
    def test_a_violation_in_another_module_is_reported_with_file_and_line(self, tmp_path):
        src = _tree(tmp_path, {"bawbel_gate/mux/other.py": VIOLATION})
        assert find_hits(src) == [
            "bawbel_gate/mux/other.py:2: return json.dumps(x, sort_keys=True)"
        ]

    def test_assert_no_hits_fails_on_a_temporary_file_with_the_text(self, tmp_path):
        src = _tree(tmp_path, {"bawbel_gate/_probe.py": VIOLATION})
        with pytest.raises(AssertionError, match="sort_keys=True found outside canonical.py"):
            assert_no_hits(src)

    def test_assert_no_hits_passes_on_a_clean_tree(self, tmp_path):
        assert_no_hits(_tree(tmp_path, {"bawbel_gate/clean.py": "X = 1\n"}))

    def test_every_violation_is_listed_not_only_the_first(self, tmp_path):
        src = _tree(tmp_path, {"bawbel_gate/a.py": VIOLATION, "bawbel_gate/b.py": VIOLATION})
        assert len(find_hits(src)) == 2

    def test_a_violation_in_a_non_ascii_source_file_is_read_and_reported(self, tmp_path):
        text = "# café → " + VIOLATION
        src = _tree(tmp_path, {"bawbel_gate/unicode_note.py": text.encode("utf-8")})
        assert len(find_hits(src)) == 1


class TestI6ScanExclusions:
    def test_canonical_py_at_its_path_is_not_reported(self, tmp_path):
        src = _tree(tmp_path, {CANONICAL: VIOLATION})
        assert find_hits(src) == []

    def test_a_file_named_canonical_py_in_another_directory_is_reported(self, tmp_path):
        src = _tree(tmp_path, {"bawbel_gate/policy/canonical.py": VIOLATION})
        assert len(find_hits(src)) == 1

    def test_a_violating_line_that_mentions_canonical_py_is_still_reported(self, tmp_path):
        line = "x = json.dumps(d, sort_keys=True)  # same as canonical.py\n"
        src = _tree(tmp_path, {"bawbel_gate/other.py": line})
        assert len(find_hits(src)) == 1

    def test_compiled_files_are_not_scanned(self, tmp_path):
        pyc = b"\x00\x01docstring: json.dumps(sort_keys=True)\x00"
        src = _tree(tmp_path, {"bawbel_gate/__pycache__/other.cpython-312.pyc": pyc})
        assert find_hits(src) == []


class TestI6ScanCannotPassVacuously:
    def test_no_python_files_is_an_error_not_a_pass(self, tmp_path):
        empty = tmp_path / "src"
        empty.mkdir()
        with pytest.raises(AssertionError, match="no .py files"):
            find_hits(empty)

    def test_a_missing_directory_is_an_error_not_a_pass(self, tmp_path):
        with pytest.raises(AssertionError, match="no .py files"):
            find_hits(tmp_path / "nowhere")

    def test_a_tree_without_canonical_py_is_an_error(self, tmp_path):
        src = tmp_path / "src"
        (src / "bawbel_gate").mkdir(parents=True)
        (src / "bawbel_gate" / "other.py").write_text("X = 1\n", encoding="utf-8")
        with pytest.raises(AssertionError, match="not found"):
            find_hits(src)

    def test_the_default_root_is_the_repository_src_from_any_working_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        assert (SRC_ROOT / CANONICAL).is_file()
        assert_no_hits()
