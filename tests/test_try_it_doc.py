"""docs/TRY-IT.md stays true: its commands are run and their output is compared with the page.

The runner is scripts/try_it_check.py. The tests of the runner always run. The test of the page
needs examples/demo and bash, and skips a block whose program (jq, bawbel) is not installed. No
network is used.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "TRY-IT.md"
CONST = REPO_ROOT / "src" / "bawbel_gate" / "_const.py"
FORM_LINK = "https://github.com/bawbel/gate/issues/new?template=first-run-report.yml"

_script = REPO_ROOT / "scripts" / "try_it_check.py"
_spec = importlib.util.spec_from_file_location("try_it_check", _script)
checker = importlib.util.module_from_spec(_spec)
sys.modules["try_it_check"] = checker
_spec.loader.exec_module(checker)

needs_bash = pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None,
                                reason="the page's commands are bash commands")

PAGE = """# Scene A

```bash try-it
echo hello
```

```text try-it-output
hello
```

## Scene B

```bash try-it requires=no-such-program-here
echo never runs
```

```text try-it-output
never runs
```

```bash
echo not a try-it block
```
"""


def _run(text: str, tmp_path: Path):
    blocks = checker.parse(text)
    return blocks, checker.run_blocks(blocks, tmp_path, dict(os.environ))


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------

def test_parse_pairs_each_command_with_its_output_and_names_the_scene():
    blocks = checker.parse(PAGE)
    assert [(b.scene, b.command, b.expected) for b in blocks] == [
        ("Scene A", "echo hello", "hello"),
        ("Scene B", "echo never runs", "never runs"),
    ]
    assert blocks[1].requires == ["no-such-program-here"]


def test_a_command_with_no_output_block_is_an_error():
    with pytest.raises(ValueError, match="no try-it-output"):
        checker.parse("```bash try-it\necho x\n```\n")
    with pytest.raises(ValueError, match="no command before it"):
        checker.parse("```text try-it-output\nx\n```\n")


@needs_bash
def test_a_matching_block_passes_and_a_missing_program_skips(tmp_path):
    _, results = _run(PAGE, tmp_path)
    assert [r.status for r in results] == ["pass", "skipped"]
    assert "no-such-program-here" in results[1].detail


@needs_bash
def test_a_block_whose_output_differs_fails_with_a_diff(tmp_path):
    _, results = _run(PAGE.replace("\nhello\n```", "\nhullo\n```"), tmp_path)
    assert results[0].status == "fail"
    assert "-hullo" in results[0].detail and "+hello" in results[0].detail


@needs_bash
def test_the_output_includes_standard_error_in_order(tmp_path):
    text = "```bash try-it\necho out; echo err >&2\n```\n\n```text try-it-output\nout\nerr\n```\n"
    assert _run(text, tmp_path)[1][0].status == "pass"


def test_hashes_times_ids_versions_and_spacing_do_not_count_as_differences():
    hash_a, hash_b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    first = (f"bawbel-gate, version 0.1.0\nhead {hash_a}\nat 2026-11-27T10:00:00.123Z\n"
             " Scan time:   20ms \n")
    second = (f"bawbel-gate, version 0.1.1\nhead {hash_b}\nat 2026-11-28T11:11:11Z\n"
              "Scan time: 9ms\n\n")
    assert checker.normalise(first) == checker.normalise(second)
    assert checker.normalise("a") != checker.normalise("b")


@needs_bash
def test_write_outputs_replaces_the_shown_output_with_the_real_one(tmp_path):
    text = PAGE.replace("\nhello\n```", "\nwrong\n```")
    blocks, results = _run(text, tmp_path)
    rewritten = checker.write_outputs(text, results)
    assert "wrong" not in rewritten and "hello" in rewritten
    assert "never runs" in rewritten, "a skipped block keeps what the page shows"


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------

@needs_bash
def test_the_commands_on_the_page_give_the_output_it_shows():
    results, reason = checker.check(DOC)
    if reason:
        pytest.skip(reason)
    failures = [r for r in results if r.status == "fail"]
    assert not failures, "\n\n".join(f"{r.block.scene}\n{r.detail}" for r in failures)
    assert any(r.status == "pass" for r in results)


# The words the page must not use. They are joined from parts, so that this file does not itself
# contain them.
def _words(*parts: str) -> str:
    return r"\b(" + "|".join(parts) + r")\b"


MUST_NOT_USE = _words("sa" + "fe", "sa" + "fely", "sec" + "ure", "sec" + "ured", "certi" + "fied",
                      "audi" + "ted", "tamper" + "-proof", "tamper" + "-evident",
                      "non" + "-bypassable")
NO_PRICING = r"(\$\s?\d|" + _words("pri" + "cing", "pri" + "ce", "pa" + "id", "sub" + "scription",
                                     "free " + "tier") + ")"


def test_the_page_has_no_dash_character_and_none_of_the_words_it_must_not_use():
    text = DOC.read_text(encoding="utf-8")
    assert chr(0x2014) not in text and chr(0x2013) not in text
    assert not re.search(MUST_NOT_USE, text, flags=re.IGNORECASE)
    assert not re.search(r"\bv1\." + "0" + r"\b", text, flags=re.IGNORECASE)
    assert not re.search(NO_PRICING, text, flags=re.IGNORECASE)


def test_the_event_counts_on_the_page_match_the_code():
    const = CONST.read_text(encoding="utf-8")
    defined = set(re.findall(r"^EVENT_([A-Z_]+)\s*=", const, flags=re.MULTILINE))
    assert len(defined) == 11, sorted(defined)
    written = set()
    for path in (REPO_ROOT / "src" / "bawbel_gate").rglob("*.py"):
        written |= set(re.findall(r'"event":\s*EVENT_([A-Z_]+)', path.read_text(encoding="utf-8")))
    assert written == {"SESSION_START", "CALL_DECIDED", "DRIFT_DETECTED", "SESSION_END",
                       "SESSION_CLEAR"}
    text = DOC.read_text(encoding="utf-8")
    assert "11 event types and writes five" in text
    for name in written:
        assert f"`{name}`" in text


def test_the_page_ends_by_linking_the_first_run_form():
    text = DOC.read_text(encoding="utf-8")
    assert FORM_LINK in text
    assert text.index(FORM_LINK) > text.index("## Limits")
