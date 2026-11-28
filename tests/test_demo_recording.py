"""The recording of the demo, examples/demo/demo.cast, is a real asciicast of the right size and
shows the demo's last screens. Written before the recording was made again, so it fails on the
commit that adds it. No network is used.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"
CAST = DEMO / "demo.cast"
SHOWED_TITLE = "What this demo showed"
LIMITS_TITLE = "Limits of this demo"


def _cast() -> tuple[dict, list[list]]:
    lines = CAST.read_text(encoding="utf-8").splitlines()
    return json.loads(lines[0]), [json.loads(line) for line in lines[1:]]


def _text() -> str:
    _, events = _cast()
    return "".join(event[2] for event in events if event[1] == "o").replace("\r\n", "\n")


def test_the_cast_is_a_v2_recording_of_120_by_36_that_ends_after_it_starts():
    header, events = _cast()
    assert header["version"] == 2
    assert (header["width"], header["height"]) == (120, 36)
    assert set(header.get("env", {})) <= {"SHELL", "TERM"}
    times = [event[0] for event in events]
    assert times == sorted(times) and 30 < times[-1] < 60, "about 45 seconds"


def test_the_cast_names_the_demo_and_holds_no_local_path_name_or_warning():
    text = _text()
    assert text.startswith("DEMO. The servers are stubs, not an attack on anything real.")
    for local in ("/home/", "/tmp/", "WARNING", "Engine error"):
        assert local not in text, local


def test_the_cast_ends_with_the_demos_two_last_screens():
    text = _text()
    assert f"== {SHOWED_TITLE} ==" in text and f"== {LIMITS_TITLE} ==" in text
    assert text.index(f"== {SHOWED_TITLE} ==") < text.index(f"== {LIMITS_TITLE} ==")
    assert text.rstrip().endswith("- Windows, or any machine other than the one this ran on.")


def _script_screens() -> str:
    script = (DEMO / "demo.sh").read_text(encoding="utf-8")
    tail = re.search(rf"scene \"{SHOWED_TITLE}\".*", script, flags=re.DOTALL).group(0)
    return "\n".join(re.findall(r"cat <<'TEXT'\n(.*?)\nTEXT\n", tail, flags=re.DOTALL))


def test_the_last_screens_in_the_cast_are_the_ones_in_demo_sh():
    if not (DEMO / "demo.sh").exists():
        pytest.skip("examples/demo/demo.sh is not in this checkout")
    wanted = [line for line in _script_screens().splitlines() if line.strip()]
    shown = _text().splitlines()
    for line in wanted:
        assert line in shown, f"missing from the cast: {line!r}"
