"""The demo's own text: its last screens, the demo README that mirrors them, and the lines of
code the README cites. Written before the text was changed, so these fail on the commit that
adds them.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "demo"
PROXY = REPO_ROOT / "src" / "bawbel_gate" / "mux" / "proxy.py"

SHOWED_TITLE = "What this demo showed"
LIMITS_TITLE = "Limits of this demo"

SHOWED = [
    "The scanner reading the stub servers' tool list before anything runs.",
    "Four calls through the gate under a manifest that allows one tool, each one recorded.",
    "A tool description changing after call 3: the gate's second tools/list still shows the text "
    "it took at session start, call 4 goes through, and no DRIFT_DETECTED record is written.",
    "The outbox tool allowed on its own, then stopped with approval_denied after private data and "
    "untrusted text, and nothing written to sink.txt.",
    "audit verify passing over the log of all three sessions.",
]
LIMITS = [
    "A real MCP client or a real MCP server. The driver and the stubs are scripts.",
    "A person answering the approval prompt. Under an MCP client it resolves to deny.",
    "Calls that never reach the gate: a host talking to a server directly, A2A, gRPC, REST, "
    "message brokers, and model traffic. The gate sees MCP calls routed through it, and no more.",
    "A log that was cut at the end, or rewritten with every later hash recomputed: audit verify "
    'passes both (README, "Verifying a log you did not write").',
    "Windows, or any machine other than the one this ran on.",
]
# What the README says about a description that changes during a session, and the line of
# proxy.py each statement rests on: (line range, text that must be on those lines).
CITED = {(152, 153): "_check_drift", (271, 271): "notification", (307, 307): "merged_tools",
         (316, 316): "_handle_tools_call"}


def _bullets(text: str) -> list[str]:
    bullets: list[str] = []
    for line in text.splitlines():
        if line.startswith("- "):
            bullets.append(line[2:].strip())
        elif line.startswith("  ") and bullets:
            bullets[-1] += " " + line.strip()
    return [re.sub(r"\s+", " ", b) for b in bullets]


def _screens() -> dict[str, list[str]]:
    script = (DEMO / "demo.sh").read_text(encoding="utf-8")
    pattern = r"scene \"([^\"]+)\"\ncat <<'TEXT'\n(.*?)\nTEXT\n"
    found = re.findall(pattern, script, flags=re.DOTALL)
    return {title: _bullets(body) for title, body in found}


def _section(title: str) -> str:
    text = (DEMO / "README.md").read_text(encoding="utf-8")
    pattern = rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)"
    match = re.search(pattern, text, flags=re.DOTALL | re.MULTILINE)
    assert match, f"the demo README has no section {title!r}"
    return match.group(1)


def test_the_last_screens_of_demo_sh_say_what_the_demo_showed_and_its_limits():
    screens = _screens()
    assert screens.get(SHOWED_TITLE) == SHOWED
    assert screens.get(LIMITS_TITLE) == LIMITS
    assert list(screens)[-2:] == [SHOWED_TITLE, LIMITS_TITLE], "the limits are the very last screen"


def test_the_demo_readme_mirrors_the_last_screens():
    assert _bullets(_section(SHOWED_TITLE)) == SHOWED
    assert _bullets(_section(LIMITS_TITLE)) == LIMITS


def test_the_readme_section_on_a_changed_description_cites_lines_that_say_what_it_claims():
    section = _section("What the gate does when a tool's description changes during a session")
    citations = re.findall(r"proxy\.py:(\d+)(?:-(\d+))?", section)
    cited = {(int(a), int(b or a)) for a, b in citations}
    assert cited == set(CITED), cited
    lines = PROXY.read_text(encoding="utf-8").splitlines()
    for (first, last), token in CITED.items():
        found = " ".join(lines[first - 1:last])
        assert token in found, f"proxy.py:{first}-{last} no longer has {token}"
    numbered = re.findall(r"^\d+\. \*\*", section, flags=re.MULTILINE)
    assert len(numbered) == 5, "five points: session start, tools/list, notification, calls, records"
    assert "**It does nothing.**" in section


def test_the_readme_names_the_test_that_checks_the_behaviour_it_describes():
    section = _section("What the gate does when a tool's description changes during a session")
    assert "tests/test_demo_driver.py" in section
    assert "checks this behaviour" in section
