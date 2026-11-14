"""The I6 scan: canonical JSON is written in audit/canonical.py and nowhere else.

Invariant I6 (see DESIGN.md 8.6 and CLAUDE.md): no module other than
`bawbel_gate/audit/canonical.py` may call json.dumps with `sort_keys=True`.

The scan reads `.py` files with pathlib, so it does not depend on the platform's grep or on the
working directory. It excludes one file, by its path relative to src/, and no line of text.
"""

from __future__ import annotations

from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
CANONICAL = "bawbel_gate/audit/canonical.py"
NEEDLE = "sort_keys=True"


def find_hits(src_root: Path = SRC_ROOT) -> list[str]:
    """`path:line: text` for each line in a .py file under src_root that contains NEEDLE.

    The one file allowed to contain it, CANONICAL, is skipped. The scan fails when it would
    otherwise pass by scanning nothing: no .py file under src_root, or no CANONICAL.
    """
    files = sorted(src_root.rglob("*.py"))
    assert files, f"no .py files under {src_root}: the I6 scan would pass without scanning"
    assert (src_root / CANONICAL).is_file(), f"{CANONICAL} not found under {src_root}"
    hits = []
    for path in files:
        rel = path.relative_to(src_root).as_posix()
        if rel == CANONICAL:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if NEEDLE in line:
                hits.append(f"{rel}:{number}: {line.strip()}")
    return hits


def assert_no_hits(src_root: Path = SRC_ROOT) -> None:
    hits = find_hits(src_root)
    assert not hits, "sort_keys=True found outside canonical.py:\n" + "\n".join(hits)
