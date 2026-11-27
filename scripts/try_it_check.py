#!/usr/bin/env python3
"""Runs the commands in docs/TRY-IT.md and compares what they print with what the page shows.

A fenced block whose info string is `bash try-it` is a command block, and the next fenced block,
with the info string `text try-it-output`, is the output it must produce. `requires=jq,bawbel` after
`try-it` skips a block (and its output) when one of those programs is not on PATH. Every other
block is prose and is not run.

The commands run in a scratch copy of examples/demo plus docs/examples/try-it, in the order they
appear, so later scenes see what earlier ones wrote. Nothing in the repository is changed, and no
network is used. Standard library only.

    python3 scripts/try_it_check.py                 compare, exit 1 on any difference
    python3 scripts/try_it_check.py --write-outputs  replace each output block with the real output

Hashes, timestamps, session ids, versions and the scanner's scan time are replaced before the
comparison, so a different gate or scanner version does not fail a scene.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "TRY-IT.md"
TIMEOUT_SECONDS = 120

NORMALISE = [
    (re.compile(r"\x1b\[[0-9;]*m"), ""),
    (re.compile(r"sha256:[0-9a-f]{64}"), "sha256:<hash>"),
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<uuid>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+00:00)?"), "<time>"),
    (re.compile(r"bawbel-gate, version \S+"), "bawbel-gate, version <version>"),
    (re.compile(r'"name":"bawbel-gate","version":"[^"]+"'),
     '"name":"bawbel-gate","version":"<version>"'),
    (re.compile(r"Bawbel Scanner v\S+"), "Bawbel Scanner v<version>"),
    (re.compile(r"Scan time:\s+\d+ms"), "Scan time: <n>ms"),
]


@dataclass
class Block:
    scene: str
    command: str
    expected: str
    requires: list[str]
    command_line: int
    output_span: tuple[int, int]  # line indexes of the output block's body in the document


@dataclass
class Result:
    block: Block
    status: str  # "pass", "fail", "skipped"
    actual: str = ""
    detail: str = ""


def parse(text: str) -> list[Block]:
    lines = text.split("\n")
    blocks: list[Block] = []
    scene = ""
    i = 0
    pending: dict | None = None
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            scene = line.lstrip("# ").strip()
        match = re.match(r"^```(\S*)\s*(.*)$", line)
        if match and line.strip() != "```":
            language, rest = match.group(1), match.group(2).split()
            start = i + 1
            end = start
            while end < len(lines) and not lines[end].startswith("```"):
                end += 1
            body = "\n".join(lines[start:end])
            if "try-it" in rest:
                if pending is not None:
                    raise ValueError(
                        f"line {pending['line']}: a try-it command has no try-it-output block")
                requires: list[str] = []
                for token in rest:
                    if token.startswith("requires="):
                        requires = [x for x in token.split("=", 1)[1].split(",") if x]
                pending = {"scene": scene, "command": body, "requires": requires, "line": i + 1}
            elif "try-it-output" in rest:
                if pending is None:
                    raise ValueError(
                        f"line {i + 1}: a try-it-output block with no command before it")
                blocks.append(Block(pending["scene"], pending["command"], body, pending["requires"],
                                    pending["line"], (start, end)))
                pending = None
            i = end
        i += 1
    if pending is not None:
        raise ValueError(f"line {pending['line']}: a try-it command has no try-it-output block")
    return blocks


def normalise(text: str) -> str:
    for pattern, replacement in NORMALISE:
        text = pattern.sub(replacement, text)
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.replace("\r", "").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def make_environment(workdir: Path) -> dict:
    """PATH with a `bawbel-gate` and a `python3` that use the interpreter running this script."""
    bin_dir = workdir / ".bin"
    bin_dir.mkdir(exist_ok=True)
    wrappers = {"python3": f'exec "{sys.executable}" "$@"'}
    if shutil.which("bawbel-gate") is None:
        wrappers["bawbel-gate"] = (
            f'exec "{sys.executable}" -c "from bawbel_gate.cli import main; main()" "$@"')
    for name, body in wrappers.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env.pop("PYTHONPATH", None)
    return env


def prepare(workdir: Path) -> Path | None:
    """Copy the scene files into workdir/try-it. None when examples/demo is not in this checkout."""
    demo = REPO_ROOT / "examples" / "demo"
    if not demo.is_dir():
        return None
    target = workdir / "try-it"
    shutil.copytree(demo, target)
    inputs = REPO_ROOT / "docs" / "examples" / "try-it"
    for item in inputs.iterdir():
        shutil.copy(item, target / item.name)
    return target


def run_blocks(blocks: list[Block], cwd: Path, env: dict) -> list[Result]:
    results: list[Result] = []
    for block in blocks:
        missing = [tool for tool in block.requires if shutil.which(tool, path=env["PATH"]) is None]
        if missing:
            results.append(Result(block, "skipped", detail="not on PATH: " + ", ".join(missing)))
            continue
        try:
            done = subprocess.run(["bash", "-c", block.command], cwd=cwd, env=env, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=TIMEOUT_SECONDS, check=False)
            actual = done.stdout
        except subprocess.TimeoutExpired:
            results.append(Result(block, "fail", detail=f"timed out after {TIMEOUT_SECONDS} s"))
            continue
        want, got = normalise(block.expected), normalise(actual)
        if want == got:
            results.append(Result(block, "pass", actual=actual))
        else:
            diff = "\n".join(difflib.unified_diff(want.split("\n"), got.split("\n"),
                                                  "shown on the page", "actual", lineterm="", n=2))
            results.append(Result(block, "fail", actual=actual, detail=diff))
    return results


def write_outputs(text: str, results: list[Result]) -> str:
    lines = text.split("\n")
    for result in sorted(results, key=lambda r: r.block.output_span[0], reverse=True):
        if result.status == "skipped":
            continue
        start, end = result.block.output_span
        lines[start:end] = result.actual.rstrip("\n").split("\n")
    return "\n".join(lines)


def check(doc: Path = DOC, update: bool = False) -> tuple[list[Result], str]:
    """Returns the results and a reason string when nothing could be run."""
    text = doc.read_text(encoding="utf-8")
    blocks = parse(text)
    if not blocks:
        return [], "the page has no try-it blocks"
    with tempfile.TemporaryDirectory(prefix="try-it-") as tmp:
        workdir = Path(tmp)
        cwd = prepare(workdir)
        if cwd is None:
            return [], "examples/demo is not in this checkout"
        results = run_blocks(blocks, cwd, make_environment(workdir))
    if update:
        doc.write_text(write_outputs(text, results), encoding="utf-8")
    return results, ""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--doc", type=Path, default=DOC)
    parser.add_argument("--write-outputs", action="store_true")
    parser.add_argument("--require-all", action="store_true",
                        help="fail when a block is skipped or nothing could be run")
    args = parser.parse_args(argv)
    results, reason = check(args.doc, update=args.write_outputs)
    if reason:
        print(f"nothing run: {reason}")
        return 2 if args.require_all else 0
    failed = skipped = 0
    for result in results:
        mark = {"pass": "ok  ", "fail": "FAIL", "skipped": "skip"}[result.status]
        first = result.block.command.strip().split("\n")[0][:70]
        print(f"{mark} {result.block.scene}: {first}")
        if result.status == "fail":
            failed += 1
            print(result.detail)
        elif result.status == "skipped":
            skipped += 1
            print(f"     ({result.detail})")
    print(f"{len(results) - failed - skipped} passed, {failed} failed, {skipped} skipped")
    if failed or (skipped and args.require_all):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
