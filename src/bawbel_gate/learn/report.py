"""Learning mode report: per-server used/unused tool table + arg observations.

Reads a JSONL observations file produced by LearnRecorder.flush() and
produces a human-readable text report. See DESIGN.md 7.5.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import TextIO


def render_report(obs_path: Path, out: TextIO) -> None:
    """Read obs_path (JSONL) and write a text report to out."""
    observations = _load(obs_path)
    if not observations:
        out.write("No observations recorded.\n")
        return

    by_server: dict[str, list[dict]] = defaultdict(list)
    for obs in observations:
        by_server[obs["server"]].append(obs)

    for server, tools in sorted(by_server.items()):
        total_calls = sum(t["call_count"] for t in tools)
        out.write(f"\n=== {server} ({len(tools)} tool(s), {total_calls} call(s)) ===\n")
        for tool in sorted(tools, key=lambda t: -t["call_count"]):
            out.write(
                f"  {tool['tool']:40s}  calls={tool['call_count']}  last={tool['last_seen']}\n"
            )
            arg_types: dict[str, set[str]] = defaultdict(set)
            arg_prefixes: dict[str, list[str]] = defaultdict(list)
            for a in tool["arg_observations"]:
                arg_types[a["arg_path"]].add(a["value_type"])
                if a["sample_prefix"]:
                    arg_prefixes[a["arg_path"]].append(a["sample_prefix"])
            for path, types in sorted(arg_types.items()):
                prefixes = sorted(set(arg_prefixes[path]))[:3]
                prefix_str = f"  samples={prefixes}" if prefixes else ""
                out.write(f"    args.{path}: {sorted(types)}{prefix_str}\n")


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records
