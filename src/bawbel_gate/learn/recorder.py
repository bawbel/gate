"""Learning mode recorder: observe-only recording of tool usage and arg shapes.

Records tool calls without enforcement. Output is a JSONL observations file
consumed by `learn report` and `learn synthesize`. See DESIGN.md 7.5.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ArgObservation:
    """Observed argument value shape for one call."""
    arg_path: str        # dotted path, e.g. "base_repo"
    value_type: str      # "str" | "int" | "bool" | "list" | "dict" | "null"
    sample_prefix: str   # first 32 chars of stringified value (no secrets)
    sample_len: int      # byte length of the raw value


@dataclass
class ToolObservation:
    """Aggregated observations for one (server, tool) pair."""
    server: str
    tool: str
    call_count: int                          = 0
    arg_observations: list[ArgObservation]   = field(default_factory=list)
    last_seen: str                           = ""


class LearnRecorder:
    """Thread-safe in-memory recorder flushed to JSONL on demand."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tools: dict[tuple[str, str], ToolObservation] = {}

    def record_call(self, server: str, tool: str, args: dict[str, Any]) -> None:
        key = (server, tool)
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if key not in self._tools:
                self._tools[key] = ToolObservation(server=server, tool=tool)
            obs = self._tools[key]
            obs.call_count += 1
            obs.last_seen = ts
            for path, value in _flatten_args(args):
                obs.arg_observations.append(ArgObservation(
                    arg_path=path,
                    value_type=_type_name(value),
                    sample_prefix=str(value)[:32],
                    sample_len=len(str(value).encode("utf-8")),
                ))

    def all_observations(self) -> list[ToolObservation]:
        with self._lock:
            return list(self._tools.values())

    def flush(self, path: Path) -> None:
        """Append current observations to a JSONL file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, path.open("a", encoding="utf-8") as fh:
            for obs in self._tools.values():
                fh.write(json.dumps(_obs_to_dict(obs), ensure_ascii=False) + "\n")


def _flatten_args(args: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    """Flatten nested args dict to (dotted_path, value) pairs (max depth 3)."""
    result = []
    for k, v in args.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict) and len(path.split(".")) < 3:
            result.extend(_flatten_args(v, path))
        else:
            result.append((path, v))
    return result


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    return type(value).__name__


def _obs_to_dict(obs: ToolObservation) -> dict:
    return {
        "server": obs.server,
        "tool": obs.tool,
        "call_count": obs.call_count,
        "last_seen": obs.last_seen,
        "arg_observations": [
            {
                "arg_path": a.arg_path,
                "value_type": a.value_type,
                "sample_prefix": a.sample_prefix,
                "sample_len": a.sample_len,
            }
            for a in obs.arg_observations
        ],
    }
