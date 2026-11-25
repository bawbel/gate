"""The environment an upstream MCP server starts with. See DESIGN.md 3.4.

It is built, not inherited: a short baseline plus each name the manifest declares in
`environment.allow` that is set in the gate's own environment. Nothing else is passed, and
no value is ever invented, logged or returned in an error.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from bawbel_gate._const import UPSTREAM_ENV_BASELINE_POSIX, UPSTREAM_ENV_BASELINE_WINDOWS


@dataclass(frozen=True)
class UpstreamEnv:
    env: dict[str, str]
    # Declared names that are not set in the gate's environment, in declaration order. Names only.
    missing: tuple[str, ...]


def build_upstream_env(
    allow: Iterable[str],
    environ: Mapping[str, str] | None = None,
    *,
    windows: bool | None = None,
) -> UpstreamEnv:
    """Return the environment for one upstream, and the declared names that were not set.

    Names match exactly on POSIX and without regard to case on Windows. A variable keeps the
    spelling it has in the gate's environment.
    """
    source = os.environ if environ is None else environ
    on_windows = sys.platform == "win32" if windows is None else windows
    baseline = UPSTREAM_ENV_BASELINE_WINDOWS if on_windows else UPSTREAM_ENV_BASELINE_POSIX

    def fold(name: str) -> str:
        return name.upper() if on_windows else name

    by_name = {fold(name): name for name in source}
    env: dict[str, str] = {}
    for wanted in baseline:
        actual = by_name.get(fold(wanted))
        if actual is not None:
            env[actual] = source[actual]

    missing: list[str] = []
    for wanted in allow:
        actual = by_name.get(fold(wanted))
        if actual is None:
            missing.append(wanted)
        else:
            env[actual] = source[actual]
    return UpstreamEnv(env=env, missing=tuple(missing))
