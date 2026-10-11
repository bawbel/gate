"""Drive mux/proxy.py run_enforce() with in-memory host streams.

Shared by tests/test_mux_proxy.py and tests/replay/test_mcp_surface.py.
"""

from __future__ import annotations

import io
import json
from typing import Callable

from bawbel_gate.console.state import ConsoleState
from bawbel_gate.mux.config import GateConfig
from bawbel_gate.mux.proxy import run_enforce


def run_enforce_session(
    cfg: GateConfig,
    messages: list[dict],
    *,
    console_state: ConsoleState | None = None,
    approval_input_fn: Callable[[], str] | None = None,
) -> list[dict]:
    """Feed messages to run_enforce() as the host; return every message sent to the host."""
    host_in = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    host_out = io.StringIO()
    run_enforce(
        cfg,
        console_state=console_state,
        host_in=host_in,
        host_out=host_out,
        approval_input_fn=approval_input_fn,
    )
    return [json.loads(line) for line in host_out.getvalue().splitlines()]


def empty_console_state(cfg: GateConfig) -> ConsoleState:
    """A ConsoleState that exposes the live SessionState to the test after the run."""
    return ConsoleState(
        sessions={}, manifests={}, audit_log=cfg.audit_log,
        started_at="2026-01-01T00:00:00Z", config_sha256="sha256:" + "0" * 64,
    )
