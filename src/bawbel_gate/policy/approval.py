"""Terminal approval channel for bawbel-gate. See DESIGN.md 7.5.

Called by the mux layer when resolve() returns EFFECT_APPROVE.
Presents a full-context prompt (tool, secret-redacted args, taint context,
AVE IDs) and waits for a y/n keystroke with a hard timeout -> deny.
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Callable

from bawbel_gate._const import (
    APPROVAL_TIMEOUT_DEFAULT_S,
    REASON_APPROVAL_DENIED,
    REASON_APPROVAL_TIMEOUT,
)
from bawbel_gate.audit.canonical import canonical_str
from bawbel_gate.policy.manifest import _secret_scan

_GRANT_RESPONSES = frozenset({"y", "yes"})
_DENY_RESPONSES  = frozenset({"n", "no"})

_REDACTED = "<redacted:secret>"


def _redact_args(args: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact strings that look like secrets."""
    if isinstance(args, dict):
        return {k: _redact_args(v) for k, v in args.items()}
    if isinstance(args, list):
        return [_redact_args(v) for v in args]
    if isinstance(args, str) and _secret_scan(args):
        return _REDACTED
    return args


def _format_prompt(
    tool: str,
    args: dict[str, Any],
    taint_classes: set[str],
    reason: str,
    ave: list[str],
    timeout_s: int,
) -> str:
    redacted = _redact_args(args)
    lines = [
        "=" * 72,
        "bawbel-gate: APPROVAL REQUIRED",
        "=" * 72,
        f"  Tool:    {tool}",
        f"  Args:    {canonical_str(redacted)}",
        f"  Reason:  {reason}",
        f"  Taint:   {', '.join(sorted(taint_classes)) or '(none)'}",
        f"  AVE:     {', '.join(ave) or '(none)'}",
        f"  Timeout: {timeout_s}s -> deny",
        "=" * 72,
        "Grant? [y/N]: ",
    ]
    return "\n".join(lines[:-1]) + "\n" + lines[-1]


def request_approval(
    tool: str,
    args: dict[str, Any],
    taint_classes: set[str],
    reason: str,
    ave: list[str],
    *,
    timeout_s: int = APPROVAL_TIMEOUT_DEFAULT_S,
    output_fn: Callable[[str], None] | None = None,
    input_fn: Callable[[], str] | None = None,
) -> str:
    """Block waiting for human approval. Return REASON_APPROVAL_DENIED or empty string.

    Returns:
        Empty string "" if approved (proceed).
        REASON_APPROVAL_DENIED if the operator denied.
        REASON_APPROVAL_TIMEOUT if the timeout expired.
    """
    out = output_fn or (lambda msg: sys.stderr.write(msg))  # noqa: E731
    inp = input_fn

    prompt = _format_prompt(tool, args, taint_classes, reason, ave, timeout_s)
    out(prompt)

    if inp is not None:
        # Injected function for tests; no timeout applied (caller controls it)
        raw = inp().strip().lower()
        if raw in _GRANT_RESPONSES:
            return ""
        return REASON_APPROVAL_DENIED

    # Real terminal path with timeout
    response_holder: list[str] = []
    done = threading.Event()

    def _read() -> None:
        try:
            line = sys.stdin.readline()
            response_holder.append(line.strip().lower())
        finally:
            done.set()

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    granted = done.wait(timeout=timeout_s)

    if not granted:
        out("\nbawbel-gate: approval timeout — denied\n")
        return REASON_APPROVAL_TIMEOUT

    raw = response_holder[0] if response_holder else ""
    if raw in _GRANT_RESPONSES:
        return ""
    out("bawbel-gate: denied by operator\n")
    return REASON_APPROVAL_DENIED
