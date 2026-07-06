"""Tool schema pinning and drift detection. See DESIGN.md 8.1.

Canonical form: JSON with sorted keys, UTF-8, arrays order-preserved,
then sha256. All hashing goes through audit/canonical.py (I6).

Tools are sorted by name before hashing to make the hash order-independent.
The sort is stable so tool lists that differ only in order hash identically,
making it impossible for a server to trigger false drift by reordering.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from bawbel_gate._const import AUDIT_HASH_PREFIX
from bawbel_gate.audit.canonical import canonical_bytes


def pin_tool_schema(tools: list[dict[str, Any]]) -> str:
    """Compute the canonical sha256 pin for a tools/list response.

    Tools are sorted by name for order-independence. Key order within each
    tool object is normalised by canonical_bytes (sorted keys).
    """
    sorted_tools = sorted(tools, key=lambda t: t.get("name", ""))
    payload = canonical_bytes(sorted_tools)
    digest = hashlib.sha256(payload).hexdigest()
    return f"{AUDIT_HASH_PREFIX}{digest}"


def check_pin(tools: list[dict[str, Any]], stored_pin: str) -> bool:
    """Return True if the tools list matches the stored pin."""
    return pin_tool_schema(tools) == stored_pin


@dataclass(frozen=True)
class DriftResult:
    drifted: bool
    current_hash: str
    stored_hash: str

    @property
    def changed_tools(self) -> list[str]:
        """Placeholder for a per-tool diff — computed externally when needed."""
        return []


def detect_drift(tools: list[dict[str, Any]], stored_pin: str) -> DriftResult:
    """Return a DriftResult describing whether the current tools match the pin."""
    current = pin_tool_schema(tools)
    return DriftResult(
        drifted=current != stored_pin,
        current_hash=current,
        stored_hash=stored_pin,
    )
