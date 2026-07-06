"""Canonical JSON serialization for hashing and pinning.

This is the ONLY place in the codebase that serialises JSON for hashing.
Never call json.dumps(sort_keys=True) anywhere else — see CLAUDE.md and
invariant I6 in references/invariants.md.

Canonical form: sorted keys, UTF-8, LF line endings, no insignificant
whitespace, arrays order-preserved. Output is bytes for direct use in
hashlib calls.
"""

import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Serialise obj to canonical JSON bytes (sorted keys, compact, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_str(obj: Any) -> str:
    """Serialise obj to canonical JSON string (sorted keys, compact)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
