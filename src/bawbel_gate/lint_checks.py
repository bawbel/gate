"""Warnings that `bawbel-gate lint` reports for a schema-valid manifest.

See DESIGN.md 2.2 and 11.5. Warnings never change the exit code.
"""

from __future__ import annotations

from bawbel_gate._const import UNENFORCED_WATCH_KINDS


def unenforced_declarations(manifest: dict) -> list[str]:
    """Name each declaration in `manifest` that the gate does not enforce, in file order.

    One entry per declaration: `subject.binary_integrity`, and each `integrity_watch`
    entry whose kind is in UNENFORCED_WATCH_KINDS. `manifest` has already passed the
    capability-manifest schema.
    """
    found: list[str] = []
    if "binary_integrity" in manifest.get("subject", {}):
        found.append("subject.binary_integrity")
    for index, watch in enumerate(manifest.get("integrity_watch", [])):
        if watch.get("kind") in UNENFORCED_WATCH_KINDS:
            found.append(f"integrity_watch[{index}] (kind: {watch['kind']})")
    return found
