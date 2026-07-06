"""harden --ave: merge an AVE mitigation stanza into a capability manifest.

See DESIGN.md 11.5. Refuses to merge unreviewed stanzas unless --allow-unreviewed
is passed. Shows a unified diff before writing.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from bawbel_gate._const import REVIEW_STATUS_REVIEWED


class HardenError(ValueError):
    """Raised when harden cannot proceed (unreviewed stanza, missing record, etc.)."""


@dataclass
class HardenResult:
    ave_id: str
    manifest_path: Path | None
    diff: str
    review_status: str
    applied: bool


def load_ave_mitigations(mitigations_path: Path) -> dict[str, Any]:
    """Load the ave-mitigations JSON envelope. Returns the mitigations dict keyed by AVE ID."""
    if not mitigations_path.exists():
        raise HardenError(f"mitigations file not found: {mitigations_path}")
    raw = json.loads(mitigations_path.read_text(encoding="utf-8"))
    return raw.get("mitigations", {})


def load_stanza(ave_id: str, mitigations_path: Path, allow_unreviewed: bool) -> dict[str, Any]:
    """Look up the manifest_stanza for an AVE ID in the mitigations file."""
    mitigations = load_ave_mitigations(mitigations_path)
    if ave_id not in mitigations:
        raise HardenError(f"AVE ID {ave_id!r} not found in {mitigations_path}")
    entry = mitigations[ave_id]
    review_status = entry.get("review_status", "unreviewed")
    if review_status != REVIEW_STATUS_REVIEWED and not allow_unreviewed:
        raise HardenError(
            f"{ave_id}: review_status is {review_status!r}; "
            "pass --allow-unreviewed to proceed with an unreviewed stanza. "
            "Merging unreviewed stanzas is the failure the gate exists to prevent."
        )
    stanza = entry.get("manifest_stanza")
    if not stanza:
        raise HardenError(f"{ave_id}: no manifest_stanza in mitigations entry")
    return stanza


def merge_stanza(manifest_raw: dict[str, Any], stanza: dict[str, Any]) -> dict[str, Any]:
    """Merge a manifest_stanza into a manifest dict. Returns a new dict (no mutation).

    Merge rules (per DESIGN.md 4.2 $defs/manifestStanza):
    - taint_rules: append (deduplicate by content)
    - integrity_watch: append
    - grants.argument_guards: append
    - approval: merge (stanza wins if more restrictive)
    """
    import copy
    result = copy.deepcopy(manifest_raw)

    if "taint_rules" in stanza:
        existing = result.get("taint_rules", [])
        for rule in stanza["taint_rules"]:
            if rule not in existing:
                existing.append(rule)
        result["taint_rules"] = existing

    if "integrity_watch" in stanza:
        existing = result.get("integrity_watch", [])
        for watch in stanza["integrity_watch"]:
            if watch not in existing:
                existing.append(watch)
        result["integrity_watch"] = existing

    if "argument_guards" in stanza:
        grants = result.setdefault("grants", {})
        existing = grants.get("argument_guards", [])
        for guard in stanza["argument_guards"]:
            if guard not in existing:
                existing.append(guard)
        grants["argument_guards"] = existing

    if "approval" in stanza:
        # Stanza approval overrides manifest only if more restrictive; never fail-open
        result["approval"] = _merge_approval(result.get("approval", {}), stanza["approval"])

    return result


def _merge_approval(existing: dict, stanza_approval: dict) -> dict:
    """Merge approval config: take the more restrictive of each field."""
    result = dict(existing)
    for key, val in stanza_approval.items():
        if key == "on_timeout":
            result[key] = "deny"  # always deny; stanza cannot relax this
        elif key == "timeout_seconds":
            # Take the shorter timeout (more restrictive)
            existing_t = result.get("timeout_seconds", 120)
            result[key] = min(existing_t, val)
        else:
            result[key] = val
    return result


def compute_diff(before_yaml: str, after_raw: dict[str, Any], ave_id: str) -> str:
    """Return a unified diff between the current manifest YAML and the hardened version."""
    after_yaml = yaml.dump(after_raw, default_flow_style=False, sort_keys=False)
    lines_before = before_yaml.splitlines(keepends=True)
    lines_after = after_yaml.splitlines(keepends=True)
    return "".join(difflib.unified_diff(
        lines_before, lines_after,
        fromfile=f"manifest (before {ave_id})",
        tofile=f"manifest (after harden --ave {ave_id})",
    ))


def apply_harden(
    ave_id: str,
    manifest_path: Path | None,
    mitigations_path: Path,
    allow_unreviewed: bool,
    write: bool = False,
) -> HardenResult:
    """Core harden logic: load stanza, merge, diff, optionally write.

    If manifest_path is None, returns the diff without writing.
    """
    mitigations = load_ave_mitigations(mitigations_path)
    if ave_id not in mitigations:
        raise HardenError(f"AVE ID {ave_id!r} not found in {mitigations_path}")

    entry = mitigations[ave_id]
    review_status = entry.get("review_status", "unreviewed")
    stanza = load_stanza(ave_id, mitigations_path, allow_unreviewed)

    if manifest_path is None:
        return HardenResult(
            ave_id=ave_id,
            manifest_path=None,
            diff="(no manifest specified — stanza loaded but not applied)",
            review_status=review_status,
            applied=False,
        )

    raw_text = manifest_path.read_text(encoding="utf-8")
    raw = yaml.safe_load(raw_text)
    merged = merge_stanza(raw, stanza)
    diff = compute_diff(raw_text, merged, ave_id)

    if write:
        manifest_path.write_text(
            yaml.dump(merged, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )

    return HardenResult(
        ave_id=ave_id,
        manifest_path=manifest_path,
        diff=diff,
        review_status=review_status,
        applied=write,
    )
