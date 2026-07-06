"""Manifest dataclasses and loader.

Validates YAML manifests against the capability-manifest/v1 JSON Schema and
builds typed, immutable dataclasses for the policy engine to consume.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from bawbel_gate._const import (
    EFFECT_DENY,
    SCHEMA_CAPABILITY_MANIFEST_V1,
    TRIFECTA_EXTERNAL_COMMS,
    TRIFECTA_PRIVATE_DATA,
    TRIFECTA_UNTRUSTED_CONTENT,
)
from bawbel_gate._schemas import schema_capability_manifest
from bawbel_gate._types import Effect


@dataclass(frozen=True)
class Condition:
    """A single predicate on one argument path (dotted notation)."""
    arg_path: str
    pattern: str | None    = None
    equals: Any            = None
    one_of: list | None    = None
    max_bytes: int | None  = None

    def matches(self, args: dict[str, Any]) -> bool:
        value = _dotpath_get(args, self.arg_path)
        if value is None:
            return False
        if self.pattern is not None:
            return fnmatch.fnmatch(str(value), self.pattern)
        if self.equals is not None:
            return value == self.equals
        if self.one_of is not None:
            return value in self.one_of
        if self.max_bytes is not None:
            return len(str(value).encode("utf-8")) <= self.max_bytes
        return True


@dataclass(frozen=True)
class ToolGrant:
    name: str
    effect: Effect
    conditions: list[Condition] = field(default_factory=list)

    def conditions_ok(self, args: dict[str, Any]) -> bool:
        return all(c.matches(args) for c in self.conditions)


@dataclass(frozen=True)
class TaintRule:
    actions: list[dict[str, Any]]          # [{tool|tools_with, effect}]
    tainted_by_any: list[str] = field(default_factory=list)
    tainted_by_all: list[str] = field(default_factory=list)

    def matches_session(self, tainted_by: set[str]) -> bool:
        if self.tainted_by_any:
            if not any(_class_matches(t, tainted_by) for t in self.tainted_by_any):
                return False
        if self.tainted_by_all:
            if not all(_class_matches(t, tainted_by) for t in self.tainted_by_all):
                return False
        return True

    def effect_for(self, tool: str, trifecta: dict[str, bool]) -> Effect | None:
        """Return the most restrictive effect from matching actions, or None."""
        from bawbel_gate.policy.engine import lattice_min
        result: Effect | None = None
        for action in self.actions:
            if "tool" in action and action["tool"] != tool:
                continue
            if "tools_with" in action:
                cap = action["tools_with"]
                if not trifecta.get(cap, False):
                    continue
            eff = action["effect"]
            result = eff if result is None else lattice_min(result, eff)
        return result


@dataclass(frozen=True)
class ArgumentGuard:
    applies_to: str
    outbound_secret_scan: bool = True
    max_outbound_bytes: int | None = None

    def applies(self, tool: str) -> bool:
        return self.applies_to == "*" or fnmatch.fnmatch(tool, self.applies_to)


@dataclass(frozen=True)
class IntegrityWatch:
    kind: str
    on_drift: str
    url_pattern: str | None  = None
    snapshot_at: str | None  = None
    diff: str | None         = None


@dataclass(frozen=True)
class Manifest:
    server: str
    provenance_class: str
    instruction_authority: str
    trifecta: dict[str, bool]
    grants: list[ToolGrant]
    taint_rules: list[TaintRule]  = field(default_factory=list)
    argument_guards: list[ArgumentGuard] = field(default_factory=list)
    integrity_watch: list[IntegrityWatch] = field(default_factory=list)
    manifest_sha256: str | None  = None

    def match_grant(self, tool: str) -> ToolGrant | None:
        """Exact name match beats wildcard; two exact matches = validation error."""
        exact = [g for g in self.grants if g.name == tool]
        if exact:
            return exact[0]
        wildcard = [g for g in self.grants if g.name == "*"]
        return wildcard[0] if wildcard else None

    def guard_violation(self, tool: str, args: dict[str, Any]) -> str | None:
        """Return violation reason string or None. Scans all args of matching guards."""
        for guard in self.argument_guards:
            if not guard.applies(tool):
                continue
            for val in _all_string_values(args):
                if guard.max_outbound_bytes and len(val.encode("utf-8")) > guard.max_outbound_bytes:
                    return "byte_cap"
                if guard.outbound_secret_scan and _secret_scan(val):
                    return "secret_scan"
        return None


class ManifestError(ValueError):
    """Raised when a manifest fails schema or semantic validation."""


def load_manifest(path: Path, server_name: str) -> Manifest:
    """Load and validate a capability manifest YAML file."""
    raw_text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(raw_text)
    if not isinstance(raw, dict):
        raise ManifestError(f"{path}: must be a YAML mapping")
    _validate_schema(raw, path)
    _validate_semantics(raw, path)
    return _build(raw, server_name, raw_text)


def _validate_schema(raw: dict, path: Path) -> None:
    schema = schema_capability_manifest()
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(raw), key=lambda e: str(e.path))
    if errors:
        msgs = "; ".join(f"{e.json_path}: {e.message}" for e in errors[:3])
        raise ManifestError(f"{path}: schema validation failed: {msgs}")


def _validate_semantics(raw: dict, path: Path) -> None:
    tools = raw.get("grants", {}).get("tools", [])
    names = [g["name"] for g in tools if g["name"] != "*"]
    if len(names) != len(set(names)):
        raise ManifestError(f"{path}: duplicate exact grant names (F811 analog)")


def _build(raw: dict, server_name: str, raw_text: str) -> Manifest:
    from bawbel_gate.audit.canonical import canonical_bytes
    import hashlib
    sha = "sha256:" + hashlib.sha256(canonical_bytes(raw)).hexdigest()

    trifecta = raw.get("trifecta", {})
    grants_raw = raw.get("grants", {}).get("tools", [])
    guards_raw = raw.get("grants", {}).get("argument_guards", [])
    taint_raw  = raw.get("taint_rules", [])
    watch_raw  = raw.get("integrity_watch", [])

    return Manifest(
        server=server_name,
        provenance_class=raw["provenance_class"],
        instruction_authority=raw["instruction_authority"],
        trifecta=trifecta,
        grants=[_build_grant(g) for g in grants_raw],
        taint_rules=[_build_taint_rule(r) for r in taint_raw],
        argument_guards=[_build_guard(g) for g in guards_raw],
        integrity_watch=[_build_watch(w) for w in watch_raw],
        manifest_sha256=sha,
    )


def _build_grant(raw: dict) -> ToolGrant:
    conditions = []
    for arg_path, pred in (raw.get("conditions") or {}).items():
        conditions.append(Condition(
            arg_path=arg_path.removeprefix("args."),
            pattern=pred.get("pattern"),
            equals=pred.get("equals"),
            one_of=pred.get("one_of"),
            max_bytes=pred.get("max_bytes"),
        ))
    return ToolGrant(name=raw["name"], effect=raw["effect"], conditions=conditions)


def _build_taint_rule(raw: dict) -> TaintRule:
    when = raw.get("when", {})
    return TaintRule(
        tainted_by_any=when.get("tainted_by_any", []),
        tainted_by_all=when.get("tainted_by_all", []),
        actions=raw.get("then", []),
    )


def _build_guard(raw: dict) -> ArgumentGuard:
    return ArgumentGuard(
        applies_to=raw["applies_to"],
        outbound_secret_scan=raw.get("outbound_secret_scan", True),
        max_outbound_bytes=raw.get("max_outbound_bytes"),
    )


def _build_watch(raw: dict) -> IntegrityWatch:
    return IntegrityWatch(
        kind=raw["kind"],
        on_drift=raw["on_drift"],
        url_pattern=raw.get("url_pattern"),
        snapshot_at=raw.get("snapshot_at"),
        diff=raw.get("diff"),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dotpath_get(obj: dict, path: str) -> Any:
    """Resolve 'a.b.c' in a nested dict. Returns None if any segment missing."""
    parts = path.split(".")
    cur: Any = obj
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _all_string_values(obj: Any) -> list[str]:
    """Flatten all string values from a nested dict/list."""
    results = []
    if isinstance(obj, str):
        results.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_all_string_values(v))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_all_string_values(item))
    return results


# Secret detection patterns (see DESIGN.md 5.3)
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),           # AWS access key
    re.compile(r"glpat-[0-9a-zA-Z\-_]{20,}"),  # GitLab PAT
    re.compile(r"hvs\.[0-9A-Za-z]{24,}"),       # Vault token
    re.compile(r"-----BEGIN [A-Z]+ PRIVATE KEY-----"),  # PEM block
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
_ENTROPY_WINDOW = 24
_ENTROPY_THRESHOLD = 4.2


def _secret_scan(value: str) -> bool:
    """Return True if value looks like a secret."""
    for pat in _SECRET_PATTERNS:
        if pat.search(value):
            return True
    if len(value) >= _ENTROPY_WINDOW and _shannon_entropy(value) >= _ENTROPY_THRESHOLD:
        return True
    return False


def _shannon_entropy(s: str) -> float:
    import math
    from collections import Counter
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _class_matches(pattern: str, tainted_by: set[str]) -> bool:
    """Match a taint pattern (may end in *) against the session taint set."""
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return any(cls.startswith(prefix) for cls in tainted_by)
    return pattern in tainted_by
