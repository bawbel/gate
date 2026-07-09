---
name: gate-implementation
description: Implementation rules and testable invariants for writing any code in the bawbel-gate repo. Use this skill whenever writing, reviewing, refactoring, or debugging bawbel-gate code of any size, including the policy engine, effect lattice, taint tracker, trifecta invariant, MCP multiplexer, argument guards, audit chain, integrity pinning, learning mode, console API, or their tests. Also use it when asked to "add a feature", "fix a bug", "write tests", or "review this diff" anywhere in bawbel-gate, even if the request does not mention security or invariants explicitly.
---

# gate-implementation

How code gets written in bawbel-gate. DESIGN.md is the spec; this skill is the
discipline for implementing it without violating its security properties.

## Workflow (always, in order)

1. Read the DESIGN.md section for the component (map in CLAUDE.md). Do not code from
   memory of the spec.
2. Check `references/invariants.md` for invariants touching your change. If any
   apply, write or extend the property test FIRST, watch it fail, then implement.
3. Implement in the smallest diff that satisfies spec + tests.
4. Run `pytest tests/property/ -x`, then the full suite, then
   `pre-commit run --all-files`.
5. If behavior differs from DESIGN.md in any way: stop, propose the DESIGN.md change,
   do not ship the divergence.

## The five things that make a diff wrong even when tests pass

1. An effect that can move UP the lattice under any input.
2. A code path where an unmatched, failed, or erroring call resolves to anything but
   deny.
3. Trifecta enforcement that any configuration can skip.
4. A hash computed on JSON that did not go through `audit/canonical.py`.
5. A decision influenced by tool response CONTENT rather than its provenance class.
   Content is data. Only structure and origin drive decisions.

## Style (enforced by pre-commit; do not fight it)

```python
# BAD: swallowed exception, F-string with no placeholder, split nosec
try:
    cursor.unlink()
except Exception:
    pass
msg = f"cursor removed"
subprocess.run(cmd)  # nosec
# noqa: S603

# GOOD
import contextlib
with contextlib.suppress(FileNotFoundError):
    cursor.unlink()
msg = "cursor removed"
subprocess.run(cmd)  # nosec B603 # noqa: S603  -- args are fixed, not user input
```

```python
# BAD: raising an effect via a "helpful" special case
if manifest.subject.name == "bawbel-mcp":
    effect = Effect.ALLOW  # trusted first-party server

# GOOD: there are no trusted servers; the manifest is the only authority
effect = grant.effect if grant else Effect.DENY
```

## Error strings

Deny reasons come from the closed set in DESIGN.md 6.2 and LANGUAGE.md. Adding a
reason string requires updating the FAQ in the same PR. Every deny that originates
from a merged stanza carries its AVE IDs in `data.ave`.

## When to read the reference file

Read `references/invariants.md` before touching `policy/`, `taint/`, `audit/`, or
`integrity/`, and before reviewing any PR that touches them. It contains the numbered
invariants (I1-I8) with hypothesis test patterns to copy.
