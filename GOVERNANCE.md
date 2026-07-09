# Governance

## Maintainer model

bawbel-gate is solo-maintained (see CLAUDE.md). One person has commit and release
authority. This is a statement of current fact, not an aspiration: there is a
bus-factor of one, and anyone relying on this project in production should weigh
that against the Apache-2.0 warranty disclaimer.

## Decision authority

- **DESIGN.md is normative.** No code change may make behavior diverge from it. A
  behavior change is a DESIGN.md change first, reviewed and merged on its own, then
  a separate implementation PR (CONTRIBUTING.md). This applies to the maintainer's
  own changes as much as anyone else's; there is no side channel that skips the
  spec.
- The maintainer has final say on what merges. Disagreement is worked out in the
  PR or issue thread; there is no separate escalation body while this is a
  single-maintainer project.
- Security-invariant changes (anything touching `policy/`, `taint/`, `audit/`,
  `integrity/`) are held to the fixed rules in
  `.claude/skills/gate-implementation/references/invariants.md`, not to maintainer
  discretion. An invariant does not get relaxed by decree; it gets relaxed by a
  DESIGN.md revision that says so explicitly, with the reasoning recorded.

## Adding maintainers

Not ruled out, not yet done. If a second maintainer joins, this document gets
rewritten before they get merge rights, covering at minimum: how disagreements
between maintainers resolve, and who can override whom on a DESIGN.md change.
Until that rewrite happens, there is exactly one person to ask.

## Release authority

Releases are cut by the maintainer from `main`. Pre-1.0, there is no fixed cadence;
see SECURITY.md's supported-versions table for what that means for security fixes.

## Scope relative to other bawbel repos

This document covers `bawbel-gate` only. `ave`, `bawbel-scanner`, `PiranhaDB`, and
`bawbel-hub` (once split out, see ARCHITECTURE.md Layer 5a) are separate
repositories with their own governance, even where they share a maintainer today.
A decision made here does not bind them, and vice versa.

## Code of Conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Reports go to the same address as
security disclosures (SECURITY.md) unless that document says otherwise.
