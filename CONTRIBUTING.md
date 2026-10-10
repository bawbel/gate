# Contributing to bawbel-gate

DESIGN.md is normative. This file is the workflow for changing code without
violating it.

Participation in this project is governed by our
[Code of Conduct](./CODE_OF_CONDUCT.md). See [GOVERNANCE.md](./GOVERNANCE.md) for
who decides what and how DESIGN.md changes get approved.

## Before you start

1. Read [DESIGN.md](./DESIGN.md) for the section your change touches (map in
   [CLAUDE.md](./CLAUDE.md) if you use Claude Code; the same map applies manually).
2. If your change makes behavior diverge from DESIGN.md in any way, open an issue
   or PR against DESIGN.md first. Do not ship a code change that the spec does not
   describe; the spec is not allowed to drift silently to match the code.
3. If you are touching `policy/`, `taint/`, `audit/`, or `integrity/`, read
   `.claude/skills/gate-implementation/references/invariants.md`. Every invariant
   listed there (I1-I8) has a property test; your change must keep them green or
   explain, in the PR description, exactly which invariant your change redefines
   and why. The property test is written and committed before the
   implementation; see [Property test before implementation](#property-test-before-implementation).

## Issue before PR

Every change starts as an issue, not a PR. Exempt: typo or doc wording fixes under
5 lines, and dependency bumps opened by Dependabot.

1. Open the issue with one of the forms under `.github/ISSUE_TEMPLATE/`. Each form
   records the area the change touches.

   | Form | Use for |
   |---|---|
   | Bug report | behavior that differs from DESIGN.md, a crash, a wrong reason string |
   | Feature request | additive work inside behavior DESIGN.md already specifies |
   | Design change | anything that adds to or changes DESIGN.md |

2. If the change diverges from DESIGN.md, use the Design change form and name the
   section. Per "Before you start", that DESIGN.md PR merges first, on its own.
3. The PR body starts with `Closes #N`, or `Refs #N` when the PR is one of several
   against the same issue. A PR with no linked issue gets asked to open one before
   review starts. This applies to the maintainer's own PRs too (GOVERNANCE.md).

Blank issues are disabled. A security bypass never goes in an issue; see
[SECURITY.md](./SECURITY.md).

## Setup

```bash
git clone https://github.com/bawbel/gate.git
cd gate
pip install -e ".[dev]" --break-system-packages
pre-commit install
```

## Development loop

```bash
pytest                              # full suite
pytest tests/property/ -x           # invariant property tests, stop on first failure
pytest tests/replay/                # scripted attack replays
pre-commit run --all-files          # must be clean before you open a PR
bawbel-gate lint manifests/ --schema capability-manifest/v1
```

## Code style

Enforced by pre-commit, not by review discussion:

- flake8: E501 (100 char limit), F401, F541, F811, E221, E251, E231.
- SIM105: use `contextlib.suppress(...)`, never bare `try`/`except`/`pass`.
- SIM102: flatten nested `if` statements where possible.
- bandit: `nosec` and `noqa` on the same line, with the rule code and a reason,
  e.g. `subprocess.run(cmd)  # nosec B603 # noqa: S603  -- args are fixed, not
  user input`.
- Tests: no duplicate class names across test files; do not `import pytest`
  unless you use `pytest.mark`, `pytest.raises`, or `pytest.param`.

No new lint exceptions without a comment on the same line explaining why. A
reviewer who cannot see the reason will ask for it removed.

## Language

Use the terms in `docs/LANGUAGE.md` exactly: `grant`, `effect`, `taint`,
`trifecta`, `stanza`, and so on have one meaning each across code, docstrings,
error strings, and docs. If your change needs a term that is not in that file,
add it there in the same PR.

## The five things that make a diff wrong even when tests pass

1. An effect that can move up the lattice (`deny -> approve -> allow`) under any
   input.
2. A code path where an unmatched, failed, or erroring call resolves to anything
   but `deny`.
3. Trifecta enforcement that any configuration, flag, or manifest field can skip.
4. A hash computed on JSON that did not go through `audit/canonical.py`.
5. A decision influenced by tool response *content* rather than its provenance
   class. Content is data. Only structure and origin drive decisions.

If your diff does one of these, it will be asked to change regardless of what
else it accomplishes.

## Tests required for merge

| Change touches | Required |
|---|---|
| `policy/`, `taint/` | property test in `tests/property/` covering the invariant |
| `audit/` | chain-integrity test; crash/truncation test if touching the writer |
| A class of attack the change newly blocks | one file in `tests/replay/` asserting the specific layer that blocks it |
| Anything user-facing (CLI, error strings, manifest fields) | doc update in the same PR (README, DESIGN.md, or the FAQ) |

### Property test before implementation

Applies to any change under `policy/`, `taint/`, `audit/`, or `integrity/`.

1. Commit the property test on its own. When the change adds or fixes behavior,
   the test fails at that commit.
2. Commit the implementation after it, in one or more separate commits.
3. Do not squash the branch, before review or at merge. The order has to stay
   visible in `git log --oneline <base>..HEAD`, and the PR template's invariant
   ordering block cites both SHAs.

If the property test passes at its own commit (for example, a refactor that
preserves behavior), say so in the PR and explain why.

## Pull requests

- Linked to an issue per "Issue before PR". Fill in
  `.github/PULL_REQUEST_TEMPLATE.md`.
- Small diffs. A behavior change is two PRs: a DESIGN.md PR containing no code,
  merged alone first, then the implementation PR stating
  `Implements DESIGN.md <N> (merged in #<M>)`.
- Description states: what changed, why, which DESIGN.md section governs it, and
  which tests prove it.
- Required before merge: full suite, property tests, replay tests, pre-commit, and
  the approval-budget corpus check (`pytest tests/test_m4_corpus.py`). A change
  that adds approval prompts on the benign workload corpus is a regression, not a
  feature. CI runs code, dependency, and secret scans; it does not run the test
  suite yet, so paste the results into the PR template's Verification block.
- Every commit carries a DCO sign-off: `git commit -s`. The sign-off is your
  statement, under the Developer Certificate of Origin, that you have the right to
  submit the contribution under this project's license. PRs with unsigned commits
  are not merged.

## Reporting a vulnerability

Do not open a public issue or PR that demonstrates a security bypass. See
[SECURITY.md](./SECURITY.md).

## Scope boundaries with other Bawbel repos

- Changes to the AVE record schema or the capability-manifest schema itself:
  propose in the `ave` repository, since bawbel-gate is a consumer of that
  schema, not its owner (see ARCHITECTURE.md §4.3, interface freeze points).
- Detection rule changes: `bawbel-scanner`.
- Fleet console / multi-gate features: DESIGN.md §14 (bawbel-hub) describes the
  boundary between what ships free in the gate's embedded console and what is
  hub-only; check there before adding fleet-shaped functionality to this repo.

## License

By contributing, you agree your contribution is licensed under this project's
Apache-2.0 license (see [LICENSE](./LICENSE)).