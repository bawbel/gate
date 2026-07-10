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
   and why.

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

## Pull requests

- Small diffs. If a change needs a DESIGN.md update, that is a separate PR that
  merges first.
- Description states: what changed, why, which DESIGN.md section governs it, and
  which tests prove it.
- CI must be green: full suite, property tests, replay tests, pre-commit, and the
  approval-budget corpus check (a change that adds approval prompts on the benign
  workload corpus is a regression, not a feature).
- Sign your commits: `git commit -s`. We use the Developer Certificate of Origin
  (DCO); the sign-off is your statement that you have the right to submit the
  contribution under this project's license.

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
