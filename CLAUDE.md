# CLAUDE.md - bawbel-gate

bawbel-gate is an MCP multiplexer proxy that enforces capability manifests, session
taint, and the rule-of-two trifecta invariant on agent tool calls, with a hash-chained
audit log. Python >= 3.11. Solo-maintained. Security product: correctness beats speed.

## Source of truth

- `DESIGN.md` is normative. `ARCHITECTURE.md` is the ecosystem map.
  `IMPLEMENTATION_PLAN.md` is the sequence.
- If the code needs to diverge from DESIGN.md: STOP. Propose the DESIGN.md change
  first. Never make the code the spec.
- NEVER duplicate spec text into code comments or docs. Reference by section:
  `# see DESIGN.md 5.2 step 3`.

- `BAWBEL_GATE_MITIGATIONS_SPEC.md` specific enforcement policy that was
deliberately kept out of the AVE standard.

## Before writing any code

1. Read the DESIGN.md section for the component you are touching (map below).
2. Read `docs/LANGUAGE.md`. Use those exact terms in identifiers, docstrings, errors.
3. If touching `policy/`, `taint/`, `audit/`, or `integrity/`: read the
   gate-implementation skill's `references/invariants.md` and write the property
   test BEFORE the implementation.

| Touching | Read first |
|---|---|
| `mux/` | DESIGN.md 3.1-3.3 |
| `policy/` | DESIGN.md 4, 5 + invariants I1-I5 |
| `taint/` | DESIGN.md 6.1, 7 + invariants I2, I3 |
| `integrity/` | DESIGN.md 8 |
| `audit/` | DESIGN.md 8.6 + invariants I6, I7 |
| `learn/` | DESIGN.md 7.5, 11.4 |
| console/API | DESIGN.md 13.1 |
| AVE records/schemas | DESIGN.md 9 + ave-record-authoring skill |

## Commands

```bash
pip install -e ".[dev]" --break-system-packages   # setup
pytest                                            # all tests
pytest tests/property/ -x                         # invariant property tests (hypothesis)
pytest tests/replay/                              # scripted attack replays
pre-commit run --all-files                        # lint gate, must pass before commit
bawbel-gate lint manifests/ --schema capability-manifest/v1
```

## Hard rules

- Effects only move DOWN the lattice (`allow -> approve -> deny`). Any code path
  that could raise an effect is a bug, even if tests pass.
- The trifecta invariant (DESIGN.md 5.2 step 6) is NOT configurable. No manifest
  field, env var, or flag may disable it. Do not add one, even behind "debug".
- Fail closed. Unknown tool -> deny. Failed condition -> deny (never fallthrough).
  Approval timeout -> deny. Parse error -> deny. There is no fail-open path.
- Enforcement decisions NEVER consult model output. The gate reads structured
  JSON-RPC only.
- Canonical JSON is `src/bawbel_gate/audit/canonical.py` and nowhere else. Never
  inline `json.dumps(sort_keys=True)` for anything hashed or pinned.
- Lint: E501 (100 chars), F401, F541, F811, E221, E251, E231, SIM105
  (`contextlib.suppress`, never try/except/pass), SIM102. Bandit `nosec` + `noqa`
  on the same line. No new exceptions without a comment citing the reason.
- Tests: no duplicate class names; no `import pytest` unless using
  `pytest.mark`/`raises`/`param`.
- Docs and errors: precise, technical, no marketing language. Exact commands, paths,
  and data structures. Examples over prose. No em dashes.

## Layout

```
src/bawbel_gate/{mux,policy,taint,integrity,audit,learn}/ + cli.py
schemas/            # vendored from ave repo; do not edit here, PR to ave
tests/{property,replay,corpus}/
```

## Definition of done

Code + property test (if policy/taint/audit) + replay test (if it blocks an attack
class) + DESIGN.md still accurate + `pre-commit run --all-files` clean + approval
budget CI green (a change that adds prompts on the benign corpus is a regression).
