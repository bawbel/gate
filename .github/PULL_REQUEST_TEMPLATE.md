Closes #

<!-- Every PR closes an issue. Open the issue first (CONTRIBUTING.md). -->

## What and why

## Governing spec

DESIGN.md section(s):

<!--
A behavior change is two PRs. The DESIGN.md PR merges alone first; this PR then
states: Implements DESIGN.md <N> (merged in #<M>).
-->

## Output contract

<!-- What a reviewer can check this PR does and does not do. Delete lines that do not apply. -->

- Changes:
- Does not change:
- New or changed CLI flags, manifest fields, reason strings, audit record fields:

## Verification

<!-- Paste the summary line of each command. No CI workflow runs the test suite yet. -->

```text
pytest                          ->
pytest tests/property/ -x       ->
pytest tests/replay/            ->
pytest tests/test_m4_corpus.py  ->   (approval budget)
pre-commit run --all-files      ->
```

## Invariant ordering

<!-- Required if this PR touches policy/, taint/, audit/, or integrity/. Delete otherwise. -->

```text
Property tests: commit <sha>
Implementation: commit <sha>
Confirm with:   git log --oneline <base>..HEAD
```

Invariants redefined: none

## Checklist

- [ ] Every commit carries a DCO sign-off (`git commit -s`)
- [ ] DESIGN.md is still accurate after this change
- [ ] Replay test in `tests/replay/` if this blocks an attack class
- [ ] Docs updated for user-facing changes (CLI, reason strings, manifest fields)
- [ ] No em dashes in docs, comments, or error strings
