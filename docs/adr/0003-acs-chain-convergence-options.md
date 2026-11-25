---
status: proposed
date: 2026-11-25
---

# 0003. Converge the audit chain with ACS ContextEntry, or keep the divergence (options)

This is a draft that records options and, below, the maintainer's decision. [ADR 0001](./0001-audit-chain-construction.md)
stands, and nothing in the gate changes: no audit format, hash rule, canonical form, pin or test.
It stays a draft, with status `proposed`, until the maintainer has read it.

## Decision

**Decision: A, maintainer, 2026-11-25.** Keep the divergence. ADR 0001 stands.

**Revisit when** ACS tags a release that ships the vector file, or when a user asks for ACS
conformance, and when the Go question (does the reference ignore or reject an extra member) has
been answered by running it.

Recorded by the executor from the maintainer's written answer of 2026-11-25. The executor chose
nothing here.

- Go is not installed and the Go reference was not run. The maintainer's answer is not to install
  it now.
- The maintainer's reason against C1: it does not make `args_sha256` equal an ACS request hash.
  The comparison table below agrees: its row "Chain could be recomputed by the ACS rule" reads
  "no" for C1.
- ADR 0001's own "Revisit when" text is not edited by this draft. Whether to copy the revisit
  condition above into it is left to the maintainer.
- Options B, C1 and C2 stay below as the record of what was weighed.

## Why this is open now

ADR 0001, "Revisit when": "An ACS release ships `entry_hash` test vectors or a conformance suite,
or a deployment needs a gate chain verified by an ACS Guardian." The maintainer has recorded that
this condition is met by the vector file named below. This ADR sets out what converging would
involve, so the maintainer can choose.

Each claim is tagged **VERIFIED** (run, with the date), **SOURCED** (a file at a named commit,
read, with the date) or **UNVERIFIED**.

## Evidence

ACS commit `ee935751454eb58521b85ad5b73095e5540843c4` (2026-11-20, `version.txt` 0.1.5). Its files
were read as data on 2026-11-25 and nothing from that repository was run. Newer ACS commits were
not checked: the clone was last fetched on 2026-11-22.

| Claim | Status |
|---|---|
| ACS ships a chain vector at `reference-implementations/agt-go/internal/chain/testdata/vectors.json` (git blob `15f017cda685f290ebfb279a962dfd65f24bc2e1`): one `request_hash` and three chained entries. It is absent at `db5c89e4`, the commit ADR 0001 was measured against | SOURCED 2026-11-25. Absence at `db5c89e4`: VERIFIED with `git cat-file`, 2026-11-25 |
| An independent RFC 8785 oracle (Node 18.19.1) reproduces it: the `request_hash` text and digest, 3 of 3 canonical contents, 3 of 3 `entry_hash` values by `sha256(content \|\| raw previous_hash)`, and the links between entries | VERIFIED 2026-11-25: `acs_check.py vectors` from #198 at `e0894bb`, exit 0 |
| The gate's `canonical_bytes` equals the RFC 8785 bytes on those 3 entries and on 5 records written by `bawbel-gate serve` 0.1.1 | VERIFIED, same run |
| A gate record fails ACS `context-entry.json`: `entry_id`, `step_id`, `step_type` and `entry_hash` are required and absent. The schema sets no `additionalProperties`, so the gate's other members cause no error | VERIFIED, 5 of 5 records, `docs/ACS_CONFORMANCE.md` 6.1 |
| ACS's Go reference has `chain.EntryHash`, `Seal` and `RequestHash`, with tests including `TestVector` | SOURCED 2026-11-25: `internal/chain/chain.go`, `chain_test.go` |
| `EntryHash` takes a typed `ContextEntry` with a fixed list of members (`entry_id`, `step_id`, `step_type`, `request_hash`, `provenance_summary`, `timestamp`, `turn_id`, `approver`, `intent_extension`, `previous_hash`, `entry_hash`) and hashes the JSON it marshals from that value | SOURCED 2026-11-25: `acs/session_context.go`, `internal/chain/chain.go`. What it does with a member outside that list: **UNVERIFIED**, because Go is not installed and nothing was run |

To repeat the first three rows: `scripts/acs_check/` in #198 (proposed, not merged when this was
written), or `docs/ACS_CONFORMANCE.md` section 7.

## What the canonical form commits to today

All five uses go through `audit/canonical.py`. Changing it changes every one of them.

| Use | Commits to | Does a number-form change reach it? |
|---|---|---|
| Audit chain hash, `audit/writer.py` | each record, `prev` included | The 5 records measured hold only objects, integers, lists and strings. VERIFIED. The records hold no arguments: DESIGN.md 8.6 names a `--store-args` option, and `serve --help` in 0.1.1 shows none. VERIFIED, 2026-11-25 |
| Tool schema pin, `integrity/pinning.py` | an upstream server's tool list | Values come from upstream servers and are not in the repository. **UNMEASURED** |
| Manifest hash, `policy/manifest.py` (`manifest_sha256`) | the manifest as loaded | The repository's fixtures hold no float in a manifest or a tool schema: of 30 tracked YAML and JSON files, 3 hold a float, all AVE corpus test fixtures, which are not manifests or tool schemas. VERIFIED, 2026-11-25. Manifests written by users: **UNMEASURED** |
| `args_sha256`, `mux/proxy.py` | the call's arguments | Yes, when the arguments hold a float, an integer above 2^53 or the key order differs. 1 of 3 calls in the measured session. VERIFIED |
| Approval prompt text, `policy/approval.py` | nothing (display only) | Display changes only |

`bawbel-gate audit verify` recomputes the chain hashes and does not recompute `args_sha256`,
because the arguments are not in the log. Read from `verify_chain` in `audit/writer.py`. SOURCED.

## What differs from ACS, and what each option does with it

The first column is ADR 0001's table. "Stays" means the gate keeps today's behaviour.

| Difference | A. Keep | B. New versioned format | C1. `args_sha256` only | C2. C1 plus shared number form |
|---|---|---|---|---|
| Canonical form of the chain hash | stays | RFC 8785 for the new version | stays | numbers as RFC 8785 writes them; keys and the rest stay |
| Removed before hashing | stays (`hash`) | `entry_hash` and `previous_hash` | stays | stays |
| Previous digest appended as | stays (71 bytes of text) | raw 32 bytes | stays | stays |
| First record | stays (`sha256:` and 64 zeros) | null, nothing appended | stays | stays |
| Digest encoding | stays (`sha256:` prefix) | bare lowercase hex | stays | stays |
| Chain head | stays (stderr at `SESSION_END`) | open: per response in ACS | stays | stays |
| Member names | stays | ContextEntry names where a member exists. Open | stays | stays |
| Request commitment | stays | open | `args_sha256` over the RFC 8785 form | same, through the shared form |

## Option A. Keep the divergence

- **What.** ADR 0001 stands. No change.
- **Gives.** Nothing new. `bawbel-gate audit verify` stays the only verifier of a gate chain.
  `args_sha256` of a float-bearing argument differs from a hash of its RFC 8785 form (VERIFIED,
  1 of 3 calls).
- **Costs.** No code. If chosen, ADR 0001's "Revisit when" should say what would change the
  answer, since its stated condition has been met. The revisit condition is now stated in the
  Decision section above.
- **Open.** Whether to run `scripts/acs_check/` again when ACS publishes a new release.

## Option B. Converge under a new versioned audit format

This is ADR 0001's option (a), with the new facts above.

- **What.** A new audit-format version whose chain rule is ACS section 8.2: the hash covers the
  RFC 8785 form of the entry with `entry_hash` and `previous_hash` removed, the previous digest is
  appended as raw bytes, digests are bare lowercase hex, and the first entry has no previous. The
  rule reproduces from ACS's own vector (VERIFIED above).
- **Would touch** (not done here): a second serialiser used only for the new version, so pins and
  manifest hashes keep today's form; `audit/writer.py` and `verify_chain` for both versions; the
  hub's `process_batch` and `_compute_hash`; the golden values in `tests/test_audit_construction.py`;
  DESIGN.md 8.6. Invariant I6 says `canonical.py` is the only place that serialises JSON for
  hashing, so I6 would need an amendment, or the new serialiser would sit behind it.
- **Existing logs.** Never rewritten, as in ADR 0001. A file that spans the change needs a rule: a
  new file at upgrade, or a bridging record. Open.
- **A design point the evidence leaves open.** The gate's own members (`effect`, `reason`,
  `taint`, `tool`, `args_sha256`, `manifest_sha256`) are not ContextEntry members. The schema
  text hashes "this object" and allows extra members (VERIFIED above). The Go reference hashes what
  it marshals from a value with a fixed member list. If an ACS verifier behaves like that, either
  the gate's members sit outside the hashed entry (two layers per record), or only verifiers that
  hash the whole object can check the chain. Not run, UNVERIFIED. This needs an answer before B
  can be sized.
- **Gives.** A chain that an implementation of the ACS rule could recompute, if the point above is
  settled.
- **Does not give.** Any evidence that an ACS Guardian would accept gate entries: no gate record
  has been mapped to a ContextEntry or checked by an ACS implementation
  (`docs/ACS_CONFORMANCE.md` 6.2, item 3).
- **Effort.** The largest of the three.

## Option C. Converge only for `args_sha256` and numbers; the chain rule stays

Two variants, because "numbers" can mean one value or the shared form.

**C1. `args_sha256` only.**

- **What.** `_hash_args` in `mux/proxy.py` hashes the RFC 8785 form of the arguments. The chain
  hash, pins and manifest hashes are unchanged.
- **Effect on logs.** `audit verify` does not recompute `args_sha256`, so every old log still
  verifies (SOURCED). For arguments that hold none of the values that differ
  (`docs/ACS_CONFORMANCE.md` 6.1), the digest does not change (VERIFIED, 2 of 3 calls). For the
  others it does, so a digest from before and after the change is not comparable, and a reader
  needs to know which rule wrote it. How a record says so is open: a new member changes the record but breaks no hash.
- **Effort.** Small.

**C2. C1 plus the shared number form.**

- **What.** `audit/canonical.py` writes numbers as RFC 8785 requires (`1.0` as `1`, `1e20` as
  `100000000000000000000`, `1e-07` as `1e-7`). Keys and strings stay as they are.
- **Effect.** Pins and manifest hashes computed over a value that holds a float change. A pin
  stored under the old form would no longer match, so a migration or a match against both forms is
  needed. The repository's fixtures hold no such value (VERIFIED), and the upstream tool schemas
  that real pins cover are not in the repository (UNMEASURED). The chain hash of the records the
  gate writes today does not change, since they hold no number that differs (VERIFIED, 5 records).
  `TestCanonicalFormIsNotJcs` in `tests/test_audit_construction.py` asserts today's number form and
  is written to fail if `canonical.py` moves toward RFC 8785 without a new ADR (SOURCED).
- **Effort.** Moderate, mostly pins.

**What C gives, and does not.** The two serialisations of the same arguments agree. It does not
make `args_sha256` equal an ACS `request_hash`: ACS hashes the request envelope's `params` object
and the gate hashes the tool arguments (ACS `chain.go` `RequestHash`, and ADR 0001's table). It
gives no chain cross-verification.

## Comparison

| | A | B | C1 | C2 |
|---|---|---|---|---|
| Changes what the gate writes | no | yes, a new version | yes, `args_sha256` for some arguments | same, and possibly pins |
| Old logs still verify | yes | yes, with a dual verifier | yes | yes |
| Pins and manifest hashes change | no | no, if the serialiser is separate | no | yes, if they hold a float |
| Chain could be recomputed by the ACS rule | no | yes, if the design point is settled | no | no |
| Argument serialisation agrees with RFC 8785 | no | for the new version | yes | yes |
| Relative effort | none | largest | small | moderate |

## Not decided

The points for B and C below matter only if the decision is revisited.

- Which option: decided as A on 2026-11-25 (see Decision). ADR 0001 remains the accepted decision.
- For B: the answer to the design point, the rule for a file that spans versions, the member names,
  and where the chain head is published.
- For C: how a record says which rule produced `args_sha256`, and whether C2's effect on pins is
  acceptable.
- What would make the maintainer revisit again, whichever is chosen.

## Not done

- No ACS code was run: Bun and Go are not installed, and the reference Guardian was not started.
- No gate record was mapped to a ContextEntry and given to an ACS implementation.
- Newer ACS commits were not checked.
- The pins of real upstream servers were not measured.

## Sources

- ACS repository, `github.com/GenAI-Security-Project/agent-control-standard`, commit
  `ee935751454eb58521b85ad5b73095e5540843c4`, read 2026-11-25: `specification/v0.1.0/context-entry.json`
  (git blob `e74119853295d118034b1b836792df996a6ec962`),
  `reference-implementations/agt-go/internal/chain/testdata/vectors.json`,
  `reference-implementations/agt-go/internal/chain/chain.go`,
  `reference-implementations/agt-go/acs/session_context.go`,
  `reference-implementations/agt-go/docs/canonical-form.md`.
- RFC 8785, JSON Canonicalization Scheme, as the specification the ACS rule names. It was not
  re-read for this ADR. The comparisons above were made with two implementations of it.
- This repository: `docs/adr/0001-audit-chain-construction.md`, `docs/ACS_CONFORMANCE.md` section 6,
  `DESIGN.md` 8.6, `src/bawbel_gate/audit/`, `integrity/pinning.py`, `policy/manifest.py`,
  `mux/proxy.py`, `tests/test_audit_construction.py`.
