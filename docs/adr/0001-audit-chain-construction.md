---
status: accepted
date: 2026-10-11
---

# 0001. Audit chain construction diverges from ACS v0.1.0

The gate keeps its own audit chain construction (DESIGN.md 8.6) instead of adopting
the ACS v0.1.0 ContextEntry rule. Gate chains are not cross-verifiable with ACS
chains, and the gate makes no ACS ContextEntry conformance claim. ACS v0.1.0 ships
nothing a gate chain could be verified against, and conforming breaks every existing
chain.

## Context

ACS `specification/v0.1.0/context-entry.json` (repository commit `db5c89e4`, version
0.1.3) defines `entry_hash` as SHA-256 over the RFC 8785 (JCS) form of the entry with
`entry_hash` and `previous_hash` removed, concatenated with the raw 32-byte previous
digest. It states: "Conformant Guardians MUST follow this rule exactly for chains to
be cross-implementation verifiable. Alternative canonicalization schemes are NOT
permitted within v0.1."

The gate's chain is the same family, not byte compatible:

| | ACS v0.1.0 | bawbel-gate (`audit/writer.py`) |
|---|---|---|
| Canonical form | RFC 8785 (JCS) | `audit/canonical.py`: sorted keys by code point, compact, UTF-8. Not JCS |
| Removed before hashing | `entry_hash` and `previous_hash` | `hash` only. `prev` stays in the hashed content |
| Previous hash concatenated as | raw 32 bytes | UTF-8 of `sha256:<hex>`, 71 bytes |
| First entry | `previous_hash` null, empty bytes appended | `prev` is `sha256:` + 64 zeros, appended |
| Hash encoding | lowercase hex | `sha256:` + lowercase hex |
| Chain head published | `chain_hash` on responses for content-bearing steps | at `SESSION_END`, on stderr |
| Request content commitment | `request_hash`, SHA-256 of JCS(params), RECOMMENDED | `args_sha256`, SHA-256 of `canonical_bytes(args)` |

## Considered options

**(a) Conform.** Adopt JCS, drop `prev` from the hashed content, concatenate raw
bytes, write bare hex, publish the chain head per response. Every existing chain stops
verifying under the new rule, so this needs an audit-format version field, a verifier
that handles both versions, and a migration. `audit/canonical.py` also produces tool
schema pins and manifest hashes (invariant I6), so switching it to JCS in place would
invalidate pinned manifests too.

**(b) Diverge deliberately.** Chosen.

## Why (b)

- ACS v0.1.0 has no verifier for a gate chain to meet. `docs/spec/conformance.md`:
  "This release ships no conformance test suite, no registry of conformant
  implementations". The repository has no `entry_hash` test vectors. The reference
  implementation's `packages/conformance` measures how much of AGT ACS can express;
  it does not check `entry_hash`.
- Conforming adds no tamper evidence. Under either construction, a chain head anchored
  outside the log (8.6) lets `audit verify` detect a change to any record that head
  covers, and without an anchored head, whoever can rewrite the log can rebuild the
  chain. Only asymmetric signing would change that, and neither construction has it.
- Conforming costs a breaking format migration and buys no cross-verification until
  an ACS Guardian can check a chain.

## Consequences

- `bawbel-gate audit verify` is the only verifier for gate chains.
- Canonical-form differences from JCS appear only for non-integer numbers, integers
  above 2^53, `NaN` and `Infinity`, and keys outside the Basic Multilingual Plane. Tool
  arguments can contain such values, so `args_sha256` can differ from an ACS
  `request_hash` over the same params.
- `tests/test_audit_construction.py` pins the construction with golden values. A
  change that alters one hashed byte fails the build and needs a new ADR.

## Revisit when

An ACS release ships `entry_hash` test vectors or a conformance suite, or a deployment
needs a gate chain verified by an ACS Guardian (GATE-14 measures this against the
reference Guardian). Conforming then means option (a) behind a new audit-format
version. Existing chains are never rewritten.
