# invariants.md - testable invariants (I1-I8)

Every invariant here has a property test in `tests/property/`. A PR that touches the
relevant module and does not keep these tests green does not merge. Patterns use
hypothesis; copy the shape, not the literals.

## I1 - Default deny

Any call with no matching grant resolves to deny. Any matched grant whose conditions
fail resolves to deny, never to the next grant.

```python
from hypothesis import given, strategies as st

@given(tool=st.text(min_size=1))
def test_unmatched_tool_is_denied(tool, empty_manifest, clean_session):
    d = resolve(ToolCall(tool=tool, args={}), empty_manifest, clean_session)
    assert d.effect is Effect.DENY
```

## I2 - Monotonicity (the big one)

For any manifest, session, and call: adding taint classes or trifecta flags to the
session can never produce a MORE permissive effect than the same call in the same
session without them.

```python
@given(session=sessions(), extra=st.sets(provenance_classes(), min_size=1), call=calls())
def test_taint_never_raises_effect(manifest, session, extra, call):
    before = resolve(call, manifest, session).effect
    after = resolve(call, manifest, session.with_taint(extra)).effect
    assert PERMISSIVENESS[after] <= PERMISSIVENESS[before]
```

## I3 - Monotone session state

`tainted_by`, `private_touched`, `untrusted_seen` only grow. The only reset is
`SESSION_CLEAR`, which requires the operator CLI (never a tool, never an endpoint)
and writes an audit record.

## I4 - Trifecta invariant is unconditional

For every manifest expressible under the schema (including adversarial ones generated
property-style): if the session holds private_touched and untrusted_seen and the tool
belongs to a server with `external_comms: true`, the resolved effect is approve or
deny. Never allow. No configuration input to this test is allowed to change the
assertion.

## I5 - Effect combination is exactly lattice_min

`lattice_min` is associative, commutative, idempotent, and `deny` is absorbing.
Resolution applies it left-to-right over (base grant, taint rules..., trifecta); the
result must equal the fold. Test both algebraic laws and pipeline equivalence.

## I6 - Canonical JSON has one implementation

Everything hashed or pinned (audit records, tool schemas, manifests, remote
snapshots) round-trips through `audit/canonical.py` and is byte-stable across runs
and platforms (sorted keys, UTF-8, LF, no insignificant whitespace, arrays
order-preserved). Grep-level test: no other module calls `json.dumps` with
`sort_keys`.

## I7 - Chain integrity

For any sequence of records: `hash_i = sha256(canonical(record_i minus hash) || prev_i)`
and `prev_i = hash_(i-1)`. `audit verify` accepts every generated valid chain,
rejects any single-byte mutation anywhere, and detects truncation of the final record
after a simulated crash (write, kill, reopen).

## I8 - Fail closed on approval

Approval timeout resolves to deny. Approval channel crash resolves to deny.
Concurrent decisions on one approval: exactly one wins, exactly one audit record is
written, the loser receives conflict semantics. There is no code path from
PENDING_APPROVAL to EXECUTED without a granted decision.

## Attack replay tests (tests/replay/)

One file per exercised AVE class. Each replay asserts the specific layer that blocks
it, not just "it was blocked". Minimum set: the poisoned-issue exfil chain (blocked
independently by base-repo condition, taint downgrade, and trifecta invariant: three
asserts, three layers) and the tool-description rug pull (drift detected at VERIFY,
server suspended, tools withheld from tools/list).
