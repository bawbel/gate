# Hub ingest protocol

Version of this document: 2026-11-26, for [#250](https://github.com/bawbel/gate/issues/250). It states the protocol
that a gate-side shipper writes to and a Hub implements, with the answers it gives, their stable codes, and its
limits. It is checked by the conformance vectors in `tests/hub/vectors/`, which any implementation can run
(section 9).

It describes the reference Hub (`src/bawbel_gate/hub/`) as changed by #222 (HUB-R12a), which is open and not
merged, and it follows the DESIGN.md 13.2 draft in #224. Until those merge, `develop` answers some of these
requests differently, and section 10 lists where. It changes no gate-side format: the record is the one the gate
already writes (DESIGN.md 8.6).

Every claim carries a tag. **SOURCED**: read from the file named. **VERIFIED**: run, and the run is a vector or a
test named here.

## 1. The request

```
POST /v1/gates/{gate_id}/records HTTP/1.1
Authorization: Bearer <credential>
Content-Type: application/x-ndjson
Content-Length: <bytes>

<one audit record per line, as JSON>
```

- **`gate_id`** is the path segment after `/v1/gates/`: one or more characters other than `/`. The Hub takes it
  from the URL and does not check it against the credential, so a credential that can ship for one gate can
  ship for any (`docs/hub/THREAT-MODEL.md`, H2). State is kept per `gate_id`.
- **The body** is newline-delimited JSON. A blank line, or a line of spaces, is skipped. The body is decoded as
  UTF-8, with undecodable bytes replaced. Each non-blank line is one JSON value and must be an object (section 3).
  A line that is not JSON refuses the whole batch.
- **`Content-Length`** is required for a body that is not empty. A chunked body is refused. A request with no
  body and no `Content-Length` is an empty batch.
- **`Content-Type`** is sent by gates and is not checked by the Hub.
- **Order.** Within a session, records are in ascending `seq` (DESIGN.md 13.2). A batch may hold several sessions.
- The reference Hub answers with HTTP/1.0 semantics and closes the connection after each answer.

## 2. Authentication

SOURCED, `hub/server.py`. Today the Hub has one admin bearer credential, sent as `Authorization: Bearer <value>`.
A request without one, or with one the Hub does not hold, gets `401 unauthorized`, and nothing is read from its
body. The console also accepts the credential in a `?t=` query parameter. That is slated for removal and is not
part of this protocol, and the vectors do not test it. DESIGN.md 13.2 specifies per-gate mTLS, which the reference
Hub does not implement: it serves plain HTTP.

## 3. What a record must look like

The Hub checks the shape of each record before it checks the chain. A record that fails is answered with `422`
and the zero-based `index` of the record in the batch, and nothing from the batch is stored. The `reason` is one of:

| `reason` | A record fails it when |
|---|---|
| `not_object` | the JSON value is not an object |
| `session` | `session` is present and is not a non-empty string |
| `seq` | `seq` is not an integer from 1 to 2^63 - 1. A boolean, a float and a string are refused |
| `hash` | `hash` is missing, not a string, or empty |
| `prev` | `prev` is missing, not a string, or empty |

A record without `session` is read as session `default`. That is how the code behaves (`hub/ingest.py`) and it is
listed as open in section 10. Members other than these four are not checked, and the whole record is stored as sent.
`seq` above 2^53 is exact only in an implementation whose JSON numbers are exact integers.

**The hash.** The Hub recomputes `hash = "sha256:" + sha256(canonical_json(record minus hash) || utf8(prev))`,
with `prev` kept inside the hashed content and its text appended (DESIGN.md 8.6, ADR 0001). `canonical_json` is
the gate's own (`audit/canonical.py`), which is not RFC 8785. An implementation can check its hash function
against any record in the vectors, which were written by the gate's writer.

## 4. Sessions and the chain rule

A gate writes one chain per audit file, and a restart of `serve` resumes the chain and the `seq` under a new
session id. The Hub keeps a chain head per `(gate_id, session)`. The batch is accepted whole or refused whole, and a
record is accepted only as one of these, checked in this order:

| Kind | Condition |
|---|---|
| replay | the Hub holds that `(gate_id, session, seq)` and the record is identical to the held one. Nothing is stored |
| next | the session is held, `seq` is the head's plus one, `prev` is the head's `hash`, and `hash` recomputes |
| first | the session is not held, `seq` is 1, `prev` is `sha256:` followed by 64 zeros, and `hash` recomputes |
| restart | the session is not held and the record is a `SESSION_START`. Its `prev` is the `hash` of a record held for the same `gate_id` in any session, or accepted earlier in the batch. No record follows that one yet. Its `seq` is that record's plus one. Its `hash` recomputes |

When a batch holds several sessions they are checked in the order of their first record's `seq`, so a restart is
explained by the records before it in the same batch, whatever order the sessions are listed in. A rotated log
starts a new chain from the genesis value and is a `first` record under a new session id. Anything else is
refused with `409` and a `reason`, and nothing is stored. The full statement is DESIGN.md 13.2 (#224).

## 5. Idempotency and `acked`

A replay is harmless: the dedup key is `(gate_id, session, seq)`, and a replay changes no row and no counter.
`acked` maps each session in the batch to the highest `seq` in that batch that was verified, whether it was stored
now or already held identically. It is never the Hub's head, so a gate that resends records 1 to 3 of a session
the Hub holds to 6 is acked to 3 and its cursor cannot move past records it did not send. An empty batch is
`200` with `{"acked": {}}`.

## 6. The answers, and their stable codes

Every answer is JSON. The code of an answer is its status, then `error`, then `reason`, joined with colons
(`409:chain_mismatch:seq_gap`). This table is the list of stable codes: a test requires every row to appear in a
vector and every code in a vector to appear here.

| Status | `error` | `reason` | Members besides `error` and `reason` | What a gate does |
|---|---|---|---|---|
| 200 | | | `acked` | advance each session's cursor to its acked `seq` |
| 400 | `bad_content_length` | | | fix the request. `Content-Length` was not a plain number |
| 400 | `incomplete_body` | | | resend. The body ended before `Content-Length` bytes |
| 401 | `unauthorized` | | | stop and report: the credential is wrong |
| 404 | `not found` | | | stop and report: the route does not exist |
| 408 | `request_timeout` | | | resend. The body did not arrive within the deadline |
| 409 | `chain_mismatch` | `prev` | `session`, `expected_prev`, `expected_seq` | `prev` does not link. Resend from `expected_seq`, or stop that session |
| 409 | `chain_mismatch` | `hash` | `session`, `expected_prev`, `expected_seq` | the hash does not recompute. Stop that session and raise `gate.chain.gap` |
| 409 | `chain_mismatch` | `seq_gap` | `session`, `expected_prev`, `expected_seq` | resend from `expected_seq`, with `expected_prev` as its `prev` |
| 409 | `chain_mismatch` | `rewrite` | `session`, `expected_prev`, `expected_seq` | the Hub holds other content for a seq: stop that session and raise `gate.chain.gap` |
| 409 | `chain_mismatch` | `fork` | `session`, `expected_prev`, `expected_seq` | a restart from a record that is already followed: stop that session |
| 411 | `length_required` | | | send a `Content-Length`. A chunked body is not accepted |
| 413 | `too_large` | | `max_bytes` | split the batch. The body was over the Hub's cap and was not read |
| 422 | `schema` | `not_object` | `index` | the batch was refused whole. Stop that session |
| 422 | `schema` | `session` | `index` | as above |
| 422 | `schema` | `seq` | `index` | as above |
| 422 | `schema` | `hash` | `index` | as above |
| 422 | `schema` | `prev` | `index` | as above |
| 422 | `invalid NDJSON` | | | a line was not JSON. The batch was refused whole |

A gate that has no way to skip a bad record cannot continue past a `422` without leaving a `seq` gap, which is why the
table says to stop that session. DESIGN.md 13.2 in #224 lists the gate's behaviour as open.

**What is not an answer of this protocol.** `429` is in DESIGN.md 13.2 and the reference Hub never sends it. A `5xx` is
a Hub fault, not a protocol answer, and that no input causes one is the property HUB-R12 will test.

The codes `not found` and `invalid NDJSON` contain a space and the others are snake_case. They are listed as they are
sent. Renaming them before the codes are declared stable is open (section 10).

## 7. Limits

SOURCED, `hub/server.py` and `_const.py`, as changed by #222.

| Limit | Value | Where set |
|---|---|---|
| Request body | 1 MiB (1,048,576 bytes) by default. Larger is answered `413` before any of it is read | `hub serve --max-body-bytes`, `BAWBEL_HUB_MAX_BODY_BYTES` |
| Time to send a body | 10 seconds in total, then `408` | `hub serve --request-timeout`, `BAWBEL_HUB_REQUEST_TIMEOUT_S` |
| Time to send the request line and headers | 10 seconds for each read | the same setting |
| Records in a batch | not limited. DESIGN.md 13.2 has gates flush at 200 records or 2 seconds, and a batch of 200 decision records measured 101 KiB | |
| Concurrency | one thread per connection. Verify and store run one at a time | |

Not bounded: the total time to send the headers, the number of connections, and the request rate for a credential
(HUB-R12 and HUB-R19).

## 8. Versioning and compatibility

The path carries `/v1/`. There is no version header. A client must ignore members of an answer that it does not know, so
a Hub can add members without a new version. Adding a `reason`, an `error` code or a status is a protocol change and
changes the table in section 6 and a vector in the same pull request. A change to the rule in section 4 changes DESIGN.md 13.2
first, and merges alone.

## 9. Conformance vectors

`tests/hub/vectors/` holds 54 vectors in five groups (valid, schema, chain, limits, auth). A vector is a list of HTTP steps with
the answer to expect: a status and a subset of the JSON. Its records are written by the gate's own audit writer, including a
two-run file written by two writers on one file, as `serve` does, and every hash is real. The vectors are derived data:
`tests/hub/vectors/generate.py` writes them and `--check` fails if the committed files differ.

To run them against any Hub that is running, with only the Python standard library:

```
python tests/hub/vectors/run_vectors.py --base-url http://127.0.0.1:8443 --token <credential> \
    --max-body-bytes 1048576 --request-timeout-s 10 --timeouts
```

Each vector uses gate ids of its own, so the same Hub can be run against again. The two boundary vectors need the Hub's configured
cap, and the deadline vector needs its deadline and `--timeouts`. `tests/hub/test_vectors.py` starts the reference Hub with a small
cap and a short deadline and runs every vector, so they run in CI.

## 10. Open, and not specified

All open. None is decided here.

- Whether a record without `session` should be refused. Today it is read as session `default`.
- Whether `not found` and `invalid NDJSON` become `not_found` and `invalid_ndjson` before the codes are declared stable.
- What a gate does after a `422`, and whether a refused batch is kept for the operator (DESIGN.md 13.2, #224).
- Per-gate mTLS and a credential that is bound to a `gate_id` (the draft in #180).
- Whether `Content-Type` is checked, and whether a `429` with `Retry-After` is implemented.
- Until #222 and #224 merge, `develop` accepts a record with no `prev`, a rewrite and a gap in `seq`, has no body cap, and handles
  one request at a time. The vectors for those cases fail against it, as they should.

## Sources

- `src/bawbel_gate/hub/server.py`, `hub/ingest.py`, `hub/store.py` and `_const.py` on the #222 branch.
- DESIGN.md 8.6 and 13.2 (the draft in #224), `docs/adr/0001-audit-chain-construction.md`, `docs/hub/THREAT-MODEL.md`.
