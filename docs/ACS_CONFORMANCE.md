# ACS conformance assessment

Measured against the OWASP Agent Control Standard (ACS) repository
`github.com/GenAI-Security-Project/agent-control-standard` at commit
`db5c89e401d2a2bdb5700683f15830bf3e4fac01` (2026-10-09), `version.txt` 0.1.3,
specification v0.1.0. Gate side: bawbel-gate `develop` at `4720b07`.

This is a paper assessment: the gate's code and DESIGN.md read against
`docs/spec/conformance.md` and `specification/v0.1.0/`. Section 6.1 records the one part
that was measured by running it, and 6.2 lists what was not run.

## 1. Verdict

bawbel-gate is not ACS-Core conformant and makes no ACS conformance claim of any
profile. It does not speak the ACS wire protocol: no `handshake/hello`, no ACS envelope,
no hook emission, no HMAC signatures. Section 3 maps each ACS-Core requirement to the
gate's nearest behavior.

ACS v0.1.0 has no third-party verification either. `docs/spec/conformance.md`: "This
release ships no conformance test suite, no registry of conformant implementations, and
no steward body to arbitrate a disputed claim."

## 2. Roles

ACS defines two parties that exchange JSON-RPC: an Observed Agent, the instrumented
agent harness that emits hooks, and a Guardian, which returns a disposition for each
hook.

The gate is neither. It is an MCP server to the agent host and an MCP client to each
upstream server (DESIGN.md 3), and it decides inline on `tools/call` (DESIGN.md 5.2).
The host does not ask the gate for a decision; the call cannot reach an upstream except
through the gate. The nearest ACS shape is a Guardian that sees only the MCP traffic of
one host.

| ACS term | Gate equivalent | Difference |
|---|---|---|
| Observed Agent | the MCP host | The host is not instrumented and emits nothing |
| Guardian | `bawbel-gate serve` | Inline proxy, not a decision service; no ACS endpoint |
| Hook | an MCP message the gate receives | Only MCP traffic is visible (DESIGN.md 10.1) |
| Disposition | effect: `allow`, `approve`, `deny` (DESIGN.md 5.1) | See row 4 below |
| SessionContext | session: one host connection (`mux/session.py`) | See row 5 below |

## 3. ACS-Core requirements

Status values: **No** (not implemented), **Partial** (the gate does the same job with a
different construction, not on the ACS wire), **Yes**.

| # | ACS-Core requirement | Status | Gate evidence |
|---|---|---|---|
| 1 | Handshake: `handshake/hello`, ClientHello / ServerHello, profile declaration | No | The gate answers MCP `initialize` only (`mux/proxy.py` `_initialize_result`, DESIGN.md 3.3) |
| 2 | Envelope: JSON-RPC 2.0 with `request_id`, `timestamp`, `acs_version`, `metadata` on every request | No | Plain MCP JSON-RPC. No `request_id`, `timestamp`, or `acs_version` is read or written |
| 3 | Hooks: `sessionStart`, `userMessage` or `agentTrigger`, `toolCallRequest`, `toolCallResult`, `agentResponse`, `sessionEnd`; `subagentStart` for subagent-capable clients | Partial | Audit events `SESSION_START`, `SESSION_END` (`mux/proxy.py`); `CALL_DECIDED` per `tools/call`; the result passes the provenance tagger (DESIGN.md 3.3). `userMessage`, `agentTrigger`, `agentResponse` are invisible to an MCP proxy (DESIGN.md 10.1). No subagent concept (DESIGN.md 1, 12) |
| 4 | Dispositions: ALLOW, DENY, ASK, DEFER MUST; MODIFY SHOULD, else DENY with `modify_unsupported` | Partial | `allow` = ALLOW, `deny` = DENY, `approve` = ASK (synchronous human approval, `policy/approval.py`). No DEFER. No MODIFY: the response body is never modified (DESIGN.md 3.3) and no arguments are rewritten |
| 5 | SessionContext: `session_id`, rolling SHA-256 `chain_hash`, append-only ContextEntry chain, chain head published on responses for content-bearing steps | Partial | `session_id` is a UUID4 (`mux/session.py`). Append-only SHA-256 hash chain (DESIGN.md 8.6), with a different construction from ContextEntry, so not cross-verifiable (`docs/adr/0001-audit-chain-construction.md`). Chain head printed once, at `SESSION_END`, to stderr. Never published per response |
| 6 | Replay protection: `request_id` UUID and `timestamp` on every request; reject replays (spec section 10.3) | No | No replay check. Each host line is decided on its own. The transport is the host's stdio pipe to its own subprocess |
| 7 | Baseline integrity: HMAC-SHA256 signature over the canonical envelope on every request and response | No | No message signing on either side of the gate |
| 8 | Decision honoring: the Observed Agent waits for and applies the decision; on decision failure applies `on_decision_failure` (default `proceed`) and audits every fail-open proceed | Partial | Honoring is structural: the host's call reaches an upstream only if the gate forwards it. There is no fail-open posture. Approval timeout is `deny` and `on_timeout` accepts no other value (`mux/config.py`); no matching grant, a failed condition, and a guard violation resolve to `deny` (DESIGN.md 5.2) |
| 9 | Liveness: `system/ping`, or a declared alternative mechanism | No | No `system/ping`. MCP `ping` returns `-32601` (DESIGN.md 3.3). Liveness is the stdio pipe: if the gate process exits, the host's calls fail |
| 10 | Wrapped MCP: `protocols/MCP/*` for sessions involving MCP, so `resources/read` cannot bypass the Guardian | Partial | Not as ACS hooks. The gate sees every MCP message between host and upstreams, forwards only `tools/call` after a decision, and rejects `resources/*`, `prompts/*`, and every other method with `-32601` (DESIGN.md 3.3). `resources/read` cannot bypass because it is never proxied |

## 4. Optional profiles

| Profile | Status | Gate evidence |
|---|---|---|
| `acs-trace`: OTel or OCSF per ACS step, per `trace/otel-mapping.json` and `trace/ocsf-mapping.json` | No | OTel decision spans (`ops/otel.py`) and CEF/syslog alerts (`ops/syslog_cef.py`) use gate-defined names, not the ACS mappings. No OCSF output |
| `acs-inspect`, `acs-inspect-dynamic`: AgBOM in CycloneDX 1.6, SPDX 3.0, or SWID | No | No AgBOM. The nearest inventory is the set of capability manifests and their `tool_schema_integrity` pins (DESIGN.md 4, 8.1) |
| `acs-provenance`: field-level Provenance objects | No | Provenance is per server, not per field: each manifest's `provenance_class` enters session taint when its `tools/call` result returns (DESIGN.md 6.1, 7) |
| `acs-crypto`: ML-DSA-65 signatures | No | No asymmetric signing |
| `acs-audit`: `request_hash` (SHA-256 of JCS(params)) on every ContextEntry | No | Each `CALL_DECIDED` record carries `args_sha256`, SHA-256 of the gate's canonical form of the arguments, which is not JCS (ADR 0001) |

## 5. Where the gate's defaults are stricter than ACS

- **Decision failure.** ACS-Core's default `on_decision_failure` is `proceed` (fail-open,
  audited). The gate has no fail-open path (DESIGN.md 2.3, 5.2). If the gate is ever
  connected to an ACS Observed Agent, that deployment must set `on_decision_failure`
  to deny, or the gate's guarantee does not hold.
- **ASK timeout.** An unresolved approval in the gate is `deny` (`approval_timeout`).
  ACS DEFER also defaults `timeout_decision` to `deny`; the gate has no DEFER.
- **Trifecta.** The gate's third-leg approval is not configurable (DESIGN.md 7.2). ACS
  leaves policy strictness to the deployment: "A permissive Guardian is a conformant
  but permissive deployment".

None of this makes the gate ACS-conformant. It records which guarantees would be lost
if the gate were placed behind ACS defaults.

## 6. Measured, and not tested

Sections 1 to 5 are a paper assessment at the commit named at the top. This section
records what has since been run. Rows 1 to 10 of section 3 and the quotation in section 1
were not re-checked against a newer ACS commit, and section 7 says a newer commit
invalidates them until they are.

### 6.1 Measured on 2026-11-22: a gate-produced chain against ContextEntry

Setup: bawbel-gate 0.1.1, built from `develop` at `8617299`, in a fresh virtualenv with an
empty HOME and `env -i`. One `bawbel-gate serve` session (a call the manifest denies, an
allowed call, and a call held for approval and answered `y`) wrote 5 records:
`SESSION_START`, three `CALL_DECIDED`, `SESSION_END`. `bawbel-gate audit verify` printed
`ok: 5 records, chain intact`.

The schema is `specification/v0.1.0/context-entry.json`. It is byte-identical at the commit
named at the top and at ACS commit `ee935751454eb58521b85ad5b73095e5540843c4`
(`version.txt` 0.1.5, 2026-11-20), so the pin does not change this result. The chain
vector in the last paragraph exists only at the second commit.

| Measurement | Result |
|---|---|
| The 5 records validated against the schema (JSON Schema 2020-12, `jsonschema` 4.26.0) | 5 of 5 invalid, with the same 4 errors each: `entry_id`, `step_id`, `step_type` and `entry_hash` are required and absent. The schema sets no `additionalProperties`, so the gate's other fields cause no error |
| The gate's `hash` against the `entry_hash` pattern `^[0-9a-f]{64}$` | 0 of 5 match as written, because of the `sha256:` prefix. 5 of 5 match with the prefix removed |
| Each hash recomputed by the rule in `audit/writer.py` (`prev` inside the hashed content, the UTF-8 text of `prev` appended) | 5 of 5 equal the stored hash |
| The same, with `prev` left out of the hashed content | 0 of 5 equal it |
| The same, with the 32 raw bytes of the previous digest appended instead of the 71-byte text | 0 of 5 equal it |
| First record | `prev` is `sha256:` and 64 zeros, appended as 71 bytes. The schema text appends the empty byte string |
| Chain head | Printed once on stderr at session end, and equal to the `SESSION_END` hash. No "chain head" text on `serve`'s stdout, and no record carries it as a field |

The canonical form was compared with RFC 8785 on 13 JSON texts. The oracles were Node
20.20.2 (`JSON.stringify` for numbers and strings, keys sorted by UTF-16 code unit) and the
`rfc8785` 0.1.4 Python package. 6 of the 13 differ from the gate's `canonical_str`:

| JSON text | Gate | RFC 8785 |
|---|---|---|
| `{"a":1.0}` | `{"a":1.0}` | `{"a":1}` |
| `{"a":1e20}` | `{"a":1e+20}` | `{"a":100000000000000000000}` |
| `{"a":1e-7}` | `{"a":1e-07}` | `{"a":1e-7}` |
| `{"a":9007199254740993}` | `{"a":9007199254740993}` | `{"a":9007199254740992}` with Node. The package refuses the integer |
| `{"😀":1,"￮":2}` (keys U+1F600 and U+FFEE) | U+FFEE first | U+1F600 first |
| `{"a":NaN}` | `{"a":NaN}` | not representable. Both oracles refuse it |

The other 7 are the same on both sides: `{"a":1}`, `{"a":0.1}`, `{"a":1e21}`,
`{"a":100000000000000000000}`, `{"b":1,"a":2}`, `{"a":"\u0001\u007f "}` and
`{"a":"café"}`. The two oracles agreed on 11 of the 13. The two they did not agree on are the integers
beyond 2^53, where the package refuses and Node rounds to a double.

ADR 0001 says the differences from RFC 8785 appear only for "non-integer numbers". `1.0` is
an integer in value, but Python parses it as a float and writes `1.0`, so it is in the
differing set. The measured set is a number written with a fraction or an exponent where
Python's form differs from the ECMAScript form, an integer beyond 2^53, `NaN`, and the
order of keys when one holds a character above U+FFFF (one pair was measured).

ACS ships a chain vector at `ee935751454e`:
`reference-implementations/agt-go/internal/chain/testdata/vectors.json`, one `request_hash`
and three chained entries. Read as data, with nothing from that repository run, it
reproduces with the Node oracle: the `request_hash` text and digest, all 3
`canonical_content` strings, and all 3 `entry_hash` values. So the rule as read from the
schema is the rule the vector uses. On those 3 entries, and on all 5 of the gate's records
from this session, the gate's `canonical_bytes` equals the RFC 8785 bytes. The gate's records
hold only objects, integers, lists and strings, with no float. On these records the
canonicalisation is therefore not what separates the two chains. The field names, the
`sha256:` prefix, `prev` staying inside the hashed content, and the 71-byte text appended
are. Where the canonical forms differ, as in the table above, an input hash such as
`args_sha256` differs when the arguments carry such a value.

ADR 0001 names the shipping of `entry_hash` test vectors as a condition for revisiting its
decision. At the commit named at the top, `entry_hash` appears only in `context-entry.json`
and in `docs/spec/instrument/specification.md`, and no file holds a vector. At
`ee935751454e` the file above does. ADR 0001 is unchanged by this section.

### 6.2 Not tested

1. No gate build was run against a reference Guardian. At `ee935751454e` there are two:
   TypeScript under `reference-implementations/agt` (it needs `bun`, `bun install` fetches
   the AGT SDK and an OPA binary, and the Claude Code walkthrough needs the Claude Code
   CLI) and Go under `reference-implementations/agt-go`, which does not exist at the
   commit named at the top. Neither `bun` nor `go` was installed on the measuring host, and
   nothing from the ACS repository was executed.
2. No wire capture was compared against `specification/v0.1.0/request-envelope.json` or
   `response-envelope.json`. Both files differ between the commit named at the top and
   `ee935751454e`, so a comparison has to name the commit it uses.
3. No gate record was mapped to a ContextEntry and run through an ACS Guardian. 6.1 shows
   that a gate record is not a ContextEntry and why the hashes differ. It does not show what
   a mapping would cost.
4. The reference implementation's conformance harness was not run. At `ee935751454e`,
   `docs/spec/conformance.md` says each reference stack's checks run at summary level and
   "No official ACS-Core conformance suite exists yet."

Items 1 to 4 remain runbook step 13 (GATE-14).

## 7. Re-measuring

```bash
git clone https://github.com/GenAI-Security-Project/agent-control-standard acs
git -C acs checkout db5c89e401d2a2bdb5700683f15830bf3e4fac01
cat acs/version.txt                               # 0.1.3
sed -n '/## ACS-Core/,/## ACS-Trace/p' acs/docs/spec/conformance.md
jq -r '.properties.entry_hash.description' acs/specification/v0.1.0/context-entry.json
```

A newer ACS commit invalidates rows 1 to 10 until re-checked. Update the commit and
version at the top of this file in the same change.

The schema and hash measurements of 6.1 can be repeated on a chain that a
`bawbel-gate serve` session wrote to `audit.jsonl`, with `acs` checked out as above and the
gate installed in the same environment:

```python
import hashlib, json
from jsonschema import Draft202012Validator
from bawbel_gate.audit.canonical import canonical_bytes

schema = json.load(open("acs/specification/v0.1.0/context-entry.json"))
for line in open("audit.jsonl"):
    r = json.loads(line)
    errors = [e.message for e in Draft202012Validator(schema).iter_errors(r)]
    body = {k: v for k, v in r.items() if k != "hash"}
    again = "sha256:" + hashlib.sha256(canonical_bytes(body) + r["prev"].encode()).hexdigest()
    print(r["seq"], r["event"], len(errors), "errors, hash recomputed:", again == r["hash"])
```

On the chain measured in 6.1 it prints `4 errors, hash recomputed: True` for every record.
The canonical-form comparison needs an RFC 8785 implementation: serialise the 13 JSON
texts of 6.1 with it and with `bawbel_gate.audit.canonical.canonical_str`, and compare.
