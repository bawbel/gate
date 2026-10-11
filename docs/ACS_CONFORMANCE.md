# ACS conformance assessment

Measured against the OWASP Agent Control Standard (ACS) repository
`github.com/GenAI-Security-Project/agent-control-standard` at commit
`db5c89e401d2a2bdb5700683f15830bf3e4fac01` (2026-10-09), `version.txt` 0.1.3,
specification v0.1.0. Gate side: bawbel-gate `develop` at `4720b07`.

This is a paper assessment: the gate's code and DESIGN.md read against
`docs/spec/conformance.md` and `specification/v0.1.0/`. Section 6 lists what was not
run.

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

## 6. Not tested

This assessment did not run anything against ACS. Specifically:

1. No gate build was run against the reference Guardian
   (`reference-implementations/agt/packages/guardian`, hosts `claude-code` and
   `opencode`).
2. No wire capture was compared against `specification/v0.1.0/request-envelope.json` or
   `response-envelope.json`.
3. No gate-produced chain was checked against `specification/v0.1.0/context-entry.json`.
   The construction difference is established by reading both (ADR 0001), not by a
   cross-verification run.
4. The ACS reference implementation's `packages/conformance` harness was not run. It
   measures what ACS can express of AGT; it does not test a Guardian.

These are runbook step 13 (GATE-14).

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
