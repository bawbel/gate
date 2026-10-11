# ACS and bawbel-gate mapping

Status: measured against the OWASP Agent Control Standard (ACS) repository
`github.com/GenAI-Security-Project/agent-control-standard` at commit `db5c89e4`
(2026-10-09), `version.txt` 0.1.3, specification v0.1.0. ACS is a project of the OWASP
GenAI Security Project. A reference implementation exists:
`reference-implementations/agt/packages/{guardian,inspector,agt-bridge,host-adapter,conformance}`,
with hosts for `claude-code` and `opencode`.

The requirement-by-requirement assessment is [ACS_CONFORMANCE.md](./ACS_CONFORMANCE.md).
This file maps concepts and records where the gate goes next relative to ACS. Neither
file is a conformance claim.

## 1. Core model correspondence

ACS defines an Observed Agent, an instrumented harness that emits hooks, and a Guardian,
which returns a disposition for each hook. The gate is an inline MCP proxy (DESIGN.md 3):
it decides on `tools/call` traffic it carries, rather than answering hooks an agent
sends it.

| ACS concept | Gate equivalent | Gap |
|---|---|---|
| Observed Agent | the MCP host the gate serves | The host emits no hooks; the gate sees MCP messages only |
| Guardian | `bawbel-gate serve` | No ACS endpoint. A non-MCP decision entry point is DESIGN.md 15 (runbook step 9) |
| Hooks `toolCallRequest` / `toolCallResult` | `tools/call` decision (DESIGN.md 5.2) and provenance tagging of the result (3.3) | Same point in the flow, not the ACS wire format |
| Hooks `userMessage`, `agentResponse`, `memoryStore`, `knowledgeRetrieval`, `turnStart`/`turnEnd` | none | Not visible to an MCP proxy (DESIGN.md 10.1) |
| Hooks `subagentStart` / `subagentStop` | none | No delegation model (DESIGN.md 12, open). Planned as DESIGN.md 16 (runbook step 11) |
| Dispositions ALLOW, DENY, ASK | effects `allow`, `deny`, `approve` (DESIGN.md 5.1) | `approve` is a synchronous human approval; an unresolved one is `deny` |
| Disposition DEFER | none | The gate resolves every call before returning |
| Disposition MODIFY (SHOULD) | none | The gate never rewrites arguments or results (DESIGN.md 3.3) |

## 2. Observability (Trace)

| ACS concept | Gate equivalent | Gap |
|---|---|---|
| `trace/otel-mapping.json`: OTel conventions per ACS step | OTel decision spans with gate-defined attributes (`ops/otel.py`) | Not the ACS conventions |
| `trace/ocsf-mapping.json`: ACS step to OCSF class UID | none; CEF/syslog alerts exist (`ops/syslog_cef.py`) | OCSF export planned by adopting the ACS mapping verbatim, no gate-invented class UIDs (runbook step 14) |

## 3. Inspect (AgBOM)

| ACS concept | Gate equivalent | Gap |
|---|---|---|
| AgBOM snapshot, serialized as CycloneDX 1.6, SPDX 3.0, or SWID (`acs-inspect`) | capability manifests, one per upstream server, with `tool_schema_integrity` pins (DESIGN.md 4, 8.1) | No AgBOM output |
| `agbom/changed` on mid-session mutation (`acs-inspect-dynamic`) | tool schema drift suspends a server at `VERIFY` (DESIGN.md 6.2, 8.1) | Checked at session start only, not mid-session |

## 4. What ACS does not cover

- **Behavioral drift.** ACS v0.1.0 has no declared-versus-observed comparison over time.
  The gate does not have one either: `ops/posture.py` is a tally. Planned as DESIGN.md 18
  (runbook step 16).
- **The authorization model behind a decision.** ACS standardizes where to intercept and
  what to return; policy is deployment-defined ("A permissive Guardian is a conformant
  but permissive deployment"). The gate's model is capability manifests, session taint,
  and the non-configurable trifecta invariant (DESIGN.md 4 to 7).

Not a differentiator: the hash-chained audit log. ACS-Core requires an append-only
ContextEntry chain with a rolling SHA-256 `chain_hash`. The gate's chain uses a different
construction and is not cross-verifiable with ACS chains
(`docs/adr/0001-audit-chain-construction.md`). Neither is tamper-evident against whoever controls the log writer: ACS-Core's baseline
is symmetric HMAC, and the gate has no signing at all. ACS-Core "does NOT assert that the
audit chain is tamper-evident against a compromised Guardian".

## 5. Integration sequence

Runbook order, after the corrections above:

1. Decision API for non-MCP callers, DESIGN.md 15 (step 9). An ACS Guardian
   integration needs the same request/decision shape.
2. Delegation and revocation, DESIGN.md 16 (step 11), named after the ACS
   `subagentStart` / `subagentStop` hooks where the semantics match.
3. Run the gate against the ACS reference Guardian (step 13) and record every
   divergence in ACS_CONFORMANCE.md section 6.
4. OCSF export through the ACS mapping (step 14).

## 6. Risk flag

ACS is at v0.1, and its schemas will change. Do not couple the gate's data model to
ACS field names. The gate's own formats stay the source of truth (the capability
manifest schema in `schemas/`, the audit record in DESIGN.md 8.6), and any ACS output
is a translation at the boundary.

## Provenance of this file

Imported from the Bawbel sprint kit draft (2026-09) and corrected against ACS
`db5c89e4` and this repository. Corrections:

- The reference implementation exists. The draft said it "lands in v1".
- Section 2: the gate already exports OTel spans. The draft said it needed an exporter.
- Section 4: the claim that hash-chained audit is Bawbel differentiation is struck.
  ACS-Core requires an audit chain.
- Former section 7, which recommended vendoring the bounded-agents / APC library as the
  gate's policy decision point, is withdrawn. The gate already has a tested policy
  engine (DESIGN.md 5), and a second enforcement path in one security product is a
  liability, as the sprint kit's AUDIT_FINDINGS.md concluded.
- References to sprint-kit schemas (`action_event`, `agent_identity`,
  `authority_chain`) are removed. Those schemas were retired.
