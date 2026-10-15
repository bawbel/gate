# Threat model: beyond DESIGN.md 2

DESIGN.md 2 is the threat model for the enforcement core: T1 to T6 in 2.1 (defended),
the exclusions in 2.2 (not defended), and the design commitments in 2.3. This file does
not restate it. It covers threats that DESIGN.md 2.1 does not list, and states for each
whether the gate defends it today.

IDs here use the prefix `X` so they never collide with DESIGN.md's `T1` to `T6`.

## Threats outside DESIGN.md 2.1

| ID | Threat | Gate today | Where |
|---|---|---|---|
| X1 | Delegation escalation: a sub-agent acts with authority its parent does not hold | Not defended. No delegation model | DESIGN.md 1 (out of scope for v1), 12 (open). Planned: DESIGN.md 16, runbook step 11 |
| X2 | Lingering authority: a task-scoped capability is used after its task ends | Not defended. Grants are per manifest for the whole session; no task scope | Same as X1 |
| X3 | Composition beyond the trifecta: individually permitted calls whose sequence is harmful (read, then write, then send) | Partially. The trifecta invariant is the one composition rule (DESIGN.md 7.2). No general sequence rules | DESIGN.md 7 |
| X4 | Composition split across sessions: private data read in session A, sent out in session B | Not defended. Taint and trifecta flags belong to one session, one host connection (DESIGN.md 6.1, `docs/LANGUAGE.md`), and end with it | No issue yet |
| X5 | Confused deputy across principals: a session acts on one user's task with another user's authority | Not defended. A session is one host connection; it has no accountable principal | No issue yet |
| X6 | Agent identity spoofing: a process presents itself as an authorized agent | Not defended. The gate trusts the host's routing and has no agent identity (DESIGN.md 2.2, 10.3) | No issue yet |
| X7 | Behavioral drift: a component's schema is unchanged but its call pattern shifts | Not detected. `ops/posture.py` is a tally, not a detector | Planned: DESIGN.md 18, runbook step 16 |
| X8 | Component swap below the tool schema: binary replaced, remote resource changed | Not enforced. Only `tool_schema` pins are checked; `binary_integrity` and `integrity_watch` entries are parsed and ignored at runtime, although DESIGN.md 2.1 lists T5 as defended | #42 |
| X9 | Audit tampering by a party who can write the log | Detected only against a chain head anchored outside the log. With no anchored head, whoever can write the log can rebuild the chain. No asymmetric signing | DESIGN.md 8.6, `docs/adr/0001-audit-chain-construction.md`. Third-party verification: runbook step 8 |
| X10 | Injection through MCP surfaces other than `tools/call`: `resources/read`, `prompts/get`, upstream notifications, server-to-client requests | Defended by not proxying. Host requests other than `initialize`, `tools/list`, `tools/call` get `-32601`; upstream notifications are dropped and server-to-client requests refused | DESIGN.md 3.3, `tests/replay/test_mcp_surface.py` |

## Residual risk

An action that the manifest permits and a human approves can still be the wrong
action. That is an approval-quality problem, not an authorization gap (DESIGN.md 2.2,
10.4). State it to deployers plainly.

## Executable form

Each defended threat has a replay test under `tests/replay/` that asserts the layer
that stops it, for example `test_github_mcp_exfil.py` (T1, T2, T6) and
`test_mcp_surface.py` (X10). A threat moves from "not defended" to "defended" in this
table only with such a test.

## Provenance of this file

Imported from the Bawbel sprint kit draft (2026-09) and rewritten against DESIGN.md.
The draft numbered its threats T1 to T10, which collided with DESIGN.md 2.1 for
different threats; those IDs are retired. Threats the draft listed that DESIGN.md 2.1
already covers (excessive agency, tool poisoning, secret exfiltration) are left to
DESIGN.md. The draft's attack trees for strategy-document demo scenarios and its news
references are not carried over.
