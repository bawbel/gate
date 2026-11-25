# Evidence model and gap analysis

Report, 2026-11-25, for [#208](https://github.com/bawbel/gate/issues/208). It asks what an auditor, a
CISO or an incident investigator can learn from what the gate writes and the Hub holds today, and
what they cannot. It proposes new gate events as options, implements none, and maps nothing to a
compliance framework. It also holds the incident questions of [#210](https://github.com/bawbel/gate/issues/210),
which are merged into it and not kept as a separate file. Companion reports:
[THREAT-MODEL.md](./THREAT-MODEL.md) (#206).

Every claim carries a tag. **VERIFIED**: run on 2026-11-25. **SOURCED**: read from the file named, at
`develop` `92ea9d3`. **UNVERIFIED**: stated without either, and said so.

## What counts as evidence here

The evidence is the audit log the gate writes (DESIGN.md 8.6) and the copy the Hub keeps of it. Four
limits apply to every answer below.

1. **The chain is tamper-evident with limits.** `audit verify` catches an edited record, a record cut
   off mid-line and a missing first record (VERIFIED 2026-11-22, step U-01 of `docs/MANUAL-TEST.md`). It does not catch removal of the
   last records, a rewrite that recomputes every hash, or an empty file, unless a chain head was kept
   outside the log (DESIGN.md 8.6, [THREAT_MODEL.md](../THREAT_MODEL.md) X9).
2. **Time is the gate host's clock.** `ts` is UTC with millisecond precision and a `Z` suffix, set by
   the gate when the record is written (VERIFIED, 5 records). No other clock backs it.
3. **Arguments are hashed, not stored.** A record holds `args_sha256`. The arguments cannot be
   recovered from the log (VERIFIED, member list below).
4. **The Hub is not yet an independent check.** It stores each record as JSON and a chain head per
   session, and its routes return counters only (SOURCED: `hub/server.py` lists the routes. VERIFIED for the state routes, #207 C7.5). The threat model records that
   its chain check can be bypassed and that a rewrite of records it already holds is accepted without
   a flag (#207, cases H3).

**The gate writes five event types.** The task text says three. The five `append` call sites in `src/`
write `SESSION_START`, `CALL_DECIDED`, `DRIFT_DETECTED`, `SESSION_CLEAR` and `SESSION_END` (SOURCED:
`mux/proxy.py`, `cli.py`). `serve` writes three of them in an ordinary session, and the other two are
written by a drift or by the `clear` command.

## Field inventory

"Run" means the member was read from a record written by `bawbel-gate serve` 0.1.1 (or `clear`) on
2026-11-25. "Source" means it was read from the code that builds the record and was not produced by a
run in this report.

| Event | Member | Meaning | How checked |
|---|---|---|---|
| all | `seq` | counter within one log file. It continues across sessions in the same file (issue #159) | run |
| all | `ts` | UTC time with milliseconds, set by the gate at write time | run |
| all | `session` | UUID of the `serve` run. For `SESSION_CLEAR` it is a string the operator types, and it is not checked against the log | run (`clear` accepted an arbitrary string and the chain still verified) |
| all | `event` | the event type | run |
| all | `prev`, `hash` | the chain links (DESIGN.md 8.6) | run |
| `SESSION_START` | `manifest_hashes` | map of upstream server name to the digest of the manifest as loaded | run |
| `CALL_DECIDED` | `server`, `tool` | the upstream's label from `gate.yaml` and the bare tool name | run |
| `CALL_DECIDED` | `effect` | `allow`, `approve` or `deny` | run |
| `CALL_DECIDED` | `reason` | for example `resolved`, `no_grant`, `trifecta_third_leg`, `approval_denied`, `approval_timeout` | run |
| `CALL_DECIDED` | `taint` | the provenance classes in the session when the call was decided | run |
| `CALL_DECIDED` | `args_sha256` | hash of the call's arguments | run |
| `CALL_DECIDED` | `manifest_sha256` | digest of the manifest that decided the call, or null if none | run |
| `CALL_DECIDED` | `ave` | AVE ids attached to the decision | run |
| `SESSION_END` | none | the chain head is printed on stderr, not written in the record | run |
| `DRIFT_DETECTED` | `server`, `stored_hash`, `current_hash` | a tool schema digest differs from the stored one | source (`mux/proxy.py` `_check_drift`); not run here |
| `SESSION_CLEAR` | `operator` | the constant string `cli`, not an identity | run |

`CALL_DECIDED` has no request id, no rule id, no time of request, and no result. `ts` is written after
the decision and any forwarding are done (SOURCED: `_audit_call` runs after `_forward_and_tag`), so it
marks the end of the call, and an approval wait is inside it.

**Defined and never written.** `_const.py` also names `TOOL_LIST`, `CALL_RECEIVED`,
`RESPONSE_RECEIVED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED` and `APPROVAL_TIMEOUT`. None is written at an
`append` call site. `ops/posture.py` reads `APPROVAL_TIMEOUT`, so its counter cannot be anything but 0
(#158). DESIGN.md 8.6 names a `--store-args` option, and `serve --help` shows none (VERIFIED).

## The ten questions

Each row says what can be answered from the gate's records, what a Hub-side join could answer if the
Hub had a read path (it has none: its routes return counters), and what cannot be answered because a
field or an event does not exist.

| # | Question | Answerable now | With a Hub-side join | Not answerable |
|---|---|---|---|---|
| Q1 | Which agent called which tool? | the upstream and the tool: `server`, `tool` | none | which agent: no agent identity member exists. The gate reads no caller identity |
| Q2 | Under which approved manifest was the call decided? | the manifest digest: `manifest_sha256` per call, `manifest_hashes` per session | the manifest's content, if the Hub kept manifests by digest. It keeps none | that the manifest was approved or reviewed: no record or manifest field says so |
| Q3 | What was decided, and why? | `effect`, `reason`, `ave`, and the session's `taint` | none | which grant or rule matched: no rule id is written |
| Q4 | Who approved it, and when? | that approval was needed and its outcome: `effect: approve`, or `deny` with `approval_denied` or `approval_timeout` | none | who approved. When it was asked: `ts` marks the end of the call. The cause of a refused approval is dropped from the record (#158) |
| Q5 | What was denied? | every denied call: `effect: deny`, `reason`, `server`, `tool`, `session`, `ts` | the Hub counts denies per gate and holds the records | the arguments of a denied call: only `args_sha256` |
| Q6 | When did scope change, and who changed it? | not in a single log | whether the digest changed: compare `manifest_hashes` between two sessions of one gate. The Hub holds the records, with no query to do it | when it changed, who changed it, and what it changed to: no event records a change. A tool schema change is `DRIFT_DETECTED`, with two digests only |
| Q7 | Which human or service principal was it acting for? | none | none | no principal member exists. `SESSION_CLEAR` has `operator: cli`, a constant |
| Q8 | In what order, and when, did the calls happen? | order: `session`, `seq`, the chain. Time: `ts`, from the gate's clock | none | a clock other than the gate's |
| Q9 | Can I show nothing was removed or altered? | an edit, a cut line and a missing first record are detected by `audit verify` | the Hub holds a head per session and could serve as the outside anchor. It does not compare a held record with an incoming one today | removal of the last records, a consistent rewrite and an empty file, without an anchored head. An empty or silent gate is absent from the Hub's fleet state (#207, H3) |
| Q10 | Which components were in force, and did a tool definition change? | the manifest digest, and a `DRIFT_DETECTED` record if the gate saw a tool schema digest differ from the stored one | the manifest content by digest, as for Q2 | a component digest for the running server (DESIGN.md 4.3 is only a draft, #183), and any change the gate did not check |

## Incident questions

For [#210](https://github.com/bawbel/gate/issues/210). An investigator asks ten questions of the records
after an agent does something that goes wrong. Where one is an auditor question above, the last column
points to it and the answer is not repeated. The wording is technical evidence that helps an
investigation. It says nothing about liability, responsibility or law.

| # | Incident question | Answerable now | With a Hub-side join | Not answerable | Same as |
|---|---|---|---|---|---|
| I1 | Which agent initiated the action? | none | none | no agent identity member | Q1 |
| I2 | Which human or service principal owned it? | none | none | no principal member | Q7 |
| I3 | Who authorized the capability? | that a grant was in force: the manifest digest on the call | what was granted: the manifest content, keyed by that digest. The Hub keeps none | who wrote or approved the grant: the manifest schema has no owner or reviewer field, and no event records a change | new |
| I4 | Which policy was active, by version or digest? | the manifest digest | the content by digest | a policy version, a rule id, a digest of `gate.yaml` | Q2, Q3 |
| I5 | Was human approval required, requested, obtained? | for a granted call, `effect: approve` after a prompt. For a refused or timed-out one, `deny` with `approval_denied` or `approval_timeout` | none | "requested" as a separate fact: no approval event is written. By whom: no approver member. The cause of a refusal is dropped (#158) | Q4 |
| I6 | Did the gate allow or deny the call? | `effect`, `reason` | none | none | Q3, Q5 |
| I7 | Which downstream system executed it? | the upstream the call was forwarded to, for an allowed or approved call: `server`, a label from `gate.yaml` | none | what the downstream system did, and whether the call succeeded: no result is recorded, because `RESPONSE_RECEIVED` is defined and never written. The label is not a verified identity of the system | new |
| I8 | Was the configuration or manifest changed recently? | none | compare `manifest_hashes` between sessions | when, by whom and to what. Any change to `gate.yaml` | Q6 |
| I9 | Which component digest was in force? | the manifest digest | the content by digest | a component digest for the running server (draft #183) | Q10 |
| I10 | What evidence exists, and can it be checked offline? | the log file and `bawbel-gate audit verify FILE`, which needs only the file | a bundle with its own verifier. None exists | completeness (Q9). The manifest content, which the log holds only as a digest, so the operator has to have kept it | Q9 |

**Checked offline.** VERIFIED 2026-11-25: `bawbel-gate audit verify` on a copy of a log,
with an empty `HOME` and `env -i`, printed `ok: 6 records, chain intact`.

**Result.** One of the ten is answerable in full from the log (I6). Six are answerable in part (I3, I4,
I5, I7, I9, I10) and I8 only with a join the Hub cannot do yet. Two are not answerable at all (I1, I2).

### The four parties

An investigation names four parties. This table says which technical records name each one today. It
draws no conclusion about who is responsible.

| Party | Records that name it today | What no record names |
|---|---|---|
| The vendor of a component | `server`, a label from `gate.yaml`. The manifest's `subject` name, in the manifest content. The AVE ids on a decision, when a finding applies | an organisation: there is no vendor member |
| The deploying organisation | none. The Hub's `gate_id` is a generated label | an organisation or tenant member |
| The permission owner | the grants in the manifest content, reached by digest | an owner, reviewer or approver: the schema has no such field and no record carries one |
| The supervisor | none. An approval names no approver, and `SESSION_CLEAR` has `operator: cli` | any member that names a person or a role |

## What gateway checklists ask for

A vendor buyer's guide for MCP gateways lists the fields and features its readers ask for. It is a
secondary source, it was not re-read for this report, and it is used as a list of questions only.

| Asked for | Have, partial or lack | Fields or reason |
|---|---|---|
| Time in UTC | have | `ts` |
| User | lack | no principal member |
| Agent | lack | no agent identity member |
| Server | have | `server` |
| Tool | have | `tool` |
| Decision | have | `effect`, `reason` |
| Policy | partial | the manifest digest, with no policy version and no rule id |
| Session id | have | `session`, `seq` |
| Tamper-evident log | partial | the chain, with the limits above |
| Exportable log | lack | the JSONL is the file. No export command exists, and `audit export` is a draft (#202). The Hub has no export route |
| SIEM-ready | partial | a CEF formatter exists for alert classes and nothing calls it. OpenTelemetry spans are sent only when an endpoint is configured |
| Retention controls | lack | neither the gate nor the Hub has any |
| Hash-pinned tool definitions with change alerts | partial | DESIGN.md 8.1 specifies pins, and the gate writes `DRIFT_DETECTED` when a stored digest differs from the live one. The alert goes out only through OpenTelemetry when it is configured. This report did not test pinning |
| Export for exit | lack | no bundle and no offline verifier exist for the Hub |

## Gaps already known, and gaps this work found

Already known: no agent identity or owner, no scope-change record, no approver record.

Found by this work:

- No request id, no rule id and no result or outcome in `CALL_DECIDED`, and `ts` marks the end of the
  call. The `Decision` type has a `rule_ids` field that nothing in `src/` fills, so it is always empty
  (SOURCED: `policy/engine.py`, and `git grep` finds no use).
- Six event names are defined and never written, including every approval event.
- The manifest schema has no owner, reviewer, approver or contact field, so no record names the person
  who is responsible for a grant.
- No record carries a format version, so a reader cannot tell which rule wrote a member such as
  `args_sha256`.
- The Hub keeps whole records but exposes counters only, keeps no manifests, and does not tell a silent
  gate from an absent one.
- `--store-args` is documented in DESIGN.md 8.6 and does not exist.

## Proposals for new gate events and fields

Proposals only. None is implemented and none is chosen. Under CONTRIBUTING, adding a member or an event
is a DESIGN.md change that merges alone first, and a change to the chain construction needs its own
ADR. Adding members does not change the chain construction, because the hash covers whatever members a
record has.

| | Proposal | Answers | Cannot show | Options |
|---|---|---|---|---|
| P1 | An agent identity and owner member, recorded as **asserted** | Q1, Q7 | that the claim is true. The gate cannot verify who is behind the host | A: set in `gate.yaml` and written on `SESSION_START`. B: read from the environment at start. C: neither, and leave it to the Hub operator |
| P2 | Approval records: a request, an outcome and an approver as **asserted** by the channel | Q4 | that a human answered. A channel answers, and the gate records what the channel says | A: write the existing `APPROVAL_*` names. B: add approval members to `CALL_DECIDED`. C: one new event that closes an approval |
| P3 | A record of a scope change | Q6 | who changed it, unless an outside system records that | A: no gate change, and the Hub compares `manifest_hashes` between sessions. B: a new event at start that carries the previous digest. C: a change record kept in the operator's repository, outside the log |
| P4 | A rule id on `CALL_DECIDED` | Q3 | nothing beyond which grant matched | A: fill and write `rule_ids`. The `Decision` type has that field, nothing in `src/` fills it, and it is always empty. B: leave it out |
| P5 | A request time, and a result status, on `CALL_DECIDED` | Q8, and part of Q4 | what a downstream system did | A: add both. B: add the request time only. C: neither |
| P6 | A format version member | every question that depends on how a member was computed | nothing about content | A: on `SESSION_START`. B: on every record. C: none |

## Decisions owed

Open, none decided here.

- Whether to add gate events for a scope change and for an approver record, and an agent identity or
  owner member (P1 to P3). The remaining proposals are smaller and are listed for the same decision.
- Whether this accountability work stays inside the gate and the Hub, with no new repository.
- Whether the Hub keeps incident objects of its own, such as an incident id and notes, that never touch
  the records.

## Not done

- No fix, no code, no test, no DESIGN.md change, and no compliance mapping.
- `DRIFT_DETECTED` was not produced by a run. Its members are read from the code.
- The Hub was not asked for a join, because it has no route that could do one.
- The checklist source was not re-read.

## Sources

- This repository at `develop` `92ea9d3`: `src/bawbel_gate/mux/proxy.py`, `cli.py`, `_const.py`,
  `audit/writer.py`, `ops/posture.py`, `hub/store.py`, `hub/server.py`, `schemas/capability-manifest-v1.json`,
  DESIGN.md 8.6.
- Records written by `bawbel-gate serve` 0.1.1 and by `bawbel-gate clear`, 2026-11-25, in a fresh
  virtualenv with an empty `HOME`.
- A vendor buyer's guide for MCP gateways, secondary, not re-read.
