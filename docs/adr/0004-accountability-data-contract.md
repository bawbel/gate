---
status: proposed
date: 2026-11-25
---

# 0004. Accountability data contract: stable identifiers and where each is minted (options)

A draft for review, for [#212](https://github.com/bawbel/gate/issues/212). It proposes. The
maintainer's written decision of 2026-11-25 is recorded in the Decision section, copied by the
executor, who chose nothing. No code, no schema file and no DESIGN.md text changes with it. Under
CONTRIBUTING, each new record member is a DESIGN.md change that merges alone first. The status stays
`proposed` and the PR stays a draft until the maintainer has read it.

## Decision

**Decision: set B, maintainer, 2026-11-25.** Set A plus `agent_id` and `principal_id`, both labelled
asserted, on `SESSION_START` only.

- A separate member says that a value is asserted: `agent_id_source` for `agent_id` and
  `principal_id_source` for `principal_id`. The member's own name does not carry that label.
- `principal_id` is an opaque value the operator supplies. The gate holds no key and does no
  pseudonymising. The documentation tells operators not to put an email address or a name in it.
- Set C waits for the delegated-authority work (DEL-4). `decision_id`, `delegation_id` and
  `evidence_id` need things that do not exist yet. Scope-change and approver events wait for it too.
- Accountability stays inside the gate and the Hub, with no new repository.
- The Hub keeps no incident objects of its own for now, so `incident_id` is outside set B and has
  no owner for now.

What this leaves for later, not decided here: where the operator supplies the two values (a
configuration member or a flag), the accepted value syntax, and the DESIGN.md amendment that adds
the four members, which merges alone before any code. A value that is stable for a person is still
a stable reference to that person, and the log cannot be edited without breaking the chain, so what
happens when a person asks for removal is open. The guidance to operators covers what to put in the
value, not erasure.

Each claim carries a tag. **VERIFIED**: run on 2026-11-25. **SOURCED**: a file read on 2026-11-25, at
`develop` `92ea9d3` for this repository and at ACS commit `ee935751454eb58521b85ad5b73095e5540843c4`
for ACS, read as data with nothing run. **UNVERIFIED**: stated without either.

## What the records name today

VERIFIED, the members of the records of a real `serve` session: `seq`, `ts`, `session`, `event`, `prev`
and `hash` on every record. A decision adds `server`, `tool`, `effect`, `reason`, `taint`, `args_sha256`,
`manifest_sha256` and `ave`. A session start adds `manifest_hashes`. No member names an agent, a
principal, a delegation, a policy version or a request. The report behind this
([#209](https://github.com/bawbel/gate/pull/209), the evidence model for issue #208) lists the questions this leaves
unanswerable.

## Principles proposed for every identifier

1. **An identifier is a reference, never a secret.** A raw access token is never stored. A reference to
   a token, or a hash of one, may be.
2. **An identity the gate cannot verify is labelled asserted.** SOURCED, the token exchange report
   ([#204](https://github.com/bawbel/gate/pull/204)): the gate reads no caller identity today, and the
   only identity it could check is an assertion handed to it at start-up.
3. **A new member is optional.** A reader that finds it absent reads "not recorded".
4. **A new member does not change the chain construction.** The hash covers whatever members a record
   has. VERIFIED: a log of five old records followed by one record with six new members
   (`agent_id`, `agent_id_source`, `principal_id`, `policy_id`, `delegation_id`, `format`) was accepted
   by `bawbel-gate audit verify`: `ok: 6 records, chain intact`. The first five records alone also
   verify. The Hub's ingest was not run on such a log, which is UNVERIFIED.
5. **No identifier comes from model output.** The gate never consults it (DESIGN.md 2.3).
6. **An identifier is stable.** It is never reused for another thing, and a change of meaning is a new
   identifier.

## ACS identifiers read

SOURCED, ACS commit `ee935751454e`, `specification/v0.1.0/request-envelope.json`,
`response-envelope.json`, `context-entry.json` and `trace/ocsf-mapping.json`.

| Where | Identifiers |
|---|---|
| Request `params` | `request_id`, `nonce`, `timestamp`, `tenant_id` |
| Request `params.metadata` | `agent_id`, `agent_name`, `session_id`, `turn_id`, `parent_turn_id`, `user_context` with `user_id`, `roles` and `authentication_method` |
| Response `result` | `request_id`, `decision`, `reasoning`, `reason_codes`, `policy_references`, `cited_provenance_ids`, `chain_hash` |
| ContextEntry | `entry_id`, `step_id`, `step_type`, `request_hash`, `timestamp`, `previous_hash`, `entry_hash`. The Go reference adds `turn_id`, `approver` and `intent_extension` |
| OCSF mapping | `metadata.correlation_uid` as `<session_id>:<request_id>`. `unmapped.acs.request_id` and `unmapped.acs.session_id`. `evidences` that carry `ai_agent` and `actor.session`. `authorizations`, one per policy reference, each with a policy that has a `policy_id` or a `policy_name` |

## The candidates

"Exists" says whether the gate has the identifier today. "Mint" says who would create it.

| Identifier | Exists today | Mint | Stability | Privacy | ACS | OCSF (mapping file, #202) | `component_id` (#183) | Proposal |
|---|---|---|---|---|---|---|---|---|
| `event_id` | partly: `(session, seq)` names a record within one file, and `hash` names it by content (VERIFIED) | the gate's writer | stable for an unchanged record, and it changes if the record changes. `(session, seq)` is unique within a file only, because `seq` continues across sessions (#159) | none, a digest | `entry_id`, and `step_id`, which ContextEntry says SHOULD equal the request id | the file names no event id field. `metadata.correlation_uid` joins steps and decisions | none | the `hash` as the id needs no new member. A separate member would be a proposal |
| `decision_id` | no. A decision is one `CALL_DECIDED` record, and the gate has no request id (DESIGN.md 8.7.3, #202) | the gate | as `event_id` | none | `request_id`, which ties a result to a request. The result has no separate decision id | `unmapped.acs.request_id` | none | a proposal, and it needs a request id first |
| `agent_id` | no. The gate reads no caller identity (#204) | the operator in `gate.yaml`, or the host. The gate records it as asserted | a label the operator keeps, never reused for another agent | low. It must not embed a person's name | `metadata.agent_id` and `agent_name` | `ai_agent` in `evidences` | an agent is not a component, but the manifest `subject.kind` includes `subagent`, so an agent that is a component could use `subagent:name`. Open | a proposal |
| `principal_id` | no | the operator, or an identity provider outside the gate. Asserted unless the gate is handed a verifiable assertion at start-up (#204) | a pseudonymous reference that stays the same for the same person | highest. It is personal data. Store a pseudonym or a salted hash that the operator holds, never an email or a name. Retention is open | `user_context.user_id`, with `roles` and `authentication_method`, and `tenant_id` | not named by the mapping file for step events | none | a proposal |
| `delegation_id` | no. There is no delegation model (`docs/THREAT_MODEL.md` X1) | depends on an open decision: the operator in a reviewed manifest, or a token exchange at run time (#204) | stable for the life of a grant, ended by revocation, never reused | a reference | no delegation identifier was found in the files read. UNVERIFIED beyond them. `parent_turn_id` and `subagentStart` relate to nesting | none | the delegate may be a component | a proposal, blocked on that decision |
| `policy_id` | partly: `manifest_sha256` is a digest of the manifest. There is no policy id or version (VERIFIED) | the gate computes the digest. A readable id or a version would be chosen by the operator | the digest is stable for a content. An operator id is stable for a policy name | none | `policy_references`, each with `policy_id` or `policy_name` | `authorizations`, one per reference, each with a `policy` | a manifest governs a component, and `manifest_sha256` is not `component_sha256` | the digest needs no new member. An id or version member would be a proposal |
| `evidence_id` | no. No export bundle exists (DESIGN.md has only the draft 8.7) | the exporter, as the digest of the bundle's list of file digests | content-addressed | none by itself, and a bundle may hold personal data | no counterpart was found. UNVERIFIED | none | none | a proposal |
| `incident_id` | no | the Hub operator, kept in the Hub and never inside the evidence records | assigned by the operator | notes may name people, so it stays out of the records | none | none | none | a proposal, blocked on whether the Hub keeps incident objects at all |

## Smallest useful set. Options

- **A. Nothing new.** `event_id` is the existing `hash`. `policy_id` is derived from `manifest_sha256`.
  The component id is the one in #183. Gives part of what an investigator asks for about the policy and
  the component. Does not name an agent or a principal.
- **B. A, plus `agent_id` and `principal_id`, both asserted, on the session start only.** Gives an
  answer to "which agent" and "which principal", labelled as asserted. Costs: a personal-data member in a
  log that cannot be edited without breaking the chain, and an operator who must supply the values.
- **C. B, plus `decision_id`, `delegation_id` and `evidence_id`.** Each needs something that does not
  exist yet: a request id, a delegation model and an export. None is a first step.

The maintainer chose B. See the Decision section.

## Versioning and backward compatibility

Proposed: a format member on the records, as proposal P6 in the evidence model (#209). A record that
lacks it is the format that exists today. New members are optional. An old verifier accepts a log
that holds them (VERIFIED above), and an old reader that does not know a member ignores it. A change to
what an existing member means, or to the chain construction, is out of scope here and needs its own ADR
(ADR 0001, and the options in the draft ADR 0003).

## Not decided

Answered on 2026-11-25 (see Decision): which set (B), that an asserted identity is labelled by a
separate `_source` member, that the gate does no pseudonymising and holds no key, that accountability
stays inside the gate and the Hub, and that the Hub keeps no incident objects for now.

Still open:

- Where the operator supplies `agent_id` and `principal_id`, and what values are accepted.
- Erasure: what happens to a value in a chained log when a person asks for removal.
- The retention of a `principal_id`, which the candidates table also lists as open.
- The mapping to OCSF, which is the subject of DESIGN.md 8.7 in #202.
- The DESIGN.md amendment for the four new members (`agent_id`, `agent_id_source`, `principal_id`,
  `principal_id_source`) and the format member of proposal P6 in #209.

## Not done

- No code, no schema, no test, and no DESIGN.md change.
- The Hub's ingest was not run on a log with new members.
- ACS was read in the five files named. Other files may name an identifier this table lacks.

## Sources

- This repository at `develop` `92ea9d3`: `src/bawbel_gate/audit/writer.py`, `mux/proxy.py`,
  `schemas/capability-manifest-v1.json`, `docs/THREAT_MODEL.md`.
- ACS, commit `ee935751454eb58521b85ad5b73095e5540843c4`, the five files named above.
- Open pull requests of this repository, read as drafts: #183, #200, #202, #204, #209.
