# Export formats: what each carries and what each loses

Report, 2026-11-26, for [#246](https://github.com/bawbel/gate/issues/246). Report only: no code, no
test, no DESIGN.md change, and nothing chosen. It maps the records the gate writes to four formats
(native JSONL, OCSF, OpenTelemetry, CSV), says what each carries and loses, sets out a sensitive-field
policy, and proposes a loss test plan. It reuses the OCSF mapping already decided for DESIGN.md 8.7
([#202](https://github.com/bawbel/gate/pull/202), a draft) and adds no class of its own.

The wording of this file is "tamper-evident, with these limits" and "technical evidence that helps an
investigation". It makes no claim about compliance. Companion reports: [THREAT-MODEL.md](./THREAT-MODEL.md)
(H7, stored injection), [EVIDENCE-MODEL.md](./EVIDENCE-MODEL.md), [ACCOUNTABILITY-LIMITS.md](./ACCOUNTABILITY-LIMITS.md).

Every claim carries a tag. **VERIFIED**: run, on the date given. **SOURCED**: read from the file or page
named, on 2026-11-26, at `develop` `b9d76a9` for this repository. **DERIVED**: follows from quoted text and
nothing was run. **UNVERIFIED**: stated without any of these, and said so.

## 1. What the gate writes, and what exists today

SOURCED, `src/` at `b9d76a9`. The five `append` call sites write five event types. Every record also has
`seq`, `ts`, `session`, `event`, `prev` and `hash`.

| Event | Members beyond the common ones |
|---|---|
| `SESSION_START` | `manifest_hashes` (a map from server name to digest) |
| `CALL_DECIDED` | `server`, `tool`, `effect`, `reason`, `taint` (a list), `args_sha256`, `manifest_sha256`, `ave` (a list) |
| `DRIFT_DETECTED` | `server`, `stored_hash`, `current_hash` |
| `SESSION_CLEAR` | `operator` (`cli`), and the `session` the operator named |
| `SESSION_END` | none |

The other event names in `_const.py` (`TOOL_LIST`, `CALL_RECEIVED`, `RESPONSE_RECEIVED`,
`APPROVAL_GRANTED`, `APPROVAL_DENIED`, `APPROVAL_TIMEOUT`) are written nowhere. A record holds no
argument payload and no tool result: only `args_sha256`. It holds no duration, no trace id and no
request id.

Two exporters exist, neither of which reads the log:

- **OpenTelemetry decision spans** (`ops/otel.py`). SOURCED: while the gate runs, a span named
  `bawbel.gate.decision` carries `gate.server`, `gate.tool`, `gate.effect`, `gate.reason`,
  `gate.taint_classes` (a comma-joined string), `gate.latency_ms` and `gate.ave_ids`. These are the gate's
  own attributes, not the MCP conventions of section 4. The span is emitted only if a tracer is configured.
- **CEF and syslog** (`ops/syslog_cef.py`). SOURCED: it formats the six alert classes of DESIGN.md 8.5, not
  audit records. DESIGN.md 8.7 says the same.

## 2. Native JSONL

The log itself, or the Hub's stored copy, which keeps the record as it arrived in `record_json`
(SOURCED, `hub/store.py`).

| | |
|---|---|
| Carries | every member of every record, in the order written, with `prev` and `hash` |
| Loses | nothing. It is the source of truth (DESIGN.md 8.5) |
| Verifies | `bawbel-gate audit verify`, offline, with no other input |
| Sensitive content | none beyond what section 5 lists. The log holds no arguments and no results |

An export in this format must be the bytes of the log, or a contiguous run of whole records of it. A
filtered or reordered copy is not the chain, and it must say it is not (section 7).

## 3. OCSF

**No new mapping is proposed.** DESIGN.md 8.7 in the draft #202 maps the gate's events to the classes that the
ACS file `specification/v0.1.0/trace/ocsf-mapping.json` names, at ACS commit `ee935751454e`. The maintainer
recorded decisions for it on 2026-11-25 and 2026-11-26. It is a draft and not implemented. SOURCED from that
branch:

| Gate event | OCSF class | Notes |
|---|---|---|
| `SESSION_START` | 3002 Authentication, activity 1 | ACS `steps/sessionStart` |
| `SESSION_END` | 3002 Authentication, activity 2 | ACS `steps/sessionEnd` |
| `CALL_DECIDED`, effect `deny` or `approve` | 2004 Detection Finding | ACS decision rules: deny and ask |
| `CALL_DECIDED`, effect `allow` | 6002 Application Lifecycle, severity 1 | unless the deployment elects Detection Findings for allows |
| `DRIFT_DETECTED` | 5001 Device Inventory Info, activity 2 | ACS `agbom/changed`, decided on the condition that `docs/ACS_GATE_MAPPING.md` section 3 relates it |
| `SESSION_CLEAR` | none: omitted, and the first line of the export says so | |

The 8.7 decisions that matter here: one decision event per record; the join value is `<session>:<seq>`,
labelled under `unmapped.gate` as built from session and seq so it is never read as an ACS request id; every
event carries `session`, `seq`, `hash` and `prev` under `unmapped.gate`; a denied call carries a member that
says the gate did not forward it; OCSF only; the log is verified first unless `--skip-verify`, and then the
first line says "verification not run".

**Class 6003.** The task asked for OCSF class 6003 only if 8.7 already uses it. It does not: no event above
maps to 6003. The existing choice stands, and this report does not add 6003.

**OWASP AOS, a cross-reference and not a dependency.** SOURCED on 2026-11-26 through a fetch tool, with
the limits of section 8. The project page at `owasp.org/www-project-agent-observability-standard/` shows
"Incubator Project" and its repository's `info.md` shows "Version 0.0.0". Its `index.md` says the project
works "by extending other existing standards" and names "OCSF and OpenTelemetry for Tracing". The pages
read contain **no trace-to-OCSF mapping**: no class, no `type_uid` and no `unmapped.aos`. The project-site
link in `index.md` returned HTTP 404. The earlier belief that AOS maps traces to API Activity (class 6003,
`type_uid` 600301) is therefore unconfirmed, and nothing in this report relies on it. If a mapping exists, I
did not find where.

## 4. OpenTelemetry

SOURCED through a fetch tool on 2026-11-26: `docs/gen-ai/mcp.md` in `open-telemetry/semantic-conventions-genai`.
The page banner reads "**Status**: [Development]". It shows no date, commit or tag, so the version read is
unknown. The links on it name semantic-conventions `v1.45.0`. The fetch read the first 39,891 of 113,626
characters verbatim. That covers the client and server span sections and their attribute tables. It did
not read the metrics section, the transport section or the examples verbatim, so statements about those
are UNVERIFIED and not made here.

**Stability.** The conventions are in Development. An export built on them can change under it, so the
version it was written against must be recorded in the export.

**What the page says**, quoted from the fetch report:

- Span name: "SHOULD follow the format `{mcp.method.name} {target}`", where the target "SHOULD match
  `{gen_ai.tool.name}`" for a tool. Kind: "SHOULD be `CLIENT`" for a client span and "SHOULD be `SERVER`" for a
  server span.
- Attributes and their levels: `mcp.method.name` Required. `gen_ai.tool.name`, `jsonrpc.request.id`,
  `error.type` and `rpc.status_code` Conditionally Required. `mcp.session.id` and `mcp.protocol.version`
  Recommended. `gen_ai.operation.name` Recommended, "SHOULD be set to `execute_tool`" for a tool call.
  `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` and `gen_ai.prompt.variables` are **Opt-In**, and each
  carries the warning "This attribute may contain sensitive information."
- It says nothing on whether the opt-in attributes are on or off by default, and gives no mechanism.
- Relation to GenAI: "MCP tool call execution spans are compatible with GenAI execute_tool spans", and
  instrumentation that sees outer GenAI tracing "SHOULD NOT create a separate span".

**Field mapping.** DERIVED. A gate record could become one span, named for the decision:

| OTel attribute | From the record | Caveat |
|---|---|---|
| `mcp.method.name` | `tools/call` for `CALL_DECIDED` | the record does not store the method. It is the only method the gate decides |
| `gen_ai.tool.name` | `tool` | the bare name. `server` has no convention attribute and stays `gate.server` |
| `gen_ai.operation.name` | `execute_tool` | for a `CALL_DECIDED` only |
| `error.type`, `rpc.status_code` | for `deny`, the gate's own error (`-32031`) | the page's rules for which codes count as errors differ between client and server spans. How a gate denial is represented is not stated and not assumed |
| `mcp.session.id` | not the gate's `session` | the gate's session id is its own. Over stdio there may be no MCP session id. Keep it as `gate.session` |
| `mcp.protocol.version` | not recorded | omitted |
| `gate.*` | `effect`, `reason`, `taint`, `ave`, `args_sha256`, `manifest_sha256`, `seq`, `hash`, `prev` | the gate's own attributes, as today's live span does |
| `gen_ai.tool.call.arguments`, `.result` | never | the log holds neither (section 5) |

**What an OTel export from the log cannot carry.** DERIVED: a record has one timestamp, written after the
call ends, and no start, no duration, no trace id and no span id. So a span built from the log has no
duration and no place in a trace, and it cannot be joined to the host's or the upstream's spans. Only the
live exporter in `ops/otel.py` knows the latency, and it does not use the MCP attribute names. That is a
gap between the live exporter and the conventions, and a reason that an OTel export from the log is
a record feed in the shape of spans and not a trace.

## 5. CSV

DERIVED. One row per record, one fixed column set for all events.

| Column | Source | Note |
|---|---|---|
| `seq`, `ts`, `session`, `event`, `prev`, `hash` | the record | |
| `server`, `tool`, `effect`, `reason`, `args_sha256`, `manifest_sha256` | `CALL_DECIDED` | empty for other events |
| `taint`, `ave` | `CALL_DECIDED` | a list. One cell holding a JSON array, so a comma inside a value cannot split it |
| `manifest_hashes` | `SESSION_START` | a map. One cell holding a JSON object |
| `stored_hash`, `current_hash` | `DRIFT_DETECTED` | |
| `operator` | `SESSION_CLEAR` | |

**Risks specific to CSV.** DERIVED, not run: a spreadsheet may read a cell that begins with `=`, `+`, `-` or `@`
as a formula. `tool` is the name the host asked for and `reason` and `server` come from the gate's own
configuration and codes, but a denied call is recorded with whatever name the agent used, so an attacker-
influenced string can reach a cell (#207, H7). The usual guard prefixes such a cell with a character that
stops it being read as a formula. That changes the value, so the export must say so (section 7). Whether to
guard by default is open. This is general knowledge about spreadsheets, was not tested here, and is UNVERIFIED.

## 6. Sensitive-field policy

SOURCED and DERIVED. Proposed as a policy for the maintainer to accept or change. Nothing is decided.

1. **Never exported, in any format:** an argument payload and a tool result. The log does not hold them
   (`args_sha256` only), so the rule is that no export adds a way to get them back, and `--store-args`, which
   DESIGN.md 8.6 says is not built, would need its own decision before any export could include it.
2. **Digests and names are not secrets but are metadata:** `args_sha256`, `manifest_sha256`, `server`, `tool`.
   They stay in every format. A hash of a small argument space can be brute forced, so `args_sha256` is
   metadata about the argument, not a protected value.
3. **`principal_id`.** If the identifier set the maintainer chose in ADR 0004 (set B) is built, the log gains
   `agent_id` and `principal_id` on `SESSION_START`. `principal_id` is the member most likely to be personal
   data. Proposal: native JSONL keeps it, because it is the log, and every other export leaves it out unless
   the operator asks for it by name.
4. **Attacker-influenced text** (`tool`, `reason`, `server`): escaped for the format's own syntax (CSV
   quoting and the formula guard, JSON escaping, OCSF and OTel string values) and never interpreted.
5. **Every export says what it is** (section 7): its format, the pinned mapping, what it omitted and whether
   the log was verified.

## 7. What each format loses, and what the export must say

| Member or property | Native | OCSF | OTel | CSV |
|---|---|---|---|---|
| order and the chain (`prev`, `hash`) | kept | `seq`, `hash`, `prev` under `unmapped.gate`. The chain cannot be recomputed from an event, because the event does not hold every member | kept as attributes. Not a chain | kept as columns. Not a chain |
| `SESSION_CLEAR` | kept | omitted, named in the first line | not mapped. Open | kept as a row |
| `DRIFT_DETECTED` | kept | class 5001, activity 2 | an event or a span. Open | kept as a row |
| a call's duration, trace id, span id | not in the log | not in the log | **absent**, so not a trace | not in the log |
| `taint`, `ave`, `manifest_hashes` (lists and maps) | kept | under `unmapped.gate` | `gate.*` attributes. The live exporter already joins taint with commas | a JSON string in one cell |
| numeric types | as written | OCSF types | OTel attribute types | everything becomes text |
| the join to the log | the log is the file | `<session>:<seq>` | `gate.session` and `gate.seq` | `session` and `seq` columns |

An export states in its first line, or its header, what it is not. For OCSF that is the DESIGN.md 8.7 first
line. For the others the proposal is the same shape: the format and version, the log it was built from (its
chain head and record count), whether the chain was verified, and what was omitted. None of the exports is a
tamper-evident copy, and the first line says so. A recipient who needs the chain asks for the native file.

## 8. Loss test plan

None of this is built. The plan is for the implementation pull requests, each with its tests first
(CONTRIBUTING, "Property test before implementation").

1. **A loss table that is a test.** A table in code states, for every member of every event type and every
   format, one of *kept*, *transformed* or *dropped*. A test fails if a member of the record is missing from the
   table, so adding a member to the log forces a decision about each export. This is the main control.
2. **Join test.** For each format that is not native, every exported event can be traced to its record by
   `session` and `seq`, and the carried `hash` and `prev` equal the record's. The count of exported events
   equals the log's record count minus the omitted ones the first line names.
3. **Sensitive-field tests.** No output holds an argument payload, a result, or a key that could (the 8.7.11
   property already says this for OCSF). With the policy of section 6, `principal_id` is absent from every
   export except native unless it is asked for.
4. **Injection tests.** A property test over arbitrary strings in `tool`, `reason` and `server`: JSON stays
   valid, CSV parses back to the same row apart from the documented guard, and a cell that begins with `=`,
   `+`, `-` or `@` is guarded. The OTel attribute value is the string, unchanged.
5. **Determinism and purity.** The same log gives the same bytes. The input file is byte-identical after a
   run. The run opens no network connection (the 8.7.11 properties, for every format).
6. **Class and attribute pinning.** Every OCSF `class_uid` is in the pinned ACS file. An OTel export names
   the conventions version it was written against, and sets no Opt-In attribute.
7. **Round trip, where it exists.** Native to native is byte-identical. CSV parses back to the records
   modulo the documented guard and the text typing, which the test states. OCSF and OTel have no
   round trip, because they drop members, and the test checks the join instead.
8. **Version drift.** A test that fails when the pinned OCSF file or the named OTel conventions version
   changes, so a move is a pull request and not a surprise.

## 9. Decisions owed

All open. None is decided here.

- Whether CSV exists at all, and whether the formula guard is on by default.
- Whether an OTel export from the log is worth building, given that it cannot carry a duration or a trace
  id, or whether the live exporter should adopt the MCP attribute names instead.
- The sensitive-field policy of section 6, in particular where `principal_id` goes.
- Whether the live OTel decision span (`bawbel.gate.decision`, `gate.*` attributes) is aligned with the MCP
  conventions. That is a change to an existing exporter.

## 10. Not done

- No code, no test, no export was produced, and no format was validated against a real consumer.
- The OTel page was read through a fetch tool: the first 39,891 of 113,626 characters verbatim. The metrics,
  transport and examples sections were not read verbatim and are not described. The page shows no date or
  version, so "the version read" is the live page on 2026-11-26 with semantic-conventions `v1.45.0` named in its links.
- The OWASP AOS pages were read through a fetch tool. The project site link returned 404, and no mapping page
  was found. That is a finding about what I could reach, not proof that no mapping exists.
- OCSF itself, CEF and the spreadsheet formula behaviour were not read or run.
- The 8.7 mapping is a draft in #202 and may change before it merges.

## Sources

- This repository at `develop` `b9d76a9`: `src/bawbel_gate/ops/otel.py`, `ops/syslog_cef.py`,
  `mux/proxy.py`, `hub/store.py`, `_const.py`, DESIGN.md 8.5 and 8.6, `docs/hub/THREAT-MODEL.md` (H7).
- Draft pull requests #202 (DESIGN.md 8.7) and #213 (ADR 0004), at their heads on 2026-11-26.
- `github.com/open-telemetry/semantic-conventions-genai`, `docs/gen-ai/mcp.md`, read on 2026-11-26 as in section 4.
- `owasp.org/www-project-agent-observability-standard/` and its repository
  `OWASP/www-project-agent-observability-standard-2` (`index.md`, `info.md`), read on 2026-11-26.
