# Implementation status: bawbel-gate and the Hub

What is built, what is partly built, what is missing, what is risky and what is duplicated, written
from the code. For [#205](https://github.com/bawbel/gate/issues/205). It holds no roadmap.

- **Commit:** `92ea9d366fa400126777da807ca1b3821eef8d35` (`develop`), checked out clean, 2026-11-25.
- **Baseline test result:** 478 tests, 0 failures, 0 errors, 0 skipped, in 23.325 s. The command:
  `env -i PATH=<venv>/bin:/usr/bin:/bin HOME=<empty dir> python -m pytest -q -p no:cacheprovider --junitxml=<file>`,
  in a fresh virtualenv with `pip install -e .[dev]`, Python 3.12.3, pytest 9.2.0. The per-file counts
  are at the end. The run prints no pytest summary line. It ends with `NETGUARD external attempts: 0`,
  so the counts come from the junit XML.

## How to read this file

| Status | Meaning |
|---|---|
| implemented | the code does what the row says, and a test or a command shows it |
| partial | some of it is built, and the row says which part |
| missing | not implemented. The row says "missing" and names what is absent |
| risky | built, and a run showed a behaviour that can mislead or expose something |
| duplicate | the same logic exists in more than one place |

The last column names a file, a test file with its count in the baseline, or a command. **Run** means
the command was run on 2026-11-25 unless a date is given, in a fresh virtualenv with an empty `HOME`.
**Source** means the row rests on reading the code and no run was made for it. References of the form
"#207 C2.1" are cases from the Hub threat model's run, which is open as
[#207](https://github.com/bawbel/gate/pull/207) and holds the run output.

The file covers the nine areas of #205 and nothing else. It is a status, and it makes no claim that
any component meets a requirement.

## Identity

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| Caller identity: a human principal, an agent identity, an owner | missing | No record names a caller. The gate reads none: the only `clientInfo` in `src/` is the gate's own name, sent to upstreams. | `mux/proxy.py`. Run: the members of every record in a `serve` session (below). `docs/THREAT_MODEL.md` X6 |
| Delegation, an authority chain | missing | There is no delegation model. | `docs/THREAT_MODEL.md` X1. DESIGN.md 1 and 12 |
| Manifest `subject` (kind and name) | implemented | Names the component a manifest governs. | `schemas/capability-manifest-v1.json`, `policy/manifest.py`. `test_schemas.py` 22, `test_m2_policy.py` 32 |
| `gate_id` at the Hub | partial, risky | Minted at enrollment, and the gate does not keep it. The Hub does not check it on ingest, and takes it from the URL path. | `hub/enroll.py` `consume_token`, `cli.py` `enroll`, `hub/server.py`. `test_m7_hub.py` 47. Run: records for another gate's id and for an id that never enrolled got HTTP 200 (#207 C2.1 to C2.3) |

## Policy and manifest

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| Grant resolution (DESIGN.md 5.2) | implemented | An effect only descends the lattice. `deny` absorbs. | `policy/engine.py` `resolve`, `lattice_min`. `test_m2_policy.py` 32, `property/test_invariants.py` 14 |
| Session taint and the trifecta rule | implemented | Taint only grows. The only reset is the `clear` command. | `mux/session.py`, `policy/engine.py` step 6. `replay/test_github_mcp_exfil.py` 11 |
| Argument guards (secret scan, size cap) | implemented | A hit denies the call. | `policy/manifest.py` `guard_violation`. Run 2026-11-22: step G-01 of `docs/MANUAL-TEST.md` |
| Manifest validation and `lint` | implemented | Schema check, a deployment check, and a warning for unenforced fields. | `schemas/capability-manifest-v1.json`. `test_schemas.py` 22, `test_lint_unenforced.py` 20. Run 2026-11-22: steps L-01 to L-03 |
| Fields declared and not enforced | partial | `subject.binary_integrity` and an `integrity_watch` entry of kind `binary` or `remote_resource` are accepted and not enforced. `lint` warns with `W-UNENFORCED`. | `test_lint_unenforced.py` 20. DESIGN.md 11.5. #42 |
| Policy version | partial | The only version is the digest of the manifest: `manifest_sha256` per call and `manifest_hashes` per session. There is no policy version, no rule id and no digest of `gate.yaml`. | Run: the members of a `serve` session |
| An owner, reviewer or approver of a manifest | missing | The schema has no such field. Its top-level properties are `approval`, `grants`, `instruction_authority`, `integrity_watch`, `provenance_class`, `schema`, `subject`, `taint_rules` and `trifecta`. | `schemas/capability-manifest-v1.json` |

## Enrollment

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| Enrollment token: mint and use once | implemented | `hub token new` mints one and a second use is refused. | `hub/enroll.py`. `test_m7_hub.py` 47. Run: a second use got HTTP 403 (#207 C1.2) |
| Enrollment token expiry | missing | The table has `token`, `created_at`, `used_at` and `gate_id`. No expiry. | Run: `PRAGMA table_info` (#207 C8.7). #49 |
| A per-gate credential | missing | `enroll` prints a `gate_id` and stores nothing. Ingest uses the admin bearer. | `cli.py` `enroll`. #49. Run: #207 C1.1 |
| The admin credential | partial, risky | One kind of bearer. Every `hub serve` start mints another and prints it on stdout, and all stay valid. They are stored as plain text, have no expiry and no role, and are accepted in a URL query. | Run: #207 C1.6, C8.1, C8.6, C8.8 |
| Revoking a gate or a token | missing | No command and no route. | `cli.py` commands, `hub/server.py` routes |
| Tokens stored as hashes | missing | They are stored as plain text. | Run: #207 C8.6, C8.7 |

## Approval channels

DESIGN.md 13.4 says approval decisions stay local to each gate's own channels, and that the fleet
platform has exactly one write path: none.

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| The terminal channel | partial | A prompt on stderr. `y` or `yes` grants, anything else denies, and a timeout denies. `serve` passes no input function, so the answer is read from the gate's own standard input. | `policy/approval.py`, `mux/proxy.py`. `test_m2_approval.py` 24. Run: standard input held open with nothing sent, 5 s timeout: the call was denied, with `approval_timeout` in the record |
| `webhook` and `slack` channels | partial: accepted and ignored | The config accepts `channel: webhook` or `slack` and a `webhook_url`. Nothing reads either after validation. | `mux/config.py`. `git grep` for `.channel` and `webhook_url` finds no other use. Run: a `webhook` config showed the terminal prompt, timed out, and `strace` showed no internet-domain socket |
| Approval through the embedded console | missing: not wired | A registry and an endpoint that decides an approval exist. Nothing in `src/` registers a pending approval. | `console/approvals.py`, `console/server.py`. `git grep` finds no caller. `mux/proxy.py` header: console-driven approval is out of scope for that pass |
| The approval record | partial | The outcome only: `CALL_DECIDED` with `effect: approve` when granted, or `deny` with `approval_denied` or `approval_timeout`. `APPROVAL_GRANTED`, `APPROVAL_DENIED` and `APPROVAL_TIMEOUT` are defined and never written. There is no request id, no nonce and no approver, and the original cause of a refused approval is dropped. | `mux/proxy.py`, `_const.py`. #158 |
| A request bound to the exact action, single use, expiring | missing | A prompt per call with a timeout. No id, no nonce, no hash of the arguments in the request. | `policy/approval.py` |

## Decision API (the #185 draft)

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| `bawbel-gate decide` | missing | Not implemented. | Run: `bawbel-gate decide` prints `Error: No such command 'decide'.` and exits 2. DESIGN.md 15 exists only in draft [#185](https://github.com/bawbel/gate/pull/185) |
| A request and decision schema | missing | `schemas/` holds `ave-1.2.json`, `bawbel-ave-mitigations-v1.json` and `capability-manifest-v1.json`. | `schemas/` |

## Event schema

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| Event types | partial | Five are written: `SESSION_START`, `CALL_DECIDED`, `DRIFT_DETECTED`, `SESSION_CLEAR`, `SESSION_END`. Six are defined and not written: `TOOL_LIST`, `CALL_RECEIVED`, `RESPONSE_RECEIVED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`, `APPROVAL_TIMEOUT`. | `mux/proxy.py` (four `append` sites), `cli.py` (one), `_const.py`. Run: a `serve` session and a `clear` |
| The hash-chained record and `audit verify` | implemented | Each record carries `prev` and `hash`. `audit verify` replays the file. | `audit/writer.py`. `test_m1_audit.py` 34, `test_audit_construction.py` 9, `test_audit_third_party_verify.py` 18. Run 2026-11-22: step U-01 |
| A JSON Schema for an audit record | missing | The record is defined by the writer code and DESIGN.md 8.6. | `schemas/` |
| A format version in a record | missing | No member carries one. | Run: the members of a `serve` session |
| Argument capture (`--store-args`) | missing | DESIGN.md 8.6 names the option. `serve --help` shows no such option, and nothing under `src/` matches. | Run: `bawbel-gate serve --help`. `git grep` |
| Alert events | partial | Six alert classes are defined. `emit_alert_event` has one call site, and it does nothing unless the OpenTelemetry SDK is installed and an endpoint is configured. DESIGN.md 8.5 says alert classes are emitted regardless of exporter. | `ops/otel.py`, `mux/proxy.py`. `test_m5_ops.py` 35 |
| The trifecta-trip rule | duplicate | The test `reason == trifecta_third_leg` on an `approve` effect is written in three places, and all three miss a refused or timed-out approval. | `hub/store.py` (two places), `ops/posture.py`. #158 |

The members of each event, as written by a `serve` session on 2026-11-25:

```text
SESSION_START  event hash manifest_hashes prev seq session ts
CALL_DECIDED   args_sha256 ave effect event hash manifest_sha256 prev reason seq server session taint tool ts
SESSION_END    event hash prev seq session ts
```

A short script printed these: it reads each line as JSON and prints the event and the sorted keys.

## Hub ingest

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| Chain verification per session | partial | Checks `prev` and the hash of each record it has not seen. A replay is idempotent. Reordered records are refused with 409. | `hub/ingest.py`, `hub/store.py`. `test_m7_hub.py` 47. Run: #207 C4.1, C4.2 |
| A log file that holds two sessions | missing: a defect | The whole file is refused with 409. | #159. Run: #207 C4.3 |
| Refusing a record with no `prev` | missing, risky | A record with a `hash`, no `prev` and a large `seq` is stored without verification and moves the stored chain head. A record with a wrong `prev` and `hash` and a lower `seq` was then accepted and counted. | Run: #207 C3.7 to C3.10 |
| Detecting a fork or a rewrite | missing | A rewritten history for records the Hub holds returns 200 and changes nothing. | Run: #207 C3.2, C3.3 |
| Limits on body, batch or time | missing | A 60 MiB body returned 200. One thread serves every client, and a half-sent request blocks the others. | Run: #207 C6.1, C6.3 |
| Strict JSON | missing | `NaN` and duplicate object keys are accepted. Five kinds of malformed record drop the connection with an exception. | Run: #207 C6.6, C6.8 |
| Quarantine | missing | The table and `quarantine()` exist. Nothing calls it. | `hub/store.py`. `git grep` finds no caller. Run: 0 rows (#207 C5.1) |
| The gate-side shipper | partial | `IngestCursor` and `build_batch` exist as a library. Nothing in `src/` calls them, so no gate sends records. `enroll` is the only HTTP call the gate makes. | `ingest/client.py`, `cli.py`. `git grep`. `test_m7_hub.py` |
| Database handling | duplicate | `FleetStore` and `EnrollmentRegistry` each open their own SQLite connection to the same file, each with its own lock. No `journal_mode` is set. | `hub/store.py`, `hub/enroll.py`, `cli.py` `hub_serve`. `git grep` |

## Hub console

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| The fleet page | partial | One page that fetches `/v1/fleet/state` and prints the JSON: per-gate counters. | `hub/server.py` `_UI_HTML`. `test_m7_hub.py` 47. Run: 634 bytes (#207 C8.3) |
| An event view, a search, an integrity panel, a freshness view | missing | No route returns a record. The routes are counters only. | `hub/server.py`. Run: #207 C7.5 |
| Login and roles | missing | One bearer, and a credential in the URL is accepted. | Run: #207 C8.1 |
| Response security headers | missing | `Content-Security-Policy`, `Referrer-Policy`, `Cache-Control` and `X-Content-Type-Options` are not sent. | Run: #207 C8.5 |
| No route toward a gate | implemented | No route sends anything to a gate, which DESIGN.md 14.6 requires. | `hub/server.py` routes. Source |

## Export

| Item | Status | What exists, and what does not | Evidence |
|---|---|---|---|
| OpenTelemetry spans | partial | One span per decision, only if the OpenTelemetry SDK is installed and an endpoint is set. Otherwise nothing is emitted. | `ops/otel.py` `record_decision_span`. `test_m5_ops.py` 35 |
| A CEF and syslog formatter | partial: not wired | `format_cef_record` formats the six alert classes. Nothing in `src/` calls it. | `ops/syslog_cef.py`. `git grep` |
| The posture report | partial | `bawbel-gate posture` tallies a log. Its trifecta count misses a refused approval, and its approval-timeout count reads an event that is never written. | `ops/posture.py`. #158 |
| Export of the audit log (OCSF, CEF of records) | missing | `audit export` is not a command. DESIGN.md 8.7 exists only in draft [#202](https://github.com/bawbel/gate/pull/202). | Run: `bawbel-gate --help` lists no `export` |
| A Hub export, an evidence bundle, an offline verifier | missing | No route and no command. | Run: `/v1/export` returned 404 (#207 C7.4) |

## Baseline: tests per file

478 tests in 25 files, 0 failed, from the junit XML of the run above.

| Tests | File |
|---|---|
| 1 | `integration/test_sdk_handshake.py` |
| 12 | `property/test_integrity.py` |
| 14 | `property/test_invariants.py` |
| 11 | `replay/test_github_mcp_exfil.py` |
| 8 | `replay/test_mcp_surface.py` |
| 13 | `replay/test_tool_schema_drift.py` |
| 9 | `test_audit_construction.py` |
| 18 | `test_audit_third_party_verify.py` |
| 10 | `test_contributor_smoke.py` |
| 13 | `test_i6_scan.py` |
| 20 | `test_lint_unenforced.py` |
| 34 | `test_m1_audit.py` |
| 24 | `test_m2_approval.py` |
| 32 | `test_m2_policy.py` |
| 27 | `test_m3_integrity.py` |
| 10 | `test_m4_corpus.py` |
| 35 | `test_m5_ops.py` |
| 34 | `test_m6_console.py` |
| 47 | `test_m7_hub.py` |
| 16 | `test_migration.py` |
| 11 | `test_mux_handshake.py` |
| 7 | `test_mux_proxy.py` |
| 38 | `test_netguard.py` |
| 12 | `test_network_surface.py` |
| 22 | `test_schemas.py` |
