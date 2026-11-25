# bawbel-hub threat model and abuse cases

Report, 2026-11-25, for [#206](https://github.com/bawbel/gate/issues/206). It describes the Hub as it
is on `develop` at `92ea9d3` and runs each abuse case against it. It proposes no fix and changes no
code. The gate side is in [THREAT_MODEL.md](../THREAT_MODEL.md) (`X1` to `X10`). This file uses the
prefix `H` so the ids never collide.

Every claim carries a tag. **VERIFIED**: run on 2026-11-25, with the case id from Appendix A.
**SOURCED**: a file or page, read on 2026-11-25. **UNVERIFIED**: stated without either, and said so.

## How the cases were run

A script started the real `bawbel-gate hub serve` 0.1.1 on `127.0.0.1` with an ephemeral port, a fresh
virtualenv, an empty `HOME`, `env -i` and a temporary database. It then sent requests with the
standard library and read the database with `sqlite3`. Nothing left loopback, and no non-loopback
address was bound. The script is not in the repository, and its output is Appendix A. Say if you want
it added as a test harness. Records were built with the gate's own hash function, so a "valid chain"
below is a chain `audit verify` would accept.

## What the Hub is today

SOURCED, `src/bawbel_gate/hub/` on `develop` at `92ea9d3`.

| Part | What exists |
|---|---|
| Server | The standard library `HTTPServer`, one thread, plain HTTP, default `127.0.0.1:8443` (`server.py`, `_const.py`). No TLS code. |
| Routes | `POST /v1/gates/{gate_id}/records`, `GET /v1/fleet/state`, `GET /v1/fleet/gates/{gate_id}`, `POST /v1/enrollment/tokens`, `POST /v1/enroll`, and a console page at `/`. `PUT` and `DELETE` return 404. |
| Credential | One kind of bearer, the admin token. Every `hub serve` start mints another, prints it on stdout, and stores it. `POST /v1/enroll` needs only a single-use enrollment token and returns a `gate_id`. |
| Ingest | Groups records by session, checks `prev` linkage and the hash of each record it has not seen, then stores them (`ingest.py`, `store.py`). |
| Storage | One SQLite file: tables for gates, records, chain heads, session counters, tokens and a `quarantine` table. |
| Console | One page that fetches `/v1/fleet/state` and shows the JSON. |
| Not present | Roles, token expiry, revocation, a per-gate credential, access logs, an export, a quarantine writer, a proxy header mode. |

## Assets, actors and trust boundaries

**Assets.** The audit records the Hub holds (what they say, and that none was altered, added or
withheld). The admin token. Enrollment tokens. A gate's identity as the Hub knows it, the `gate_id`. The
fleet counters. The database file.

**Actors.** An honest gate. A compromised gate host. Whoever holds the admin token, whether the
operator or a thief. A network observer between a gate and the Hub. Another user on the Hub's host. A
browser user of the console. The operator's reverse proxy, which does not exist yet. A consumer of an
export, which does not exist yet.

**Boundaries.**

| | Boundary | Crossing today |
|---|---|---|
| B1 | gate to Hub ingest | NDJSON over plain HTTP, authenticated by the admin token |
| B2 | operator or browser to the Hub | the same admin token, in a header or in the URL |
| B3 | Hub process to storage | a SQLite file in the working directory |
| B4 | Hub to an exporter | none exists |
| B5 | operator proxy to the Hub | none exists |

## Abuse cases

Each case gives preconditions, steps, impact, current behaviour, mitigation and residual risk.
"Mitigation" names what is planned and where it is written, and says nothing is fixed here. The planned
credential model is DESIGN.md 14.3 as drafted in [#180](https://github.com/bawbel/gate/pull/180), which
is not merged.

### H1. A stolen shared admin bearer

- **Preconditions.** The attacker has an admin token. It is printed on stdout when the Hub starts
  (`cli.py`, and the script read it from there), stored as plain text in the database (C8.6), and
  accepted in a URL query (C8.1, C8.2). It does not expire.
- **Steps and impact.** With the one token the attacker can read fleet state, mint enrollment tokens
  (C1), and ship records for any gate (H2). Nothing identifies the caller. After a restart the earlier
  token still works (C1.6: first start's token HTTP 200, the new one HTTP 200, two tokens stored).
  There is no expiry (C8.8: `admin_tokens` has `token` and `created_at` only) and no revocation.
- **Current behaviour.** VERIFIED: C1.4, C1.5, C1.6, C8.1, C8.6, C8.8.
- **Mitigation.** Planned, not built (#180, 14.3): one admin credential with a 30 day lifetime that a
  start reuses, rotation without a restart, a 15 minute grace, credentials stored as SHA-256 hashes
  and shown once, a cookie session in place of a URL token, and a revoke command. The Hub never sends
  anything toward a gate (14.6).
- **What that does not fix.** A per-gate secret "identifies whoever holds it" (#180's own words), so a
  thief of a gate's secret still ships as that gate. A compromised gate host can still ship records
  that are false and correctly chained. TLS is the operator's job, and without it the credentials cross
  the network in clear text. The admin credential's holder can still enroll and revoke.
- **Status.** Open. **Owner.** HUB-R3 implementation (#179, #180), HUB-R13.

### H2. `gate_id` spoofing and cross-gate injection

- **Preconditions.** The attacker has the admin token, which every gate uses today.
- **Steps and impact.** Ship records under another gate's id, or an id that never enrolled. The Hub
  takes `gate_id` from the URL path and checks nothing against the credential. The records are stored
  and counted for that id.
- **Current behaviour.** VERIFIED. `POST /v1/enroll` returns a `gate_id` and nothing else (C1.1). The
  same bearer shipped a chain labelled gate B (C2.1), a different chain labelled gate A (C2.2), and a
  chain for a gate id that never enrolled (C2.3). All returned HTTP 200. The never-enrolled id then
  appeared in fleet state (C2.4), and gate A's counters changed (C2.5: allow 4, deny 3, 2 sessions).
- **Mitigation.** Planned (#180, 14.3): the Hub takes the `gate_id` from the per-gate credential, and a
  path that disagrees is refused with 403. "A value in the path or the query string is never an
  identity."
- **What that does not fix.** A compromised gate can still inject into its own id. The record's
  content is still the gate's word.
- **Status.** Open. **Owner.** HUB-R3 implementation.

### H3. Chain truncation, a consistent rewrite, an empty file, a fork

- **Preconditions.** For the first four: a party who can write or replace a gate's log before or after
  it is shipped. For the last: the admin token.
- **Limits of the chain itself.** SOURCED, DESIGN.md 8.6 and [THREAT_MODEL.md](../THREAT_MODEL.md) X9:
  the chain detects an edit to a record, and does not detect removal of the last records, a rewrite
  that recomputes every hash, or an empty file. Detection of those needs a chain head kept outside
  the log. The Hub holds a head for each session, so it could be that place.
- **Current behaviour.** VERIFIED, and this is the most serious ingest result.
  - The Hub accepts a rewritten history for records it already holds. Records 5 and 6 replaced, with
    a valid chain from record 4, returned HTTP 200 and changed no stored row (C3.2). It is neither
    stored nor flagged. A fork is visible only if the gate continues past what the Hub holds: record 7
    of the rewritten chain got 409 (C3.3).
  - A truncated copy of a shipped chain returned 200 (C3.4). An empty body returned 200 (C3.5).
  - A gate that enrolled and never shipped is absent from fleet state (C3.6), so an empty log and a
    silent gate look the same as no gate.
  - **The chain check can be bypassed.** A record with a `hash`, no `prev` and `seq` 1000000 returned
    200 (C3.7) and set the stored head for its session to 1000000 (C3.8). A record 4 with a wrong
    `prev` and a wrong `hash` shipped afterwards returned 200 and was stored (C3.9), and gate A's deny
    count rose from 3 to 4 (C3.10). Cause, read from `ingest.py`, `store.py` and `server.py`: a record
    that has a `hash` and no `prev` is skipped by verification and only noted in an error list that the
    HTTP response never returns. It is still stored, and the stored head moves to its `seq`. After that
    every record with a lower `seq` is treated as already seen and is not verified.
- **Mitigation.** Not built. Options only: compare each already-held `seq` against the stored hash and
  flag a mismatch as a fork, refuse a record without `hash` and `prev`, and keep signed checkpoints
  (HUB-R8). None is decided.
- **Status.** Open. **Owners.** HUB-R12 (verification), HUB-R8 (checkpoints), HUB-R17 (silent gates).

### H4. Replay, reordering, duplicate session ids

- **Steps and impact.** Ship an old valid batch again, ship records out of order, reuse a session id.
- **Current behaviour.** VERIFIED. The same valid batch shipped twice left the counters and the rows
  unchanged (C4.1). Records 2, 1, 3 in one batch got 409 (C4.2). The same session id from two gates is
  stored separately, because the key is `(gate_id, session, seq)` (C4.4). A log file that holds two
  sessions, which is what `serve` writes when run twice on one file, is refused whole with 409 (C4.3,
  [#159](https://github.com/bawbel/gate/issues/159)). From C3.2 it follows that a gate which reuses a
  session id and starts a new chain has its new records ignored wherever the `seq` is already held,
  and the response does not say so. That consequence was inferred from C3.2 and not run on its own.
- **Status.** Partial: replay and reordering are handled, and session handling is open.
  **Owners.** HUB-R11 (#159), HUB-R12.

### H5. Quarantine abuse

- **Current behaviour.** The database has a `quarantine` table and `FleetStore.quarantine()`. VERIFIED
  by `git grep` on 2026-11-25: nothing in `src/` calls it. After every case in this report the table had
  0 rows (C5.1). Bad input is either refused whole (409) or stored without verification (C3.9).
- **Consequence.** Neither flooding quarantine to hide other gates nor getting a gate quarantined to
  hide its records can happen today, because nothing is ever quarantined.
- **Open design question for when it is built.** What quarantine keeps, how large it may grow per
  gate, and that a quarantined record is not deleted.
- **Status.** Open. **Owner.** HUB-R12.

### H6. Denial of service

- **Current behaviour.** VERIFIED.
  - One thread. A client that sends a request line and some headers and never finishes (C6.1, first
    line), or sends an authenticated POST that promises 100 body bytes and sends none (C6.1, second
    line), blocks every other client for as long as it stays open: the second client waited 3.0 s and
    got no answer, then got HTTP 200 in under 10 ms once the first closed. The handler class sets no
    per-connection timeout (`server.py`, SOURCED).
  - No body limit. A 60 MiB body returned 200 (C6.3). The server's resident memory went from 25 MiB
    to 67 MiB, with a peak of 145 MiB.
  - No batch limit and linear verification. 2000 valid records in one request took 0.09 s and 20000
    took 0.71 s (C6.4).
  - Malformed input. `Content-Length: abc` closes the connection with no response (C6.5). `Content-Length: -1` returned
    HTTP 200 once the client closed its side (C6.5). The handler calls `read(-1)`, which reads to the end
    of the stream, so a client that keeps its side open would hold the thread. That last point is read
    from the source and was not run. A JSON list, a JSON string, a `session` that is a
    list, a `seq` that is a string and a `seq` that is null each close the connection with no response
    and print an exception on stderr (C6.6, C6.8: `AttributeError`, `TypeError`, `ValueError`). The
    server stayed up (C6.7).
  - `NaN` as a value and duplicate object keys are accepted (C6.6). With duplicate keys the last
    wins, so another parser could read a different record.
- **Not run.** Many small gates at once. UNVERIFIED.
- **Mitigation.** Not built. HUB-R12 lists body and batch limits, a rate limit per credential, bounded
  verification work, strict JSON and a fuzz test.
- **Status.** Open. **Owners.** HUB-R12, HUB-R19 (published limits).

### H7. Stored injection

- **Current behaviour.** VERIFIED. A record with script text in `tool` and `event`, shipped under the
  gate id `gate-<i>x`, was accepted (C7.1). Fleet state does not contain the injected tool text
  (C7.2), because the state is counters and the `gate_id` only (C7.5). The `gate_id` appears verbatim
  in the JSON (C7.2). The console page puts the JSON in the page with `textContent` and never uses
  `innerHTML` (C7.3), so nothing stored is interpreted as markup today.
- **Spreadsheet formula injection.** There is no export (C7.4: `/v1/export` is 404). Not applicable
  yet.
- **Log injection.** The Hub writes no access log and no structured log: 0 access-log lines in 229
  lines of stderr (C8.9). That removes the risk and also removes the forensic record.
- **Residual.** This holds only because nothing renders or exports event fields. It stops holding when a
  console renders them or an export writes them.
- **Status.** Partial. **Owners.** HUB-R14 (rendering), HUB-R16 (export), HUB-R17 (logs).

### H8. Token handling

- **Current behaviour.** VERIFIED. The admin token is accepted in the URL query on a GET and on an
  ingest POST (C8.1, C8.2). The console page reads it from `location.search` (C8.3). The page's response
  headers are `Content-Length`, `Content-Type`, `Date` and `Server`, so there is no
  `Content-Security-Policy`, `Referrer-Policy`, `Cache-Control` or `X-Content-Type-Options` (C8.4,
  C8.5). The Hub prints the admin token on stdout when it starts. Admin and enrollment tokens are stored
  as plain text (C8.6, C8.7), so a copy of the database, a backup included, holds every credential.
  The Hub's own stderr held no token and no access-log line (C8.9).
- **Not run.** What a reverse proxy would log for a request with `?t=`. UNVERIFIED. A URL token would
  reach the proxy's log, the browser history, and a `Referer` header if the page links elsewhere.
- **Mitigation.** Planned (#180, 14.3): hashed tokens shown once, a cookie session, and no credential
  accepted in a URL.
- **Status.** Open. **Owners.** HUB-R3 implementation, HUB-R13.

### H9. Proxy header spoofing

- **Current behaviour.** VERIFIED. There is no proxy header mode. `X-Forwarded-User: admin` with no
  token returned 401 (C9.1).
- **Requirement for when it is built.** A header is trusted only from a declared proxy, and only when
  TLS is declared (HUB-R13).
- **Status.** Mitigated today only because the feature does not exist. **Owner.** HUB-R13.

### H10. Operator misconfiguration

- **Database file.** VERIFIED. The database was created with mode `0644`, so it is readable by every
  user on the host (C10.1, run with umask 002). It holds the plain-text tokens (H8).
- **Bind address.** DESIGN.md 14.3 as drafted in #180 requires that the Hub refuses a non-loopback
  address unless TLS in front of it is declared with `--tls-terminated-by-proxy`. SOURCED: the draft's
  status paragraph says the credential model is "specified, not implemented". The default bind is
  `127.0.0.1` (`_const.py`). No non-loopback bind was run for this report, and this file does not
  state what the Hub does on one.
- **Status.** Open. **Owners.** HUB-R3 implementation, HUB-R18 (deploy guide).

## Summary

| Case | Status | Owning task |
|---|---|---|
| H1 stolen shared admin bearer | open | HUB-R3 implementation (#179, #180), HUB-R13 |
| H2 `gate_id` spoofing, cross-gate injection | open | HUB-R3 implementation |
| H3 truncation, rewrite, empty file, fork, and the chain check bypass | open | HUB-R12, HUB-R8, HUB-R17 |
| H4 replay, reordering, duplicate session ids | partial | HUB-R11 (#159), HUB-R12 |
| H5 quarantine abuse | open (nothing is quarantined) | HUB-R12 |
| H6 denial of service | open | HUB-R12, HUB-R19 |
| H7 stored injection | partial (nothing stored is rendered or exported today) | HUB-R14, HUB-R16, HUB-R17 |
| H8 token handling | open | HUB-R3 implementation, HUB-R13 |
| H9 proxy header spoofing | mitigated (feature absent) | HUB-R13 |
| H10 operator misconfiguration | open | HUB-R3 implementation, HUB-R18 |

## MCP pages: used and dropped

SOURCED, read 2026-11-25. The pages show no date, so the revision is the URL path: `2026-07-28`.

- **Security best practices**, `https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices.md`.
  **Used, as an analogy for H2.** "MCP servers MUST NOT treat possession of a state handle as
  authentication." The Hub treats the `gate_id` in the URL path the same way. The page is about MCP
  servers, and the Hub is not one, so the rule is not a requirement here.
- **Same page, scope minimization.** **Used, as an analogy for H1.** Its mitigation is a least-privilege
  scope model, which the planned `admin` and `viewer` split follows. Not a requirement here.
- **Same page, confused deputy and token passthrough.** **Dropped.** Both concern an MCP server or
  proxy that holds a third-party client identity or forwards a token. The Hub forwards nothing and
  makes no outbound call.
- **Authorization**, `https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization.md`.
  **Dropped.** It governs HTTP transports between an MCP client and an MCP server, and the Hub's
  ingest and console are neither. The Hub's credential model is its own (DESIGN.md 14.3).

## Not done

- No fix, no code, no test, no DESIGN.md change.
- No non-loopback run, so nothing is stated about the Hub's behaviour on another address.
- Not run: many small gates at once, a Hub behind a real reverse proxy, a browser, a Hub restored from a
  backup. The console was read as source and fetched as text, not rendered.
- One database, one host, bawbel-gate 0.1.1. Timings are from one machine and are not limits.

## Appendix A. Run output

The output of the script described under "How the cases were run", with long digests shortened. The
port and the generated gate ids differ on every run.

```text
setup  hub up on 127.0.0.1:34783 (loopback); admin token length 32
C1.1   enroll response keys: ['gate_id'] (a gate_id only, no credential for the gate)
C1.2   enrollment token used twice: HTTP 403 {'error': 'token already used'}
C1.3   unknown enrollment token: HTTP 403 {'error': "token not found: 'no-such-token'"} (the response echoes the input)
C1.4   gate A ships a valid 4-record chain with the admin bearer: HTTP 200 {'acked': {'sA1': 4}}
C2.1   the same bearer ships a chain labelled as gate B: HTTP 200 {'acked': {'sB1': 3}}
C2.2   the same bearer ships a different, validly chained session labelled as gate A: HTTP 200 {'acked': {'sA-forged': 3}}
C2.3   records for a gate id that never enrolled: HTTP 200 {'acked': {'sX': 2}}
C2.4   fleet state now lists 3 gates: ['gate-0f954960e7c9', 'gate-d6caa3bdee2f', 'gate-never-enrolled']; never-enrolled present: True
C2.5   gate A counters after the forged session: allow=4 deny=3 sessions=2
C1.5   no credential: HTTP 401
C8.1   admin token in the URL query on a GET: HTTP 200
C8.2   admin token in the URL query on an ingest POST: HTTP 200 {'acked': {'sQ': 1}}
C8.3   console page: HTTP 200, 634 bytes, reads the token from location.search: True
C8.4   response headers on the page: Content-Length, Content-Type, Date, Server
C8.5   security headers present (Content-Security-Policy, Referrer-Policy, Cache-Control, X-Content-Type-Options): []
C9.1   X-Forwarded-User: admin with no token: HTTP 401
C8.6   admin tokens stored: 1; stored value equals the issued token (plaintext): True
C8.7   enrollment tokens stored: 2; stored as plaintext 32-hex: True; columns: ['token', 'created_at', 'used_at', 'gate_id']
C8.8   admin_tokens columns: ['token', 'created_at'] (no expiry, no role)
C10.1  database file mode: 0o644 (umask of this run: 0o2); world-readable: True
C10.2  non-loopback bind: not run, by instruction; the requirement is DESIGN.md 14.3
C3.1   valid 6-record chain shipped: HTTP 200 {'acked': {'sF': 6}}
C3.2   a rewritten history (records 5 and 6 replaced, valid chain from record 4) shipped: HTTP 200 {'acked': {'sF': 6}}; stored rows changed: False
C3.3   the rewritten chain continues with record 7: HTTP 409 {'error': 'chain_mismatch', 'session': 'sF', 'expected_prev': 'sha256:<64 hex>'}
C3.4   the first 3 records of the chain shipped again (a truncated copy): HTTP 200 {'acked': {'sF': 6}}
C3.5   empty body: HTTP 200 {'acked': {}}
C3.6   a gate enrolled and never shipped: present in fleet state: False
C3.7   a record with a hash, no prev and seq 1000000: HTTP 200 {'acked': {'sP': 3}}
C3.8   stored chain head seq for that session: 1000000
C3.9   a record 4 whose prev and hash are wrong, shipped after that: HTTP 200 {'acked': {'sP': 1000000}}; stored: True
C3.10  gate A deny_count after the unverifiable record: 4
C4.1   the same valid batch shipped twice: counters unchanged: True; rows for the session: 3
C4.2   records 2,1,3 in one batch: HTTP 409 {'error': 'chain_mismatch', 'session': 'sO', 'expected_prev': 'sha256:<64 hex>'}
C4.3   one log file holding two sessions, as `serve` writes it twice (issue 159): HTTP 409 {'error': 'chain_mismatch', 'session': 'sS2', 'expected_prev': 'sha256:<64 hex>'}
C4.4   the same session id from two gates: HTTP 200 and 200; rows per gate: [('gate-0f954960e7c9', 2), ('gate-d6caa3bdee2f', 2)]
C5.1   rows in the quarantine table after every case above: 0
C7.1   a record with script text in tool and event, shipped under the gate id 'gate-<i>x': HTTP 200 {'acked': {'sI': 1}}
C7.2   fleet state: Content-Type application/json; contains the injected tool text: False; contains the tagged gate id verbatim: True
C7.3   console page source uses textContent: True; uses innerHTML: False
C7.4   an export route (/v1/export): HTTP 404
C7.5   per-gate state keys: ['allow_count', 'approve_count', 'deny_count', 'drift_events', 'gate_id', 'session_count', 'trifecta_trips']
C6.1   a client that sent a request line and some headers, never the blank line: a second client's request answered while it is open: False (waited 3.0s); after it closes: HTTP 200 in 0.00s
C6.1   an authenticated POST that promised 100 body bytes and sent none: a second client's request answered while it is open: False (waited 3.0s); after it closes: HTTP 200 in 0.00s
C6.3   a 60 MiB body: HTTP 200 {'acked': {}} in 0.2s; server RSS MiB before 25, after 67; peak 145
C6.4   2000 valid records in one request (670 KiB): HTTP 200 in 0.09s
C6.4   20000 valid records in one request (6746 KiB): HTTP 200 in 0.71s
C6.5   Content-Length: abc: (connection closed, no response)
C6.5   Content-Length: -1: HTTP/1.0 200 OK
C6.6   a line that is a JSON list: (connection closed, no response)
C6.6   a line that is a JSON string: (connection closed, no response)
C6.6   session is a list: (connection closed, no response)
C6.6   seq is a string, hash and prev set: (connection closed, no response)
C6.6   seq is null: (connection closed, no response)
C6.6   NaN as a value: HTTP/1.0 200 OK
C6.6   duplicate keys, last wins: HTTP/1.0 200 OK
C6.7   the server still answers after those inputs: HTTP 200
C8.9   hub stderr after the whole run: 229 lines; access-log lines (GET or POST with a path): 0; contains the admin token: False
C6.8   exceptions printed on the hub's stderr: 16 lines, kinds: ['AttributeError', 'TypeError', 'ValueError']
C1.6   after a restart on the same database: the first start's admin token: HTTP 200; the new one: HTTP 200; admin tokens stored: 2
done   hub stopped
```
