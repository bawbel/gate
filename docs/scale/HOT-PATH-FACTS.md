# Hot-path facts from the code

Report, 2026-11-26, for [#254](https://github.com/bawbel/gate/issues/254) (GATE-42). Report only: no code, no test, no
DESIGN.md change, and nothing decided. It states how the gate behaves under fast agents, from the code on `develop` at
`b9d76a9` and from runs.

Every statement about code carries a file and line, read on 2026-11-26. **A statement without a line is marked
UNVERIFIED.** A **VERIFIED** result was run, and the run is named. Paths are under `src/bawbel_gate/`.

Every result below was produced on one machine, with one process at a time, and the same spec is printed with each:

```
machine: Linux-6.8.0-147-generic-x86_64-with-glibc2.39 | 11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz | 8 logical CPUs | 31820 MiB RAM | Python 3.12.3
seed:    none where the input is one fixed call; 20261126 where random strings were generated
```

## 1. The answers

| Question | Answer | Evidence |
|---|---|---|
| **Concurrency model** | One thread runs the whole request path. It reads a host message, decides, forwards, waits for the upstream, writes the answer, then reads the next. There is no asyncio and no worker pool. A gate process holds one session | `mux/proxy.py:88-91` (the loop), `:128` (one `SessionState` per `_bootstrap`), `:237-249` (`_send_and_recv` reads the upstream with a blocking `next()`) |
| **Does one slow upstream block the host or other servers?** | **Yes.** The upstream read has no timeout, so a call to an upstream that never answers blocks the loop. The host's next requests, including `tools/list`, and calls to every other server wait behind it | `mux/proxy.py:246` (`next(incoming)`), `mux/transport.py:25` (`for raw in stream`). **VERIFIED**, experiment E1 |
| **Upstream that exits during a call** | `next()` raises `StopIteration`. Only `KeyboardInterrupt` is caught around the loop, so the exception ends the process. The host gets no answer to that call | `mux/proxy.py:246`, `:92-95`. **VERIFIED**, experiment E2 |
| **Timeouts that exist** | The approval wait: default 120 s (`_const.py:85`), configurable from 5 to 3600 s (`mux/config.py:34`, `:44-47`), and a timeout denies (`policy/approval.py:108-112`). A 2 s wait for an upstream to exit at shutdown (`mux/proxy.py:281`). **No timeout on any upstream read: not on a call, not on `initialize`** (`mux/proxy.py:199-209`, `:243-249`), **and none on the write to the host** (`mux/transport.py:35-38`). A host that stops reading is UNVERIFIED, not run |
| **Size limits** | None by default. A request line is read whole with no cap (`mux/transport.py:25`). An argument byte cap exists only if a manifest sets `max_outbound_bytes`, and the default is none (`policy/manifest.py:93`, `:225`), checked for each string value (`:135`). An upstream response is copied back with no cap (`mux/proxy.py:384-388`) |
| **Order of forward and audit write** | The call is forwarded first and the `CALL_DECIDED` record is written after (`mux/proxy.py:353` then `:360`). A call that was forwarded can leave no record if the process stops between the two (#215, experiment E1; DESIGN.md 8.6 draft #230) |
| **Flush and fsync** | The writer opens the file, writes one line, and closes it, with no `fsync` and no explicit flush (`audit/writer.py:61-62`). A record that was written survives the gate being killed (**VERIFIED**, #230). A power loss is UNVERIFIED, not run |
| **Audit file growth and rotation** | The log only grows. There is no rotation code: `git grep -i rotat -- src` finds nothing. The gate reads the whole file at start to find the chain head (`audit/writer.py:77-93`, `read_text` at `:83`) |
| **Disk full or a failed write** | The exception propagates out of `append` (`audit/writer.py:61-62`), out of `_audit_call` (`mux/proxy.py:360`) and ends the process. **The call was already forwarded.** The sequence number is taken before the write (`audit/writer.py:53`), so a failed write leaves a gap in `seq`. **VERIFIED**, experiments E3a and E3b |
| **Per-session memory** | A session holds a set of taint classes, a set of suspended servers, a map of manifest digests and a counter (`mux/session.py:17-27`). The classes are one per server and the sets are bounded by the number of servers. Nothing in the request path grows with the number of calls. **VERIFIED** over 10,000 calls (E5) |
| **Structures that do grow** | Learning mode appends an observation for every argument of every call, with no cap and no de-duplication (`learn/recorder.py:52-58`). Not run. The console reads the whole audit file to build a summary (`console/state.py:36`, `read_text`), although its docstring says it does not (`:30`) |
| **Approval threads** | Each terminal approval starts a daemon thread that waits for an answer (`policy/approval.py:96-107`). After a timeout the thread is not stopped. **VERIFIED**, experiment E4: 100 timed-out approvals left 100 threads |
| **Telemetry export** | One span per decision is started in the decision path, synchronously (`mux/proxy.py:361-364`, `ops/otel.py:55-77`). `setup_otel` configures a `BatchSpanProcessor` (`ops/otel.py:30-52`), and **nothing under `src/` calls it**: its only caller is a test (`tests/test_m5_ops.py:356`). So the gate exports nothing today. Whether the SDK's queue is bounded, and what happens when the endpoint is down, are UNVERIFIED: the OTel SDK was not installed and no exporter was run |
| **Deny-burst alert** | `DENY_BURST_THRESHOLD_PER_MIN` and `ALERT_DENY_BURST` are defined and used nowhere else (`_const.py:141`, `:156`, `:180`, and `git grep` finds no other use) |
| **Minimum Python version** | `pyproject.toml:10` says `>=3.10`. DESIGN.md 11.1 says "Python >= 3.11" (`DESIGN.md:868`) and so does `CLAUDE.md:5`. CI runs a 3.10 job (`.github/workflows/ci.yml:25`) and it passed on the pull requests of 2026-11-26. **The code and the package metadata say 3.10, and the two documents say 3.11.** Which one is intended is for the maintainer. Whether any 3.11-only feature is used is UNVERIFIED beyond that CI result |

## 2. Experiments

Scripts are scratch files, not in the repository. They run the gate's real request loop (`run_enforce`) on real pipes, with the
stub upstream `tests/fixtures/fake_mcp_server.py`.

**E1. A stalled upstream.** An upstream answers `initialize` and `tools/list` and sleeps on `tools/call`. The host sends the call,
waits 6 s, sends `tools/list`, and waits 6 s more.
```
answer to the call: no | answer to the next request: no | gate still running | audit: SESSION_START only
```

**E2. An upstream that exits on `tools/call`.**
```
gate exit code 1, last stderr line "StopIteration" | host write then fails with a broken pipe | audit: SESSION_START, SESSION_END (no CALL_DECIDED)
```

**E3a. A failed write consumes a sequence number.** A writer appended record 1, then one append raised `ENOSPC`, then it appended again.
```
seqs on disk: [1, 3] | writer.seq: 3
```

**E3b. A write failure after the call was forwarded.** The `CALL_DECIDED` write was made to fail.
```
upstream was sent the call: True | the request loop raised OSError [Errno 28] and ended
```

**E4. Approval timeouts.** 100 approvals each timed out after 10 ms with nothing answering.
```
threads before 1, after 100 timed-out approvals 101
```

**E5. A tight loop of 10,000 calls**, one at a time, through the gate and, as a measured baseline in the same run, straight to the same
stub. One run. A manifest with no argument guards and no trifecta flags was used so every call is allowed.
```
                 calls/s   p50 ms   p95 ms   p99 ms   CPU s per 1000 calls   RSS MiB before->after   fds
direct (stub)     52,428    0.017    0.022    0.025            0.012            10.7 -> 10.7           3
through the gate  10,768    0.086    0.124    0.181            0.074            27.0 -> 27.0           5
added latency (gate minus direct): p50 0.069 ms, p95 0.102 ms, p99 0.156 ms
(CPU and RSS are of the process that was measured: the stub in the first row, the gate in the second. The stub's own work is not in the second row.)
first 1,000 calls p50 0.086 ms, last 1,000 calls p50 0.085 ms | audit 10,001 records, 572 bytes per call
```
No call was refused or slowed by any limit, and memory and descriptors did not grow. This is one run on one machine with a stub that
answers at once, and it does not exercise the secret scan (no guard is set) or any approval. It is a baseline for GATE-43 and not a
capacity figure.

**E6. Reading a long log at start.** 30,000 records were appended in 0.80 s (37,366 per second, each an open, an append and a close), a
file of 15.3 MB. `AuditWriter.from_existing` took 0.64 s and its Python allocation peak was 32.1 MB, about twice the file size.
Larger files were not run. That the cost grows with the file follows from `audit/writer.py:83` and is not measured beyond this size.

## 3. What this says

- **The gate is one thread with no timeout on its upstreams.** One slow or dead upstream stops every call and every other request,
  or ends the process. That is a fact about the code and is run, and a limit or a timeout is a DESIGN.md decision.
- **A failed audit write ends the process after the call was forwarded and leaves a gap in `seq`.** With #238 (`audit verify` checks `seq`),
  a file written that way fails verification at the record after the gap.
- **Nothing in the request path grows with the number of calls.** Learning mode and the console summary do.
- **At this size the added latency is far below the 5 ms budget.** The expensive parts are not in this run (the secret scan,
  see the GATE-44 report, and approvals).
- **Telemetry is not wired.** Whether it can slow a decision cannot be answered until it is.

## 4. Not done

- No code, no test and no DESIGN.md change.
- No exporter was run. A host that stops reading, a power loss, and larger audit files were not run.
- Concurrency was not measured: the gate has one session and one outstanding request.
- Windows and macOS were not run.
- A single run per result. Variance was not measured.

## Sources

`src/bawbel_gate/mux/proxy.py`, `mux/transport.py`, `mux/config.py`, `mux/session.py`, `audit/writer.py`, `policy/approval.py`,
`policy/manifest.py`, `learn/recorder.py`, `console/state.py`, `ops/otel.py`, `_const.py` on `develop` `b9d76a9`; `pyproject.toml`,
`DESIGN.md`, `CLAUDE.md`, `.github/workflows/ci.yml`; `docs/hub/ACCOUNTABILITY-LIMITS.md` (#215).
