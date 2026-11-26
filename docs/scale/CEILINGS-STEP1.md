# Per-session ceilings, step 1: what the code does today

Report, 2026-11-26, for [#256](https://github.com/bawbel/gate/issues/256) (GATE-40, step 1). Report only: no code, no test, no DESIGN.md
change, and nothing decided. Step 2, a DESIGN.md change for ceilings, is not started: it waits for the maintainer's answer on whether
ceilings are a gate feature and what happens at the limit. Nothing is implemented.

Every statement about code carries a file and line, read on 2026-11-26 from `develop` at `b9d76a9` (paths under `src/bawbel_gate/`).
A statement without one is marked UNVERIFIED. A **VERIFIED** result was run. The machine and the seed are printed with the results.

```
machine: Linux-6.8.0-147-generic-x86_64-with-glibc2.39 | 11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz | 8 logical CPUs | 31820 MiB RAM | Python 3.12.3
seed:    none for the loop (one fixed call); 20261126 for the counter timings
```

## 1. Does any call count, rate, repeat or depth limit exist?

**No, for a call made through the gate.** Confirmed in the code and by a run.

- **The decision does not read a count.** `_handle_tools_call` resolves each call from the tool, its arguments, the manifest and the session's taint, and then forwards or refuses
  (`mux/proxy.py:337-353`). `resolve` takes the manifest and the session (`mux/proxy.py:337`), and the session holds a taint set, a suspended set, a map of manifest digests and a sequence
  counter (`mux/session.py:17-27`), none of which counts calls.
- **A search found no limit.** `git grep -n -i -E "rate|ceiling|max_calls|per_minute|limit|depth|repeat|throttle|circuit" -- src`, read line by line, finds no call limit.
  The matches that exist are unrelated: the approval budget (`_const.py:91-93`), the latency budget (`_const.py:89`), a depth of 3 when learning mode flattens arguments
  (`learn/recorder.py:72-73`), and `call_count` in learning mode, which only counts (`learn/recorder.py:31`, `:50`).
- **A deny-rate alert is defined and not wired.** `DENY_BURST_THRESHOLD_PER_MIN = 10` and `ALERT_DENY_BURST` exist (`_const.py:141`, `:156`, `:180`) and nothing else uses them.
  It would raise an alert, not refuse a call.
- **Nothing limits nesting depth or length.** The request is parsed by `json.loads` on a whole line (`mux/transport.py:25-30`) and `_all_string_values` recurses over the arguments
  with no depth limit (`policy/manifest.py:254-265`). Whether a very deep argument is handled is UNVERIFIED, not run.
- **VERIFIED, the loop (section 4):** 10,000 calls to the same tool with the same arguments were all allowed, none was refused or slowed, and the audit log holds 10,001 records.

## 2. Where a per-session counter would sit

- **The state.** `SessionState` (`mux/session.py:17-27`) is the one place session state lives. It is monotone by design: "only grow ... No method on this class clears state"
  (`mux/session.py:3-5`). A call counter, a per-minute window and a repeat table would be fields of it, and they would only grow within a session, which fits.
- **The decision point.** Between `resolve` and the forward in `_handle_tools_call` (`mux/proxy.py:337-353`), where the effect is already a value that can be lowered to `approve` or `deny`
  (`mux/proxy.py:338-350`). A ceiling that lowers an effect there needs no new path: a refusal is built the same way as any other (`mux/proxy.py:354-357`).
- **The repeat key.** The audit record already computes `args_sha256` for every call (`mux/proxy.py:460-461`, `_hash_args`), so an identical `(tool, argument hash)` repeat counter needs no second hash,
  if the hash is computed once per call and shared.
- **One gate process, one session** (`mux/proxy.py:128`). A counter per session is a counter per process. A loop that spans sessions, agents or gate processes is not seen by it.

## 3. What a counter costs

Measured, one process, best of five, in microseconds per call, on the machine above:

| Counter | Cost per call |
|---|---|
| A total call count (`c += 1`) | 0.018 us |
| A rolling per-minute window (append a timestamp, drop the expired ones) | 0.100 us |
| A repeat table keyed by `(tool, argument hash)` (`d[key] += 1`) | 0.113 us |
| For comparison, `canonical_bytes` plus `sha256` of the arguments, which is already done once per call | 0.003 ms for 100 B, 0.028 ms for 10 KiB, 2.56 ms for 1 MiB |

**Against the 5 ms p95 budget** (`_const.py:89`, DESIGN.md 11.2), the three counters together cost about 0.23 microseconds, under 0.01 percent of it. The only
cost that approaches the budget is hashing a very large argument, which the gate already pays. A repeat table has one growing structure: after 1,000,000 distinct
`(tool, hash)` keys it held about 200 MiB (traced allocations), so a repeat counter needs a bound on the number of distinct keys, or it becomes the memory growth it is meant to prevent.
These are micro-timings of the operations and not of an integrated change, which was not built.

## 4. The loop: what the gate does today with 10,000 identical calls

A tight loop of 10,000 calls, one at a time, through the real request loop on real pipes, with a stub upstream (`tests/fixtures/fake_mcp_server.py`), and, as a measured baseline in the
same run, the same calls straight to the stub. A manifest with no argument guard and no trifecta flags, so every call is allowed. One run.

```
                 calls/s   p50 ms   p95 ms   p99 ms   CPU s per 1000 calls   RSS MiB before->after   fds
direct (stub)     52,428    0.017    0.022    0.025            0.012            10.7 -> 10.7           3
through the gate  10,768    0.086    0.124    0.181            0.074            27.0 -> 27.0           5
added latency (gate minus direct): p50 0.069 ms, p95 0.102 ms, p99 0.156 ms
first 1,000 calls p50 0.086 ms, last 1,000 calls p50 0.085 ms | audit 10,001 records, 572 bytes per call
```

What the gate does: **nothing different at the 10,000th call from the first.** Every call is allowed and forwarded and recorded, latency does not drift, and memory and descriptors do not
grow. The cost that does grow is the audit file, at 572 bytes a call, about 5.7 MB for this loop. The CPU and RSS figures are of the process measured: the stub in the first row, the gate in the second.
This run does not exercise the secret scan or an approval, and it is not a capacity figure.

## 5. What step 2 would have to answer, for the maintainer

Listed, not decided. These are questions the DESIGN.md change would need to settle, stated from this report.

- Whether ceilings are a gate feature at all, and the effect at the limit (`approve` or `deny`). What `approve` does when no one answers belongs to the approval design (#228), and
  the answer decides whether `approve` and `deny` differ in practice.
- Which ceilings: total calls, calls per minute, and identical `(tool, argument hash)` repeats, as the plan lists. The costs above are small, and the repeat table needs a bound.
- The defaults. The plan says defaults should come from measured data (GATE-43), and the only data here is one run of a stub.
- What it cannot see, as the plan says: a loop that spans sessions, agents or processes, and a loop of distinct calls. A counter also does not see what the calls do.

## 6. Not done

- No code, no test, no DESIGN.md change. Step 2 is not started.
- Depth of nested arguments was not run. A multi-session or concurrent loop was not run (the gate has one session and one outstanding request, see GATE-42).
- One run per result, on one machine, with a stub that answers at once. Windows and macOS were not run.
- The counters were timed as isolated operations, not as a change to the gate.

## Sources

`src/bawbel_gate/mux/proxy.py`, `mux/session.py`, `mux/transport.py`, `policy/manifest.py`, `learn/recorder.py`, `_const.py` on `develop` `b9d76a9`; DESIGN.md 5, 7.5, 11.2;
`docs/scale/HOT-PATH-FACTS.md` (GATE-42, #254) for the measured loop and the concurrency model.
