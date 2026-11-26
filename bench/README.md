# Benchmark harness

A reproducible harness for the gate under fast agents. Standard library only: it adds no dependency. It reads `/proc`, so it
runs on Linux. Nothing in it sets a performance threshold, and it states no throughput: the numbers are for whoever runs it,
on their machine.

```bash
python -m bench.run --list
python -m bench.run single --calls 500 --seed 20261126
python -m bench.run --all --seed 20261126
python -m bench.run loop-10000 --json          # one JSON object per result
```

It needs the gate importable: run it from a checkout with `pip install -e .`, or set `PYTHONPATH=src`.

## What it measures

For each scenario it starts the gate's real request loop (`bench/gate_proc.py`) with a stub upstream
(`bench/stub_upstream.py`, a real subprocess), and, **in the same run**, the same calls straight to the same stub. The overhead is
the gate minus that baseline, so a number from another machine is never the comparison.

| Metric | Meaning |
|---|---|
| `calls_per_s` | calls answered per second, over the measured window (after 20 warm-up calls per session) |
| `added_p50_ms`, `added_p95_ms`, `added_p99_ms` | a percentile of the gate's latency minus the same percentile of the baseline's |
| `cpu_s_per_1000_calls` | CPU seconds of the gate processes (user plus system) per 1,000 calls |
| `peak_rss_mib`, `peak_rss_mib_sum` | the largest peak resident memory of one gate process, and the sum over sessions |
| `audit_bytes_per_s` | audit log growth during the window |
| `open_fds` | the most open file descriptors in any gate process at the end |
| `calls_not_answered_with_a_result` | calls that got an error and not a result, for the gate and the baseline |

Every result prints the **machine spec** (OS, CPU, logical CPUs, RAM, Python) and the **seed** first. The seed fixes the argument
strings. The default is 20261126.

## Scenarios

`single`, `concurrent-10`, `concurrent-100` (that many gate processes at once, each with its own upstream), `args-100B`, `args-10KiB`,
`args-1MiB`, `approval-wait`, `loop-10000`, `stalled-upstream`, `audit-write-fails`, `telemetry-down`.

## Things to know before reading a number

- **Arguments** are words from a four-word set, so their entropy is below the secret scan's threshold: a large argument measures the
  scan and is not refused by it. The manifest has the scan on and no byte cap.
- **One driver process** sends all the calls, with one thread per session. At 100 sessions the driver and the gate processes share the
  machine's cores, so the 100-session figure includes that contention. The baseline pays the driver's cost too, which is why it is
  subtracted, but the gate processes also compete for CPU and the baseline's stubs much less.
- **`approval-wait`** answers each approval after 50 ms through the function the tests use (no person, no terminal). The baseline sleeps 50 ms
  as well, so timer jitter cancels. The added latency is the gate's own cost of an approval.
- **`stalled-upstream`** reports whether the host got an answer within 3 s to a call and to the next request. It is a yes or no, not a rate.
- **`audit-write-fails`** limits the file size the gate may write (`RLIMIT_FSIZE`), so the write fails with `EFBIG`, not `ENOSPC`. A
  size-limited filesystem needs privileges. It reports how many calls were answered, the exit code and the last stderr line.
- **`telemetry-down`** needs the OpenTelemetry SDK (the `ops` extra). Without it the scenario is skipped and says why. The gate does not call
  `setup_otel` today, so the scenario calls it before the loop, to measure what wiring it would cost.
- One run per scenario, one machine. Run it several times before comparing two builds.
- The gate has one session per process, so "concurrent sessions" means concurrent gate processes.

## CI

`tests/test_bench_harness.py` checks the harness: the percentile function, the filler string, that every result carries the spec and the
seed, the scenario list, and one 200-call run that must produce every metric. It never checks a speed. A threshold on added latency is the
maintainer's to set, and none is set.
