"""Benchmark harness for the gate under fast agents. Standard library only; reads /proc (Linux).

Every run measures the gate and, in the same run, a direct passthrough to the same stub, so the
overhead is gate minus baseline and not a number from another machine. Every result carries the
machine spec and the seed. Nothing here sets a performance threshold.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import random
import subprocess
import sys
import tempfile
import threading
import time
from importlib.util import find_spec
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
WORDS = ("alpha", "beta", "gamma", "delta")
WARMUP_CALLS = 20


# ---- helpers that do not need a process -----------------------------------------------------


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile of `values` (any order). An empty list is an error."""
    if not values:
        raise ValueError("percentile of an empty list")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def filler(size: int, rng: random.Random) -> str:
    """A string of exactly `size` bytes of words from a small set. Its entropy is far below the
    gate's secret scan threshold, so a large argument measures the scan and is not refused by it."""
    pieces: list[str] = []
    length = 0
    while length < size:
        word = rng.choice(WORDS) + " "
        pieces.append(word)
        length += len(word)
    return "".join(pieces)[:size]


def _cpu_model() -> str:
    try:
        for line in open("/proc/cpuinfo", encoding="utf-8"):
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _ram_mib() -> Any:
    try:
        for line in open("/proc/meminfo", encoding="utf-8"):
            if line.startswith("MemTotal"):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return "unknown"


def machine_spec() -> dict[str, Any]:
    return {
        "os": platform.platform(),
        "cpu": _cpu_model(),
        "logical_cpus": os.cpu_count() or "unknown",
        "ram_mib": _ram_mib(),
        "python": platform.python_version(),
    }


def make_result(
    scenario: str, seed: int, metrics: dict[str, Any], skipped: str = ""
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "scenario": scenario,
        "seed": seed,
        "machine": machine_spec(),
        "metrics": metrics,
    }
    if skipped:
        result["skipped"] = skipped
    return result


def render(result: dict[str, Any]) -> str:
    m = result["machine"]
    lines = [
        f"machine: {m['os']} | {m['cpu']} | {m['logical_cpus']} logical CPUs | "
        f"{m['ram_mib']} MiB RAM | "
        f"Python {m['python']}",
        f"seed: {result['seed']}",
        f"scenario: {result['scenario']}",
    ]
    if result.get("skipped"):
        lines.append(f"SKIPPED: {result['skipped']}")
    lines += [f"  {key}: {value}" for key, value in result["metrics"].items()]
    return "\n".join(lines)


def proc_stats(pid: int) -> dict[str, float]:
    """Resident memory, peak resident memory, open descriptors and CPU seconds of one process."""
    status = dict(
        line.split(":", 1) for line in open(f"/proc/{pid}/status", encoding="utf-8") if ":" in line
    )
    fields = open(f"/proc/{pid}/stat", encoding="utf-8").read().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    return {
        "rss_mib": int(status["VmRSS"].split()[0]) / 1024,
        "peak_rss_mib": int(status["VmHWM"].split()[0]) / 1024,
        "fds": len(os.listdir(f"/proc/{pid}/fd")),
        "cpu_s": (int(fields[11]) + int(fields[12])) / ticks,
    }


def otel_sdk_available() -> bool:
    try:
        return find_spec("opentelemetry.sdk") is not None
    except ModuleNotFoundError:
        return False


# ---- processes ---------------------------------------------------------------------------------


class Peer:
    """A process speaking line-delimited JSON-RPC on its stdin and stdout."""

    def __init__(self, cmd: list[str], env: dict[str, str] | None = None) -> None:
        # stderr goes to a file: nothing reads a pipe here, and a full pipe would block the gate
        self._err = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._err,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )
        self.next_id = 1

    def request(self, method: str, params: dict[str, Any] | None = None) -> str:
        self.next_id += 1
        assert self.proc.stdin and self.proc.stdout
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        return self.proc.stdout.readline()

    def call(self, tool: str, args: dict[str, Any]) -> str:
        return self.request("tools/call", {"name": tool, "arguments": args})

    def stderr_text(self) -> str:
        self._err.flush()
        self._err.seek(0)
        return self._err.read()

    def close(self) -> None:
        import signal

        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc.wait(timeout=10)
        for stream in (self.proc.stdin, self.proc.stdout, self._err):
            if stream:
                stream.close()


def _env() -> dict[str, str]:
    env = dict(os.environ)
    root = str(HERE.parent)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (root, str(HERE.parent / "src"), env.get("PYTHONPATH", "")) if p
    )
    return env


def _stub_cmd(*extra: str) -> list[str]:
    return [sys.executable, str(HERE / "stub_upstream.py"), *extra]


def _gate_cmd(audit: Path, *extra: str, stub_args: tuple[str, ...] = ()) -> list[str]:
    return [sys.executable, "-m", "bench.gate_proc", str(audit), *extra, "--", *stub_args]


def _open_peer(kind: str, audit: Path, extra: tuple[str, ...], stub_args: tuple[str, ...]) -> Peer:
    cmd = (
        _stub_cmd(*stub_args) if kind == "direct" else _gate_cmd(audit, *extra, stub_args=stub_args)
    )
    peer = Peer(cmd, env=_env())
    peer.request("initialize")
    return peer


# ---- measurement -------------------------------------------------------------------------------


def _drive(
    peers: list[Peer], tool: str, args: dict[str, Any], calls_each: int, pause_ms: float = 0.0
) -> tuple[list[float], float, int]:
    """Run `calls_each` calls on every peer at once, one thread per peer. Latencies in ms."""
    latencies: list[list[float]] = [[] for _ in peers]
    failures = [0] * len(peers)

    def work(index: int) -> None:
        peer = peers[index]
        for _ in range(WARMUP_CALLS):
            peer.call(tool, args)
        mine = latencies[index]
        for _ in range(calls_each):
            started = time.perf_counter_ns()
            if pause_ms:
                time.sleep(pause_ms / 1000.0)
            line = peer.call(tool, args)
            mine.append((time.perf_counter_ns() - started) / 1e6)
            if '"result"' not in line:
                failures[index] += 1

    threads = [threading.Thread(target=work, args=(i,)) for i in range(len(peers))]
    started = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return [x for per in latencies for x in per], time.perf_counter() - started, sum(failures)


def measure(
    seed: int,
    calls: int,
    sessions: int = 1,
    arg_bytes: int = 100,
    tool: str = "get_file",
    gate_extra: tuple[str, ...] = (),
    wait_ms: float = 0.0,
    stub_args: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Gate and direct baseline, back to back, with the same calls. Returns the metrics."""
    args = {"path": filler(arg_bytes, random.Random(seed))}
    each = max(1, calls // sessions)
    tmp = Path(tempfile.mkdtemp(prefix="bench-"))
    out: dict[str, Any] = {"calls": each * sessions, "sessions": sessions, "arg_bytes": arg_bytes}

    base = [_open_peer("direct", tmp / "unused", (), stub_args) for _ in range(sessions)]
    try:
        base_lat, base_wall, base_fail = _drive(base, tool, args, each, pause_ms=wait_ms)
    finally:
        for p in base:
            p.close()

    audits = [tmp / f"audit-{i}.jsonl" for i in range(sessions)]
    gates = [_open_peer("gate", audits[i], gate_extra, stub_args) for i in range(sessions)]
    try:
        before = [proc_stats(g.proc.pid) for g in gates]
        sizes0 = [a.stat().st_size if a.exists() else 0 for a in audits]
        gate_lat, gate_wall, gate_fail = _drive(gates, f"bench__{tool}", args, each)
        after = [proc_stats(g.proc.pid) for g in gates]
        grown = sum((a.stat().st_size if a.exists() else 0) - s for a, s in zip(audits, sizes0))
    finally:
        for g in gates:
            g.close()

    total = each * sessions
    cpu = sum(a["cpu_s"] - b["cpu_s"] for a, b in zip(after, before))
    out.update(
        {
            "calls_per_s": round(total / gate_wall, 1),
            "baseline_calls_per_s": round(total / base_wall, 1),
            "gate_p50_ms": round(percentile(gate_lat, 0.50), 4),
            "gate_p95_ms": round(percentile(gate_lat, 0.95), 4),
            "gate_p99_ms": round(percentile(gate_lat, 0.99), 4),
            "baseline_p50_ms": round(percentile(base_lat, 0.50), 4),
            "baseline_p95_ms": round(percentile(base_lat, 0.95), 4),
            "baseline_p99_ms": round(percentile(base_lat, 0.99), 4),
            "added_p50_ms": round(percentile(gate_lat, 0.50) - percentile(base_lat, 0.50), 4),
            "added_p95_ms": round(percentile(gate_lat, 0.95) - percentile(base_lat, 0.95), 4),
            "added_p99_ms": round(percentile(gate_lat, 0.99) - percentile(base_lat, 0.99), 4),
            "cpu_s_per_1000_calls": round(cpu / total * 1000, 4),
            "peak_rss_mib": round(max(a["peak_rss_mib"] for a in after), 1),
            "peak_rss_mib_sum": round(sum(a["peak_rss_mib"] for a in after), 1),
            "audit_bytes_per_s": round(grown / gate_wall),
            "open_fds": max(a["fds"] for a in after),
            "calls_not_answered_with_a_result": gate_fail,
            "baseline_calls_not_answered_with_a_result": base_fail,
        }
    )
    if wait_ms:
        out["simulated_approval_wait_ms"] = wait_ms
    return out


def _stalled(seed: int, calls: int) -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix="bench-"))
    gate = _open_peer("gate", tmp / "audit.jsonl", (), ("--mode", "stall"))
    result: dict[str, Any] = {}
    try:
        for label in ("call", "next_request"):
            assert gate.proc.stdin and gate.proc.stdout
            import select

            gate.next_id += 1
            method, params = (
                ("tools/call", {"name": "bench__get_file", "arguments": {"path": "x"}})
                if label == "call"
                else ("tools/list", {})
            )
            gate.proc.stdin.write(
                json.dumps(
                    {"jsonrpc": "2.0", "id": gate.next_id, "method": method, "params": params}
                )
                + "\n"
            )
            gate.proc.stdin.flush()
            ready, _, _ = select.select([gate.proc.stdout], [], [], 3.0)
            result[f"answered_{label}_within_3s"] = bool(ready)
        result["gate_still_running"] = gate.proc.poll() is None
    finally:
        gate.close()
    return result


def _write_fails(seed: int, calls: int) -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix="bench-"))
    audit = tmp / "audit.jsonl"
    gate = _open_peer("gate", audit, ("--fsize-limit", "4096"), ())
    answered = 0
    try:
        for _ in range(calls):
            line = gate.call("bench__get_file", {"path": "x"})
            if '"result"' not in line:
                break
            answered += 1
        gate.proc.wait(timeout=10) if gate.proc.poll() is None else None
        err = gate.stderr_text().strip().splitlines()
    finally:
        gate.close()
    return {
        "calls_sent_at_most": calls,
        "calls_answered_before_the_failure": answered,
        "gate_exit_code": gate.proc.returncode,
        "last_stderr_line": (err[-1] if err else "")[:120],
        "audit_bytes": audit.stat().st_size if audit.exists() else 0,
        "note": "the write limit is RLIMIT_FSIZE, so the error is EFBIG and not ENOSPC",
    }


def run_scenario(name: str, seed: int, calls: int | None = None) -> dict[str, Any]:
    if name not in SCENARIOS:
        raise KeyError(name)
    n = calls if calls is not None else SCENARIOS[name]["calls"]
    if name == "telemetry-down":
        if not otel_sdk_available():
            return make_result(
                name,
                seed,
                {},
                skipped=(
                    "the OpenTelemetry SDK is not installed (the `ops` extra), "
                    "and this harness adds no dependency"
                ),
            )
        return make_result(
            name, seed, measure(seed, n, gate_extra=("--otel-endpoint", "http://127.0.0.1:9"))
        )
    if name == "stalled-upstream":
        return make_result(name, seed, _stalled(seed, n))
    if name == "audit-write-fails":
        return make_result(name, seed, _write_fails(seed, n))
    spec = SCENARIOS[name]
    kwargs: dict[str, Any] = {k: v for k, v in spec.items() if k not in ("calls", "doc")}
    return make_result(name, seed, measure(seed, n, **kwargs))


SCENARIOS: dict[str, dict[str, Any]] = {
    "single": {"calls": 2000, "doc": "one session, 100 B arguments"},
    "concurrent-10": {"calls": 5000, "sessions": 10, "doc": "10 gate processes at once"},
    "concurrent-100": {"calls": 20000, "sessions": 100, "doc": "100 gate processes at once"},
    "args-100B": {"calls": 2000, "arg_bytes": 100, "doc": "100 B argument"},
    "args-10KiB": {"calls": 1000, "arg_bytes": 10 * 1024, "doc": "10 KiB argument"},
    "args-1MiB": {"calls": 100, "arg_bytes": 1024 * 1024, "doc": "1 MiB argument"},
    "approval-wait": {
        "calls": 100,
        "tool": "needs_ok",
        "gate_extra": ("--approval-wait-ms", "50"),
        "wait_ms": 50.0,
        "doc": "each call waits 50 ms for an approval; the baseline sleeps 50 ms too",
    },
    "loop-10000": {"calls": 10000, "doc": "a tight loop of 10,000 calls, one at a time"},
    "stalled-upstream": {"calls": 1, "doc": "an upstream that never answers a call"},
    "audit-write-fails": {
        "calls": 200,
        "doc": "the audit write fails (file size limit) during a loop",
    },
    "telemetry-down": {
        "calls": 1000,
        "doc": "an OTLP endpoint that refuses connections (needs the SDK)",
    },
}
