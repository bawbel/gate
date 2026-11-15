"""THROWAWAY diagnostic for issue #105. Fails on purpose so the report is in the CI log."""
import platform
import statistics
import sys
import time

from bawbel_gate.console.approvals import ApprovalRegistry


def _body(expires_in_s, sleep_s):
    reg = ApprovalRegistry()
    i = reg.register(session="s", server="s", tool="t", cause="c", expires_in_s=expires_in_s)
    time.sleep(sleep_s)
    return reg.get(i) is None  # True means the approval was seen as expired


def _poll(expires_in_s):
    reg = ApprovalRegistry()
    i = reg.register(session="s", server="s", tool="t", cause="c", expires_in_s=expires_in_s)
    deadline = time.perf_counter() + 5
    while reg.get(i) is not None and time.perf_counter() < deadline:
        time.sleep(0.01)
    return reg.get(i) is None


def test_diag_clock():
    out = []
    out.append(f"platform={platform.platform()} python={sys.version.split()[0]}")
    for name in ("monotonic", "perf_counter", "time"):
        ci = time.get_clock_info(name)
        out.append(f"clock {name}: impl={ci.implementation} resolution={ci.resolution}")
    # distinct values of time.monotonic() seen in 0.5 s of spinning
    seen, t0 = [], time.perf_counter()
    last = None
    while time.perf_counter() - t0 < 0.5:
        v = time.monotonic()
        if v != last:
            seen.append(v)
            last = v
    steps = [b - a for a, b in zip(seen, seen[1:])]
    out.append(
        f"monotonic distinct values in 0.5s: {len(seen)}; step min={min(steps)*1000:.3f}ms "
        f"median={statistics.median(steps)*1000:.3f}ms max={max(steps)*1000:.3f}ms"
    )
    # how long time.sleep(0.01) really takes, by perf_counter
    durs = []
    for _ in range(200):
        a = time.perf_counter()
        time.sleep(0.01)
        durs.append((time.perf_counter() - a) * 1000)
    out.append(
        f"sleep(0.01) real: min={min(durs):.2f}ms median={statistics.median(durs):.2f}ms max={max(durs):.2f}ms"
    )
    N = 2000
    f_orig = sum(1 for _ in range(N) if not _body(0.001, 0.01))
    out.append(f"EXACT TEST BODY (expires 0.001, sleep 0.01): {f_orig} of {N} saw an unexpired approval")
    f_wide = sum(1 for _ in range(N) if not _body(0.001, 0.05))
    out.append(f"same, sleep 0.05: {f_wide} of {N} saw an unexpired approval")
    M = 300
    f_poll = sum(1 for _ in range(M) if not _poll(0.05))
    out.append(f"poll-until-expired (expires 0.05, up to 5 s): {f_poll} of {M} never expired")
    assert False, "DIAG REPORT\n" + "\n".join(out)
