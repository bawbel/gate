"""Run the gate's real request loop on real stdin and stdout, for the benchmark.

    python -m bench.gate_proc AUDIT_LOG [--approval-wait-ms N] [--fsize-limit BYTES]
                              [--otel-endpoint URL] [-- STUB ARGS...]

The upstream is bench/stub_upstream.py, started by the gate as a real subprocess. With
--approval-wait-ms the approval answer is supplied by a function that waits that long and says yes,
which stands in for a person. With --fsize-limit the process may not write a file larger than that,
which makes the audit write fail with EFBIG (not ENOSPC: a tmpfs of a fixed size needs privileges).
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("audit", type=Path)
    parser.add_argument("--approval-wait-ms", type=float, default=0.0)
    parser.add_argument("--fsize-limit", type=int, default=0)
    parser.add_argument("--otel-endpoint", default="")
    argv = sys.argv[1:]
    split = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:split])
    stub_args = argv[split + 1 :]

    if args.fsize_limit:
        import resource

        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (args.fsize_limit, args.fsize_limit))
    if args.otel_endpoint:
        from bawbel_gate.ops.otel import setup_otel

        setup_otel(endpoint=args.otel_endpoint)

    from bawbel_gate.mux.config import ApprovalConfig, GateConfig, ServerConfig
    from bawbel_gate.mux.proxy import run_enforce

    cfg = GateConfig(
        audit_log=args.audit,
        servers=[
            ServerConfig(
                name="bench",
                command=sys.executable,
                args=[str(HERE / "stub_upstream.py"), *stub_args],
                manifest=HERE / "manifest.cap.yaml",
            )
        ],
        approval=ApprovalConfig(channel="terminal", timeout_seconds=30),
    )

    def answer() -> str:
        time.sleep(args.approval_wait_ms / 1000.0)
        return "y"

    run_enforce(cfg, approval_input_fn=answer if args.approval_wait_ms else None)


if __name__ == "__main__":
    main()
