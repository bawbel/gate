"""Run the Hub ingest conformance vectors against a Hub that is already running.

Standard library only, and no import from bawbel_gate, so any implementation of the ingest protocol
(docs/hub/INGEST-PROTOCOL.md) can be run against the same vectors:

    python run_vectors.py --base-url http://127.0.0.1:8443 --token ADMIN_TOKEN

Each vector is a list of HTTP steps with the answer to expect. Every vector uses gate ids of its own
(`<run id>-<vector id>-<gate>`), so the same Hub can be run against again without clearing it.

Options that match the Hub under test:

    --max-body-bytes N      the Hub's request body cap (default 1048576)
    --request-timeout-s S   the Hub's body deadline, for the vector that waits for it (default 10)
    --timeouts              also run the vectors that wait for the Hub's deadline
    --only ID               run one vector by id
    --run-id TEXT           prefix for gate ids (default: random)

Exit status: 0 if every vector run passed, 1 if any failed, 2 for a usage error.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import secrets
import socket
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

FORMAT = "bawbel-hub-ingest-vectors/v1"
HERE = Path(__file__).parent


def load_vectors(directory: Path = HERE) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != FORMAT:
            raise ValueError(f"{path.name}: format is {data.get('format')!r}, expected {FORMAT!r}")
        for vector in data["vectors"]:
            vectors.append({**vector, "group": data["group"]})
    return vectors


def answer_code(status: int, body: Any) -> str:
    """The stable code of an answer: status, then `error`, then `reason`, joined with colons."""
    parts = [str(status)]
    if isinstance(body, dict):
        for key in ("error", "reason"):
            if isinstance(body.get(key), str):
                parts.append(body[key])
    return ":".join(parts)


def subset(expected: Any, actual: Any) -> bool:
    """True if every member of `expected` is in `actual`, recursively. Lists must be equal."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and subset(value, actual[key]) for key, value in expected.items()
        )
    return bool(expected == actual)


def _body(step: dict[str, Any], max_body_bytes: int) -> bytes:
    out = b""
    for line in step.get("lines", []):
        text = line if isinstance(line, str) else json.dumps(line, separators=(",", ":"))
        out += text.encode("utf-8") + b"\n"
    pad = step.get("pad_to")
    if pad:
        target = max_body_bytes + int(pad.get("offset", 0))
        if len(out) > target:
            raise ValueError("vector body is longer than the size it asks to be padded to")
        out += b"\n" * (target - len(out))
    return out


def _parse(raw: bytes) -> tuple[int, Any]:
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    status = int(status_line.split(" ", 2)[1])
    try:
        return status, json.loads(body) if body else None
    except ValueError:
        return status, None


def _raw_step(
    host: str,
    port: int,
    step: dict[str, Any],
    gate: str,
    token: str,
    timeout_s: float,
) -> tuple[int, Any]:
    raw = step["raw"]
    lines = [line.format(gate=gate, token=token) for line in raw["send"]]
    payload = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + raw.get("body", "").encode(
        "utf-8"
    )
    sock = socket.create_connection((host, port), timeout=timeout_s)
    try:
        sock.sendall(payload)
        if raw.get("half_close"):
            sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                chunk = sock.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
    finally:
        sock.close()
    if not data:
        raise ConnectionError("the Hub closed the connection without an answer")
    return _parse(data)


def _http_step(
    host: str,
    port: int,
    step: dict[str, Any],
    gate: str,
    token: str,
    max_body_bytes: int,
) -> tuple[int, Any]:
    path = step.get("path", "/v1/gates/{gate}/records").format(gate=gate)
    method = step.get("method", "POST")
    headers = {"Content-Type": "application/x-ndjson"}
    auth = step.get("auth", "admin")
    if auth == "admin":
        headers["Authorization"] = f"Bearer {token}"
    elif auth == "wrong":
        headers["Authorization"] = "Bearer not-the-credential"
    body = _body(step, max_body_bytes) if method == "POST" else None
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        # The Hub may answer before it has read the whole body.
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        try:
            return resp.status, json.loads(data) if data else None
        except ValueError:
            return resp.status, None
    finally:
        conn.close()


def run_vector(
    vector: dict[str, Any],
    base_url: str,
    token: str,
    *,
    run_id: str,
    max_body_bytes: int,
    request_timeout_s: float,
    timeouts: bool,
) -> tuple[str, str]:
    """Return ("pass" | "fail" | "skip", detail)."""
    if any(step.get("slow") for step in vector["steps"]) and not timeouts:
        return "skip", "waits for the Hub's deadline; run with --timeouts"
    parsed = urllib.parse.urlparse(base_url)
    host, port = parsed.hostname or "127.0.0.1", parsed.port or 80
    for number, step in enumerate(vector["steps"], start=1):
        gate = f"{run_id}-{vector['id']}-{step.get('gate', 'a')}"
        try:
            if "raw" in step:
                status, body = _raw_step(host, port, step, gate, token, request_timeout_s + 5)
            else:
                status, body = _http_step(host, port, step, gate, token, max_body_bytes)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return "fail", f"step {number}: {type(exc).__name__}: {exc}"
        expect = step["expect"]
        if status != expect["status"] or not subset(expect.get("json", {}), body):
            return "fail", (
                f"step {number}: expected {expect['status']} {json.dumps(expect.get('json', {}))}, "
                f"got {status} {json.dumps(body)}"
            )
    return "pass", ""


def run_all(
    base_url: str,
    token: str,
    directory: Path = HERE,
    *,
    run_id: str | None = None,
    max_body_bytes: int = 1048576,
    request_timeout_s: float = 10.0,
    timeouts: bool = False,
    only: str | None = None,
) -> list[tuple[str, str, str]]:
    run_id = run_id or secrets.token_hex(3)
    results = []
    for vector in load_vectors(directory):
        if only and vector["id"] != only:
            continue
        outcome, detail = run_vector(
            vector,
            base_url,
            token,
            run_id=run_id,
            max_body_bytes=max_body_bytes,
            request_timeout_s=request_timeout_s,
            timeouts=timeouts,
        )
        results.append((vector["id"], outcome, detail))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Hub ingest conformance vectors.")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--vectors", type=Path, default=HERE)
    parser.add_argument("--max-body-bytes", type=int, default=1048576)
    parser.add_argument("--request-timeout-s", type=float, default=10.0)
    parser.add_argument("--timeouts", action="store_true")
    parser.add_argument("--only")
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        results = run_all(
            args.base_url,
            args.token,
            args.vectors,
            run_id=args.run_id,
            max_body_bytes=args.max_body_bytes,
            request_timeout_s=args.request_timeout_s,
            timeouts=args.timeouts,
            only=args.only,
        )
    except (OSError, ValueError) as exc:
        print(f"run_vectors: {exc}", file=sys.stderr)
        return 2
    for vector_id, outcome, detail in results:
        print(f"{outcome.upper():5} {vector_id}" + (f"  {detail}" if detail else ""))
    counts = {k: sum(1 for _, o, _ in results if o == k) for k in ("pass", "fail", "skip")}
    print(
        f"{counts['pass']} passed, {counts['fail']} failed, {counts['skip']} skipped "
        f"in {time.monotonic() - started:.1f}s"
    )
    return 1 if counts["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
