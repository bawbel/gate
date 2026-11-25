#!/usr/bin/env python3
"""Measure a bawbel-gate audit chain against a checkout of the ACS repository (GATE-14c).

Read only and offline. It reads an ACS checkout, a log written by `bawbel-gate serve` and the
gate's own code. It writes nothing, refuses to open a socket, and is not part of CI: run it by
hand. The RFC 8785 oracle is Node (`node` on PATH, through jcs.js beside this file). The
`rfc8785` package is a second oracle if it is already installed. Nothing from the ACS
repository is executed: its JSON files are read as data. See README.md.

  acs_check.py chain     --acs DIR --audit FILE [--serve-stderr FILE]
  acs_check.py args      --audit FILE --calls FILE
  acs_check.py canonical
  acs_check.py vectors   --acs DIR [--audit FILE]

Exit status: 0 done, 1 the oracle failed to reproduce ACS's own vector (so no measurement made
with it can be trusted), 2 a usage or input error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import socket
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
JCS_JS = HERE / "jcs.js"
CONTEXT_ENTRY = "specification/v0.1.0/context-entry.json"
VECTORS = "reference-implementations/agt-go/internal/chain/testdata/vectors.json"

# The JSON texts compared in docs/ACS_CONFORMANCE.md 6.1. The backslash escapes are literal
# text in these strings, so every text is plain ASCII.
CASES = [
    ("integer", '{"a":1}'),
    ("1.0", '{"a":1.0}'),
    ("0.1", '{"a":0.1}'),
    ("1e20", '{"a":1e20}'),
    ("1e21", '{"a":1e21}'),
    ("1e-7", '{"a":1e-7}'),
    ("20 digit integer", '{"a":100000000000000000000}'),
    ("2^53 + 1", '{"a":9007199254740993}'),
    ("key order, ASCII", '{"b":1,"a":2}'),
    ("keys U+1F600 and U+FFEE", '{"\\ud83d\\ude00":1,"\\uffee":2}'),
    ("control characters", '{"a":"\\u0001\\u007f\\u2028"}'),
    ("accented text", '{"a":"caf\\u00e9"}'),
    ("NaN", '{"a":NaN}'),
]


class Fail(Exception):
    """A usage or input error: printed as one line, exit status 2."""


# ----------------------------------------------------------------------------- offline guard


def forbid_network() -> None:
    """Make any socket use in this process raise. It does not cover the Node child."""

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("acs_check is offline: network access is not allowed")

    for name in ("connect", "connect_ex", "sendto"):
        setattr(socket.socket, name, refuse)
    socket.create_connection = refuse  # type: ignore[assignment]
    socket.getaddrinfo = refuse  # type: ignore[assignment]


# ----------------------------------------------------------------------------- input helpers


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Fail(f"cannot read {path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise Fail(f"{path} is not UTF-8") from exc


def read_json(path: Path) -> Any:
    try:
        return json.loads(read_text(path))
    except ValueError as exc:
        raise Fail(f"{path} is not valid JSON: {exc}") from exc


def read_log(path: Path) -> list[dict[str, Any]]:
    """Every non-empty line of an audit log as a JSON object."""
    records: list[dict[str, Any]] = []
    for number, line in enumerate(read_text(path).splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise Fail(f"{path}:{number}: not valid JSON: {exc}") from exc
        if not isinstance(record, dict) or not {"hash", "prev"} <= record.keys():
            raise Fail(f"{path}:{number}: not an audit record (needs 'hash' and 'prev')")
        records.append(record)
    if not records:
        raise Fail(f"{path} holds no records")
    return records


def acs_file(acs: Path, relative: str) -> Path:
    path = acs / relative
    if not path.is_file():
        raise Fail(f"{relative} is not in {acs}: is it an ACS checkout at a commit that has it?")
    return path


# ----------------------------------------------------------------------------- gate and oracles


def gate_canonical() -> tuple[Callable[[Any], bytes], Callable[[Any], str]]:
    try:
        from bawbel_gate.audit.canonical import canonical_bytes, canonical_str
    except ImportError as exc:
        raise Fail(
            "bawbel_gate is not importable: run this with the python of the environment "
            "where bawbel-gate is installed"
        ) from exc
    return canonical_bytes, canonical_str


def node_oracle(texts: list[str]) -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["node", str(JCS_JS)], input=json.dumps(texts), capture_output=True, text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise Fail("node is not on PATH: it is the RFC 8785 oracle") from exc
    if proc.returncode != 0:
        raise Fail("node failed: " + (proc.stderr.strip() or "no message")[:200])
    return json.loads(proc.stdout)


def second_oracle(texts: list[str]) -> list[dict[str, Any]] | None:
    """The `rfc8785` package, only if it is already installed."""
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError:
        return None
    out: list[dict[str, Any]] = []
    for text in texts:
        try:
            out.append({"ok": True, "text": rfc8785.dumps(json.loads(text)).decode("utf-8")})
        except Exception as exc:  # the package raises its own error types
            out.append({"ok": False, "error": type(exc).__name__})
    return out


def jcs_bytes(objects: list[Any]) -> list[bytes]:
    """The RFC 8785 bytes of each object, by the Node oracle."""
    texts = [json.dumps(o, ensure_ascii=False) for o in objects]
    out = node_oracle(texts)
    if not all(o["ok"] for o in out):
        raise Fail("the oracle refused a value: " + next(o["error"] for o in out if not o["ok"]))
    return [o["text"].encode("utf-8") for o in out]


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def header(acs: Path | None) -> None:
    try:
        gate = metadata.version("bawbel-gate")
    except metadata.PackageNotFoundError:
        gate = "not installed"
    try:
        node = subprocess.run(["node", "--version"], capture_output=True, text=True, check=False)
        node_version = node.stdout.strip() or "unknown"
    except FileNotFoundError:
        node_version = "not found"
    print(f"bawbel-gate {gate}; python {platform.python_version()}; node {node_version}")
    if acs is not None:
        rev = "not a git checkout"
        try:
            git = subprocess.run(
                ["git", "-C", str(acs), "rev-parse", "HEAD"], capture_output=True, text=True,
                check=False,
            )
            if git.returncode == 0:
                rev = git.stdout.strip()
        except FileNotFoundError:
            rev = "git not found"
        print(f"ACS checkout at {rev}")
    print()


# ----------------------------------------------------------------------------- subcommands


def cmd_chain(args: argparse.Namespace) -> int:
    """The gate's records against context-entry.json, and the hash rule by experiment."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise Fail("jsonschema is not importable in this environment") from exc
    canonical_bytes, _ = gate_canonical()
    records = read_log(args.audit)
    schema = read_json(acs_file(args.acs, CONTEXT_ENTRY))
    validator = Draft202012Validator(schema)
    header(args.acs)
    print(f"records: {len(records)}; events: {[r.get('event') for r in records]}")

    print("\nM1 each record against ACS context-entry.json (JSON Schema 2020-12)")
    for r in records:
        errors = [e.message for e in validator.iter_errors(r)]
        absent = [k for k in schema["required"] if k not in r]
        verdict = "valid" if not errors else "INVALID"
        print(f"  seq {r.get('seq')} {r.get('event')}: {verdict}; required fields absent: "
              f"{absent}; errors: {len(errors)}")
    print("  additionalProperties in the schema:",
          schema.get("additionalProperties", "not set (extra fields allowed)"))
    pattern = schema["properties"]["entry_hash"]["pattern"]
    print(f"  entry_hash pattern {pattern}")
    print("  gate 'hash' matches it as written:",
          [bool(re.fullmatch(pattern, r["hash"])) for r in records])
    print("  gate 'hash' matches it without the 'sha256:' prefix:",
          [bool(re.fullmatch(pattern, r["hash"].removeprefix("sha256:"))) for r in records])
    names = ("entry_id", "step_id", "step_type", "entry_hash", "previous_hash")
    print("  gate records carry these ACS field names:",
          {k: any(k in r for r in records) for k in names})

    print("\nM2 each record's hash recomputed, then one rule changed at a time")
    rows: dict[str, list[bool]] = {
        "the gate's rule (prev inside the hashed content, UTF-8 text of prev appended)": [],
        "prev left out of the hashed content": [],
        "32 raw bytes of the previous digest appended instead of the text": [],
    }
    for r in records:
        body = {k: v for k, v in r.items() if k != "hash"}
        stored, prev = r["hash"], r["prev"]
        gate_rule = "sha256:" + sha_hex(canonical_bytes(body) + prev.encode("utf-8"))
        no_prev = {k: v for k, v in body.items() if k != "prev"}
        without_prev = "sha256:" + sha_hex(canonical_bytes(no_prev) + prev.encode("utf-8"))
        try:
            raw = bytes.fromhex(prev.removeprefix("sha256:"))
        except ValueError:
            raw = b""
        raw_rule = "sha256:" + sha_hex(canonical_bytes(body) + raw)
        for key, value in zip(rows, (gate_rule, without_prev, raw_rule)):
            rows[key].append(value == stored)
    for label, results in rows.items():
        print(f"  {label}: matches the stored hash on {sum(results)} of {len(results)} records")
    print("  first record's prev is 'sha256:' and 64 zeros:",
          records[0]["prev"] == "sha256:" + "0" * 64)
    print("  bytes appended per record (UTF-8 of prev):",
          sorted({len(r["prev"].encode("utf-8")) for r in records}))
    print("  each prev equals the earlier record's hash:",
          all(records[i]["prev"] == records[i - 1]["hash"] for i in range(1, len(records))))
    if args.serve_stderr:
        err = read_text(args.serve_stderr)
        heads = re.findall(r"chain head (sha256:[0-9a-f]{64})", err)
        print("  chain head printed on serve's stderr:", bool(heads),
              "| equals the last record's hash:", bool(heads) and heads[-1] == records[-1]["hash"])
    print("  a record carries the chain head as a field:",
          any("chain_head" in r or "head" in r for r in records))
    return 0


def cmd_args(args: argparse.Namespace) -> int:
    """args_sha256 of each call against the gate's form and the RFC 8785 form of its arguments."""
    canonical_bytes, _ = gate_canonical()
    records = [r for r in read_log(args.audit) if r.get("event") == "CALL_DECIDED"]
    calls = read_json(args.calls)
    if not isinstance(calls, list) or not all(
        isinstance(c, dict) and {"tool", "args"} <= c.keys() for c in calls
    ):
        raise Fail(f"{args.calls} must be a JSON list of {{\"tool\": ..., \"args\": <JSON text>}}")
    if len(calls) != len(records):
        raise Fail(f"{len(calls)} calls listed but the log holds {len(records)} CALL_DECIDED")
    texts = [c["args"] for c in calls]
    oracle = node_oracle(texts)
    header(None)

    def digest(data: bytes) -> str:
        return "sha256:" + sha_hex(data)

    for call, record, jcs in zip(calls, records, oracle):
        if record.get("tool") != call["tool"]:
            raise Fail(f"call order differs: log has {record.get('tool')}, list has {call['tool']}")
        try:
            gate_form = canonical_bytes(json.loads(call["args"]))
        except ValueError as exc:
            raise Fail(f"arguments of {call['tool']} are not valid JSON: {exc}") from exc
        print(f"{call['tool']:<22} args {call['args']}")
        print("  recorded args_sha256 equals the hash of the gate's canonical form:",
              digest(gate_form) == record.get("args_sha256"))
        if jcs["ok"]:
            print("  recorded args_sha256 equals the hash of the RFC 8785 form:",
                  digest(jcs["text"].encode("utf-8")) == record.get("args_sha256"))
            print("  the two forms are the same bytes:", gate_form == jcs["text"].encode("utf-8"))
        else:
            print("  the RFC 8785 form does not exist for these arguments:", jcs["error"])
    return 0


def cmd_canonical(_args: argparse.Namespace) -> int:
    """The gate's canonical_str against RFC 8785 on the fixed JSON texts."""
    _, canonical_str = gate_canonical()
    texts = [t for _, t in CASES]
    node = node_oracle(texts)
    second = second_oracle(texts)
    header(None)
    print("the same JSON text serialised by the gate's canonical_str and by RFC 8785")
    differing = disagreeing = 0
    for index, (name, text) in enumerate(CASES):
        gate_text = canonical_str(json.loads(text))
        n = node[index]
        jcs_text = n["text"] if n["ok"] else f"<rejected: {n['error']}>"
        same = n["ok"] and gate_text == jcs_text
        note = ""
        if second is not None:
            s = second[index]
            second_text = s["text"] if s["ok"] else f"<rejected: {s['error']}>"
            agrees = second_text == jcs_text or (not s["ok"] and not n["ok"])
            disagreeing += not agrees
            note = f" | second oracle: {second_text} ({'agrees' if agrees else 'DISAGREES'})"
        differing += not same
        print(f"  {name:<24} gate {gate_text:<34} rfc8785 {jcs_text:<34} "
              f"{'same' if same else 'DIFFERENT'}{note}")
    print(f"  {differing} of {len(CASES)} cases differ")
    if second is None:
        print("  second oracle (the rfc8785 package): not installed, not used")
    else:
        print(f"  the two oracles disagree on {disagreeing} of {len(CASES)} cases")
    return 0


def cmd_vectors(args: argparse.Namespace) -> int:
    """ACS's own chain vector, then the gate's canonical form on ACS's entries and the log."""
    canonical_bytes, _ = gate_canonical()
    vec = read_json(acs_file(args.acs, VECTORS))
    for key in ("request_hash", "chain"):
        if key not in vec:
            raise Fail(f"{VECTORS} has no '{key}': it is not the vector file this expects")
    header(args.acs)

    print("A  ACS's vector, reproduced with the Node oracle")
    request = vec["request_hash"]
    (params_bytes,) = jcs_bytes([request["params"]])
    ok_request = (
        params_bytes.decode("utf-8") == request["canonical"]
        and sha_hex(params_bytes) == request["hash"]
    )
    print("  request_hash: the canonical text and the digest both reproduce:", ok_request)
    chain = vec["chain"]
    stripped = [
        {k: v for k, v in c["entry"].items() if k not in ("entry_hash", "previous_hash")}
        for c in chain
    ]
    contents = jcs_bytes(stripped)
    ok_content, ok_hash, ok_link = [], [], []
    earlier = None
    for item, content in zip(chain, contents):
        previous = item["previous_hash"]
        raw = b"" if not previous else bytes.fromhex(previous)
        ok_content.append(content.decode("utf-8") == item["canonical_content"])
        ok_hash.append(sha_hex(content + raw) == item["entry_hash"])
        ok_link.append(previous == earlier)
        earlier = item["entry_hash"]
    print(f"  chain of {len(chain)} entries: canonical_content reproduced: {ok_content}")
    print(f"  chain: entry_hash = sha256(content || raw previous_hash) reproduced: {ok_hash}")
    print(f"  chain: each previous_hash is the earlier entry_hash (first is null): {ok_link}")
    print("  entry field names:", sorted(chain[0]["entry"].keys()))

    print("\nB  the gate's canonical form against RFC 8785")
    same_acs = [canonical_bytes(s) == j for s, j in zip(stripped, contents)]
    print(f"  equal on the {len(chain)} ACS entries: {same_acs}")
    if args.audit:
        records = read_log(args.audit)
        bodies = [{k: v for k, v in r.items() if k != "hash"} for r in records]
        same_gate = [canonical_bytes(b) == j for b, j in zip(bodies, jcs_bytes(bodies))]
        print(f"  equal on the log's {len(records)} records: {same_gate}")
        print("  value types in those records:",
              sorted({type(v).__name__ for b in bodies for v in b.values()}))
        print("  float values in those records:",
              [k for b in bodies for k, v in b.items() if isinstance(v, float)])
    reproduced = ok_request and all(ok_content) and all(ok_hash) and all(ok_link)
    if not reproduced:
        print("\nthe oracle did not reproduce ACS's own vector: do not trust the numbers above",
              file=sys.stderr)
    return 0 if reproduced else 1


# ----------------------------------------------------------------------------- entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acs_check.py", description="Measure a bawbel-gate audit chain against ACS."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    chain = sub.add_parser("chain", help="records against context-entry.json, hash rule")
    chain.add_argument("--acs", type=Path, required=True, help="an ACS checkout")
    chain.add_argument("--audit", type=Path, required=True, help="an audit log")
    chain.add_argument("--serve-stderr", type=Path, help="stderr captured from the serve run")
    chain.set_defaults(run=cmd_chain)

    call_args = sub.add_parser("args", help="args_sha256 against the two canonical forms")
    call_args.add_argument("--audit", type=Path, required=True, help="an audit log")
    call_args.add_argument("--calls", type=Path, required=True,
                           help='JSON list of {"tool": ..., "args": <JSON text>}, in call order')
    call_args.set_defaults(run=cmd_args)

    canonical = sub.add_parser("canonical", help="canonical_str against RFC 8785, 13 texts")
    canonical.set_defaults(run=cmd_canonical)

    vectors = sub.add_parser("vectors", help="ACS's chain vector, then the gate's form")
    vectors.add_argument("--acs", type=Path, required=True, help="an ACS checkout")
    vectors.add_argument("--audit", type=Path, help="an audit log, to compare its records too")
    vectors.set_defaults(run=cmd_vectors)
    return parser


def main(argv: list[str] | None = None) -> int:
    forbid_network()
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except Fail as exc:
        print(f"acs_check: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
