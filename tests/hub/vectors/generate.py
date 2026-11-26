"""Write the Hub ingest conformance vectors, from the gate's own audit writer.

The vectors are derived data: they are produced here and committed, and `--check` fails if the
committed files differ from what this script writes. The records are real: every chain is written by
`AuditWriter`, and a two-run file by two writers on one file, as `serve` does. Everything is
deterministic: fixed timestamps and fixed digests, so the same script writes the same bytes.

    python tests/hub/vectors/generate.py            # write the files next to this script
    python tests/hub/vectors/generate.py --check    # fail if the committed files are out of date
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from bawbel_gate._const import AUDIT_CHAIN_GENESIS
from bawbel_gate.audit.writer import AuditWriter, _compute_hash

FORMAT = "bawbel-hub-ingest-vectors/v1"
HERE = Path(__file__).parent
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


# --- Records ---------------------------------------------------------------------------------


def _ts(i: int) -> str:
    return f"2026-11-26T00:00:{i % 60:02d}.000Z"


def decided(session: str, i: int, effect: str = "allow") -> dict[str, Any]:
    return {
        "ts": _ts(i),
        "session": session,
        "event": "CALL_DECIDED",
        "server": "github",
        "tool": "get_issue",
        "effect": effect,
        "reason": "resolved",
        "taint": [],
        "args_sha256": DIGEST_A,
        "manifest_sha256": DIGEST_B,
        "ave": [],
    }


def started(session: str) -> dict[str, Any]:
    return {
        "ts": _ts(0),
        "session": session,
        "event": "SESSION_START",
        "manifest_hashes": {"github": DIGEST_B},
    }


def _read(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def chain(session: str, count: int, effect: str = "allow") -> list[dict[str, Any]]:
    """`count` real records of one session, from the genesis value."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "a.jsonl"
        writer = AuditWriter(path)
        for i in range(count):
            writer.append(decided(session, i, effect))
        return _read(path)


def two_runs() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """What `serve` writes when it is run twice on one audit_log: one chain, two sessions.

    Each run starts with its SESSION_START, and the second run resumes the chain and the seq.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "two.jsonl"
        first = AuditWriter(path)
        first.append(started("s1"))
        first.append(decided("s1", 1))
        first.append(decided("s1", 2))
        second = AuditWriter.from_existing(path)
        second.append(started("s2"))
        second.append(decided("s2", 4, "deny"))
        second.append(decided("s2", 5, "deny"))
        records = _read(path)
    return (
        [r for r in records if r["session"] == "s1"],
        [r for r in records if r["session"] == "s2"],
    )


def rehash(record: dict[str, Any], prev: str, **changes: Any) -> dict[str, Any]:
    """Change a record, give it another prev, and recompute its hash: a consistent rewrite."""
    body = {k: v for k, v in record.items() if k != "hash"}
    body.update(changes)
    body["prev"] = prev
    body["hash"] = _compute_hash(body, prev)
    return body


def with_seqs(seqs: list[int], session: str = "s1") -> list[dict[str, Any]]:
    """Links and hashes all correct, and the seq values as given."""
    out, prev = [], AUDIT_CHAIN_GENESIS
    for i, seq in enumerate(seqs):
        record = {"seq": seq, **decided(session, i), "prev": prev}
        record["hash"] = _compute_hash({k: v for k, v in record.items() if k != "hash"}, prev)
        prev = record["hash"]
        out.append(record)
    return out


# --- Vectors ---------------------------------------------------------------------------------


def post(lines: list[Any], status: int, json_: dict[str, Any] | None = None, **extra: Any) -> dict:
    step: dict[str, Any] = {"lines": lines, "expect": {"status": status}}
    if json_ is not None:
        step["expect"]["json"] = json_
    step.update(extra)
    return step


def vec(vector_id: str, description: str, *steps: dict[str, Any]) -> dict[str, Any]:
    return {"id": vector_id, "description": description, "steps": list(steps)}


def refused(reason: str, session: str = "s1", **members: Any) -> dict[str, Any]:
    return {"error": "chain_mismatch", "reason": reason, "session": session, **members}


def schema(index: int, reason: str) -> dict[str, Any]:
    return {"error": "schema", "index": index, "reason": reason}


def valid() -> dict[str, Any]:
    c3, c6 = chain("s1", 3), chain("s1", 6)
    run1, run2 = two_runs()
    other = chain("s9", 2)
    return {
        "format": FORMAT,
        "group": "valid",
        "vectors": [
            vec(
                "valid-single-session",
                "Three records of one session from genesis are accepted.",
                post(c3, 200, {"acked": {"s1": 3}}),
            ),
            vec(
                "valid-empty-body",
                "An empty batch is accepted and acks nothing.",
                post([], 200, {"acked": {}}),
            ),
            vec(
                "valid-blank-lines-are-ignored",
                "Blank and whitespace-only lines between records are skipped.",
                post([c3[0], "", c3[1], "   ", c3[2]], 200, {"acked": {"s1": 3}}),
            ),
            vec(
                "valid-two-run-file-in-one-batch",
                "A file written by two serve runs (one chain, two sessions, seq continuing) "
                "is accepted.",
                post(run1 + run2, 200, {"acked": {"s1": 3, "s2": 6}}),
            ),
            vec(
                "valid-two-run-file-in-two-batches",
                "The second run's SESSION_START restarts from the first run's last record.",
                post(run1, 200, {"acked": {"s1": 3}}),
                post(run2, 200, {"acked": {"s2": 6}}),
            ),
            vec(
                "valid-two-run-file-sessions-listed-in-reverse",
                "Sessions are checked in the order of their first seq, "
                "whatever order the batch lists them in.",
                post(run2 + run1, 200, {"acked": {"s1": 3, "s2": 6}}),
            ),
            vec(
                "valid-next-batch-continues-the-session",
                "The next records of a held session are accepted.",
                post(c6[:3], 200, {"acked": {"s1": 3}}),
                post(c6[3:], 200, {"acked": {"s1": 6}}),
            ),
            vec(
                "valid-replay-is-idempotent",
                "Records the Hub holds, resent unchanged, are accepted.",
                post(c3, 200, {"acked": {"s1": 3}}),
                post(c3, 200, {"acked": {"s1": 3}}),
            ),
            vec(
                "valid-replay-of-a-prefix-acks-the-prefix-only",
                "Resending records 1 to 3 of a session held to 6 is acked to 3, "
                "not to the Hub's head.",
                post(c6, 200, {"acked": {"s1": 6}}),
                post(c6[:3], 200, {"acked": {"s1": 3}}),
            ),
            vec(
                "valid-duplicate-record-inside-one-batch",
                "A record repeated inside one batch is accepted once.",
                post([c3[0], c3[0], c3[1]], 200, {"acked": {"s1": 2}}),
            ),
            vec(
                "valid-rotated-chain-is-a-new-session",
                "A new chain from the genesis value under a new session id "
                "is accepted next to an old one.",
                post(c3, 200, {"acked": {"s1": 3}}),
                post(other, 200, {"acked": {"s9": 2}}),
            ),
            vec(
                "valid-same-session-id-on-two-gates",
                "State is kept per gate: two gates may use one session id.",
                post(c3, 200, {"acked": {"s1": 3}}, gate="a"),
                post(c3, 200, {"acked": {"s1": 3}}, gate="b"),
            ),
        ],
    }


def schemas() -> dict[str, Any]:
    c3 = chain("s1", 3)

    def broken(**changes: Any) -> dict[str, Any]:
        record = dict(c3[0])
        for key, value in changes.items():
            if value is None:
                record.pop(key, None)
            else:
                record[key] = value
        return record

    return {
        "format": FORMAT,
        "group": "schema",
        "vectors": [
            vec(
                "schema-record-is-not-an-object",
                "A JSON line that is not an object is refused with its index.",
                post([c3[0], "[1,2]"], 422, schema(1, "not_object")),
            ),
            vec(
                "schema-session-is-not-a-string",
                "session must be a string.",
                post([broken(session=7)], 422, schema(0, "session")),
            ),
            vec(
                "schema-session-is-empty",
                "session must not be empty.",
                post([broken(session="")], 422, schema(0, "session")),
            ),
            vec(
                "schema-seq-is-a-string",
                "seq must be an integer.",
                post([broken(seq="1")], 422, schema(0, "seq")),
            ),
            vec(
                "schema-seq-is-a-float",
                "seq must be an integer.",
                post([broken(seq=1.5)], 422, schema(0, "seq")),
            ),
            vec(
                "schema-seq-is-a-boolean",
                "seq must not be a boolean.",
                post([broken(seq=True)], 422, schema(0, "seq")),
            ),
            vec(
                "schema-seq-is-zero",
                "seq starts at 1.",
                post([broken(seq=0)], 422, schema(0, "seq")),
            ),
            vec(
                "schema-seq-is-negative",
                "seq starts at 1.",
                post([broken(seq=-1)], 422, schema(0, "seq")),
            ),
            vec(
                "schema-seq-is-above-int64",
                "seq is at most 2^63 - 1.",
                post([broken(seq=2**63)], 422, schema(0, "seq")),
            ),
            vec(
                "schema-hash-is-missing",
                "hash is required.",
                post([broken(hash=None)], 422, schema(0, "hash")),
            ),
            vec(
                "schema-hash-is-empty",
                "hash must not be empty.",
                post([broken(hash="")], 422, schema(0, "hash")),
            ),
            vec(
                "schema-prev-is-missing",
                "A record with a hash and no prev is refused, whatever its seq. "
                "It was once stored and moved the head.",
                post([broken(prev=None, seq=1000000)], 422, schema(0, "prev")),
            ),
            vec(
                "schema-line-is-not-json",
                "A line that is not JSON refuses the batch.",
                post(["{not json"], 422, {"error": "invalid NDJSON"}),
            ),
            vec(
                "schema-one-bad-record-refuses-the-whole-batch",
                "Nothing is stored from a batch that has a bad record: "
                "its good records are refused later as not first.",
                post([c3[0], c3[1], broken(session=7)], 422, schema(2, "session")),
                post(c3[1:], 409, refused("prev")),
            ),
        ],
    }


def chains() -> dict[str, Any]:
    c3, c6 = chain("s1", 3), chain("s1", 6)
    run1, run2 = two_runs()
    forged = rehash(c3[0], c3[0]["hash"], seq=2)
    forged["prev"] = "sha256:" + "1" * 64
    bad_hash = dict(c3[2], hash="sha256:" + "2" * 64)
    rewritten5 = rehash(c6[4], c6[3]["hash"], effect="deny", seq=5)
    rewritten6 = rehash(c6[5], rewritten5["hash"], effect="deny", seq=6)
    skipped = rehash(run2[0], run1[-1]["hash"], seq=run2[0]["seq"] + 3)
    fork = rehash(run2[0], run1[-1]["hash"], session="s3")
    return {
        "format": FORMAT,
        "group": "chain",
        "vectors": [
            vec(
                "chain-prev-does-not-link",
                "The next record names a prev that is not the head.",
                post(c3[:2], 200, {"acked": {"s1": 2}}),
                post([rehash(c3[2], "sha256:" + "1" * 64)], 409, refused("prev", expected_seq=3)),
            ),
            vec(
                "chain-hash-does-not-recompute",
                "The record links but its hash is not the hash of its content.",
                post(c3[:2], 200, {"acked": {"s1": 2}}),
                post([bad_hash], 409, refused("hash", expected_seq=3)),
            ),
            vec(
                "chain-gap-in-one-batch",
                "A seq that skips is refused, naming the seq expected.",
                post(with_seqs([1, 2, 5, 6]), 409, refused("seq_gap", expected_seq=3)),
            ),
            vec(
                "chain-gap-after-held-records",
                "Records that skip past the held head are refused with the seq to resend from.",
                post(c6[:3], 200, {"acked": {"s1": 3}}),
                post(c6[4:], 409, refused("seq_gap", expected_seq=4)),
            ),
            vec(
                "chain-session-starts-high",
                "A first record from the genesis value must have seq 1.",
                post(with_seqs([7, 8, 9]), 409, refused("seq_gap", expected_seq=1)),
            ),
            vec(
                "chain-rewrite-of-held-records",
                "A consistent rewrite of records the Hub holds is refused.",
                post(c6, 200, {"acked": {"s1": 6}}),
                post([rewritten5, rewritten6], 409, refused("rewrite")),
            ),
            vec(
                "chain-held-seq-with-other-content",
                "A held seq resent with other content is refused as a rewrite.",
                post(c3, 200, {"acked": {"s1": 3}}),
                post([dict(c3[1], effect="deny")], 409, refused("rewrite")),
            ),
            vec(
                "chain-repeated-seq",
                "A seq repeated with different content inside one batch is a rewrite.",
                post(with_seqs([1, 2, 2, 3]), 409, refused("rewrite")),
            ),
            vec(
                "chain-out-of-order",
                "A batch must list a session's records in ascending seq.",
                post([c3[1], c3[0], c3[2]], 409, refused("prev", expected_seq=1)),
            ),
            vec(
                "chain-restart-from-a-record-the-hub-does-not-hold",
                "A SESSION_START whose prev names no held record of the gate is refused.",
                post(run1[:2], 200, {"acked": {"s1": 2}}),
                post(run2, 409, refused("prev", session="s2")),
            ),
            vec(
                "chain-restart-must-be-a-session-start",
                "A first record that is not a SESSION_START is not a restart.",
                post(run1, 200, {"acked": {"s1": 3}}),
                post(run2[1:], 409, refused("prev", session="s2")),
            ),
            vec(
                "chain-restart-with-the-wrong-seq",
                "A restart must carry the predecessor's seq plus one.",
                post(run1, 200, {"acked": {"s1": 3}}),
                post([skipped], 409, refused("seq_gap", session="s2", expected_seq=4)),
            ),
            vec(
                "chain-second-restart-from-the-same-record-is-a-fork",
                "A restart from a record that something already follows is refused.",
                post(run1 + run2, 200, {"acked": {"s1": 3, "s2": 6}}),
                post([fork], 409, refused("fork", session="s3", expected_seq=4)),
            ),
            vec(
                "chain-restart-may-not-borrow-another-gates-records",
                "A restart names a record of the same gate only.",
                post(run1, 200, {"acked": {"s1": 3}}, gate="b"),
                post(run2, 409, refused("prev", session="s2"), gate="a"),
            ),
            vec(
                "chain-nothing-is-stored-from-a-refused-batch",
                "A refused batch leaves nothing behind: "
                "the same session starts cleanly afterwards.",
                post(with_seqs([1, 2, 5, 6]), 409, refused("seq_gap", expected_seq=3)),
                post(with_seqs([1, 2, 3, 4]), 200, {"acked": {"s1": 4}}),
            ),
            {
                "id": "chain-forged-link-is-never-accepted",
                "description": "A record 2 with a wrong prev and a wrong hash "
                "after a held record 1 is refused.",
                "steps": [
                    post(c3[:1], 200, {"acked": {"s1": 1}}),
                    post([forged], 409, refused("prev", expected_seq=2)),
                ],
            },
        ],
    }


def limits() -> dict[str, Any]:
    c3 = chain("s1", 3)
    sock = ["Host: hub", "Authorization: Bearer {token}"]
    head = "POST /v1/gates/{gate}/records HTTP/1.1"
    return {
        "format": FORMAT,
        "group": "limits",
        "vectors": [
            vec(
                "limits-body-exactly-at-the-cap-is-accepted",
                "A body of exactly the cap is read. Padding is blank lines, which are skipped.",
                post(
                    c3,
                    200,
                    {"acked": {"s1": 3}},
                    pad_to={"relative_to": "max_body_bytes", "offset": 0},
                ),
            ),
            vec(
                "limits-body-one-byte-over-the-cap-is-refused",
                "A body over the cap is answered with 413 before it is read.",
                post(
                    c3,
                    413,
                    {"error": "too_large"},
                    pad_to={"relative_to": "max_body_bytes", "offset": 1},
                ),
            ),
            vec(
                "limits-content-length-is-not-a-number",
                "A Content-Length that is not a plain number is refused.",
                {
                    "raw": {"send": [head, *sock, "Content-Length: abc"]},
                    "expect": {"status": 400, "json": {"error": "bad_content_length"}},
                },
            ),
            vec(
                "limits-content-length-is-negative",
                "A negative Content-Length is refused.",
                {
                    "raw": {"send": [head, *sock, "Content-Length: -1"]},
                    "expect": {"status": 400, "json": {"error": "bad_content_length"}},
                },
            ),
            vec(
                "limits-chunked-body-is-refused",
                "A chunked body is not accepted: send a Content-Length.",
                {
                    "raw": {
                        "send": [head, *sock, "Transfer-Encoding: chunked"],
                        "body": "0\r\n\r\n",
                    },
                    "expect": {"status": 411, "json": {"error": "length_required"}},
                },
            ),
            vec(
                "limits-body-ends-early",
                "The client promises 100 bytes, sends 5 and closes its side.",
                {
                    "raw": {
                        "send": [head, *sock, "Content-Length: 100"],
                        "body": "xxxxx",
                        "half_close": True,
                    },
                    "expect": {"status": 400, "json": {"error": "incomplete_body"}},
                },
            ),
            vec(
                "limits-client-that-sends-no-body-times-out",
                "The client promises 100 bytes and sends none, and keeps the connection open: "
                "408 at the deadline.",
                {
                    "slow": True,
                    "raw": {"send": [head, *sock, "Content-Length: 100"]},
                    "expect": {"status": 408, "json": {"error": "request_timeout"}},
                },
            ),
        ],
    }


def auth() -> dict[str, Any]:
    c3 = chain("s1", 3)
    return {
        "format": FORMAT,
        "group": "auth",
        "vectors": [
            vec(
                "auth-no-credential",
                "A request with no credential is refused.",
                post(c3, 401, {"error": "unauthorized"}, auth="none"),
            ),
            vec(
                "auth-wrong-credential",
                "A request with a credential the Hub does not hold is refused.",
                post(c3, 401, {"error": "unauthorized"}, auth="wrong"),
            ),
            vec(
                "auth-refused-request-stores-nothing",
                "A refused request leaves nothing: the same chain is then accepted.",
                post(c3, 401, {"error": "unauthorized"}, auth="none"),
                post(c3, 200, {"acked": {"s1": 3}}),
            ),
            vec(
                "auth-unknown-route",
                "A route the Hub does not have is 404 for an authenticated client.",
                {
                    "path": "/v1/nothing",
                    "lines": [],
                    "expect": {"status": 404, "json": {"error": "not found"}},
                },
            ),
            vec(
                "auth-get-on-the-ingest-route",
                "The ingest route takes POST only.",
                {"method": "GET", "expect": {"status": 404, "json": {"error": "not found"}}},
            ),
        ],
    }


def build() -> dict[str, dict[str, Any]]:
    return {
        "valid.json": valid(),
        "schema.json": schemas(),
        "chain.json": chains(),
        "limits.json": limits(),
        "auth.json": auth(),
    }


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write or check the Hub ingest vectors.")
    parser.add_argument("--check", action="store_true", help="fail if the committed files differ")
    parser.add_argument("--out", type=Path, default=HERE)
    args = parser.parse_args(argv)
    stale = []
    for name, doc in build().items():
        text = render(doc)
        path = args.out / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            path.write_text(text, encoding="utf-8")
    if stale:
        print(
            f"out of date: {', '.join(stale)}. Run: python tests/hub/vectors/generate.py",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
