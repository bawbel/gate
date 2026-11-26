"""HUB-R11: the Hub ingest conformance vectors, run against the reference Hub.

`tests/hub/vectors/` holds the vectors and a runner that needs only the standard library, so any
implementation of docs/hub/INGEST-PROTOCOL.md can be run against them. This file starts the
reference Hub with a small body cap and a short deadline, runs every vector, and checks that the
vectors, the generator and the protocol document agree.
"""

from __future__ import annotations

import ast
import re
import tempfile
from pathlib import Path

import pytest

from bawbel_gate.hub.enroll import EnrollmentRegistry
from bawbel_gate.hub.server import HubServer
from bawbel_gate.hub.store import FleetStore
from tests.hub.vectors import generate, run_vectors

PROTOCOL = Path(__file__).parents[2] / "docs" / "hub" / "INGEST-PROTOCOL.md"
CAP = 4096
DEADLINE_S = 1.0
VECTORS = run_vectors.load_vectors()


@pytest.fixture(scope="module")
def hub():
    server = HubServer(
        store=FleetStore(":memory:"),
        enroll=EnrollmentRegistry(":memory:"),
        host="127.0.0.1",
        port=0,
        max_body_bytes=CAP,
        request_timeout_s=DEADLINE_S,
    )
    server.start_background()
    try:
        yield f"http://127.0.0.1:{server.port}", server.admin_token
    finally:
        server.stop()


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_the_reference_hub_passes_the_vector(hub, vector):
    base_url, token = hub
    outcome, detail = run_vectors.run_vector(
        vector,
        base_url,
        token,
        run_id="t",
        max_body_bytes=CAP,
        request_timeout_s=DEADLINE_S,
        timeouts=True,
    )
    assert outcome == "pass", detail


def _codes_in_vectors() -> set[str]:
    codes = set()
    for vector in VECTORS:
        for step in vector["steps"]:
            expect = step["expect"]
            codes.add(run_vectors.answer_code(expect["status"], expect.get("json")))
    return codes


def _codes_in_the_protocol() -> set[str]:
    codes = set()
    in_table = False
    for line in PROTOCOL.read_text(encoding="utf-8").splitlines():
        if line.startswith("| Status | `error` | `reason`"):
            in_table = True
            continue
        if in_table and not line.startswith("|"):
            break
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        if in_table and cells[0].isdigit():
            parts = [cells[0], *[c for c in cells[1:3] if c]]
            codes.add(":".join(parts))
    return codes


class TestTheVectorsAndTheProtocolAgree:
    def test_every_stable_code_in_the_protocol_appears_in_a_vector(self):
        missing = _codes_in_the_protocol() - _codes_in_vectors()
        assert not missing, f"no vector shows these codes: {sorted(missing)}"

    def test_every_code_a_vector_expects_is_in_the_protocol(self):
        undocumented = _codes_in_vectors() - _codes_in_the_protocol()
        assert not undocumented, f"the protocol does not list: {sorted(undocumented)}"

    def test_the_protocol_table_was_found(self):
        assert len(_codes_in_the_protocol()) >= 15

    def test_the_protocol_says_how_many_vectors_there_are(self):
        match = re.search(r"holds (\d+) vectors", PROTOCOL.read_text(encoding="utf-8"))
        assert match and int(match.group(1)) == len(VECTORS)

    def test_vector_ids_are_unique(self):
        ids = [v["id"] for v in VECTORS]
        assert len(ids) == len(set(ids))


class TestTheGeneratorIsTheSource:
    def test_the_committed_vectors_are_what_the_generator_writes(self):
        assert generate.main(["--check"]) == 0

    def test_the_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            generate.main(["--out", one])
            generate.main(["--out", two])
            for name in generate.build():
                assert (Path(one) / name).read_bytes() == (Path(two) / name).read_bytes()

    def test_a_two_run_file_is_in_the_vectors_and_is_written_by_two_writers(self):
        run1, run2 = generate.two_runs()
        assert [r["seq"] for r in run1 + run2] == [1, 2, 3, 4, 5, 6]
        assert run2[0]["event"] == "SESSION_START"
        assert run2[0]["prev"] == run1[-1]["hash"]


class TestTheRunner:
    def test_the_runner_imports_nothing_from_the_gate(self):
        tree = ast.parse(Path(run_vectors.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert "bawbel_gate" not in imported
        assert "tests" not in imported

    def test_it_reports_a_failure_and_exits_1(self, hub):
        base_url, token = hub
        bad = [
            {
                "id": "wrong-expectation",
                "group": "x",
                "steps": [{"lines": [], "expect": {"status": 418}}],
            }
        ]
        outcome, detail = run_vectors.run_vector(
            bad[0],
            base_url,
            token,
            run_id="t",
            max_body_bytes=CAP,
            request_timeout_s=DEADLINE_S,
            timeouts=False,
        )
        assert outcome == "fail" and "418" in detail

    def test_it_skips_a_vector_that_waits_for_the_deadline_unless_asked(self, hub):
        base_url, token = hub
        slow = next(v for v in VECTORS if any(s.get("slow") for s in v["steps"]))
        outcome, _ = run_vectors.run_vector(
            slow,
            base_url,
            token,
            run_id="t",
            max_body_bytes=CAP,
            request_timeout_s=DEADLINE_S,
            timeouts=False,
        )
        assert outcome == "skip"
