"""A third party verifies a chain file they did not write.

The verifier holds the chain file and nothing else: no gate config, no manifests, no home
directory state, no access to the host that wrote it. These tests pin what
`bawbel-gate audit verify` detects from that file alone, and the two changes it cannot
detect without a chain head recorded somewhere the log writer cannot rewrite
(DESIGN.md 8.6, docs/adr/0001-audit-chain-construction.md).

README "Verifying a log you did not write" and SECURITY.md "Limits of the audit chain"
state these results. If one of the "not detected" tests starts failing, the verifier got
stronger: update those two documents in the same change.
"""

import json
import os
import shutil
import subprocess  # nosec B404 # noqa: S404 -- runs the CLI of this package in a clean directory
import sys
from pathlib import Path

import pytest

from bawbel_gate.audit.writer import AuditWriter

EVENTS = [
    {"event": "SESSION_START", "session": "s1"},
    {"event": "CALL_DECIDED", "session": "s1", "tool": "get_issue", "effect": "allow"},
    {"event": "CALL_DECIDED", "session": "s1", "tool": "create_pull_request", "effect": "deny"},
    {"event": "CALL_DECIDED", "session": "s1", "tool": "get_file", "effect": "allow"},
    {"event": "SESSION_END", "session": "s1"},
]


def _write_chain(path: Path, events: list[dict]) -> str:
    """Write a chain with the real writer and return its head."""
    writer = AuditWriter(path)
    for event in events:
        writer.append(event)
    return writer.head


def _cli(args: list[str], cwd: Path, home: Path) -> subprocess.CompletedProcess:
    """Run bawbel-gate as a separate process in an empty directory with an empty home."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("BAWBEL")}
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home))
    return subprocess.run(  # nosec B603 # noqa: S603 -- fixed argv, no shell
        [sys.executable, "-c", "from bawbel_gate.cli import main; main()", *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=60,
    )


@pytest.fixture
def origin(tmp_path):
    """The host that wrote the chain. Returns (chain path, head hash)."""
    path = tmp_path / "origin" / "gate.audit.jsonl"
    head = _write_chain(path, EVENTS)
    return path, head


@pytest.fixture
def verifier(tmp_path):
    """A clean machine: an empty working directory and an empty home directory."""
    cwd = tmp_path / "verifier"
    home = tmp_path / "verifier-home"
    cwd.mkdir()
    home.mkdir()
    return cwd, home


def _verify(chain: Path, verifier) -> subprocess.CompletedProcess:
    cwd, home = verifier
    return _cli(["audit", "verify", str(chain)], cwd=cwd, home=home)


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _handed_over(origin_chain: Path, lines: list[str], verifier) -> Path:
    """Put a (possibly altered) copy of the chain on the verifier's machine."""
    copy = verifier[0] / origin_chain.name
    copy.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return copy


def _documented_head(chain: Path, verifier) -> str:
    """The README command: take the hash of the last record from `audit tail -n 1`."""
    cwd, home = verifier
    tail = _cli(["audit", "tail", str(chain), "-n", "1"], cwd=cwd, home=home)
    assert tail.returncode == 0, tail.stderr
    return json.loads(tail.stdout)["hash"]


def _records_with_hash(chain: Path, head: str) -> int:
    """The README comparison: how many records carry the anchored head as their hash."""
    found = subprocess.run(  # nosec B603 B607 # noqa: S603 S607 -- fixed argv, no shell
        ["grep", "-Fc", f'"hash":"{head}"', str(chain)],
        capture_output=True, text=True, timeout=60,
    )
    return int(found.stdout.strip())


class TestVerifyFromTheFileAlone:
    def test_intact_chain_verifies_on_a_clean_machine(self, origin, verifier):
        chain, _ = origin
        copy = Path(shutil.copy(chain, verifier[0]))
        before = copy.read_bytes()

        result = _verify(copy, verifier)

        assert result.returncode == 0, result.stderr
        assert "ok: 5 records, chain intact" in result.stdout
        assert copy.read_bytes() == before, "verify must not modify the file"
        assert sorted(p.name for p in verifier[0].iterdir()) == [copy.name]
        assert list(verifier[1].iterdir()) == [], "verify must not write to the home directory"

    def test_the_writer_host_is_not_needed(self, origin, verifier):
        chain, _ = origin
        copy = Path(shutil.copy(chain, verifier[0]))
        shutil.rmtree(chain.parent)

        assert _verify(copy, verifier).returncode == 0


class TestDetectedFromTheFileAlone:
    """Each change below leaves the file with a break that verify reports on its own."""

    def test_edited_field(self, origin, verifier):
        chain, _ = origin
        lines = _lines(chain)
        lines[2] = lines[2].replace('"effect":"deny"', '"effect":"allow"')
        assert lines[2] != _lines(chain)[2]

        result = _verify(_handed_over(chain, lines, verifier), verifier)

        assert result.returncode == 1
        assert "seq 3: hash mismatch" in result.stderr

    def test_deleted_record(self, origin, verifier):
        chain, _ = origin
        lines = _lines(chain)
        del lines[2]

        result = _verify(_handed_over(chain, lines, verifier), verifier)

        assert result.returncode == 1
        assert "seq 4: prev mismatch" in result.stderr

    def test_reordered_records(self, origin, verifier):
        chain, _ = origin
        lines = _lines(chain)
        lines[1], lines[2] = lines[2], lines[1]

        result = _verify(_handed_over(chain, lines, verifier), verifier)

        assert result.returncode == 1
        assert "prev mismatch" in result.stderr

    def test_inserted_record(self, origin, verifier):
        chain, _ = origin
        lines = _lines(chain)
        lines.insert(2, lines[1])

        result = _verify(_handed_over(chain, lines, verifier), verifier)

        assert result.returncode == 1
        assert "prev mismatch" in result.stderr

    def test_record_cut_off_mid_line(self, origin, verifier):
        chain, _ = origin
        lines = _lines(chain)
        lines[-1] = lines[-1][: len(lines[-1]) // 2]

        result = _verify(_handed_over(chain, lines, verifier), verifier)

        assert result.returncode == 1
        assert "line 5" in result.stderr


class TestNotDetectedWithoutAnAnchoredHead:
    """The two changes verify passes. Only a head recorded elsewhere exposes them."""

    def test_final_records_removed(self, origin, verifier):
        chain, head = origin
        truncated = _handed_over(chain, _lines(chain)[:3], verifier)

        result = _verify(truncated, verifier)

        assert result.returncode == 0, "if this fails, verify got stronger: update the docs"
        assert "ok: 3 records, chain intact" in result.stdout
        assert _documented_head(truncated, verifier) != head

    def test_log_rewritten_with_every_hash_recomputed(self, origin, verifier):
        chain, head = origin
        forged_events = [dict(e) for e in EVENTS]
        forged_events[2]["effect"] = "allow"
        forged = verifier[0] / "forged" / chain.name
        forged_head = _write_chain(forged, forged_events)

        result = _verify(forged, verifier)

        assert result.returncode == 0, "if this fails, verify got stronger: update the docs"
        assert forged_head != head


@pytest.mark.skipif(shutil.which("grep") is None, reason="the documented comparison uses grep")
class TestAnchoredHead:
    def test_the_documented_command_yields_the_writer_head(self, origin, verifier):
        chain, head = origin
        copy = Path(shutil.copy(chain, verifier[0]))

        assert _documented_head(copy, verifier) == head

    def test_anchored_head_is_still_in_a_log_that_has_grown(self, origin, verifier):
        chain, anchored = origin
        writer = AuditWriter.from_existing(chain)
        writer.append({"event": "CALL_DECIDED", "session": "s2", "tool": "get_issue"})
        copy = Path(shutil.copy(chain, verifier[0]))

        assert _verify(copy, verifier).returncode == 0
        assert _documented_head(copy, verifier) != anchored
        assert _records_with_hash(copy, anchored) == 1

    def test_anchor_comparison_exposes_both_undetected_changes(self, origin, verifier):
        chain, anchored = origin

        truncated = _handed_over(chain, _lines(chain)[:3], verifier)
        assert _documented_head(truncated, verifier) != anchored
        assert _records_with_hash(truncated, anchored) == 0

        forged_events = [dict(e) for e in EVENTS]
        forged_events[2]["effect"] = "allow"
        forged = verifier[0] / "forged" / chain.name
        _write_chain(forged, forged_events)
        assert _documented_head(forged, verifier) != anchored
        assert _records_with_hash(forged, anchored) == 0
