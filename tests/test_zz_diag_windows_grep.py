"""Throwaway diagnostic for #114. Fails on purpose so the log shows what grep sees."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

from bawbel_gate.audit.writer import AuditWriter
from tests.test_audit_third_party_verify import EVENTS, _write_chain


def _run(args, **kw):
    p = subprocess.run(args, capture_output=True, timeout=60, **kw)
    return f"rc={p.returncode} out={p.stdout!r} err={p.stderr[:200]!r}"


def test_diag(tmp_path):
    info = [f"platform={sys.platform} os.name={os.name} python={sys.version.split()[0]}"]
    chain = tmp_path / "origin" / "gate.audit.jsonl"
    anchored = _write_chain(chain, EVENTS)
    before = chain.read_bytes()
    writer = AuditWriter.from_existing(chain)
    writer.append({"event": "CALL_DECIDED", "session": "s2", "tool": "get_issue"})
    dest = tmp_path / "verifier"
    dest.mkdir()
    copy = Path(shutil.copy(chain, dest))
    needle = f'"hash":"{anchored}"'
    raw = copy.read_bytes()
    info.append(f"which grep={shutil.which('grep')}")
    info.append("grep --version: " + _run(["grep", "--version"]).split("\\n")[0][:160])
    info.append(f"needle={needle!r}")
    info.append(f"list2cmdline={subprocess.list2cmdline(['grep', '-Fc', needle, str(copy)])!r}")
    info.append(f"file before append: {len(before)} bytes, lf={before.count(b'\n')} crlf={before.count(b'\r\n')}")
    info.append(f"file after append (copy): {len(raw)} bytes, lf={raw.count(b'\n')} crlf={raw.count(b'\r\n')}")
    info.append(f"needle in bytes before append: {needle.encode() in before}; after: {needle.encode() in raw}")
    info.append(f"python line count with needle: {sum(1 for l in raw.split(b'\n') if needle.encode() in l)}")
    info.append(f"first record bytes: {raw.split(b'\n')[0][:260]!r}")
    info.append("A current argv:        " + _run(["grep", "-Fc", needle, str(copy)]))
    info.append("B with -e:             " + _run(["grep", "-Fc", "-e", needle, str(copy)]))
    info.append("C posix path:          " + _run(["grep", "-Fc", needle, copy.as_posix()]))
    info.append("D stdin:               " + _run(["grep", "-Fc", needle], input=raw))
    info.append("E pattern 'hash':      " + _run(["grep", "-Fc", "hash", str(copy)]))
    info.append("F pattern sha256 only: " + _run(["grep", "-Fc", anchored, str(copy)]))
    info.append("G cwd=dir, bare name:  " + _run(["grep", "-Fc", needle, copy.name], cwd=str(dest)))
    assert False, "DIAG\n" + "\n".join(info)
