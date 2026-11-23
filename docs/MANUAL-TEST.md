# bawbel-gate manual test guide

Run every feature of bawbel-gate that exists today, one numbered step at a time, and see pass or
fail yourself. Each step has a negative twin that must fail the way it should, so the guide tests
what the gate refuses as well as what it allows.

Captured on `develop` at `8617299` (2026-11-22), `bawbel-gate` 0.1.1, Python 3.12.3, pip 24.0,
FastMCP 4.2.4, Linux 6.8. The macOS commands are the same, but this guide was not run on macOS, so
that is unverified. Windows is out of scope.

## The rule that makes this guide trustworthy

Every **Expect** block and every **Captured** block below was captured by running the step, in a
fresh environment, by `scripts/manual_test.sh --markdown`. Nothing was written from DESIGN.md or from
memory. Where the code and the documentation disagree, the guide shows what the code did and the
step fails. A failing step is a finding, not a typo. At the capture commit one step fails: S-01.

An output line that varies from run to run (a session id, a timestamp, a hash) is shown as it was
captured. The **Pass if** line says what must hold.

## How to run it

```bash
bash scripts/manual_test.sh --list              # the steps
bash scripts/manual_test.sh --step P-02         # one step, with its commands, raw output and verdict
bash scripts/manual_test.sh --all               # fresh environment, every step, then a checklist table
bash scripts/manual_test.sh --all --verbose     # the same, with the raw output of every step
bash scripts/manual_test.sh --markdown          # the step sections of this guide, from a fresh run
bash scripts/manual_test.sh --reset             # delete the environment the script created
```

A step passes only when its positive commands behave as documented and its negative twin fails as
documented. The runner prints the raw output next to the verdict, and prints the output of every
failing step straight away. It does not hide a failure. The commands under **Run** are exactly the
commands the runner executes, so you can paste them into a shell yourself. They expect the
environment variables `REPO` (this checkout), `BASE` (the working area) and `VENV` (the virtualenv)
that the runner sets.

## Environment rules

- A fresh virtualenv for every run, an empty `HOME`, `env -i` with only `PATH` and a few variables,
  and a temporary working directory. `MANUAL_TEST_DIR` chooses where; the default is
  `${TMPDIR:-/tmp}/bawbel-manual-test`.
- No network except `pip install`: the wheel's dependencies in A-01, and FastMCP in P-05. FastMCP
  checks PyPI for a newer version when it starts, so P-05 turns that off with
  `FASTMCP_CHECK_FOR_UPDATES=off`. With that set, `strace -f -e trace=connect` over every step after
  the installs found no connection to a non-loopback address.
- No real API key is used. The runner starts every command with `env -i`, so none is inherited.
- The gate is installed from the **built wheel**, not an editable install (A-01 checks).
- Step `A-02` creates every file the other steps use. `--reset` removes them all.

## Feature table

Built from the code: the full `bawbel-gate --help` tree (every command and subcommand), the section
headings of DESIGN.md, and the names under `tests/`.

| Feature | Command or place | Steps | Status |
|---|---|---|---|
| Install from the built wheel, version | `bawbel-gate --version` | A-01 | covered |
| The command tree | `bawbel-gate --help` and every subcommand | A-03 | covered |
| Manifest schema check | `lint DIR` | L-01 | covered |
| Deployment check: forbid an effect on a class of tool | `lint --forbid-effect --tools-with` | L-02 | covered |
| Warning for a declared field the gate does not enforce | `lint`, `W-UNENFORCED` | L-03 | covered |
| stdio proxy: merged, prefixed tool list, default deny | `serve -c gate.yaml` | P-01, P-02 | covered |
| Approval: wait, refuse, time out | `serve` with an `approve` grant | P-03 | covered |
| Methods other than initialize, tools/list, tools/call are refused | `serve` | P-04 | covered |
| Upstream handshake with a FastMCP server | `serve` | P-05 | covered |
| Session taint and the trifecta rule | `serve` | T-01 | covered |
| Argument guards: secret scan, size cap | manifest `argument_guards` | G-01 | covered |
| Audit log: tail, verify, tamper cases, anchoring a head | `audit tail`, `audit verify` | U-01, U-02, U-03 | covered |
| Follow a log as it grows | `audit tail --follow` | none | not covered: needs a second process |
| Clear a session's taint, recorded in the log | `clear` | C-01 | covered |
| Posture report | `posture` | PO-01 | covered |
| Learning mode: record, report, synthesise | `serve --learn`, `learn report`, `learn synthesize` | LN-01 | covered |
| Learning mode for a set duration (DESIGN.md 11.5 shows `learn --duration 7d`) | none | LN-01, negative | designed, not built |
| stdout is JSON-RPC only | `serve` | S-01 | covered, and the step fails on this commit |
| Merge an AVE mitigation stanza into a manifest | `harden` | none | private until disclosure |
| The `verify` command | `verify` | none | private until disclosure |
| Integrity pinning and drift reports (DESIGN.md 8.1 to 8.3) | none | none | private until disclosure |
| The local operator API, an option of `serve` (DESIGN.md 13.1) | none | none | not covered in this version of the guide |
| bawbel-hub: enroll, hub serve, hub token | `enroll`, `hub serve`, `hub token` | none | QA-2, after the Hub work lands |
| Decision API | `decide` | A-03, negative | specification in a draft, not built |
| Delegation and revocation | none | none | not built, not yet specified |
| Behavioural drift | none | none | specification in a draft, not built |
| Shared component identifier | none | none | specification in a draft, not built |
| Remote resource watch and binary integrity (DESIGN.md 2.2, 8.2) | `lint` warns | L-03 | not enforced; the warning is covered |
| Taint scoping (DESIGN.md 7.3) | none | none | designed, not built (v1.1) |
| CEF and syslog export (DESIGN.md 8.5) | none | none | designed, not built (v1.1) |
| OpenTelemetry export (DESIGN.md 8.5) | none | none | not covered: needs an OTLP collector |
| Flagship demo `examples/rug-pull-exfil/` | none | none | held |
| The automated suite: `tests/property`, `tests/replay`, `tests/corpus`, `tests/integration`, `tests/test_m1` to `tests/test_m7`, and the rest | `pytest` | none | run `pytest`, see docs/TESTING.md |

"Private until disclosure" means the step is not in this public guide and has no detail here.

## The steps

<!-- generated by scripts/manual_test.sh --markdown; every Expect block below was captured by running the step -->

### STEP A-01  Install the built wheel and report the version

**Proves** the wheel (not an editable install) installs into a clean virtualenv and the entry point runs

**Needs** Python 3.10 or later, pip, network access for pip only

**Run**

```bash
python3 -m venv "$VENV" >/dev/null 2>&1 || { rm -rf "$VENV"; virtualenv -q "$VENV"; }
"$VENV/bin/python" -m pip wheel --no-deps -q -w "$BASE/dist" "$REPO"
"$VENV/bin/python" -m pip install -q "$BASE"/dist/bawbel_gate-*.whl
ls "$BASE/dist"
bawbel-gate --version
echo "editable lines: $("$VENV/bin/python" -m pip show bawbel-gate | grep -c 'Editable project location' || true)"
```

**Expect** (captured, exit 0)

```text
bawbel_gate-0.1.1-py3-none-any.whl
bawbel-gate, version 0.1.1
editable lines: 0
```

**Pass if** exit 0, a line 'bawbel-gate, version <x.y.z>', a wheel in dist, and 0 editable lines

**Negative** exit 2 and 'No such option': a flag that does not exist is refused

```bash
bawbel-gate --no-such-flag
echo "exit $?"
```

Captured:

```text
Error: No such option '--no-such-flag'.
exit 2
```

**Cleanup** python3 scripts/manual_test.sh --reset

### STEP A-02  Create the stand-in server, manifests and configs

**Proves** the fixtures the other steps use exist; nothing else is needed from the network or the host

**Needs** A-01

**Run**

```bash
mkdir -p manifests manifests-approve manifests-guard manifests-fm

cat > fake_server.py <<'EOF'
"""A stand-in stdio MCP server. It lists three tools and answers every call with 'ok: <tool>'."""
import json
import sys

NAME = sys.argv[1] if len(sys.argv) > 1 else "github"
TOOLS = ["get_issue", "create_pull_request", "delete_repo"]
for line in sys.stdin:
    msg = json.loads(line)
    rid, method = msg.get("id"), msg.get("method")
    if rid is None:
        continue
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": NAME, "version": "0"},
                  "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": [{"name": t, "description": t,
                             "inputSchema": {"type": "object", "properties": {}}} for t in TOOLS]}
    else:
        result = {"content": [{"type": "text", "text": "ok: " + msg.get("params", {}).get("name", "")}]}
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}), flush=True)
EOF

cat > msgs.py <<'EOF'
"""Print the JSON-RPC messages of a session: initialize, tools/list, then one request per argument.
   call:<tool>[:<json args>]  is a tools/call.  Any other word is sent as a method name."""
import json
import sys

out = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "manual-test", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
]
n = 3
for arg in sys.argv[1:]:
    kind, _, rest = arg.partition(":")
    if kind == "call":
        name, _, args = rest.partition(":")
        out.append({"jsonrpc": "2.0", "id": n, "method": "tools/call",
                    "params": {"name": name, "arguments": json.loads(args) if args else {}}})
    else:
        out.append({"jsonrpc": "2.0", "id": n, "method": kind, "params": {}})
    n += 1
for message in out:
    print(json.dumps(message))
EOF

cat > summ.py <<'EOF'
"""Summarise what the gate wrote to stdout. With -q a line that is not JSON is counted, not shown."""
import json
import sys

quiet = "-q" in sys.argv
bad = 0
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    try:
        m = json.loads(line)
    except ValueError:
        bad += 1
        if not quiet:
            print("NOT-JSON:", line[:100])
        continue
    if "error" in m:
        e = m["error"]
        print(m["id"], "ERROR", e["code"], e.get("data", {}).get("reason", e["message"]))
    elif "tools" in m["result"]:
        print(m["id"], "tools:", sorted(t["name"] for t in m["result"]["tools"]))
    elif "serverInfo" in m["result"]:
        print(m["id"], "initialize", m["result"]["serverInfo"]["name"])
    else:
        print(m["id"], "result", "".join(c.get("text", "") for c in m["result"].get("content", [])))
print("stdout lines that are not JSON:", bad)
EOF

cat > auditsum.py <<'EOF'
"""One line per audit record: seq, event, tool, effect, reason."""
import json
import sys

for line in open(sys.argv[1]):
    if line.strip():
        r = json.loads(line)
        print(r["seq"], r["event"], r.get("tool", "-"), r.get("effect", "-"), r.get("reason", "-"))
EOF

cat > attack.py <<'EOF'
"""Build a damaged copy of an audit log.  usage: attack.py MODE SRC DST
   edit     change the effect of record 3                      (verify must reject)
   trunc    cut the last line in half                           (verify must reject)
   first    remove the first record                             (verify must reject)
   last2    remove the last two records                         (documented: not detected)
   rewrite  change record 3 and recompute every later hash      (documented: not detected)
   empty    an empty file                                       (documented: not detected)"""
import hashlib
import json
import sys

from bawbel_gate.audit.canonical import canonical_bytes

mode, src, dst = sys.argv[1:4]
lines = open(src).read().splitlines()
recs = [json.loads(x) for x in lines]


def dump(rs):
    return "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rs) + "\n"


if mode == "edit":
    recs[2]["effect"] = "allow" if recs[2].get("effect") != "allow" else "deny"
    text = dump(recs)
elif mode == "trunc":
    lines[-1] = lines[-1][: len(lines[-1]) // 2]
    text = "\n".join(lines) + "\n"
elif mode == "first":
    text = dump(recs[1:])
elif mode == "last2":
    text = dump(recs[:-2])
elif mode == "rewrite":
    recs[2]["effect"] = "allow" if recs[2].get("effect") != "allow" else "deny"
    for i in range(2, len(recs)):
        recs[i]["prev"] = recs[i - 1]["hash"]
        body = {k: v for k, v in recs[i].items() if k != "hash"}
        recs[i]["hash"] = "sha256:" + hashlib.sha256(
            canonical_bytes(body) + recs[i]["prev"].encode()).hexdigest()
    text = dump(recs)
elif mode == "empty":
    text = ""
else:
    sys.exit("unknown mode " + mode)
open(dst, "w").write(text)
EOF

cat > nonjson.py <<'EOF'
"""Count the lines of a file that are not JSON.  usage: nonjson.py FILE LABEL"""
import json
import sys

bad = []
for line in open(sys.argv[1]):
    if line.strip():
        try:
            json.loads(line)
        except ValueError:
            bad.append(line.rstrip()[:90])
print(sys.argv[2] + ": non-JSON lines: " + str(len(bad)))
for line in bad[:3]:
    print("   ", line)
EOF

cat > fm_server.py <<'EOF'
"""A FastMCP stdio server with one tool."""
from fastmcp import FastMCP

mcp = FastMCP("fm-demo")


@mcp.tool
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


if __name__ == "__main__":
    mcp.run()
EOF

cat > manifests/github.yaml <<'EOF'
schema: bawbel/capability-manifest/v1
subject: {kind: mcp-server, name: github, transport: stdio}
provenance_class: tool.response.github
instruction_authority: none
trifecta: {private_data: true, untrusted_content: true, external_comms: true}
grants:
  tools:
    - {name: get_issue, effect: allow}
    - {name: create_pull_request, effect: allow}
    - {name: "*", effect: deny}
EOF

cat > manifests/docs.yaml <<'EOF'
schema: bawbel/capability-manifest/v1
subject: {kind: mcp-server, name: docs, transport: stdio}
provenance_class: tool.response.docs
instruction_authority: none
trifecta: {private_data: false, untrusted_content: false, external_comms: false}
grants:
  tools:
    - {name: get_issue, effect: allow}
    - {name: "*", effect: deny}
EOF

cat > manifests-approve/github.yaml <<'EOF'
schema: bawbel/capability-manifest/v1
subject: {kind: mcp-server, name: github, transport: stdio}
provenance_class: tool.response.github
instruction_authority: none
trifecta: {private_data: false, untrusted_content: false, external_comms: false}
grants:
  tools:
    - {name: create_pull_request, effect: approve}
    - {name: "*", effect: deny}
EOF

cat > manifests-guard/github.yaml <<'EOF'
schema: bawbel/capability-manifest/v1
subject: {kind: mcp-server, name: github, transport: stdio}
provenance_class: tool.response.github
instruction_authority: none
trifecta: {private_data: false, untrusted_content: false, external_comms: false}
grants:
  tools:
    - {name: create_pull_request, effect: allow}
    - {name: "*", effect: deny}
  argument_guards:
    - applies_to: "*"
      outbound_secret_scan: true
      max_outbound_bytes: 256
EOF

cat > manifests-fm/fm.yaml <<'EOF'
schema: bawbel/capability-manifest/v1
subject: {kind: mcp-server, name: fm, transport: stdio}
provenance_class: tool.response.fm
instruction_authority: none
trifecta: {private_data: false, untrusted_content: false, external_comms: false}
grants:
  tools:
    - {name: add, effect: allow}
    - {name: "*", effect: deny}
EOF

cat > gate.yaml <<'EOF'
schema: bawbel/gate-config/v1
audit_log: audit.jsonl
approval: {channel: terminal, timeout_seconds: 5}
servers:
  - name: github
    command: python3
    args: ["fake_server.py", "github"]
    manifest: manifests/github.yaml
  - name: docs
    command: python3
    args: ["fake_server.py", "docs"]
    manifest: manifests/docs.yaml
EOF

sed -e 's#manifests/github.yaml#manifests-approve/github.yaml#' -e 's#audit.jsonl#audit-approve.jsonl#' \
    -e '/name: docs/,$d' gate.yaml > gate-approve.yaml
sed -e 's#manifests/github.yaml#manifests-guard/github.yaml#' -e 's#audit.jsonl#audit-guard.jsonl#' \
    -e '/name: docs/,$d' gate.yaml > gate-guard.yaml
sed -e 's#name: github#name: fm#' -e 's#"fake_server.py", "github"#"fm_server.py"#' \
    -e 's#manifests/github.yaml#manifests-fm/fm.yaml#' -e 's#audit.jsonl#audit-fm.jsonl#' \
    -e '/name: docs/,$d' gate.yaml > gate-fm.yaml
sed -e 's#"fm_server.py"#"-c", "pass"#' -e 's#audit-fm.jsonl#audit-dead.jsonl#' gate-fm.yaml > gate-dead.yaml

echo "created $(ls | wc -l | tr -d ' ') files"
```

**Expect** (captured, exit 0)

```text
created 16 files
```

**Pass if** exit 0 and a line 'created <n> files'

**Negative** exit 2 and 'does not exist': the gate refuses a config path that is not there

```bash
bawbel-gate serve -c does-not-exist.yaml
echo "exit $?"
```

Captured:

```text
Error: Invalid value for '--config' / '-c': Path 'does-not-exist.yaml' does not exist.
exit 2
```

**Cleanup** none

### STEP A-03  Every command and subcommand answers --help

**Proves** the command tree is what this guide covers: ten commands, and the subcommands of audit, learn and hub

**Needs** A-01

**Run**

```bash
bawbel-gate --help | sed -n '/^Commands:/,$p' | awk 'NR == 1 {print; next} {print "  " $1}'
for c in audit clear enroll harden hub learn lint posture serve verify; do
  bawbel-gate $c --help >/dev/null && echo "ok   $c --help" || echo "FAIL $c --help"
done
for c in "audit tail" "audit verify" "learn report" "learn synthesize" "hub serve" "hub token"; do
  bawbel-gate $c --help >/dev/null && echo "ok   $c --help" || echo "FAIL $c --help"
done
```

**Expect** (captured, exit 0)

```text
Commands:
  audit
  clear
  enroll
  harden
  hub
  learn
  lint
  posture
  serve
  verify
ok   hub token --help
```

**Pass if** exit 0 and no line starting FAIL

**Negative** exit 2 and 'No such command': a command that is designed and not built is not there

```bash
bawbel-gate decide --help
echo "exit $?"
```

Captured:

```text
Error: No such command 'decide'.
exit 2
```

**Cleanup** none

### STEP L-01  lint accepts a valid manifest and rejects each bad one

**Proves** a manifest is checked against the capability-manifest schema before it is used; serve does not start on a manifest that fails it

**Needs** A-02

**Run**

```bash
rm -rf lint-case && mkdir -p lint-case/ok lint-case/unknown lint-case/nosubject lint-case/badeffect
cp manifests/github.yaml lint-case/ok/m.yaml
cp manifests/github.yaml lint-case/unknown/m.yaml && echo "colour: blue" >> lint-case/unknown/m.yaml
grep -v '^subject' manifests/github.yaml > lint-case/nosubject/m.yaml
sed 's/effect: allow/effect: maybe/' manifests/github.yaml > lint-case/badeffect/m.yaml
bawbel-gate lint lint-case/ok
```

**Expect** (captured, exit 0)

```text
ok   m.yaml
```

**Pass if** exit 0 and a line 'ok   m.yaml' for the valid manifest

**Negative** three rejections with a clear message (unknown field, missing subject, bad effect), each with exit 1; serve exits 1 and names the schema failure

```bash
for d in unknown nosubject badeffect; do
  echo "--- $d"
  bawbel-gate lint lint-case/$d
  echo "exit $?"
done
echo "--- serve with the unknown-field manifest"
sed 's#manifests/github.yaml#lint-case/unknown/m.yaml#' gate.yaml > gate-bad.yaml
python3 msgs.py call:github__get_issue | bawbel-gate serve -c gate-bad.yaml > bad-out.txt 2> bad-err.txt
echo "exit $?"
tail -n 1 bad-err.txt
```

Captured:

```text
--- unknown
FAIL m.yaml: 1 schema error(s)
  $: Additional properties are not allowed ('colour' was unexpected)
exit 1
--- nosubject
FAIL m.yaml: 1 schema error(s)
  $: 'subject' is a required property
exit 1
--- badeffect
FAIL m.yaml: 2 schema error(s)
  $.grants.tools[0].effect: 'maybe' is not one of ['allow', 'approve', 'deny']
  $.grants.tools[1].effect: 'maybe' is not one of ['allow', 'approve', 'deny']
exit 1
--- serve with the unknown-field manifest
exit 1
bawbel_gate.policy.manifest.ManifestError: lint-case/unknown/m.yaml: schema validation failed: $: Additional properties are not allowed ('colour' was unexpected)
```

**Cleanup** none

### STEP L-02  lint --forbid-effect fails a grant of the forbidden effect on the named tools

**Proves** a deployment check can fail CI when an allow grant reaches a tool of an external-comms server

**Needs** A-02

**Run**

```bash
bawbel-gate lint manifests-guard --forbid-effect allow --tools-with external_comms
```

**Expect** (captured, exit 0)

```text
ok   github.yaml
```

**Pass if** exit 0 for a manifest with no external-comms server

**Negative** exit 1 and 'forbidden effect' for a manifest that allows a tool on an external-comms server

```bash
bawbel-gate lint manifests --forbid-effect allow --tools-with external_comms
echo "exit $?"
```

Captured:

```text
FAIL github.yaml: grant 'get_issue' has forbidden effect 'allow'
exit 1
```

**Cleanup** none

### STEP L-03  lint warns W-UNENFORCED for a field the gate does not enforce, and keeps the exit code

**Proves** a declaration that has no effect is called out, one warning per declaration, and does not fail the run

**Needs** A-02

**Run**

```bash
rm -rf lint-warn && mkdir lint-warn
sed 's#transport: stdio}#transport: stdio, binary_integrity: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}#' manifests/github.yaml > lint-warn/m.yaml
bawbel-gate lint lint-warn
echo "exit $?"
```

**Expect** (captured, exit 0)

```text
warn m.yaml: W-UNENFORCED subject.binary_integrity is declared and not enforced (DESIGN.md 2.2, issue #42)
ok   m.yaml
exit 0
```

**Pass if** exit 0, a line 'W-UNENFORCED subject.binary_integrity' and a line 'ok'

**Negative** a manifest without the declaration prints no W-UNENFORCED line

```bash
bawbel-gate lint manifests
echo "exit $?"
```

Captured:

```text
ok   docs.yaml
ok   github.yaml
exit 0
```

**Cleanup** none

### STEP P-01  tools/list is merged across servers, prefixed, and hides denied tools

**Proves** the host sees one list, each tool named {server}__{tool}, and a tool no grant allows is not offered

**Needs** A-02

**Run**

```bash
rm -f audit.jsonl
python3 msgs.py | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
```

**Expect** (captured, exit 0)

```text
1 initialize bawbel-gate
2 tools: ['docs__get_issue', 'github__create_pull_request', 'github__get_issue']
```

**Pass if** a tools line holding docs__get_issue, github__create_pull_request and github__get_issue, and no delete_repo

**Negative** calling the hidden tool github__delete_repo is refused with -32031

```bash
rm -f audit.jsonl
python3 msgs.py call:github__delete_repo | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
```

Captured:

```text
3 ERROR -32031 resolved
```

**Cleanup** none

### STEP P-02  an allow grant passes, an unprefixed name is denied

**Proves** a call to {server}__{tool} that a grant allows reaches the server; a name with no grant is denied by default

**Needs** A-02

**Run**

```bash
rm -f audit.jsonl
python3 msgs.py call:github__get_issue:'{"n":1}' | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
```

**Expect** (captured, exit 0)

```text
3 result ok: get_issue
```

**Pass if** a result line 'ok: get_issue'

**Negative** the unprefixed name get_issue is refused with -32031 and the reason no_grant

```bash
rm -f audit.jsonl
python3 msgs.py call:get_issue:'{"n":1}' | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
```

Captured:

```text
3 ERROR -32031 no_grant
```

**Cleanup** none

### STEP P-03  an approve grant waits for the operator; a refusal or silence denies

**Proves** a call whose grant says approve is held until the operator answers on stdin; no answer within the timeout is a deny

**Needs** A-02

**Run**

```bash
rm -f audit-approve.jsonl
(python3 msgs.py call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate-approve.yaml 2>approve-err.txt | python3 summ.py -q
grep -E 'APPROVAL REQUIRED|Reason:' approve-err.txt
```

**Expect** (captured, exit 0)

```text
3 result ok: create_pull_request
bawbel-gate: APPROVAL REQUIRED
  Reason:  resolved
```

**Pass if** the prompt 'APPROVAL REQUIRED' on stderr and a result line 'ok: create_pull_request' after the answer y

**Negative** the answer n gives -32031 approval_denied; silence for longer than 5 s gives -32031 approval_timeout

```bash
rm -f audit-approve.jsonl
echo "--- answer n"
(python3 msgs.py call:github__create_pull_request:'{"title":"t"}'; echo n) | bawbel-gate serve -c gate-approve.yaml 2>/dev/null | python3 summ.py -q
echo "--- no answer for 8 s (the timeout is 5 s)"
(python3 msgs.py call:github__create_pull_request:'{"title":"t"}'; sleep 8) | bawbel-gate serve -c gate-approve.yaml 2>/dev/null | python3 summ.py -q
```

Captured:

```text
--- answer n
3 ERROR -32031 approval_denied
--- no answer for 8 s (the timeout is 5 s)
3 ERROR -32031 approval_timeout
```

**Cleanup** none

### STEP P-04  resources and prompts methods return -32601

**Proves** the gate serves initialize, tools/list and tools/call only; every other method is refused, not forwarded

**Needs** A-02

**Run**

```bash
python3 msgs.py resources/list prompts/list | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
```

**Expect** (captured, exit 0)

```text
3 ERROR -32601 Method not found: resources/list
4 ERROR -32601 Method not found: prompts/list
```

**Pass if** resources/list and prompts/list each return error -32601

**Negative** tools/list, a method the gate does serve, returns a result and no -32601

```bash
python3 msgs.py | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
```

Captured:

```text
2 tools: ['docs__get_issue', 'github__create_pull_request', 'github__get_issue']
```

**Cleanup** none

### STEP P-05  the upstream handshake works against a FastMCP server

**Proves** the gate initializes a real FastMCP stdio server, lists its tool with the prefix, and forwards an allowed call

**Needs** A-02, and pip with network access to install fastmcp. FastMCP checks PyPI for a newer version when it starts, so the step turns that off with FASTMCP_CHECK_FOR_UPDATES=off

**Run**

```bash
python3 -m pip install -q fastmcp
echo "fastmcp $(python3 -m pip show fastmcp | sed -n 's/^Version: //p')"
export FASTMCP_CHECK_FOR_UPDATES=off   # FastMCP otherwise contacts PyPI when it starts
rm -f audit-fm.jsonl
python3 msgs.py call:fm__add:'{"a":2,"b":3}' | bawbel-gate serve -c gate-fm.yaml 2>/dev/null | python3 summ.py -q
```

**Expect** (captured, exit 0)

```text
fastmcp 4.2.4
1 initialize bawbel-gate
2 tools: ['fm__add']
3 result 5
```

**Pass if** a tools line holding fm__add and a result line with the text 5

**Negative** a server that exits at once instead of answering initialize makes serve exit 1 with no tools offered

```bash
rm -f audit-dead.jsonl
python3 msgs.py | bawbel-gate serve -c gate-dead.yaml > dead-out.txt 2> dead-err.txt
echo "exit $?"
python3 summ.py -q < dead-out.txt
```

Captured:

```text
exit 1
stdout lines that are not JSON: 1
```

**Cleanup** none

### STEP T-01  a read of untrusted content then an external call trips the trifecta rule

**Proves** after a call that reads private and untrusted content, a call that can send it out is held for approval, and the reason is recorded

**Needs** A-02

**Run**

```bash
rm -f audit.jsonl
(python3 msgs.py call:github__get_issue:'{"n":1}' call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate.yaml 2>serve-err.txt | python3 summ.py -q
grep 'Reason:' serve-err.txt
python3 auditsum.py audit.jsonl
```

**Expect** (captured, exit 0)

```text
3 result ok: get_issue
4 result ok: create_pull_request
  Reason:  trifecta_third_leg
2 CALL_DECIDED get_issue allow resolved
3 CALL_DECIDED create_pull_request approve trifecta_third_leg
```

**Pass if** the prompt shows 'Reason:  trifecta_third_leg' and the audit log has an approve record with reason trifecta_third_leg

**Negative** the same external call with no earlier read resolves to allow, reason resolved

```bash
rm -f audit.jsonl
python3 msgs.py call:github__create_pull_request:'{"title":"t"}' | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
python3 auditsum.py audit.jsonl
```

Captured:

```text
3 result ok: create_pull_request
2 CALL_DECIDED create_pull_request allow resolved
```

**Cleanup** none

### STEP G-01  argument guards stop a secret and an oversize payload

**Proves** a manifest guard scans outbound arguments for secrets and caps their size, before the call leaves the gate

**Needs** A-02

**Run**

```bash
rm -f audit-guard.jsonl
python3 msgs.py call:github__create_pull_request:'{"title":"fix a typo"}' | bawbel-gate serve -c gate-guard.yaml 2>/dev/null | python3 summ.py -q
```

**Expect** (captured, exit 0)

```text
3 result ok: create_pull_request
```

**Pass if** a call with clean arguments returns a result

**Negative** a call carrying the AWS documentation example key is refused with guard:secret_scan, and a 400 byte value with guard:byte_cap

```bash
rm -f audit-guard.jsonl
BIG=$(python3 -c 'print("x" * 400)')
python3 msgs.py call:github__create_pull_request:'{"title":"AKIAIOSFODNN7EXAMPLE"}' call:github__create_pull_request:"{\"title\":\"$BIG\"}" | bawbel-gate serve -c gate-guard.yaml 2>/dev/null | python3 summ.py -q
python3 auditsum.py audit-guard.jsonl
```

Captured:

```text
3 ERROR -32031 guard:secret_scan
4 ERROR -32031 guard:byte_cap
2 CALL_DECIDED create_pull_request deny guard:secret_scan
3 CALL_DECIDED create_pull_request deny guard:byte_cap
```

**Cleanup** none

### STEP U-01  audit verify passes an intact log and rejects an edit, a cut line and a missing first record

**Proves** the hash chain catches a changed effect, a record cut off mid-line, and a removed first record, from the file alone

**Needs** A-02

**Run**

```bash
rm -f audit.jsonl
(python3 msgs.py call:github__get_issue:'{"n":1}' call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate.yaml >/dev/null 2>&1
bawbel-gate audit verify audit.jsonl
python3 auditsum.py audit.jsonl
```

**Expect** (captured, exit 0)

```text
ok: 4 records, chain intact
chain verified: audit.jsonl
1 SESSION_START - - -
2 CALL_DECIDED get_issue allow resolved
3 CALL_DECIDED create_pull_request approve trifecta_third_leg
4 SESSION_END - - -
```

**Pass if** exit 0 and 'ok: 4 records, chain intact'

**Negative** three FAIL lines with exit 1 (hash mismatch, a JSON error, prev mismatch), and a missing path is a usage error with exit 2

```bash
for m in edit trunc first; do
  python3 attack.py $m audit.jsonl audit-$m.jsonl
  echo "--- $m"
  bawbel-gate audit verify audit-$m.jsonl
  echo "exit $?"
done
echo "--- a path that does not exist"
bawbel-gate audit verify no-such-file.jsonl 2>&1 | tail -n 1
bawbel-gate audit verify no-such-file.jsonl >/dev/null 2>&1; echo "exit $?"
```

Captured:

```text
--- edit
FAIL: seq 3: hash mismatch
exit 1
--- trunc
FAIL: line 4: Unterminated string starting at: line 1 column 120 (char 119)
exit 1
--- first
FAIL: seq 2: prev mismatch (expected 'sha256:0000000000000000000000000000000000000000000000000000000000000000', got 'sha256:406c863796d85e468601dff0c2de3d532245612b265e3b91b59245de9f29a084')
exit 1
--- a path that does not exist
Error: Invalid value for 'FILE': Path 'no-such-file.jsonl' does not exist.
exit 2
```

**Cleanup** none

### STEP U-02  audit verify does not detect three changes (expected: not detected, see SECURITY.md Limits)

**Proves** the chain has no key, so a log cut at the end, a log rewritten from one record onward, and an emptied log all still verify; an anchored head is what catches them

**Needs** U-01

**Run**

```bash
for m in last2 rewrite empty; do
  python3 attack.py $m audit.jsonl audit-$m.jsonl
  echo "--- $m"
  bawbel-gate audit verify audit-$m.jsonl | head -n 1
done
```

**Expect** (captured, exit 0)

```text
--- last2
ok: 2 records, chain intact
--- rewrite
ok: 4 records, chain intact
--- empty
ok: 0 records, chain intact
```

**Pass if** 'ok' for each of the three damaged logs, which is the documented behaviour, not a defect found here

**Negative** the intact log also prints ok, so 'ok' alone does not tell the three apart: only the record count and an anchored head do

```bash
bawbel-gate audit verify audit.jsonl | head -n 1
```

Captured:

```text
ok: 4 records, chain intact
```

**Cleanup** none

### STEP U-03  an anchored head catches a cut or rewritten log that verify passes

**Proves** a head recorded outside the log is still one of the log's records only if the log was not cut before it or rewritten from before it

**Needs** U-01

**Run**

```bash
HEAD=$(bawbel-gate audit tail audit.jsonl -n 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["hash"])')
echo "$HEAD" > anchor.txt
echo "anchor found in the intact log: $(grep -Fc "\"hash\":\"$HEAD\"" audit.jsonl)"
```

**Expect** (captured, exit 0)

```text
anchor found in the intact log: 1
```

**Pass if** the anchored head is found once in the intact log

**Negative** in a log cut before the head, and in one rewritten from record 3, verify still prints ok but the head is found 0 times

```bash
HEAD=$(cat anchor.txt)
head -n 3 audit.jsonl > audit-cut.jsonl
echo "--- cut before the head"
bawbel-gate audit verify audit-cut.jsonl | head -n 1
echo "anchor found: $(grep -Fc "\"hash\":\"$HEAD\"" audit-cut.jsonl)"
python3 attack.py rewrite audit.jsonl audit-rw.jsonl
echo "--- rewritten from record 3"
bawbel-gate audit verify audit-rw.jsonl | head -n 1
echo "anchor found: $(grep -Fc "\"hash\":\"$HEAD\"" audit-rw.jsonl)"
```

Captured:

```text
--- cut before the head
ok: 3 records, chain intact
anchor found: 0
--- rewritten from record 3
ok: 4 records, chain intact
anchor found: 0
```

**Cleanup** none

### STEP C-01  clear appends a SESSION_CLEAR record and the chain still verifies

**Proves** an operator can reset taint for a session as a recorded action, and it cannot be done by accident

**Needs** A-02

**Run**

```bash
rm -f audit.jsonl
(python3 msgs.py call:github__get_issue:'{"n":1}' call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate.yaml >/dev/null 2>&1
SID=$(python3 -c "import json; print(json.loads(open('audit.jsonl').readline())['session'])")
echo "$SID" > session.txt
bawbel-gate clear --session "$SID" --confirm --audit-log audit.jsonl | sed -n 1p
bawbel-gate audit verify audit.jsonl | sed -n 1p
python3 auditsum.py audit.jsonl | tail -n 1
```

**Expect** (captured, exit 0)

```text
bawbel-gate: SESSION_CLEAR written for session f98d67ba-1ed9-4ec7-b70e-043d61c661c2
ok: 5 records, chain intact
5 SESSION_CLEAR - - -
```

**Pass if** a line 'SESSION_CLEAR written', then 'ok: 5 records', and a last record SESSION_CLEAR

**Negative** without --confirm the command exits 2 with "Missing option '--confirm'"

```bash
bawbel-gate clear --session "$(cat session.txt)" --audit-log audit.jsonl
echo "exit $?"
```

Captured:

```text
Error: Missing option '--confirm'.
exit 2
```

**Cleanup** none

### STEP PO-01  posture summarises an audit log, and refuses a log that is not there

**Proves** the one-page report counts decisions and security events from the log alone

**Needs** C-01

**Run**

```bash
bawbel-gate posture --audit-log audit.jsonl --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print({k: d[k] for k in ('allow_count', 'approve_count', 'deny_count', 'trifecta_trips', 'session_count')})"
bawbel-gate posture --audit-log audit.jsonl | sed -n '/DECISION SUMMARY/,/total/p'
```

**Expect** (captured, exit 0)

```text
{'allow_count': 1, 'approve_count': 1, 'deny_count': 0, 'trifecta_trips': 1, 'session_count': 1}
```

**Pass if** allow 1, approve 1, deny 0, trifecta trips 1, one session

**Negative** a log that does not exist gives exit 1 and 'audit log not found'

```bash
bawbel-gate posture --audit-log no-such-file.jsonl
echo "exit $?"
```

Captured:

```text
bawbel-gate: audit log not found: no-such-file.jsonl
exit 1
```

**Cleanup** none

### STEP LN-01  learning mode records and enforces nothing, report and synthesize use the record

**Proves** serve --learn passes every call through and records it; learn report shows the usage; learn synthesize writes a draft manifest that lint accepts

**Needs** A-02

**Run**

```bash
rm -rf learn.observations.jsonl learn-out && mkdir learn-out
python3 msgs.py call:github__get_issue:'{"n":1}' call:github__delete_repo | bawbel-gate serve -c gate.yaml --learn 2>/dev/null | python3 summ.py -q
bawbel-gate learn report
bawbel-gate learn synthesize --out learn-out | sed -n 1p
bawbel-gate lint learn-out >/dev/null; echo "lint of the draft manifests: exit $?"
```

**Expect** (captured, exit 0)

```text
3 result ok: get_issue
4 result ok: delete_repo
  get_issue                                 calls=1  last=2026-11-22T00:17:44.631434+00:00
  delete_repo                               calls=1  last=2026-11-22T00:17:44.631791+00:00
wrote learn-out/github.cap.yaml  (2 allow grants, wildcard deny)
lint of the draft manifests: exit 0
```

**Pass if** a call the manifest would deny returns a result, the report lists the calls, and a draft github.cap.yaml is written and lints

**Negative** the same denied call in enforce mode is refused, and learn synthesize without --out exits 2

```bash
rm -f audit.jsonl
python3 msgs.py call:github__delete_repo | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
bawbel-gate learn synthesize
echo "exit $?"
bawbel-gate learn --duration 7d
echo "exit $?"
```

Captured:

```text
3 ERROR -32031 resolved
Error: Missing option '--out'.
exit 2
Error: No such option '--duration'.
exit 2
```

**Cleanup** none

### STEP S-01  stdout carries JSON-RPC only while serve runs, text goes to stderr

**Proves** an MCP client reads the gate's stdout as a JSON-RPC stream, so any other line there breaks the client

**Needs** A-02

**Run**

```bash
rm -f audit.jsonl
python3 msgs.py call:github__get_issue:'{"n":1}' | bawbel-gate serve -c gate.yaml > serve-out.txt 2> serve-err.txt
python3 nonjson.py serve-out.txt stdout
```

**Expect** (captured, exit 0)

```text
stdout: non-JSON lines: 1
    bawbel-gate: enforcement mode active
```

**Pass if** 0 lines on stdout that are not JSON

**Negative** stderr has non-JSON lines (the session-end line), so the same count on stderr is not 0

```bash
python3 nonjson.py serve-err.txt stderr
```

Captured:

```text
stderr: non-JSON lines: 1
    bawbel-gate: session end -- chain head sha256:bee3192a98d98f0e2a505e108bd3e8165cd5c74875df
```

**Cleanup** none

### Checklist table from this run

| Step | Name | Positive | Negative twin | Verdict |
|---|---|---|---|---|
| A-01 | Install the built wheel and report the version | ok | ok | PASS |
| A-02 | Create the stand-in server, manifests and configs | ok | ok | PASS |
| A-03 | Every command and subcommand answers --help | ok | ok | PASS |
| L-01 | lint accepts a valid manifest and rejects each bad one | ok | ok | PASS |
| L-02 | lint --forbid-effect fails a grant of the forbidden effect on the named tools | ok | ok | PASS |
| L-03 | lint warns W-UNENFORCED for a field the gate does not enforce, and keeps the exit code | ok | ok | PASS |
| P-01 | tools/list is merged across servers, prefixed, and hides denied tools | ok | ok | PASS |
| P-02 | an allow grant passes, an unprefixed name is denied | ok | ok | PASS |
| P-03 | an approve grant waits for the operator; a refusal or silence denies | ok | ok | PASS |
| P-04 | resources and prompts methods return -32601 | ok | ok | PASS |
| P-05 | the upstream handshake works against a FastMCP server | ok | ok | PASS |
| T-01 | a read of untrusted content then an external call trips the trifecta rule | ok | ok | PASS |
| G-01 | argument guards stop a secret and an oversize payload | ok | ok | PASS |
| U-01 | audit verify passes an intact log and rejects an edit, a cut line and a missing first record | ok | ok | PASS |
| U-02 | audit verify does not detect three changes (expected: not detected, see SECURITY.md Limits) | ok | ok | PASS (documented limit) |
| U-03 | an anchored head catches a cut or rewritten log that verify passes | ok | ok | PASS |
| C-01 | clear appends a SESSION_CLEAR record and the chain still verifies | ok | ok | PASS |
| PO-01 | posture summarises an audit log, and refuses a log that is not there | ok | ok | PASS |
| LN-01 | learning mode records and enforces nothing, report and synthesize use the record | ok | ok | PASS |
| S-01 | stdout carries JSON-RPC only while serve runs, text goes to stderr | FAILED | ok | FAIL |
