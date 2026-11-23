#!/usr/bin/env bash
# Run the manual test guide (docs/MANUAL-TEST.md) one step at a time, or all of it.
#
# Every step runs in a fresh environment: a new virtualenv, an empty HOME, `env -i` with only
# PATH and a few variables, and a temporary working directory. Nothing needs network access
# except `pip` (the wheel's dependencies, and FastMCP in step P-05). No API key is read.
#
# A step passes only when its positive commands behave as documented AND its negative twin
# fails the way it should. The raw output is printed next to the verdict. A failure is never
# hidden: the commands that failed and their output are printed straight away.
#
# Usage:
#   bash scripts/manual_test.sh --list            list the steps
#   bash scripts/manual_test.sh --step P-02       run one step (sets up the environment first if needed)
#   bash scripts/manual_test.sh --all             fresh environment, every step, then a checklist table
#   bash scripts/manual_test.sh --all --verbose   the same, with the raw output of every step
#   bash scripts/manual_test.sh --markdown        the step sections of the guide, from a fresh run
#   bash scripts/manual_test.sh --reset           delete the environment this script created
#
# Environment:
#   MANUAL_TEST_DIR   where the environment lives (default: ${TMPDIR:-/tmp}/bawbel-manual-test)
#   PYTHON            interpreter used to create the virtualenv (default: python3)
#
# Needs bash, Python 3.10 or later, and `pip`. Linux and macOS (bash 3.2 or later).

set -u

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE=${MANUAL_TEST_DIR:-${TMPDIR:-/tmp}/bawbel-manual-test}
BASE=${BASE%/}
VENV=$BASE/venv
WORKD=$BASE/work
HOMEDIR=$BASE/home
OUTD=$BASE/out
MARKER=$BASE/.bawbel-manual-test
TIMEOUT=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT="timeout 180"; fi

# ---------------------------------------------------------------------------------------
# Step table. Parallel arrays, indexed by step number, so this runs on bash 3.2 (macOS).
# ---------------------------------------------------------------------------------------
N=-1
t_id=(); t_name=(); t_proves=(); t_needs=(); t_run=(); t_pass=(); t_pexp=(); t_neg=()
t_npass=(); t_nexp=(); t_show=(); t_nshow=(); t_limit=(); t_cleanup=()

step()    { N=$((N + 1)); t_id[N]=$1; t_name[N]=$2; t_limit[N]=0; t_needs[N]="A-02"; t_cleanup[N]="none"; t_show[N]=""; t_nshow[N]=""; }
proves()  { t_proves[N]=$1; }
needs()   { t_needs[N]=$1; }
passif()  { t_pass[N]=$1; }
negpass() { t_npass[N]=$1; }
showpos() { t_show[N]=$1; }
showneg() { t_nshow[N]=$1; }
limit()   { t_limit[N]=1; }
cleanup() { t_cleanup[N]=$1; }
run()     { t_run[N]=$(cat); }
expect()  { t_pexp[N]=$(cat); }
neg()     { t_neg[N]=$(cat); }
negexpect() { t_nexp[N]=$(cat); }

# ----- A: environment ------------------------------------------------------------------

step A-01 "Install the built wheel and report the version"
proves "the wheel (not an editable install) installs into a clean virtualenv and the entry point runs"
needs "Python 3.10 or later, pip, network access for pip only"
passif "exit 0, a line 'bawbel-gate, version <x.y.z>', a wheel in dist, and 0 editable lines"
negpass "exit 2 and 'No such option': a flag that does not exist is refused"
showpos '^bawbel-gate, version|\.whl$|editable lines'
showneg 'No such option|^exit'
run <<'RUN_END'
python3 -m venv "$VENV" >/dev/null 2>&1 || { rm -rf "$VENV"; virtualenv -q "$VENV"; }
"$VENV/bin/python" -m pip wheel --no-deps -q -w "$BASE/dist" "$REPO"
"$VENV/bin/python" -m pip install -q "$BASE"/dist/bawbel_gate-*.whl
ls "$BASE/dist"
bawbel-gate --version
echo "editable lines: $("$VENV/bin/python" -m pip show bawbel-gate | grep -c 'Editable project location' || true)"
RUN_END
expect <<'EXP_END'
rc 0
has ^bawbel-gate, version [0-9]+\.[0-9]+\.[0-9]+
has bawbel_gate-[0-9.]+-py3-none-any\.whl
has editable lines: 0
EXP_END
neg <<'NEG_END'
bawbel-gate --no-such-flag
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has No such option
has ^exit 2
NEXP_END
cleanup 'python3 scripts/manual_test.sh --reset'

step A-02 "Create the stand-in server, manifests and configs"
proves "the fixtures the other steps use exist; nothing else is needed from the network or the host"
needs "A-01"
passif "exit 0 and a line 'created <n> files'"
negpass "exit 2 and 'does not exist': the gate refuses a config path that is not there"
showpos '^created'
showneg 'does not exist|^exit'
run <<'RUN_END'
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
RUN_END
expect <<'EXP_END'
rc 0
has ^created [0-9]+ files
EXP_END
neg <<'NEG_END'
bawbel-gate serve -c does-not-exist.yaml
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has does not exist
has ^exit 2
NEXP_END

step A-03 "Every command and subcommand answers --help"
proves "the command tree is what this guide covers: ten commands, and the subcommands of audit, learn and hub"
needs "A-01"
passif "exit 0 and no line starting FAIL"
negpass "exit 2 and 'No such command': a command that is designed and not built is not there"
showpos '^Commands:|^  [a-z]+$|^ok   hub token|^FAIL'
showneg 'No such command|^exit'
run <<'RUN_END'
bawbel-gate --help | sed -n '/^Commands:/,$p' | awk 'NR == 1 {print; next} {print "  " $1}'
for c in audit clear enroll harden hub learn lint posture serve verify; do
  bawbel-gate $c --help >/dev/null && echo "ok   $c --help" || echo "FAIL $c --help"
done
for c in "audit tail" "audit verify" "learn report" "learn synthesize" "hub serve" "hub token"; do
  bawbel-gate $c --help >/dev/null && echo "ok   $c --help" || echo "FAIL $c --help"
done
RUN_END
expect <<'EXP_END'
rc 0
has ^ok   hub token --help
has ^ok   audit verify --help
lacks ^FAIL
EXP_END
neg <<'NEG_END'
bawbel-gate decide --help
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has No such command 'decide'
has ^exit 2
NEXP_END

# ----- L: lint -------------------------------------------------------------------------

step L-01 "lint accepts a valid manifest and rejects each bad one"
proves "a manifest is checked against the capability-manifest schema before it is used; serve does not start on a manifest that fails it"
passif "exit 0 and a line 'ok   m.yaml' for the valid manifest"
negpass "three rejections with a clear message (unknown field, missing subject, bad effect), each with exit 1; serve exits 1 and names the schema failure"
showpos '^ok|^FAIL'
showneg '^---|^FAIL|not allowed|required property|is not one of|^exit|schema validation failed'
run <<'RUN_END'
rm -rf lint-case && mkdir -p lint-case/ok lint-case/unknown lint-case/nosubject lint-case/badeffect
cp manifests/github.yaml lint-case/ok/m.yaml
cp manifests/github.yaml lint-case/unknown/m.yaml && echo "colour: blue" >> lint-case/unknown/m.yaml
grep -v '^subject' manifests/github.yaml > lint-case/nosubject/m.yaml
sed 's/effect: allow/effect: maybe/' manifests/github.yaml > lint-case/badeffect/m.yaml
bawbel-gate lint lint-case/ok
RUN_END
expect <<'EXP_END'
rc 0
has ^ok +m\.yaml
EXP_END
neg <<'NEG_END'
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
NEG_END
negexpect <<'NEXP_END'
has Additional properties are not allowed
has 'subject' is a required property
has is not one of \['allow', 'approve', 'deny'\]
has ^exit 1
has schema validation failed
NEXP_END

step L-02 "lint --forbid-effect fails a grant of the forbidden effect on the named tools"
proves "a deployment check can fail CI when an allow grant reaches a tool of an external-comms server"
passif "exit 0 for a manifest with no external-comms server"
negpass "exit 1 and 'forbidden effect' for a manifest that allows a tool on an external-comms server"
showpos '^ok|^FAIL'
showneg '^FAIL|^exit'
run <<'RUN_END'
bawbel-gate lint manifests-guard --forbid-effect allow --tools-with external_comms
RUN_END
expect <<'EXP_END'
rc 0
has ^ok +github\.yaml
EXP_END
neg <<'NEG_END'
bawbel-gate lint manifests --forbid-effect allow --tools-with external_comms
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has forbidden effect 'allow'
has ^exit 1
NEXP_END

step L-03 "lint warns W-UNENFORCED for a field the gate does not enforce, and keeps the exit code"
proves "a declaration that has no effect is called out, one warning per declaration, and does not fail the run"
passif "exit 0, a line 'W-UNENFORCED subject.binary_integrity' and a line 'ok'"
negpass "a manifest without the declaration prints no W-UNENFORCED line"
showpos 'W-UNENFORCED|^ok|^exit'
showneg 'W-UNENFORCED|^ok|^exit'
run <<'RUN_END'
rm -rf lint-warn && mkdir lint-warn
sed 's#transport: stdio}#transport: stdio, binary_integrity: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}#' manifests/github.yaml > lint-warn/m.yaml
bawbel-gate lint lint-warn
echo "exit $?"
RUN_END
expect <<'EXP_END'
has W-UNENFORCED subject\.binary_integrity
has ^ok +m\.yaml
has ^exit 0
EXP_END
neg <<'NEG_END'
bawbel-gate lint manifests
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
lacks W-UNENFORCED
has ^exit 0
NEXP_END

# ----- P: the stdio proxy --------------------------------------------------------------

step P-01 "tools/list is merged across servers, prefixed, and hides denied tools"
proves "the host sees one list, each tool named {server}__{tool}, and a tool no grant allows is not offered"
passif "a tools line holding docs__get_issue, github__create_pull_request and github__get_issue, and no delete_repo"
negpass "calling the hidden tool github__delete_repo is refused with -32031"
showpos '^[0-9]+ (initialize|tools)'
showneg '^[0-9]+ ERROR'
run <<'RUN_END'
rm -f audit.jsonl
python3 msgs.py | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
RUN_END
expect <<'EXP_END'
has ^1 initialize bawbel-gate
has ^2 tools: \['docs__get_issue', 'github__create_pull_request', 'github__get_issue'\]
lacks delete_repo
EXP_END
neg <<'NEG_END'
rm -f audit.jsonl
python3 msgs.py call:github__delete_repo | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
NEG_END
negexpect <<'NEXP_END'
has ^3 ERROR -32031 resolved
NEXP_END

step P-02 "an allow grant passes, an unprefixed name is denied"
proves "a call to {server}__{tool} that a grant allows reaches the server; a name with no grant is denied by default"
passif "a result line 'ok: get_issue'"
negpass "the unprefixed name get_issue is refused with -32031 and the reason no_grant"
showpos '^[0-9]+ result'
showneg '^[0-9]+ ERROR'
run <<'RUN_END'
rm -f audit.jsonl
python3 msgs.py call:github__get_issue:'{"n":1}' | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
RUN_END
expect <<'EXP_END'
has ^3 result ok: get_issue
EXP_END
neg <<'NEG_END'
rm -f audit.jsonl
python3 msgs.py call:get_issue:'{"n":1}' | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
NEG_END
negexpect <<'NEXP_END'
has ^3 ERROR -32031 no_grant
NEXP_END

step P-03 "an approve grant waits for the operator; a refusal or silence denies"
proves "a call whose grant says approve is held until the operator answers on stdin; no answer within the timeout is a deny"
passif "the prompt 'APPROVAL REQUIRED' on stderr and a result line 'ok: create_pull_request' after the answer y"
negpass "the answer n gives -32031 approval_denied; silence for longer than 5 s gives -32031 approval_timeout"
showpos 'APPROVAL REQUIRED|Reason:|^[0-9]+ result'
showneg '^---|^[0-9]+ ERROR'
run <<'RUN_END'
rm -f audit-approve.jsonl
(python3 msgs.py call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate-approve.yaml 2>approve-err.txt | python3 summ.py -q
grep -E 'APPROVAL REQUIRED|Reason:' approve-err.txt
RUN_END
expect <<'EXP_END'
has APPROVAL REQUIRED
has ^3 result ok: create_pull_request
EXP_END
neg <<'NEG_END'
rm -f audit-approve.jsonl
echo "--- answer n"
(python3 msgs.py call:github__create_pull_request:'{"title":"t"}'; echo n) | bawbel-gate serve -c gate-approve.yaml 2>/dev/null | python3 summ.py -q
echo "--- no answer for 8 s (the timeout is 5 s)"
(python3 msgs.py call:github__create_pull_request:'{"title":"t"}'; sleep 8) | bawbel-gate serve -c gate-approve.yaml 2>/dev/null | python3 summ.py -q
NEG_END
negexpect <<'NEXP_END'
has ^3 ERROR -32031 approval_denied
has ^3 ERROR -32031 approval_timeout
NEXP_END

step P-04 "resources and prompts methods return -32601"
proves "the gate serves initialize, tools/list and tools/call only; every other method is refused, not forwarded"
passif "resources/list and prompts/list each return error -32601"
negpass "tools/list, a method the gate does serve, returns a result and no -32601"
showpos '^[0-9]+ ERROR'
showneg '^[0-9]+ (tools|ERROR)'
run <<'RUN_END'
python3 msgs.py resources/list prompts/list | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
RUN_END
expect <<'EXP_END'
has ^3 ERROR -32601 Method not found: resources/list
has ^4 ERROR -32601 Method not found: prompts/list
EXP_END
neg <<'NEG_END'
python3 msgs.py | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
NEG_END
negexpect <<'NEXP_END'
has ^2 tools:
lacks -32601
NEXP_END

step P-05 "the upstream handshake works against a FastMCP server"
proves "the gate initializes a real FastMCP stdio server, lists its tool with the prefix, and forwards an allowed call"
needs "A-02, and pip with network access to install fastmcp. FastMCP checks PyPI for a newer version when it starts, so the step turns that off with FASTMCP_CHECK_FOR_UPDATES=off"
passif "a tools line holding fm__add and a result line with the text 5"
negpass "a server that exits at once instead of answering initialize makes serve exit 1 with no tools offered"
showpos '^fastmcp|^[0-9]+ (initialize|tools|result)'
showneg '^exit|^[0-9]+ (initialize|tools)|^stdout'
run <<'RUN_END'
python3 -m pip install -q fastmcp
echo "fastmcp $(python3 -m pip show fastmcp | sed -n 's/^Version: //p')"
export FASTMCP_CHECK_FOR_UPDATES=off   # FastMCP otherwise contacts PyPI when it starts
rm -f audit-fm.jsonl
python3 msgs.py call:fm__add:'{"a":2,"b":3}' | bawbel-gate serve -c gate-fm.yaml 2>/dev/null | python3 summ.py -q
RUN_END
expect <<'EXP_END'
has ^fastmcp [0-9]
has ^2 tools: \['fm__add'\]
has ^3 result 5
EXP_END
neg <<'NEG_END'
rm -f audit-dead.jsonl
python3 msgs.py | bawbel-gate serve -c gate-dead.yaml > dead-out.txt 2> dead-err.txt
echo "exit $?"
python3 summ.py -q < dead-out.txt
NEG_END
negexpect <<'NEXP_END'
has ^exit 1
lacks ^2 tools
NEXP_END

# ----- T: taint and the trifecta rule ---------------------------------------------------

step T-01 "a read of untrusted content then an external call trips the trifecta rule"
proves "after a call that reads private and untrusted content, a call that can send it out is held for approval, and the reason is recorded"
passif "the prompt shows 'Reason:  trifecta_third_leg' and the audit log has an approve record with reason trifecta_third_leg"
negpass "the same external call with no earlier read resolves to allow, reason resolved"
showpos 'Reason:|^[0-9]+ result|CALL_DECIDED'
showneg '^[0-9]+ result|CALL_DECIDED'
run <<'RUN_END'
rm -f audit.jsonl
(python3 msgs.py call:github__get_issue:'{"n":1}' call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate.yaml 2>serve-err.txt | python3 summ.py -q
grep 'Reason:' serve-err.txt
python3 auditsum.py audit.jsonl
RUN_END
expect <<'EXP_END'
has Reason: +trifecta_third_leg
has ^4 result ok: create_pull_request
has CALL_DECIDED create_pull_request approve trifecta_third_leg
EXP_END
neg <<'NEG_END'
rm -f audit.jsonl
python3 msgs.py call:github__create_pull_request:'{"title":"t"}' | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
python3 auditsum.py audit.jsonl
NEG_END
negexpect <<'NEXP_END'
has ^3 result ok: create_pull_request
has CALL_DECIDED create_pull_request allow resolved
lacks trifecta_third_leg
NEXP_END

# ----- G: argument guards ---------------------------------------------------------------

step G-01 "argument guards stop a secret and an oversize payload"
proves "a manifest guard scans outbound arguments for secrets and caps their size, before the call leaves the gate"
passif "a call with clean arguments returns a result"
negpass "a call carrying the AWS documentation example key is refused with guard:secret_scan, and a 400 byte value with guard:byte_cap"
showpos '^[0-9]+ result'
showneg '^[0-9]+ ERROR|CALL_DECIDED'
run <<'RUN_END'
rm -f audit-guard.jsonl
python3 msgs.py call:github__create_pull_request:'{"title":"fix a typo"}' | bawbel-gate serve -c gate-guard.yaml 2>/dev/null | python3 summ.py -q
RUN_END
expect <<'EXP_END'
has ^3 result ok: create_pull_request
EXP_END
neg <<'NEG_END'
rm -f audit-guard.jsonl
BIG=$(python3 -c 'print("x" * 400)')
python3 msgs.py call:github__create_pull_request:'{"title":"AKIAIOSFODNN7EXAMPLE"}' call:github__create_pull_request:"{\"title\":\"$BIG\"}" | bawbel-gate serve -c gate-guard.yaml 2>/dev/null | python3 summ.py -q
python3 auditsum.py audit-guard.jsonl
NEG_END
negexpect <<'NEXP_END'
has ^3 ERROR -32031 guard:secret_scan
has ^4 ERROR -32031 guard:byte_cap
has CALL_DECIDED create_pull_request deny guard:secret_scan
NEXP_END

# ----- U: the audit chain ---------------------------------------------------------------

step U-01 "audit verify passes an intact log and rejects an edit, a cut line and a missing first record"
proves "the hash chain catches a changed effect, a record cut off mid-line, and a removed first record, from the file alone"
passif "exit 0 and 'ok: 4 records, chain intact'"
negpass "three FAIL lines with exit 1 (hash mismatch, a JSON error, prev mismatch), and a missing path is a usage error with exit 2"
showpos '^ok|^chain verified|^[0-9]+ [A-Z_]+ '
showneg '^---|^FAIL|^exit|^Error'
run <<'RUN_END'
rm -f audit.jsonl
(python3 msgs.py call:github__get_issue:'{"n":1}' call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate.yaml >/dev/null 2>&1
bawbel-gate audit verify audit.jsonl
python3 auditsum.py audit.jsonl
RUN_END
expect <<'EXP_END'
rc 0
has ^ok: 4 records, chain intact
has ^chain verified: audit\.jsonl
has ^3 CALL_DECIDED create_pull_request approve trifecta_third_leg
EXP_END
neg <<'NEG_END'
for m in edit trunc first; do
  python3 attack.py $m audit.jsonl audit-$m.jsonl
  echo "--- $m"
  bawbel-gate audit verify audit-$m.jsonl
  echo "exit $?"
done
echo "--- a path that does not exist"
bawbel-gate audit verify no-such-file.jsonl 2>&1 | tail -n 1
bawbel-gate audit verify no-such-file.jsonl >/dev/null 2>&1; echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has ^FAIL: seq 3: hash mismatch
has ^FAIL: line 4:
has ^FAIL: seq 2: prev mismatch
has ^Error: Invalid value for 'FILE': Path 'no-such-file.jsonl' does not exist\.
has ^exit 2
NEXP_END

step U-02 "audit verify does not detect three changes (expected: not detected, see SECURITY.md Limits)"
proves "the chain has no key, so a log cut at the end, a log rewritten from one record onward, and an emptied log all still verify; an anchored head is what catches them"
needs "U-01"
limit
passif "'ok' for each of the three damaged logs, which is the documented behaviour, not a defect found here"
negpass "the intact log also prints ok, so 'ok' alone does not tell the three apart: only the record count and an anchored head do"
showpos '^---|^ok'
showneg '^ok'
run <<'RUN_END'
for m in last2 rewrite empty; do
  python3 attack.py $m audit.jsonl audit-$m.jsonl
  echo "--- $m"
  bawbel-gate audit verify audit-$m.jsonl | head -n 1
done
RUN_END
expect <<'EXP_END'
has ^ok: 2 records, chain intact
has ^ok: 4 records, chain intact
has ^ok: 0 records, chain intact
EXP_END
neg <<'NEG_END'
bawbel-gate audit verify audit.jsonl | head -n 1
NEG_END
negexpect <<'NEXP_END'
has ^ok: 4 records, chain intact
NEXP_END

step U-03 "an anchored head catches a cut or rewritten log that verify passes"
proves "a head recorded outside the log is still one of the log's records only if the log was not cut before it or rewritten from before it"
needs "U-01"
passif "the anchored head is found once in the intact log"
negpass "in a log cut before the head, and in one rewritten from record 3, verify still prints ok but the head is found 0 times"
showpos 'anchor'
showneg '^---|^ok|anchor'
run <<'RUN_END'
HEAD=$(bawbel-gate audit tail audit.jsonl -n 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["hash"])')
echo "$HEAD" > anchor.txt
echo "anchor found in the intact log: $(grep -Fc "\"hash\":\"$HEAD\"" audit.jsonl)"
RUN_END
expect <<'EXP_END'
has ^anchor found in the intact log: 1
EXP_END
neg <<'NEG_END'
HEAD=$(cat anchor.txt)
head -n 3 audit.jsonl > audit-cut.jsonl
echo "--- cut before the head"
bawbel-gate audit verify audit-cut.jsonl | head -n 1
echo "anchor found: $(grep -Fc "\"hash\":\"$HEAD\"" audit-cut.jsonl)"
python3 attack.py rewrite audit.jsonl audit-rw.jsonl
echo "--- rewritten from record 3"
bawbel-gate audit verify audit-rw.jsonl | head -n 1
echo "anchor found: $(grep -Fc "\"hash\":\"$HEAD\"" audit-rw.jsonl)"
NEG_END
negexpect <<'NEXP_END'
has ^ok: 3 records, chain intact
has ^ok: 4 records, chain intact
has ^anchor found: 0
NEXP_END

# ----- C, PO: clear and posture ---------------------------------------------------------

step C-01 "clear appends a SESSION_CLEAR record and the chain still verifies"
proves "an operator can reset taint for a session as a recorded action, and it cannot be done by accident"
passif "a line 'SESSION_CLEAR written', then 'ok: 5 records', and a last record SESSION_CLEAR"
negpass "without --confirm the command exits 2 with \"Missing option '--confirm'\""
showpos 'SESSION_CLEAR|^ok|^5 '
showneg "Missing option|^exit"
run <<'RUN_END'
rm -f audit.jsonl
(python3 msgs.py call:github__get_issue:'{"n":1}' call:github__create_pull_request:'{"title":"t"}'; echo y) | bawbel-gate serve -c gate.yaml >/dev/null 2>&1
SID=$(python3 -c "import json; print(json.loads(open('audit.jsonl').readline())['session'])")
echo "$SID" > session.txt
bawbel-gate clear --session "$SID" --confirm --audit-log audit.jsonl | sed -n 1p
bawbel-gate audit verify audit.jsonl | sed -n 1p
python3 auditsum.py audit.jsonl | tail -n 1
RUN_END
expect <<'EXP_END'
rc 0
has ^bawbel-gate: SESSION_CLEAR written for session [0-9a-f-]+
has ^ok: 5 records, chain intact
has ^5 SESSION_CLEAR
EXP_END
neg <<'NEG_END'
bawbel-gate clear --session "$(cat session.txt)" --audit-log audit.jsonl
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has Missing option '--confirm'
has ^exit 2
NEXP_END

step PO-01 "posture summarises an audit log, and refuses a log that is not there"
proves "the one-page report counts decisions and security events from the log alone"
needs "C-01"
passif "allow 1, approve 1, deny 0, trifecta trips 1, one session"
negpass "a log that does not exist gives exit 1 and 'audit log not found'"
showpos "allow_count|trifecta|^exit"
showneg 'not found|^exit'
run <<'RUN_END'
bawbel-gate posture --audit-log audit.jsonl --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print({k: d[k] for k in ('allow_count', 'approve_count', 'deny_count', 'trifecta_trips', 'session_count')})"
bawbel-gate posture --audit-log audit.jsonl | sed -n '/DECISION SUMMARY/,/total/p'
RUN_END
expect <<'EXP_END'
rc 0
has 'allow_count': 1, 'approve_count': 1, 'deny_count': 0, 'trifecta_trips': 1, 'session_count': 1
has ^  total   : +2
EXP_END
neg <<'NEG_END'
bawbel-gate posture --audit-log no-such-file.jsonl
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has audit log not found
has ^exit 1
NEXP_END

# ----- LN: learning mode ----------------------------------------------------------------

step LN-01 "learning mode records and enforces nothing, report and synthesize use the record"
proves "serve --learn passes every call through and records it; learn report shows the usage; learn synthesize writes a draft manifest that lint accepts"
passif "a call the manifest would deny returns a result, the report lists the calls, and a draft github.cap.yaml is written and lints"
negpass "the same denied call in enforce mode is refused, and learn synthesize without --out exits 2"
showpos '^[0-9]+ result|calls=|^wrote|^lint of'
showneg '^[0-9]+ ERROR|Missing option|No such option|^exit'
run <<'RUN_END'
rm -rf learn.observations.jsonl learn-out && mkdir learn-out
python3 msgs.py call:github__get_issue:'{"n":1}' call:github__delete_repo | bawbel-gate serve -c gate.yaml --learn 2>/dev/null | python3 summ.py -q
bawbel-gate learn report
bawbel-gate learn synthesize --out learn-out | sed -n 1p
bawbel-gate lint learn-out >/dev/null; echo "lint of the draft manifests: exit $?"
RUN_END
expect <<'EXP_END'
has ^3 result ok: get_issue
has ^4 result ok: delete_repo
has delete_repo +calls=1
has ^wrote learn-out/github\.cap\.yaml
has ^lint of the draft manifests: exit 0
EXP_END
neg <<'NEG_END'
rm -f audit.jsonl
python3 msgs.py call:github__delete_repo | bawbel-gate serve -c gate.yaml 2>/dev/null | python3 summ.py -q
bawbel-gate learn synthesize
echo "exit $?"
bawbel-gate learn --duration 7d
echo "exit $?"
NEG_END
negexpect <<'NEXP_END'
has ^3 ERROR -32031 resolved
has Missing option '--out'
has No such option '--duration'
has ^exit 2
NEXP_END

# ----- S: stdout -------------------------------------------------------------------------

step S-01 "stdout carries JSON-RPC only while serve runs, text goes to stderr"
proves "an MCP client reads the gate's stdout as a JSON-RPC stream, so any other line there breaks the client"
passif "0 lines on stdout that are not JSON"
negpass "stderr has non-JSON lines (the session-end line), so the same count on stderr is not 0"
showpos 'non-JSON|^    '
showneg 'non-JSON|^    '
run <<'RUN_END'
rm -f audit.jsonl
python3 msgs.py call:github__get_issue:'{"n":1}' | bawbel-gate serve -c gate.yaml > serve-out.txt 2> serve-err.txt
python3 nonjson.py serve-out.txt stdout
RUN_END
expect <<'EXP_END'
has ^stdout: non-JSON lines: 0$
EXP_END
neg <<'NEG_END'
python3 nonjson.py serve-err.txt stderr
NEG_END
negexpect <<'NEXP_END'
has ^stderr: non-JSON lines: [1-9]
NEXP_END

NSTEPS=$((N + 1))

# ---------------------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------------------

index_of() { local i; for ((i = 0; i < NSTEPS; i++)); do [ "${t_id[i]}" = "$1" ] && { echo "$i"; return 0; }; done; return 1; }

# run a block of shell in the clean environment; output to $2, exit code in $RC
run_block() {
  mkdir -p "$WORKD" "$HOMEDIR" "$OUTD"
  printf '%s\n' "$1" > "$BASE/.block.sh"
  (cd "$WORKD" && env -i HOME="$HOMEDIR" PATH="$VENV/bin:/usr/bin:/bin" TERM=dumb LC_ALL=C.UTF-8 \
     PYTHONDONTWRITEBYTECODE=1 REPO="$REPO" BASE="$BASE" VENV="$VENV" WORK="$WORKD" \
     $TIMEOUT bash "$BASE/.block.sh") > "$2" 2>&1
  RC=$?
}

# check expectations ($1) against output file ($2) and exit code ($3); print each failure
check() {
  local bad=0 line kind arg
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    kind=${line%% *}; arg=${line#* }
    case $kind in
      rc)    if [ "$arg" = nz ]; then [ "$3" -ne 0 ] || { echo "    expected a non-zero exit, got $3"; bad=1; }
             else [ "$3" -eq "$arg" ] || { echo "    expected exit $arg, got $3"; bad=1; }; fi ;;
      has)   grep -E -q -e "$arg" "$2" || { echo "    missing a line matching: $arg"; bad=1; } ;;
      lacks) if grep -E -q -e "$arg" "$2"; then echo "    unexpected line matching: $arg"; bad=1; fi ;;
    esac
  done <<EOF_CHECK
$1
EOF_CHECK
  return $bad
}

ensure_marker() { mkdir -p "$BASE"; [ -f "$MARKER" ] || date > "$MARKER"; }

reset_env() {
  if [ -d "$BASE" ]; then
    if [ -f "$MARKER" ]; then rm -rf "$BASE"; echo "removed $BASE"
    else echo "refusing to remove $BASE: it has no $MARKER file, so this script did not create it" >&2; return 1; fi
  fi
}

# execute step $1 (index); sets POS_OK NEG_OK; writes $OUTD/<id>.pos and .neg and .prc .nrc
exec_step() {
  local i=$1 id=${t_id[$1]} f
  ensure_marker; mkdir -p "$OUTD" "$WORKD" "$HOMEDIR"
  run_block "${t_run[i]}" "$OUTD/$id.pos"; echo "$RC" > "$OUTD/$id.prc"
  POS_FAIL=$(check "${t_pexp[i]}" "$OUTD/$id.pos" "$RC"); POS_OK=$?
  run_block "${t_neg[i]}" "$OUTD/$id.neg"; echo "$RC" > "$OUTD/$id.nrc"
  NEG_FAIL=$(check "${t_nexp[i]}" "$OUTD/$id.neg" "$RC"); NEG_OK=$?
}

prereq() {   # make sure A-01 and A-02 have run in this environment
  if [ ! -x "$VENV/bin/bawbel-gate" ]; then exec_step "$(index_of A-01)"; [ "$POS_OK" -eq 0 ] || { echo "A-01 failed:"; cat "$OUTD/A-01.pos"; exit 1; }; fi
  if [ ! -f "$WORKD/gate.yaml" ]; then exec_step "$(index_of A-02)"; [ "$POS_OK" -eq 0 ] || { echo "A-02 failed:"; cat "$OUTD/A-02.pos"; exit 1; }; fi
}

verdict_of() {   # sets VERDICT from POS_OK and NEG_OK
  if [ "$POS_OK" -eq 0 ] && [ "$NEG_OK" -eq 0 ]; then VERDICT=PASS; else VERDICT=FAIL; fi
}

print_step_result() {   # $1 index, $2 = show raw output always (1) or only on failure (0)
  local i=$1 id=${t_id[$1]}
  verdict_of
  echo "[$VERDICT] $id  ${t_name[i]}"
  if [ "$VERDICT" = FAIL ] || [ "$2" -eq 1 ]; then
    echo "  positive: ${t_pass[i]}"
    echo "  --- commands"; sed 's/^/    $ /' <<EOF_SHOW
${t_run[i]}
EOF_SHOW
    echo "  --- raw output (exit $(cat "$OUTD/$id.prc"))"; sed 's/^/    /' "$OUTD/$id.pos"
    [ "$POS_OK" -eq 0 ] || { echo "  positive did not behave as documented:"; echo "$POS_FAIL"; }
    echo "  negative twin: ${t_npass[i]}"
    echo "  --- commands"; sed 's/^/    $ /' <<EOF_SHOW
${t_neg[i]}
EOF_SHOW
    echo "  --- raw output (exit $(cat "$OUTD/$id.nrc"))"; sed 's/^/    /' "$OUTD/$id.neg"
    [ "$NEG_OK" -eq 0 ] || { echo "  negative twin did not behave as documented:"; echo "$NEG_FAIL"; }
  fi
}

table() {
  echo
  echo "| Step | Name | Positive | Negative twin | Verdict |"
  echo "|---|---|---|---|---|"
  local i id p n v
  for ((i = 0; i < NSTEPS; i++)); do
    id=${t_id[i]}
    p=${R_POS[i]}; n=${R_NEG[i]}; v=${R_VER[i]}
    [ "${t_limit[i]}" -eq 1 ] && [ "$v" = PASS ] && v="PASS (documented limit)"
    echo "| $id | ${t_name[i]} | $p | $n | $v |"
  done
}

run_all() {   # $1 = verbose
  local i
  R_POS=(); R_NEG=(); R_VER=()
  reset_env || exit 1
  ensure_marker
  for ((i = 0; i < NSTEPS; i++)); do
    exec_step "$i"
    if [ "$POS_OK" -eq 0 ]; then R_POS[i]=ok; else R_POS[i]=FAILED; fi
    if [ "$NEG_OK" -eq 0 ]; then R_NEG[i]=ok; else R_NEG[i]=FAILED; fi
    verdict_of; R_VER[i]=$VERDICT
    print_step_result "$i" "$1"
  done
  table
  local fails=0; for ((i = 0; i < NSTEPS; i++)); do [ "${R_VER[i]}" = PASS ] || fails=$((fails + 1)); done
  echo; echo "$((NSTEPS - fails)) of $NSTEPS steps passed, $fails failed."
  [ "$fails" -eq 0 ]
}

scrub() { sed -e "s#$BASE#<BASE>#g" -e "s#$REPO#<REPO>#g"; }

show_lines() {   # $1 file $2 regex ($2 empty: first 30 lines)
  if [ -n "$2" ]; then grep -E -e "$2" "$1" | head -n 30 | scrub || true; else head -n 30 "$1" | scrub; fi
}

markdown() {
  local i id
  local log; log=$(mktemp); run_all 0 > "$log" 2>&1; local status=$?; rm -f "$log"
  echo "<!-- generated by scripts/manual_test.sh --markdown; every Expect block below was captured by running the step -->"
  for ((i = 0; i < NSTEPS; i++)); do
    id=${t_id[i]}; POS_OK=0; NEG_OK=0
    echo; echo "### STEP $id  ${t_name[i]}"; echo
    echo "**Proves** ${t_proves[i]}"; echo
    echo "**Needs** ${t_needs[i]}"; echo
    echo "**Run**"; echo; echo '```bash'; printf '%s\n' "${t_run[i]}"; echo '```'; echo
    echo "**Expect** (captured, exit $(cat "$OUTD/$id.prc"))"; echo; echo '```text'; show_lines "$OUTD/$id.pos" "${t_show[i]}"; echo '```'; echo
    echo "**Pass if** ${t_pass[i]}"; echo
    echo "**Negative** ${t_npass[i]}"; echo; echo '```bash'; printf '%s\n' "${t_neg[i]}"; echo '```'; echo
    echo "Captured:"; echo; echo '```text'; show_lines "$OUTD/$id.neg" "${t_nshow[i]}"; echo '```'; echo
    echo "**Cleanup** ${t_cleanup[i]}"
  done
  echo; echo "### Checklist table from this run"; table
  return $status
}

case "${1:-}" in
  --list)  for ((i = 0; i < NSTEPS; i++)); do printf '%-6s %s\n' "${t_id[i]}" "${t_name[i]}"; done ;;
  --step)  [ -n "${2:-}" ] || { echo "usage: $0 --step ID" >&2; exit 2; }
           idx=$(index_of "$2") || { echo "no such step: $2 (see --list)" >&2; exit 2; }
           ensure_marker; prereq
           if [ "$2" != A-01 ] && [ "$2" != A-02 ]; then needs_id=${t_needs[idx]%%[ ,]*}
             case $needs_id in U-01|C-01) j=$(index_of "$needs_id"); exec_step "$j" ;; esac; fi
           exec_step "$idx"; print_step_result "$idx" 1; [ "$POS_OK" -eq 0 ] && [ "$NEG_OK" -eq 0 ] ;;
  --all)   run_all "$([ "${2:-}" = --verbose ] && echo 1 || echo 0)" ;;
  --markdown) markdown ;;
  --reset) reset_env ;;
  *)       sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
