#!/usr/bin/env bash
# DEMO. Runs the scenes in README.md against two installed commands, `bawbel-gate` and `bawbel`.
# The servers are stubs (stub_server.py): not an attack on anything real, and no network is used.
# Every line of output below the commands comes from a run of that command.
#
#   DEMO_PAUSE=2 ./demo.sh     pause 2 seconds after each caption and each command (for recording)
#   DEMO_END_PAUSE=6           hold the last screen this long (default: the same as DEMO_PAUSE)
#   DEMO_GATE="python3 -m ..." ./demo.sh    use another command line for the gate
set -u
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAUSE="${DEMO_PAUSE:-0}"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "demo.sh needs '$1' on PATH. See README.md." >&2; exit 2; }
}
need python3
need bawbel
if [ -z "${DEMO_GATE:-}" ]; then need bawbel-gate; fi

# Work in a scratch copy so the repository stays clean and every path on screen is relative.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -R "$SRC"/. "$WORK"/
cd "$WORK" || exit 2

pause() { sleep "$PAUSE"; }
scene() { printf '\n== %s ==\n' "$1"; pause; }
say() { printf '# %s\n' "$*"; pause; }
show() {
  printf '$ %s\n' "$*"
  "$@"
  local code=$?
  printf '(exit code %s)\n' "$code"
  pause
}
show_sh() {
  printf '$ %s\n' "$1"
  bash -c "$1"
  local code=$?
  printf '(exit code %s)\n' "$code"
  pause
}
GATE="${DEMO_GATE:-bawbel-gate}"

printf 'DEMO. The servers are stubs, not an attack on anything real. No network is used.\n'
printf 'Every line of output below a command comes from a run of that command.\n'
show $GATE --version
show bawbel --version

scene "1. The scanner reads the stub servers' tool list, before anything runs"
say "bawbel-scanner reads the one file that describes the three stub MCP servers."
show bawbel scan stub-server.json

scene "2. The gate runs with a reviewed manifest, and calls go through"
say "Session A has one stub server, notes. Its manifest allows one tool and denies the rest."
show cat manifests/notes.cap.yaml
say "The driver plays the MCP client and sends fixed JSON-RPC lines. Calls 1 and 2 go through."
say "On call 3 the stub changes the description of its tool. We look at what the gate does next."

scene "3. A tool description changes during the session"
show python3 driver.py a
say "Scene 1 scanned the reviewed tool list, which the stub serves until call 3. After call 3 it serves the other text."
say "The gate's second tools/list still shows the text it took at session start, and call 4 went through."
say "Counts of audit events for this session, and its records:"
show python3 driver.py events gate.audit.jsonl
show python3 driver.py records gate.audit.jsonl 6

scene "4. Private data, then untrusted text, then a send out"
say "Control: the outbox tool alone, in a session where nothing else came first."
show python3 driver.py control
show cat sink.txt
rm -f sink.txt
say "Session B: read private notes, fetch untrusted text, then send a report. Three stub servers."
say "Under an MCP client the terminal approval prompt cannot be answered (README, Approvals):"
say "an approve resolves to deny. The driver sends the client's next request at once, as a client does."
show python3 driver.py b
say "The prompt text says 'denied by operator'. No person was asked: the client's next request was consumed."
show_sh 'test -e sink.txt && echo "sink.txt exists" || echo "sink.txt does not exist: nothing was sent"'
show python3 driver.py records gate.audit.jsonl 4

scene "5. The audit chain"
show $GATE audit verify gate.audit.jsonl
show python3 driver.py events gate.audit.jsonl

scene "What this demo showed"
cat <<'TEXT'
- The scanner reading the stub servers' tool list before anything runs.
- Four calls through the gate under a manifest that allows one tool, each one recorded.
- A tool description changing after call 3: the gate's second tools/list still shows the text it
  took at session start, call 4 goes through, and no DRIFT_DETECTED record is written.
- The outbox tool allowed on its own, then stopped with approval_denied after private data and
  untrusted text, and nothing written to sink.txt.
- audit verify passing over the log of all three sessions.
TEXT
pause

scene "Limits of this demo"
cat <<'TEXT'
- A real MCP client or a real MCP server. The driver and the stubs are scripts.
- A person answering the approval prompt. Under an MCP client it resolves to deny.
- Calls that never reach the gate: a host talking to a server directly, A2A, gRPC, REST, message
  brokers, and model traffic. The gate sees MCP calls routed through it, and no more.
- A log that was cut at the end, or rewritten with every later hash recomputed: audit verify
  passes both (README, "Verifying a log you did not write").
- Windows, or any machine other than the one this ran on.
TEXT
sleep "${DEMO_END_PAUSE:-$PAUSE}"
