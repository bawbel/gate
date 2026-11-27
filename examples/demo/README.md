# DEMO: the gate and the scanner, with stub servers

This is a demo. The three MCP servers in it are **stubs** (`stub_server.py`): fixed replies, local files only, **no network**.
They are not an attack on anything real. The "client" is a script (`driver.py`) that sends fixed JSON-RPC lines. Every line of
output that `demo.sh` shows comes from a run of the command printed above it.

## What you need

- A clone of this repository. `examples/` is not in the PyPI package.
- `bawbel-gate` and `bawbel` (the scanner) on your `PATH`: `pip install bawbel-gate bawbel-scanner`.
- `bash` and `python3`. Linux and macOS. The gate does not support Windows yet (see the main README).
- Nothing else. Installing needs a network. Running the demo does not use one.

## Run it

```bash
cd examples/demo
./demo.sh                  # about 5 seconds
DEMO_PAUSE=2 ./demo.sh     # a 2 second pause after each caption and each command
DEMO_PAUSE=2 DEMO_END_PAUSE=6 ./demo.sh   # and hold the last screen for 6 seconds
```

The script copies this directory into a temporary one and removes it at the end, so the repository stays clean and every path on
screen is relative.

## The scenes

| Scene | What runs | What you see |
|---|---|---|
| 1 | `bawbel scan stub-server.json` | the scanner's real result for the file that lists the three stubs' tools. At the version this was written against it reports no findings |
| 2 | `gate.a.yaml`: the gate with one stub server (`notes`) and a manifest that allows one tool | calls go through, and each is recorded |
| 3 | the same session, a description change after call 3 | see the next section |
| 4 | `gate.b.yaml`: three stubs, one per leg (private data, untrusted text, send out) | the outbox tool alone is allowed. Read notes, then fetch the page, then send the report: the third call is denied with `approval_denied` and nothing is written to `sink.txt` |
| 5 | `bawbel-gate audit verify gate.audit.jsonl` | `ok: 14 records, chain intact` for the three sessions |
| last | text | what the demo does not show |

**The approval limit, stated as the main README states it.** Under an MCP client the terminal approval prompt cannot be answered,
so every `approve` resolves to `deny` (see "Approvals" in the main README). The driver sends its next request at once, as a client
does, and that request gets no answer. The gate's prompt text says `denied by operator`. No person was asked.

## What the gate does when a tool's description changes during a session

Read from the code and DESIGN.md before the demo was built (`develop` at `d5c7912`, 2026-11-27), then run in scene 3.

**It does nothing.** It does not deny the call and it does not flag it. In detail:

1. **The check runs once, at session start.** `_check_drift` is called from one place, `_bootstrap`
   (`src/bawbel_gate/mux/proxy.py:152-153`), and only when the manifest has a stored pin. The session lifecycle in DESIGN.md
   (lines 567-585) has one `VERIFY` step, before `ACTIVE`. Nothing returns to it.
2. **`tools/list` is answered from the list taken at session start.** `_dispatch_enforce` returns `ctx.merged_tools`
   (`proxy.py:307`), which `_bootstrap` built once. The host keeps seeing the old text.
3. **The upstream's `notifications/tools/list_changed` is dropped,** not forwarded (`proxy.py:271`).
4. **Calls are forwarded as before.** `_handle_tools_call` (`proxy.py:316`) neither hashes nor re-lists, and writes its normal
   `CALL_DECIDED` record.
5. **There is no `DRIFT_DETECTED` record and no alert** for a change during a session. Scene 3 prints the event counts: 0.

What that means: the gate does not catch a description that changes after the session has started. The host's `tools/list`
stays on the old text, and nothing records that the server's text changed. A host that connects straight to the server sees the
new text, which scene 3 also shows. At the next session
start the gate compares the server's list with a stored pin, if the manifest has one (`proxy.py:152`). This demo uses no pin
and does not show that comparison.

`tests/test_demo_driver.py` pins this behaviour. If the gate starts to notice a change during a session, that test fails and
this section and scene 3 need to change with it.

## What this demo does not show

- A real MCP client or a real MCP server.
- A person answering the approval prompt.
- Calls that never reach the gate: a host talking to a server directly, A2A, gRPC, REST, message brokers, and model traffic.
  The gate sees MCP calls routed through it, and no more.
- Any check of tool descriptions after the session started.
- Tool-schema pinning. The demo does not pin.
- A log cut at the end, or rewritten with every later hash recomputed: `audit verify` passes both (see "Verifying a log you
  did not write" in the main README).
- Windows, or any machine other than the one the demo was run on.

## Files

| File | What it is |
|---|---|
| `demo.sh` | the scenes above |
| `driver.py` | the client: fixed sessions, and a view of the audit log. Standard library only |
| `stub_server.py` | the stub MCP server, one role per process: `notes`, `web`, `outbox`. Standard library only |
| `stub-server.json` | the three stubs' reviewed tool lists. This is the file the scanner reads in scene 1 |
| `notes.txt` | the fake text `notes` returns |
| `manifests/`, `gate.a.yaml`, `gate.b.yaml` | the gate's manifests and its two configs |

The tests for the driver and the stub are `tests/test_demo_driver.py`. They also run the demo's two session types through the
real gate.
