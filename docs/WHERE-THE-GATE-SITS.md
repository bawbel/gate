# Where the gate sits, and what it does not do

**Draft, for the maintainer to review.** Each statement names its source: DESIGN.md, the README, a file and line on `develop` at
`b9d76a9`, or **UNVERIFIED** where it is not read from any of them.

## What the gate sees

The gate is a proxy for MCP over standard input and output. The host talks to the gate, and the gate starts each upstream MCP server
as a local process and talks to it the same way (DESIGN.md 1; `src/bawbel_gate/mux/transport.py:51-60`). It answers `initialize` and
`tools/list`, and it decides every `tools/call`: allow, approve or deny, from the manifest, the arguments and the session's taint, and then
it writes a record (`src/bawbel_gate/mux/proxy.py:296-313`). Any other request gets `-32601`. Upstream notifications are dropped, and
`resources/read` and `prompts/get` are not proxied (DESIGN.md 3.3). One gate process holds one session (`mux/proxy.py:128`).

## What the gate does not see

| Traffic | Why the gate is not in it |
|---|---|
| **A2A**, agent to agent | It is another protocol. The gate is an MCP proxy, and multi-agent delegation is out of scope for v1 (DESIGN.md 1) |
| **gRPC, REST and message brokers** | Nothing routes them through the gate. It sees only MCP over standard input and output |
| **A direct tool call by a host that bypasses the gate** | "A host that calls upstream servers directly bypasses everything" (DESIGN.md 10, item 3), and a malicious host is not defended against (DESIGN.md 2.2). The guidance is to keep upstream credentials only in the gate's environment, so a direct connection fails to authenticate |
| **Model traffic**, prompts and completions | Out of scope for v1. Provenance of user input is assumed, not attested (DESIGN.md 1 and 10, item 1) |
| **A fetch or file read the host does itself,** not through an MCP tool | The same as a bypass |
| **What an allowed tool does once it is called** | The gate sees a call and a reply. It does not see side effects in another system (`docs/hub/ACCOUNTABILITY-LIMITS.md`) |

## It is not a sandbox

The gate does not confine a process. An upstream server runs with the gate's privileges, and what it does on the network or the file system
"is whatever you configured them to do. The gate does not restrict it" (README, "Network behavior"). The manifest limits which tools the
host may call and with which arguments. It does not limit what a permitted tool can reach.

Isolation is a separate layer. Examples of what operators pair a proxy like this with are gVisor, Firecracker, and network policy. This page names them and does not recommend one,
and none was tested with the gate here (UNVERIFIED).

## It is not a real-time or safety-instrumented component

Do not put the gate in the safety path of a control loop, and do not rely on it as a safety function. Reasons that are read from the design and the code:

- It is one Python process with a latency budget of 5 ms at the 95th percentile, excluding approval waits (DESIGN.md 11.1 and 11.2). That is a budget the design sets, not a guarantee.
- It runs one request at a time and has no timeout on an upstream read, so one slow or stalled upstream holds every call behind it (`mux/proxy.py:88-91`, `:246`).
- An approval can wait up to an hour: the configured timeout is 5 to 3600 seconds, 120 by default (`mux/config.py:34`, `:44-47`).
- There is no high availability. A crashed process loses its session and the host reconnects (DESIGN.md 11.1).

A decision that the gate makes is deterministic given its inputs, and the gate never consults model output (DESIGN.md 2.3). That is a property of how a decision is reached.
It is not a statement that the gate stops harm, and nothing here says it prevents any particular outcome.

## What this means for a deployment

1. Route every tool use that matters through MCP, and through the gate. What does not pass through it is not covered.
2. Keep the upstream credentials in the gate's environment only.
3. Run the upstream servers under whatever isolation your environment already uses for untrusted code.
4. Keep the gate out of any loop that has a deadline and a physical consequence.

## Not verified here

No isolation layer was run with the gate. Whether a given host reliably routes all tool use through the gate is a property of that host and was not checked.
