# Which upstream servers start under the environment baseline

Report, 2026-11-26, for [#244](https://github.com/bawbel/gate/issues/244). Report only: no code, no
test, no change to the baseline, and nothing decided. It tests the environment rule of DESIGN.md 3.4
([#232](https://github.com/bawbel/gate/pull/232)) and its implementation
([#233](https://github.com/bawbel/gate/pull/233)) against upstream commands that actually run.

Every claim carries a tag. **VERIFIED**: run on 2026-11-26, with the case named. **SOURCED**: read from
a file. **UNVERIFIED**: stated without either, and said so.

## The rule under test

Under #233 an upstream starts with the gate's environment filtered to a baseline, plus any names its
manifest lists under `environment.allow`. The baseline in `_const.py` is `PATH`, `HOME`, `LANG`, `LC_ALL`
and `TMPDIR` on POSIX. A name in the baseline that the gate does not itself have is not passed.

## Method

Each case starts one upstream through the gate's own request loop (`run_enforce`), on the #233 branch at
`2040f4a`, with a manifest that grants one `echo` tool. The host sends `initialize`, `tools/list` and one
`tools/call`. A case **starts** when the upstream completes the handshake, lists its tool through the
gate, and answers the call. Each case runs twice:

- `baseline`: the environment the new rule builds, with nothing declared;
- `full`: the old behaviour, the whole environment of the gate's process, as a control.

Commands that are not MCP servers (`npx` with a cached package) are started directly with the same
environment and judged by their exit status. The harness is a scratch script and is not in the
repository. It prints names and never values. The gate's own process had `PATH` (with the node and
virtualenv directories first), `HOME` and `LANG`. `LC_ALL` and `TMPDIR` were not set in it, so the
baseline passed `HOME`, `LANG` and `PATH` only and those two were not exercised.

## Results

| Case | Command | Under the baseline | Under the full environment |
|---|---|---|---|
| Python, the official SDK, by absolute path | the virtualenv's `python` and a server built on the `mcp` SDK 2.3.0 (`tests/fixtures/sdk_echo_server.py`) | **starts**, `echo` returned `hello` | starts |
| The same, found through `PATH` | `python` | **starts** | starts |
| Node, a local script | `node` 20.20.2, a stdlib-only stdio server written for this test | **starts** | starts |
| `npx`, offline, a cached package | `npx --offline -y playwright --version` | **exit 0**, prints the version | exit 0 |
| `npx`, offline, a cached package | `npx --offline -y serve --version` | **exit 0** | exit 0 |
| `uvx` | `uvx` | **not run: `uvx` is not installed** | not run |
| A published MCP server through `npx` or `uvx` | for example the reference servers | **not run**, see below | not run |

VERIFIED, all of the rows that ran. The baseline needed no declared name in any of them.

Two details. With `HOME` removed from the baseline as a diagnostic, `npx --offline` for `playwright` still
exited 0, so `HOME` was not what that run needed. That run does not say it is never needed: other tools
write caches under it. And the `serve` command printed a line that says a newer version exists. That is
the tool's own update check. I did not intend it, I do not know whether it made a network request or read
a cached answer, and I did not run it again.

## What was not run, and why

- **No published MCP server was run.** `npx -y <package>` and `uvx <package>` fetch the package and then
  run it, which means a request to a package registry and running code I have not read. The standing rule
  is not to contact a third party, and the instruction for this task did not say that registries are
  allowed. The offline npm cache holds no MCP server (VERIFIED: a search of its index for names that
  contain `mcp` or `modelcontextprotocol` found none), so there was nothing to run offline. This is the
  main gap in the report.
- **`uvx` is not installed**, and I did not install it. The earlier decision not to install Bun or Go was
  about those two. I applied the same caution to `uv`.
- **The node case is a stand-in.** A local script shows that `node` starts under the baseline. It does not
  show how a published Node server behaves.
- **Windows and macOS** were not run. The Windows baseline (`PATH`, `PATHEXT`, `SYSTEMROOT`, `COMSPEC`,
  `TEMP`, `TMP`) is untested.
- **The full environment control** passed the whole environment of the process that ran it, which
  included credentials of that session, to two offline `npx` commands and to local scripts. That is the
  old behaviour, which is why #231 exists, and I note it here.

## What this does and does not show

It shows that a Python server built on the official SDK, a Node process and an offline `npx` start with
`PATH`, `HOME` and `LANG` and nothing else, on this machine. It does not show that a server that fetches
packages, reaches the network through a proxy, reads a cache under another variable, or needs a
credential will start. Such a server needs its names declared in `environment.allow`, which is the rule's
purpose. The baseline was not changed to make any case pass.

Names that such servers may need are candidates for the manifest, not for the baseline, and none was
tested: a proxy setting, a certificate bundle, an XDG directory, a package manager's cache or registry
setting, and the server's own credentials. This list is UNVERIFIED.

## To finish the report

With the maintainer's go-ahead to use the public package registries, the missing rows are a published
reference server through `npx -y` and one through `uvx`, each under the baseline and the full
environment, in a scratch home and cache. I would run them the same way and add them here. Without the
go-ahead they stay unrun.

## Sources

- `src/bawbel_gate/mux/environment.py`, `_const.py` and `mux/proxy.py` on the #233 branch (`2040f4a`);
  DESIGN.md 3.4 in #232.
- Runs on 2026-11-26 on one Linux host: Python 3.12 with `mcp` 2.3.0, Node 20.20.2, npm 10.8.2, an offline
  npm cache. `uv`, `uvx`, `deno`, `bun` and `go` were not installed.
