# Recording the demo

How `demo.cast` was made and how to make it again. The recording is **not** linked from the main README: that waits for the
maintainer to approve the caption (see the end of this file). This page describes `demo.sh` from pull request #268, which has to
be merged first.

## Which tools were available (2026-11-27, `command -v` on the machine that prepared this)

| Tool | Result |
|---|---|
| `asciinema` | **Found, and broken as installed.** `~/.local/bin/asciinema` starts `/usr/bin/python3` (3.12.3), and asciinema 2.4.0 is installed for Python 3.10 (`~/.local/lib/python3.10/site-packages`), so plain `asciinema` ends in `ModuleNotFoundError: No module named 'asciinema'`. With that directory on `PYTHONPATH` for the one command, `asciinema --version` prints `asciinema 2.4.0` and `asciinema rec` works. Nothing on the machine was changed |
| `vhs` | not found |
| `agg` | not found |
| `ttyd`, `ffmpeg`, `svg-term` | not found |
| `script` | found (`/usr/bin/script`) |

## How long `demo.sh` takes

Measured with the gate from `develop` (0.1.1) and `bawbel-scanner` 1.3.0 from PyPI, on one machine, one run each:

| Run | Wall time |
|---|---|
| `./demo.sh` | 5.4 s |
| `DEMO_PAUSE=1 ./demo.sh` | 40.4 s |

The script waits at 35 points: 34 pauses and the end pause (counted with `bash -x ./demo.sh`, 35 `sleep` calls), so
`DEMO_PAUSE=1` adds 35 s to the 5.4 s. With `DEMO_PAUSE=1.2 DEMO_END_PAUSE=6` the recording is **46.2 s** long, measured as the time of the
last event in the cast. The command took 52.4 s of wall time: the last 6 seconds produce no output, so they are not an event in the
cast, and a player stays on the final frame.

## The commands

On your machine, in a terminal window set to 120 columns by 36 rows, with `bawbel-gate` and `bawbel` on `PATH`:

```bash
cd examples/demo
asciinema rec --overwrite -t "bawbel-gate demo (stub servers)" \
  -c "env DEMO_PAUSE=1.2 DEMO_END_PAUSE=6 ./demo.sh" demo.cast
asciinema cat demo.cast       # prints the output without the timing, to read it through
asciinema play demo.cast      # plays it back
```

What was run to make the cast in this directory. There was no terminal to size, so a pseudo-terminal of 120 by 36 was made with
`script`, and the 3.10 directory was put on `PYTHONPATH` for asciinema only (the demo itself ran without it):

```bash
cd examples/demo
export PATH="<gate venv>/bin:<scanner venv>/bin:/usr/bin:/bin"
script -qec 'stty cols 120 rows 36; PYTHONPATH=$HOME/.local/lib/python3.10/site-packages \
  asciinema rec --overwrite -t "bawbel-gate demo (stub servers)" \
  -c "env -u PYTHONPATH DEMO_PAUSE=1.2 DEMO_END_PAUSE=6 ./demo.sh" demo.cast' /dev/null
```

`asciinema cat` was run on the result and printed 162 lines of the demo. `asciinema play` was not run, because it needs a terminal.

**Two things that change the recording:**

- **`semgrep` on `PATH` changes scene 1.** A first recording was made with `semgrep` (from `~/.local/bin`) on `PATH`. The scanner then printed a
  warning line, `[WARNING] bawbel.scanner.engines.semgrep_engine: Engine error: engine=semgrep path=/tmp/... error=None`, in the middle of its box. That is
  real output of a run, and it shows a temporary path. The cast in this directory was recorded again with `semgrep` off `PATH`.
- **The gate and scanner versions are on screen** (`bawbel-gate, version 0.1.1`, `Bawbel Scanner v1.3.0`). Record again after a release if the
  versions should match it.

## The cast in this directory

| | |
|---|---|
| File | `examples/demo/demo.cast`, 13,360 bytes, asciicast v2 |
| Size and length | 120 x 36, 46.2 s, 86 events |
| sha256 | `acd84ad43f43bbf75eba5adfe7da10a514a589f390e0575ec95ebda91b4e98c2` |
| Made from | `demo.sh` at `0b85705` (pull request #268), gate `develop` at `d5c7912` (0.1.1), scanner 1.3.0 from PyPI |
| Checked | no `/home/`, no `/tmp/`, no user name, no hostname, no warning line (searched in the output text of the cast). The header has only `SHELL` and `TERM` in `env` |

To turn it into a GIF: `agg demo.cast demo.gif`. `agg` is not installed on the machine that prepared this, so that command has not been run.

## The caption, for the maintainer to edit

Not added to the README. A draft to start from:

> bawbel-gate between a script that plays an MCP client and three stub MCP servers: a tool description that changes during a
> session, a private-data, untrusted-text, send-out sequence, and the audit log. It is a demo with stubs, not an attack on
> anything real. It does not show a real MCP client, a person answering an approval prompt, or calls that bypass the gate.

## Not done

- The recording is not at the top of the README, and no caption is committed.
- No GIF, and no run of `asciinema play` or `agg`.
- One machine, one run for each timing. Variance was not measured.

## Checked by a test

`tests/test_demo_recording.py` checks the cast: asciicast version 2, 120 by 36, a length between 30 and 60 seconds, the opening DEMO line, no local path
or warning in the output, and that the last two screens in the cast are the ones in `demo.sh`. The last check skips when `demo.sh` is not in the checkout.
