# acs_check: repeat the ACS chain measurements

These scripts repeat the measurements recorded in
[docs/ACS_CONFORMANCE.md](../../docs/ACS_CONFORMANCE.md) section 6.1: a chain written by
`bawbel-gate serve` against ACS `context-entry.json`, the gate's canonical form against
RFC 8785, and ACS's own chain vector.

They are a measuring tool, not a check:

- **Read only.** They read an ACS checkout and an audit log and write nothing.
- **Offline.** `acs_check.py` makes any socket use in its own process raise. The Node
  child, `jcs.js`, is not covered by that guard. It opens no socket, and a `strace` run over
  all four subcommands showed no inet socket. Cloning ACS is your step, the script never does.
- **Not in CI.** No workflow runs them and no test imports them. Run them by hand.
- **No ACS code is executed.** The ACS repository is read as JSON data.
- **No format change.** Nothing here touches `src/`, an audit format or a hash rule.

## What you need

- A Python 3.10 or later environment where `bawbel-gate` is installed (the script imports
  `bawbel_gate.audit.canonical`) and `jsonschema` is importable. `jsonschema` is a dependency
  of the gate.
- `node` on `PATH`. It is the RFC 8785 oracle. It was run on Node 18.19.1 and 20.20.2 with the
  same results.
- Optional: the `rfc8785` Python package, used as a second oracle only if it is installed.
- An ACS checkout at a commit you name. The script prints the commit it was given.
  `vectors` needs a commit that has `reference-implementations/agt-go/internal/chain/testdata/vectors.json`.
- An audit log written by `bawbel-gate serve`. Any session will do. For `args`, also the
  arguments of each call, in call order.

```bash
git clone https://github.com/GenAI-Security-Project/agent-control-standard acs
git -C acs checkout <the commit you want to name>
```

## The four subcommands

Run each with the python of the environment where the gate is installed.

```bash
python scripts/acs_check/acs_check.py chain     --acs acs --audit audit.jsonl [--serve-stderr serve-err.txt]
python scripts/acs_check/acs_check.py args      --audit audit.jsonl --calls calls.json
python scripts/acs_check/acs_check.py canonical
python scripts/acs_check/acs_check.py vectors   --acs acs [--audit audit.jsonl]
```

| Subcommand | Measures |
|---|---|
| `chain` | M1: each record against `context-entry.json`. M2: each record's hash recomputed by the gate's rule, then with one rule changed at a time (`prev` left out of the hashed content, 32 raw bytes appended instead of the 71-byte text). Also the first record's `prev`, the chain head on `serve`'s stderr, and whether any record carries the head |
| `args` | `args_sha256` of each call against the hash of the gate's canonical form and the hash of the RFC 8785 form of the arguments you actually sent |
| `canonical` | The gate's `canonical_str` against RFC 8785 on 13 fixed JSON texts, and how many differ |
| `vectors` | ACS's own chain vector reproduced with the oracle (the check that the oracle can be trusted), then the gate's canonical bytes against RFC 8785 on ACS's entries and on your log's records |

`calls.json` is a list with one entry per `CALL_DECIDED` record, in order:
`[{"tool": "get_issue", "args": "{\"n\":1,\"x\":1.0}"}, ...]`, where `args` is the JSON text
you sent.

## Reading the result

- Every printed line is a measurement of the inputs you gave. Nothing is written from the
  design documents.
- `vectors` exits 1 and says so on stderr if the oracle does not reproduce ACS's own vector.
  Then no other number from that run can be trusted.
- Exit 2 is a usage or input error: a missing `node`, a missing ACS file, a malformed or
  empty log. It is one line, not a traceback.
- A different ACS commit can change the answers. `context-entry.json` was byte-identical at
  the two commits compared in section 6.1, and `request-envelope.json`,
  `response-envelope.json` and `ocsf-mapping.json` were not. Always record the commit.

## Limits

- One log shows only the records that session wrote. The gate writes three event types today.
- The oracles are Node and, if installed, the `rfc8785` package. They agree on 11 of the 13
  texts. For the two integers beyond 2^53 the package refuses and Node rounds to a double.
- The 13 texts are fixed in `acs_check.py` (`CASES`). Add a case there to widen the
  comparison, and say so in the section 6.1 table.
- Python 3.10 is the floor because the repository supports it. The script was run on
  Python 3.12 only.
- The second-oracle path was exercised by putting the pure Python `rfc8785` 0.1.4 package on
  `PYTHONPATH`, without `-I`, which ignores `PYTHONPATH`. It disagreed with Node on 2 of the 13
  texts, the two integers above.
