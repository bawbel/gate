# What the gate can attest: completeness and execution outcomes

Report, 2026-11-25, for [#214](https://github.com/bawbel/gate/issues/214). Report only: no code, no
test, no DESIGN.md change, and nothing chosen. It states what the audit log and the Hub's copy of it
can and cannot show, tests the two limits that matter most, and lists options for narrowing the rest.
Companion reports: [EVIDENCE-MODEL.md](./EVIDENCE-MODEL.md) (#208), [THREAT-MODEL.md](./THREAT-MODEL.md)
(#206).

The wording of this file is "tamper-evident, with these limits" and "technical evidence that helps an
investigation". It makes no claim about liability, responsibility, compliance or law.

Every claim carries a tag. **VERIFIED**: run on 2026-11-25, with the run named. **SOURCED**: read from
the file named, at `develop` `92ea9d3`. **UNVERIFIED**: stated without either, and said so.

## What a hash chain does and does not show

SOURCED, DESIGN.md 8.6 and [THREAT_MODEL.md](../THREAT_MODEL.md) X9. The chain shows that a record was
not edited after it was written, and that records were not removed from the middle. It does not show
that every call was recorded, that what was recorded is true, that the last records were not removed,
or that the whole log was not rewritten. Detecting the last two needs a chain head kept outside the
log.

The sections below take the limits one at a time.

## Limit 1: a forwarded call can leave no record

**What the code does.** SOURCED: in `mux/proxy.py` the proxy resolves the decision, forwards the call to
the upstream with `_forward_and_tag`, and only then calls `_audit_call`. The writer opens the file,
appends one line and closes it, with no `fsync` (`audit/writer.py`). DESIGN.md says records are durable
before they are sent to the Hub (13.2, the cursor), and says nothing about the order of forwarding and
recording.

**What a run showed.** VERIFIED (experiment E1). A real `bawbel-gate serve` was given an upstream that
blocks when it receives `tools/call`. One allowed call was sent. When the upstream had received it, the
gate was stopped with `SIGKILL`.

```text
the upstream received the call: True
the gate was stopped with SIGKILL, exit status: -9
records in the audit log: [(1, 'SESSION_START', None, None)]
a CALL_DECIDED record exists for the forwarded call: False
a SESSION_END record exists: False
```

**What follows.** A call the gate allowed and forwarded can have no record if the gate stops between
the forward and the write. That covers an abrupt stop, and also a call that is still running upstream.
A log that ends without `SESSION_END` shows that the session ended unusually, and shows nothing about
what was forwarded. A reader cannot tell from the log whether a call was in flight.

**Not run.** A stop with `SIGTERM`, a stop by the operating system, and a power loss. The write uses no
`fsync`, so a record that was written may also be lost with the machine. The loss on power failure is
SOURCED from the writer and was not run.

## Limit 2: nothing checks that `seq` is contiguous

**What the code does.** SOURCED: `verify_chain` in `audit/writer.py` checks `prev` and `hash`. The Hub's
`process_batch` checks `prev` and `hash`, and uses `seq` only to skip records it has seen.

**What a run showed.** VERIFIED (experiment E2). Chains built with the gate's own hash function, with
correct links and a `seq` that skips or starts high:

| Chain `seq` | `audit verify` | The Hub's ingest |
|---|---|---|
| 1, 2, 3, 4 | `ok: 4 records, chain intact` | accepted |
| 1, 2, 5, 6 | `ok: 4 records, chain intact` | accepted |
| 7, 8, 9 | `ok: 3 records, chain intact` | accepted |
| 1, 2, 2, 3 | `ok: 4 records, chain intact` | refused: chain mismatch |

**What follows.** A gap in `seq` is not a signal that either verifier uses. A removal that is
re-linked into the chain is not caught by the chain, and `seq` could have caught it but nothing reads
it. A party who can recompute every hash can also renumber, so this narrows the limit and does not
close it.

## Limit 3: the contents are the gate's word

SOURCED and VERIFIED. The chain makes a record tamper-evident. It does not make it true. A compromised
gate host can write false records with a correct chain. VERIFIED in the Hub threat model (#207, C2.2):
a validly chained session of different content, shipped under another gate's id, was accepted with HTTP
200. The Hub cannot tell a true chain from a false one, and today it cannot tell a rewrite of records it
already holds from a replay (#207, C3.2).

## Limit 4: the clock

VERIFIED, five records: `ts` is UTC with milliseconds, set by the gate when it writes the record. No
other clock backs it. Since the record is written after the call completes (Limit 1), `ts` marks the end
of the call, and an approval wait is inside it (the evidence model, #208).

## What the gate can attest about an execution outcome

SOURCED, `mux/proxy.py` and `_const.py`.

| Question | What the gate can say | What it cannot say |
|---|---|---|
| Was the call decided? | yes: the `CALL_DECIDED` record, when it was written (Limit 1) | |
| Was it forwarded? | the record says `allow` or `approve` and no `deny`. That means the gate meant to forward it. There is no separate record at the moment of forwarding | that the forward happened, if the record is missing (Limit 1) |
| Did the upstream receive and run it? | the gate reads the upstream's reply on the same pipe | what the upstream did. The reply is not recorded: `_audit_call` takes the decision and no response, and `RESPONSE_RECEIVED` is defined and never written |
| Did it succeed? | nothing in the record | success or failure. An allowed call that the upstream refused is still `effect: allow` |
| What did it change downstream? | nothing | the gate sees a call and a reply. It does not see a system's side effects |

## What a downstream system must attest itself

Bawbel cannot attest these, and the report does not suggest it should:

- that it received the request, and when, by its own clock;
- what it executed and with which authority;
- the result, and any side effect;
- its own log of the above, kept where the gate does not control it.

If an investigation needs them, they come from the downstream system's own records. A receipt signed
by the upstream and kept with the gate's record would be one way to link the two. That is outside what
the gate does today, and this report does not propose it.

## Options for narrowing the limits

Options only. None is chosen. Each says what it closes and what it leaves. Under CONTRIBUTING, any
change to a record is a DESIGN.md change that merges alone first, and a change to the chain
construction needs an ADR.

| | Option | Closes | Leaves | Cost |
|---|---|---|---|---|
| O1 | Check `seq` for gaps, in `audit verify` and in the Hub's ingest | a removal that is re-linked without renumbering (Limit 2) | a rewrite that renumbers. The rule must allow that `seq` continues across the sessions in one file (#159) | small. No format change |
| O2 | A write-ahead record: the gate writes a record at the moment it decides to forward, before it forwards, and a second record when the upstream answers | a forwarded call with no record (Limit 1) | what the upstream did. Two records per call | a format change, and a doubled record count. Variants: A, both records. B, the first only. C, neither, and document Limit 1 |
| O3 | Flush the record to disk after each write | a record lost on power failure after it was written | the order problem of Limit 1 | latency on every call |
| O4 | Authenticated sources: a per-gate credential and TLS in front of the Hub (#180) | records from something that is not the gate (Limit 3, in part) | a compromised gate, which holds its own credential | the credential model, which is drafted and not built |
| O5 | A second clock: the Hub records its own receipt time for each batch, outside the record | a gate that backdates records it has already shipped | records not yet shipped, and any backdating before the first send | small, in the Hub only |
| O6 | Signed checkpoints of the chain head, held outside the gate | removal of the last records, a consistent rewrite, and an empty file, after the checkpoint (the limits in the first section) | records written after the last checkpoint | key management. This is the subject of the integrity options report, which is not written yet, so this option is listed and not evaluated here |

## What a decision record would need to show its inputs and rule

The gate decides from structured inputs only and never consults model output (SOURCED, DESIGN.md 2.3),
so a record can state what produced a decision without a model's reasoning. DESIGN.md 2.3: "No enforcement decision consults model output." Today a `CALL_DECIDED`
record holds the result and some of the inputs.

| Input to the decision | In the record today | Note |
|---|---|---|
| The manifest | yes: `manifest_sha256` | the content itself is not in the log |
| The tool and the server | yes | |
| The arguments | only as `args_sha256` | a reviewer cannot re-run the decision without them. `--store-args` is named in DESIGN.md 8.6 and does not exist |
| The session's taint | yes: `taint` | the flags `private_touched` and `untrusted_seen`, which the trifecta rule reads, are not recorded |
| Which grant matched | no | the `Decision` type has a `rule_ids` field. Nothing in `src/` fills it, so it is always empty, and the record does not write it |
| The reason | yes: `reason` | for a refused approval the original cause is dropped (#158) |

Options, none chosen: fill and write the matched rule ids and write the two session flags (small, additive), keep the
arguments out of the log as now, or add `--store-args` as DESIGN.md 8.6 already says.

## Decisions owed

Open, none decided here: whether the gate writes a record at the moment it forwards a call (O2 and its
variants), and whether `seq` gaps are checked (O1). The accountability work also depends on two open
decisions listed in the evidence model: whether it stays inside the gate and the Hub, and whether the
Hub keeps incident objects of its own.

## Not done

- No fix, no code, no test, and no DESIGN.md change.
- A stop with `SIGTERM`, a stop by the operating system and a power loss were not run.
- The Hub's second clock (O5) and the checkpoints (O6) were not built or tried.
- The report on signed checkpoints and witnesses is not written, so O6 is not evaluated.

## Sources

- This repository at `develop` `92ea9d3`: `src/bawbel_gate/mux/proxy.py`, `audit/writer.py`, `_const.py`,
  `hub/ingest.py`, DESIGN.md 2.3, 8.6 and 14.4, `docs/THREAT_MODEL.md`.
- Experiment E1: `bawbel-gate serve` 0.1.1 with an upstream that blocks on `tools/call`, stopped with
  `SIGKILL`. Experiment E2: chains built with the gate's hash function, checked by `bawbel-gate audit verify` and by `process_batch`.
  Both run 2026-11-25 in a fresh virtualenv with an empty `HOME`. The scripts are not in the repository.
- The Hub threat model (#206, PR #207) and the evidence model (#208, PR #209).
