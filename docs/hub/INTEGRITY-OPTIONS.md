# Tamper-evidence beyond the chain: signed checkpoints and witnesses

Report, 2026-11-26, for [#225](https://github.com/bawbel/gate/issues/225). Report only: no code, no
test, no DESIGN.md change, and nothing chosen. It states what the audit chain plus an anchored head
shows and does not show, reads the C2SP pages on signed notes, checkpoints, cosignatures and
witnesses, and lists four options with what each closes and costs. It ends with a recommendation for
the maintainer to accept or not.

The maintainer's provisional answer of 2026-11-25 is signed checkpoints, Hub-signed first. This report
is an input to that answer and does not decide it.

The wording of this file is "tamper-evident, with these limits". It makes no claim about liability,
compliance or law. Companion reports: [THREAT-MODEL.md](./THREAT-MODEL.md) (#206),
[ACCOUNTABILITY-LIMITS.md](./ACCOUNTABILITY-LIMITS.md) (#214), [EVIDENCE-MODEL.md](./EVIDENCE-MODEL.md) (#208).

Every claim carries a tag. **VERIFIED**: run, on the date given. **SOURCED**: read from the file or page
named, on 2026-11-26, at `develop` `b9d76a9` for this repository. **DERIVED**: follows from quoted text,
and nothing was run. **UNVERIFIED**: stated without any of these, and said so.

## 1. What the chain, plus an anchored head, shows

SOURCED, DESIGN.md 8.6 and [THREAT_MODEL.md](../THREAT_MODEL.md) X9. Each record's hash covers its
content and the previous hash. `bawbel-gate audit verify` replays the chain. DESIGN.md 8.6 says the chain
head "is printed at `SESSION_END` and can be anchored externally (git note, Vault KV, or a transparency
log later)". X9 says tampering "is detected only against a chain head anchored outside the log. With no
anchored head, whoever can write the log can rebuild the chain. No asymmetric signing."

SOURCED: nothing in `src/` stores, ships or checks an anchor (`git grep -i anchor -- src` finds
nothing). The only head output is a line on standard error at the end of a session
(`mux/proxy.py`, "session end -- chain head"). VERIFIED in #215 (experiment E1) that a gate stopped with
`SIGKILL` writes no `SESSION_END`, so such a session prints no head.

What an anchor adds, where the anchor is a chain head and its `seq` that a verifier holds from a source the
log writer did not control:

| Attack on a log | The chain alone | The chain plus an anchor at `seq` N |
|---|---|---|
| Edit one record | detected | detected |
| Remove a record from the middle | detected | detected |
| Remove the last records | not detected | detected if the log now has fewer than N records, or a different hash at N |
| Rewrite the log, recomputing every hash | not detected. The hash rule is public (ADR 0001) | detected for records at or before N |
| Replace the log with an empty file | not detected | detected |
| Change anything after N | not detected | not detected |
| A forwarded call that was never recorded | not detected (#215, Limit 1) | not detected |
| False content, correctly chained | not detected (#215, Limit 3) | not detected |

The last two rows are not integrity problems of the file. No option below touches them.

What the Hub does today, SOURCED from `hub/ingest.py` and `hub/store.py` at `b9d76a9`, and VERIFIED in
#207 (H3): it keeps a head for each session in its own database, accepted a rewrite of records it already
held (C3.2), and accepted a truncated copy (C3.4). Pull request #222, open and not merged, would make it
refuse a rewrite and a seq gap. That closes the Hub silently accepting a rewrite. It does not make the Hub's own copy
tamper-evident to someone who can write its database, and nothing the Hub holds is signed.

## 2. The C2SP pages

SOURCED on 2026-11-26. I did not read these pages myself. A fetch tool read them and returned verbatim
quotes of at most 125 characters, and every quote below is copied from that report. Each fetch returned
HTTP 200 and no truncation notice. No page shows a date, a version header or a status marker. Their link
targets name `v1.1.0` for signed-note, tlog-checkpoint and tlog-cosignature. Pages read:
`c2sp.org/signed-note`, `c2sp.org/tlog-checkpoint`, `c2sp.org/tlog-cosignature` and
`c2sp.org/tlog-witness`.

| Topic | What the page says |
|---|---|
| A signed note | "A note is text signed by one or more keys." "The text MUST be ignored unless the note is signed by a trusted key and the signature has been verified." |
| Note layout | text ending in a newline, a blank line, then signature lines, each an em dash (U+2014), a space, `<key name>`, a space and `base64(32-bit key ID || signature)` |
| Ed25519 note key | type `0x01`: "Ed25519 signatures are generated according to RFC 8032 over the note text." "key ID = SHA-256(key name \|\| 0x0A \|\| 0x01 \|\| 32-byte Ed25519 public key)[:4]" |
| Verifier key | "<key name>+hex(32-bit key ID)+base64(signature type \|\| public key)" |
| Checkpoint body | "a sequence of at least three non-empty lines": the origin, "the tree size, the number of leaves in the tree encoded as an ASCII decimal", and "the base64 encoding of the root of the [RFC 6962][] Merkle hash tree at the specified tree size". Optional extension lines follow, and their use "is NOT RECOMMENDED" |
| Checkpoint consistency | "A log or cosigner MUST NOT sign any checkpoint which is inconsistent with any checkpoint it previously signed." "Two checkpoints are inconsistent if they are for the same log, and a consistency proof can't be constructed from one to the other." |
| Ed25519 log signature | "Ed25519 log signatures do not include a timestamp." The key name "SHOULD be the log origin" |
| What a cosigner says | "Semantically, a checkpoint cosignature is a statement that the specified tree hash is consistent with all other historical views of the log observed by the cosigner." "Log clients can verify a quorum of cosignatures to prevent split-view attacks before trusting an inclusion proof." |
| Witness | "A witness is an entity exposing an HTTP service identified by a name and a public key." "Witnesses verify that the checkpoint is consistent with their previously recorded state of the log (if any), and return a timestamped cosignature." |
| Witness request | `POST <submission prefix>/add-checkpoint`. The body is an old size line (`old <size>`), "zero or more consistency proof lines", an empty line and a checkpoint. "The client MUST NOT send more than 63 consistency proof lines." |
| Witness answers | `409` if the old size does not match what it last cosigned for that origin, with that size in the body. `422` "if a Merkle Consistency Proof doesn't verify". `403` for no valid signature from a trusted key. `404` for an unknown origin |
| Witness limits | "There is no authentication of requests beyond the validation of the signature on the checkpoint." A witness keeps "the latest checkpoint it observed and verified" for each origin. It is "configured with a list of supported log public keys" |

Not read: RFC 6962 itself, `tlog-mirror`, the `sign-subtree` part of the witness page beyond the fact
that it is optional, and anything else under c2sp.org.

## 3. The central finding: a checkpoint is about a Merkle tree, and the gate's chain is not one

DERIVED from the quotes above and from ADR 0001. Nothing was run against a witness.

- A checkpoint's third line is the root of an RFC 6962 Merkle tree and its second line is a leaf count. The
  gate's chain head is the hash of one record: `sha256(canonical record || previous hash text)`. It is
  not a Merkle root, and it has no tree size other than the record count.
- A witness checks a Merkle consistency proof of at most 63 hashes. A linear chain has no proof of that
  shape. The only evidence that a later head extends an earlier one is the records between them, which
  can be any number.

So a chain head cannot be submitted to a witness as the protocol is written. A witness would answer
`422`. There are two routes, and every option below that uses a checkpoint takes one of them.

**Route 1. A signed note whose body is shaped like a checkpoint, with the chain head in the third line.**
It uses the signed-note format as it is, and adapts the checkpoint body. The adaptation, field by field:

| Line | A checkpoint says | Route 1 would put | Why it is adapted |
|---|---|---|---|
| origin | the log's identifier, a string of at most 255 bytes with no spaces or `+` | a Hub-defined string that names one chain: the Hub's name, the `gate_id` and an identifier of the chain. The identifier is open: the hash of the chain's first record is one candidate | a gate's log can be rotated and start a new chain from the genesis value (DESIGN.md 13.2, retention), so a gate id alone does not name one chain. A `gate_id` today may hold characters the origin rule forbids (#207, H2) |
| tree size | the number of leaves | the `seq` of the last record in the chain, which is the record count when `seq` is contiguous (the rule #222 enforces, and DESIGN.md 13.2 in #224) | a chain has records, not leaves |
| root hash | the base64 root of an RFC 6962 tree | the base64 of the 32 digest bytes of the chain head | the head is the commitment the gate already makes (ADR 0001). It is not a Merkle root, so a standard checkpoint tool would read it wrongly. The note must say what it is, in the origin or in an extension line, so no tool treats it as a tlog checkpoint |
| extension lines | optional, not recommended | none | the page says they are not covered by every signature type |

It is not interoperable with checkpoint tooling and not usable with a witness as written. It is small.

**Route 2. The Hub keeps an RFC 6962 Merkle tree over each gate's records, and signs real checkpoints.**
It follows the C2SP formats with no adaptation and works with witnesses as written. It adds a data
structure the gate does not have: the tree lives in the Hub, with the leaf definition (for example, the
record's own hash) and the proofs the Hub must be able to produce. The gate's chain stays as the gate-side
evidence. It is a larger piece of work, and the leaf and ordering rules are decisions this report does not
make.

## 4. The options

None is chosen. "Closes" is stated against the table in section 1.

| | Option | Closes | Leaves |
|---|---|---|---|
| A | Nothing more. The head is printed at the end of a clean session and anchored by hand if the operator does it | nothing by itself. With a hand-kept anchor, the rows of section 1 for that anchor | everything the chain leaves, unless the operator keeps anchors. No Hub change |
| B | The Hub signs a checkpoint for each gate at an interval, with a key the operator holds, and the notes are exported off the Hub | an edit, truncation or rewrite of the Hub's copy by someone who can write its database and cannot sign, against a note the verifier holds | a party who holds both the key and the database, a Hub that shows different histories to different readers, records after the last note, the whole of section 1's last two rows |
| C | B, plus an external witness that cosigns each checkpoint | B, and a Hub that rewrites its own history and re-signs, or shows two readers two histories, as far as the witness's record reaches | the witness's coverage ends at the last checkpoint it saw. A witness the operator does not run is a third party. Needs Route 2 |
| D | The Hub publishes each checkpoint to an append-only place the operator chooses | B, and a Hub that rewrites its own history and re-signs, if the place is outside the Hub's control and really is append-only | whether the place is append-only is the operator's to establish. Records after the last checkpoint |

### Key management for one operator (B, C, D)

- **The algorithm.** Ed25519 is the signed-note type `0x01` (SOURCED above). The Python standard library
  has no signing primitive for it that I know of (UNVERIFIED). The project's declared dependencies are
  `jsonschema`, `pyyaml`, `click` and `anyio` (SOURCED, `pyproject.toml`). A `cryptography` package was
  present in my test environment and the project does not declare it. Signing therefore means adding a
  dependency, or a decision to sign elsewhere. Adding one is the maintainer's call, so this report adds none.
- **Where the key lives.** SOURCED in #207 (H1, C8.6): the Hub keeps its bearer tokens as plain text in the
  same SQLite database as the records. A signing key stored in that database would give no separation from
  someone who can write it. The key would have to sit in a separate file with restricted permissions, or
  be supplied at start-up from the operator's own secret store.
- **Rotation.** A new key has a new name or id. Notes already signed still verify against the old public
  key, so the old public key is kept. Which key signed which note is in the note.
- **Compromise.** Whoever holds the key can sign any history. Under B this is the main leftover. C and D
  are what narrow it, because a copy outside the Hub holds an earlier head.
- **Loss.** The Hub can no longer sign new checkpoints. Old notes still verify.

### Effort, in relative terms

A: none. B on Route 1: small to moderate, one signing step, a note writer, an export command and a
verifier, plus the dependency question. B on Route 2: large, because of the Merkle structure. C: B on
Route 2, plus running or choosing a witness. D: B, plus whatever the append-only place needs.

### Failure modes

- A signature is a statement that the Hub held this head at this time. It is not a statement that the
  records are true (#215, Limit 3).
- A checkpoint covers records up to its size. Records after it are covered by nothing until the next
  checkpoint, so the interval is the coverage. The interval is not chosen here.
- B is only as good as where the notes go. Notes kept only in the Hub's database can be removed by the
  same party who edits the rows, which makes B no better than A for that party.
- A witness that is down blocks C only if the Hub waits for it. Whether it waits is a design decision.
  The witness protocol has the witness persist its record before it answers (SOURCED), so a witness that
  lost its state would refuse (`409` or `422`) and could not be told apart from an attack without
  operator judgement.
- A gate that never ships has no checkpoint. Nothing here detects that. That is HUB-R17.
- With Route 1, a rotated log is a new chain with a new origin. The relation between the two chains is not
  recorded by anything here.

### What an offline verifier needs

For B on Route 1: the public key in the verifier-key format of signed-note, the note, and the records of
that chain. It checks the signature, replays the chain with `bawbel-gate audit verify`-style hashing, and
compares the head at the note's size with the note's third line. It then sees whether the log it holds is at
least that long and agrees at that position. For Route 2 it also needs the proof format. For C it needs
the witness's public key and its cosignature. For D it needs the place's own record of what was published
and when.

## 5. Attacks against options

| Attack | A | B | C | D |
|---|---|---|---|---|
| Someone edits or truncates the Hub's rows, no key | not detected | detected against a held note | detected | detected |
| The Hub's operator, or an intruder with key and database, rewrites history and re-signs | not detected | not detected | detected, as far as the witness saw | detected if the place is outside their control |
| The Hub shows two readers different histories | not detected | not detected | detected | detected if both read the place |
| A gate's log is edited before it is shipped | not detected | not detected | not detected | not detected |
| A compromised gate writes false records | not detected | not detected | not detected | not detected |
| Records written after the last checkpoint | not detected | not detected | not detected | not detected |
| A gate that never ships | not detected | not detected | not detected | not detected |

## 6. Recommendation

For the maintainer to accept, change or reject. Nothing is decided here.

**B on Route 1 first, with three conditions, and leave C and D open.**

1. The notes leave the Hub. An export command writes them to a file the operator can copy out. Without that,
   B protects against no one who can write the database.
2. The key is not in the Hub's database.
3. The note says plainly that its head is a chain head and not a Merkle root, so no checkpoint tool misreads
   it.

Why this and not the others. A leaves X9 as it stands. C needs Route 2 and a witness, and a witness the
operator does not run is a third party this repository does not contact. D is something an operator can do
by hand with the exported notes today, so it needs no product work. B on Route 1 matches the maintainer's
provisional answer and is the smallest step that makes the Hub's copy checkable by a party who holds a
note.

The cost to be clear about: Route 1 is not interoperable with checkpoint tooling, and it will not work with a
witness as written. If witnesses or a public log are a goal, the work is Route 2 and Route 1 is then thrown away.
So the choice that matters is the route, not the option letter.

## 7. Decisions owed

All open. None is decided here.

- Route 1 or Route 2, which is a question about whether witnesses are wanted.
- Whether to add a signing dependency, or sign outside the project's declared dependencies.
- What names one chain: the origin line's identifier, given that a log can be rotated.
- The checkpoint interval, and who exports the notes and where they go.
- Where the key lives, and who rotates it.
- Whether the Hub waits for a witness before it answers an ingest request.

## 8. Not done

- No code, no key was generated, no note was signed, and no witness or log was contacted or run.
- The C2SP pages were read through a fetch tool, with quotes copied from its report. They show no date or
  version. RFC 6962, `tlog-mirror` and the rest of the witness page were not read.
- The statement that a chain head cannot be given to a witness as written is derived from the quoted rules
  and was not tried.
- No performance was measured, and no checkpoint size or interval was chosen.
- The standard library claim in section 4 is UNVERIFIED.
- The relation between a gate's rotated chains, and a Hub that holds more than one chain for a gate, is
  not designed.

## Sources

- This repository at `develop` `b9d76a9`: DESIGN.md 8.6 and 13.2, `docs/THREAT_MODEL.md` X9,
  `docs/adr/0001-audit-chain-construction.md`, `src/bawbel_gate/mux/proxy.py`,
  `src/bawbel_gate/hub/ingest.py`, `src/bawbel_gate/hub/store.py`, `pyproject.toml`.
- The Hub threat model (#206, #207), the accountability limits report (#214, #215), and pull requests
  #222 and #224.
- `c2sp.org/signed-note`, `c2sp.org/tlog-checkpoint`, `c2sp.org/tlog-cosignature` and
  `c2sp.org/tlog-witness`, read on 2026-11-26 as described in section 2.
