# Hub UX research: personas, screens, content rules and a usability script

Report, 2026-11-26, for [#248](https://github.com/bawbel/gate/issues/248). Report only: no code, no test, no
DESIGN.md change, and nothing chosen. It describes who would use the Hub console, what each of them has to
see, ten screens drawn only from data the Hub has or could have, the rules for the words on those screens,
an accessibility checklist, and a script for testing the screens with people.

**No user research was done for this report.** The personas are hypotheses written from the Hub's own
documents. There are no user quotes, no interview findings and no usage data in it, and none should be
read into it. The usability script at the end is how the hypotheses would be tested.

The wording of this file is "tamper-evident, with these limits" and "technical evidence that helps an
investigation". It makes no claim about compliance, certification or law. Companion reports:
[THREAT-MODEL.md](./THREAT-MODEL.md), [EVIDENCE-MODEL.md](./EVIDENCE-MODEL.md) (questions I1 to I10 and Q1 to
Q10), [ACCOUNTABILITY-LIMITS.md](./ACCOUNTABILITY-LIMITS.md), `EXPORT-FORMATS.md` (#246, not merged).

Every claim carries a tag. **VERIFIED**: run, on the date given. **SOURCED**: read from the file or page
named, on 2026-11-26, at `develop` `b9d76a9` for this repository. **HYPOTHESIS**: a persona claim, to be tested.
**UNVERIFIED**: stated without any of these, and said so.

## 1. What exists today

SOURCED, `hub/server.py`, `hub/store.py`, `hub/fleet.py`. The console is one HTML page. It fetches
`/v1/fleet/state` every 5 seconds and prints the JSON in a `<pre>` element, authenticating with the admin
token in the URL query (`?t=`). The state is a set of counters for each gate: allow, approve and deny counts,
trifecta trips, drift events and a session count. There is no page for a gate, a session or an event.

What the Hub stores, from the schema: a `gates` table with `gate_id` and `enrolled_at`; an `audit_records`
table with `gate_id`, `session_id`, `seq`, `event`, `effect`, `reason`, `server`, `tool`, `hash`, `prev` and the
whole record as `record_json`; a head per session in `chain_heads`; counters in `session_state`; enrollment
and admin tokens. It does **not** store: when a batch arrived, the gate's version, the time of a record as a
column (`ts` is inside `record_json`), who did an admin action, or any checkpoint.

The Hub has no write path back to a gate and no decision route. The screens below keep that: nothing on
them sends anything to a gate, approves a call or changes a manifest (DESIGN.md 14.6, 13.4).

## 2. Personas

Five hypotheses. For each: the top three jobs, what they must see in under 10 seconds, and what would make
them distrust the tool. The jobs come from the incident questions I1 to I10 in the evidence model.

### P1. SOC analyst

- **Jobs.** (1) Triage a denial or a drift alert: what was asked, by which server, why it was refused (I6).
  (2) Follow one session from its start to its end. (3) Tell whether a gap in the data means "nothing
  happened" or "the data did not arrive".
- **Under 10 seconds.** Which gates reported in the last hour, how many denies and drift events there were,
  and whether any chain failed.
- **Distrust.** A count they cannot click through to the records behind it. A time that is not UTC. A screen
  that is green when a gate has gone silent. A record shown without its hash and its position.

### P2. Security architect

- **Jobs.** (1) Check what policy was in force for a call, by digest (I4, I9). (2) See which tools and servers
  are actually used against what was granted. (3) Decide whether the Hub can sit in the deployment without
  giving the gates anything new to depend on.
- **Under 10 seconds.** The manifest digest of each gate and whether it changed between sessions (I8), and the
  read-only property stated on the page.
- **Distrust.** Any control that looks like it could act on a gate. A shared bearer in a URL. A claim about
  what the Hub covers that the documents do not support.

### P3. CISO or deputy

- **Jobs.** (1) Answer "what do we know, and what do we not know" about agent activity this month. (2) Hand
  something to an auditor or an outside reviewer without re-describing it. (3) See whether the evidence
  can be checked without trusting the vendor.
- **Under 10 seconds.** A plain statement of what is covered, what is not, and how fresh it is.
- **Distrust.** A score or a grade with no stated basis. Any word that claims protection or compliance. A
  number that changes when nothing happened.

### P4. GRC or internal audit

- **Jobs.** (1) Export a bounded set of records with the means to verify them offline (I10). (2) Check that
  the export says what it omits and whether the chain was verified. (3) Record which human did what in the
  tool itself, including enrollment and token changes.
- **Under 10 seconds.** What an export contains, what it leaves out, and the chain head and record count it
  was built from.
- **Distrust.** An export that looks like a copy of the log and is not. A gap that is not named. An admin action
  with no record of who did it.

### P5. Platform operator

- **Jobs.** (1) Enroll and retire gates. (2) Find out why a gate has stopped reporting. (3) Rotate the admin
  credential and back up the database.
- **Under 10 seconds.** Which gates are silent, since when, and whether the last batch was refused and why.
- **Distrust.** A token that cannot be revoked. A refused batch that leaves no trace. A backup that has no
  stated way to be restored.

## 3. Information architecture

Seven top-level places, in this order. The names are the words the screens use (section 5).

```
Fleet                      one row per gate: freshness, chain, counts
  Gate                     one gate: sessions, manifests, versions it reported
    Session                one session: its records in order
      Event                one record: all members, its hash and position
Search                     records across gates, filtered
Integrity                  chain status, what is covered, anchors and checkpoints
Freshness and gaps         silent gates, refused batches, seq gaps
Export                     bounded export with offline verification
Administration             tokens, enrollment, Hub's own admin actions
```

There is no "Policy" or "Approvals" place. The Hub shows the manifest digest a call was decided under and does
not hold the manifest, and it decides nothing.

## 4. The ten screens

Every wireframe is **SAMPLE** data and says so in its frame. Times are UTC. A box marked `[not recorded]`
shows a thing the log does not hold, instead of leaving it out: the evidence model's rule is that the screen
says what the evidence does not show.

For each screen: what feeds it, and whether that exists today.

### 4.1 Fleet

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Fleet                                          2026-11-26 14:02 UTC     |
| 3 gates | read-only: this Hub cannot send anything to a gate            |
+-------------------------------------------------------------------------+
| Gate            Last batch (UTC)       Chain      Allow Appr. Deny Drift|
| gate-sample-01  2026-11-26 14:01       intact      412    3    9    0   |
| gate-sample-02  2026-11-26 09:40  (4h) intact      188    0    2    1   |
| gate-sample-03  never reported         no data       -    -    -    -   |
+-------------------------------------------------------------------------+
| Covered: records the gates sent. Not covered: records not yet sent,     |
| records never written, whether the content is true.            [Limits] |
+-------------------------------------------------------------------------+
```

- **Feeds it.** Counters per gate: exist. "Chain intact": the Hub can recompute from stored rows, but it does
  not do so today. "Last batch": **does not exist**, since the Hub stores no receipt time. The gate's own `ts`
  must not stand in for it, because a gate controls its clock (#215, Limit 4). A gate that is enrolled and
  never shipped is absent from the state today (#207, C3.6), so "never reported" needs the `gates` table.

### 4.2 Gate detail

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| gate-sample-01            enrolled 2026-11-01 08:00 UTC                 |
| Gate version        [not recorded]     Agent / owner   [not recorded]   |
+-------------------------------------------------------------------------+
| Manifests in force at the last session start                            |
|   github   sha256:77e0...a1   same as the previous session              |
|   files    sha256:c41d...09   CHANGED since 2026-11-20                  |
| Sessions: 14   Records: 1,206   First seq 1   Last seq 1,206            |
| [Sessions]  [Search this gate]  [Integrity]                             |
+-------------------------------------------------------------------------+
```

- **Feeds it.** `manifest_hashes` in each `SESSION_START`, and the digest in each decision: exist. "Changed
  since" is a comparison between sessions (Q6): derivable. Gate version and agent or owner: **not in the
  records** (evidence model, Q1 and Q7), so the screen shows `[not recorded]`.

### 4.3 Event search

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Search   Gate [all v]  Event [CALL_DECIDED v]  Effect [deny v]          |
|          Server [any]  Tool [         ]  From [2026-11-25 00:00] UTC    |
|          To [2026-11-26 14:00] UTC                       [Search]       |
+-------------------------------------------------------------------------+
| 9 records                                                               |
| When (UTC)           Gate            Server  Tool        Effect  Reason |
| 2026-11-26 13:50:12  gate-sample-01  github  create_pr   deny    no_grant |
| 2026-11-26 11:02:44  gate-sample-01  files   delete_all  deny    no_grant |
+-------------------------------------------------------------------------+
```

- **Feeds it.** Gate, session, event, effect, server and tool are columns: exist. **A time range is not
  indexed**: `ts` lives inside `record_json`, so a time filter needs a column or a JSON extraction. Free text
  over `tool` and `reason` shows attacker-influenced strings and must escape them (#207, H7).

### 4.4 Event detail

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Record  gate-sample-01 / session 6f1c... / seq 1042                     |
| 2026-11-26 13:50:12.220 UTC (gate's clock)       event CALL_DECIDED     |
| Decision: deny   Reason: no_grant   Server: github   Tool: create_pr    |
| Taint at decision: tool.response.github   AVE: AVE-2026-00038           |
| Arguments: not stored (digest only) sha256:ab12...   Result: [not recorded]|
| Position: record 1042 of 1206 in this session chain                     |
|   prev sha256:e3d1...   hash sha256:90fa...   chain check: intact       |
| [Previous record] [Next record] [Raw JSON]                              |
+-------------------------------------------------------------------------+
```

- **Feeds it.** Every member shown exists in a `CALL_DECIDED` record, except that the taint shown is the one
  the decision was made against only after #243 merges (today it is read after the call). The raw record is
  `record_json`. The result is never recorded.

### 4.5 Chain and integrity

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Integrity   gate-sample-01                                              |
| What this checks: each record was not edited, and none was removed from |
| the middle of what the Hub holds.                                       |
| Session   Records  seq 1..N contiguous  prev/hash links   Head          |
| 6f1c...   1,206    yes                  intact            sha256:90fa...|
+-------------------------------------------------------------------------+
| Anchors held outside the Hub:        none                               |
| Signed checkpoints:                  none                               |
| So the Hub cannot show that the last records were not removed, that     |
| the log was not rewritten, or that every call was recorded.             |
+-------------------------------------------------------------------------+
```

- **Feeds it.** Head per session: exists. Contiguity of `seq`: refused at ingest after #222 and checkable on
  stored rows. Anchors and checkpoints: **do not exist**, and the options are in
  `INTEGRITY-OPTIONS.md` (#226, not merged). The sentence under the box is the content rule of
  section 5 in action.

### 4.6 Freshness and gaps

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Freshness and gaps                                                      |
| Gate            Last batch (UTC)   Silent for   Last refused batch      |
| gate-sample-02  2026-11-26 09:40   4 h 22 min   none                    |
| gate-sample-03  never              -            2026-11-26 13:12: seq_gap|
+-------------------------------------------------------------------------+
| A silent gate and a gate with nothing to report look the same here.     |
| The Hub cannot tell them apart.                                         |
+-------------------------------------------------------------------------+
```

- **Feeds it.** "Last batch" and "silent for": **not stored today**. "Last refused batch" and its reason:
  the 409 and 422 answers exist after #222, but the Hub keeps no record of a refusal (the `quarantine` table
  has no caller, #207, H5), so the screen needs one. The sentence in the box is true and must stay.

### 4.7 Evidence export

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Export   gate-sample-01   session 6f1c...                               |
| Format [native JSONL v]   Verify first [x]                              |
| This export contains   1,206 records, seq 1..1206                       |
| It leaves out          nothing (native)                                 |
| Built from chain head  sha256:90fa...                                   |
| Verify offline with    bawbel-gate audit verify <file>                  |
|                                                       [Download]        |
+-------------------------------------------------------------------------+
```

- **Feeds it.** A Hub-side export **does not exist**. The gate-side `audit export` is a draft (DESIGN.md 8.7,
  #202). The first-line rules and the loss table are in `EXPORT-FORMATS.md` (#246, not merged). The
  screen states the omissions and the chain head before the download, and never offers a format that hides
  what it dropped.

### 4.8 Settings and tokens

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Administration > Tokens                                                 |
| Admin credential    created 2026-11-20 06:00 UTC    no expiry           |
|                                                       [Rotate]          |
| Enrollment tokens   1 unused, 2 used                  [Create token]    |
| Roles: one admin credential only. Viewer role: not available.           |
+-------------------------------------------------------------------------+
```

- **Feeds it.** `admin_tokens` and `enrollment_tokens` exist with a creation time. There is one admin bearer
  that never expires, no role and no revocation (#207, H1, C8.8). "Rotate" and a viewer role are planned
  (HUB-R13) and are **not built**, so the screen shows them as unavailable and does not draw working buttons.
  A token is shown once at creation and never in a URL.

### 4.9 Administration log

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Administration > Hub's own actions                                      |
| When (UTC)           Who           Action              Target           |
| 2026-11-26 08:00:03  [not recorded] token created      enrollment       |
| 2026-11-26 08:04:19  [not recorded] gate enrolled      gate-sample-03   |
+-------------------------------------------------------------------------+
| Who: the Hub has one shared credential, so it cannot say who acted.     |
+-------------------------------------------------------------------------+
```

- **Feeds it.** **Does not exist.** The Hub writes no record of its own admin actions. With one shared bearer
  it could record the action and not the actor, and the screen must say so. An append-only table is planned
  (HUB-R13).

### 4.10 Empty and error states

```
+--SAMPLE DATA, NOT REAL--------------------------------------------------+
| Empty    No gate has been enrolled. Create an enrollment token under    |
|          Administration, then run `bawbel-gate enroll`.                 |
| Empty    gate-sample-03 has enrolled and has not sent anything. This    |
|          is different from a gate with nothing to report.               |
| Error    The Hub could not read its database. Nothing on this page is   |
|          current. Last good read: 2026-11-26 13:58 UTC.                 |
| Error    Chain check failed for session 6f1c... at seq 733: prev does   |
|          not link. Records after seq 733 are shown with a warning.      |
+-------------------------------------------------------------------------+
```

- **Feeds it.** Counters and heads exist. A chain-check result per session is derivable. The "last good read"
  timestamp must come from the Hub's clock.

## 5. Content rules

1. **Plain words.** Short sentences. "The gate refused the call" and not "a policy violation was mitigated".
   A term of art (taint, trifecta, drift) is defined on the page that uses it, in one line.
2. **Say what is not covered, on the screen.** Fleet, Integrity and Export each carry a "not covered" line.
   Nothing is omitted to make a page look complete: a missing member is shown as `[not recorded]`.
3. **No score, grade, badge or traffic light without a stated basis.** A status has a rule that is shown. Green
   means "the Hub recomputed the chain and it linked", and never "good".
4. **Words that are not used:** any word that claims protection, safety, compliance, certification, audit status,
   immutability or proof, and any commercial or hosting wording. "Verified" appears only next to the
   check that was run and its date. The wording is "tamper-evident, with these limits".
5. **Dates are UTC,** written `2026-11-26 14:01 UTC`, with the relative time ("4 h ago") in the element's
   hover text and in a visually hidden span, not as the only form. A gate's own timestamp is labelled "gate's
   clock". A time the Hub assigned is labelled "received".
6. **Numbers come from the data,** with the query that produced them one click away. No number is typed into a
   page. Counts of events say which events (the gate writes five types).
7. **Hashes are shown shortened with the full value on demand,** never altered, and copyable.
8. **Attacker-influenced text** (`tool`, `reason`, `server`) is escaped and shown as text, never as markup or a
   link (#207, H7).
9. **SAMPLE.** Anything built from fixtures carries a "SAMPLE DATA" banner on every page, `sample: true` in
   every record, and the word in the file name.
10. **Read-only.** No control on any page sends anything to a gate. The only state changes are in
    Administration (create or rotate a token, enroll, revoke), and each of them is recorded.

## 6. Accessibility checklist

For the implementation. UNVERIFIED: I did not read the WCAG text for this report. These are the checks I
would make, to be matched against WCAG 2.2 success criteria when building, and nothing here claims
conformance.

- Every action works from the keyboard, in a logical order, with a visible focus indicator.
- No information is carried by colour alone. Chain status, effect and age each have a word or symbol with a
  text alternative.
- Text and interactive elements meet the contrast minimum of the criteria in use, in both light and dark
  themes, and the page is readable at 200 percent zoom and at 320 CSS pixels wide without two-direction scrolling.
- Tables have header cells, a caption and a way to skip to the results. A table of hundreds of rows is paged and
  the page does not move when it refreshes.
- Auto-refresh (the present console refreshes every 5 seconds) is off by default or can be paused, and never
  moves focus or replaces the element being read.
- Relative times have an absolute form in text. Hover text is not the only place a value appears.
- Errors say what happened and what to do, are announced to assistive technology, and keep the user's input.
- Forms have labels, and a token is shown in a field that can be selected and copied.
- No content flashes. Motion is not needed for meaning.
- A screen-reader pass and a keyboard-only pass are part of the usability script below.

## 7. Usability script, 30 minutes

**Setup.** The Hub is built from the SAMPLE fixtures: three gates, one silent for more than a day, one with a
drift event, one never reported, and a session with a refused batch. The participant is one of the five
personas, or close to it. The facilitator reads the task and does not hint. One observer takes notes. Nothing the
participant says is edited afterwards. No result is recorded in this document: the table below is the script,
and its results column stays empty until sessions are held.

| Minutes | Task | Pass criteria |
|---|---|---|
| 0 to 3 | Welcome, read the consent line aloud, explain that the data is SAMPLE and that we test the screens, not the person. Ask what they do today with agent logs | Participant has said yes to recording notes |
| 3 to 9 | **Task 1.** "Which gates have not reported in the last 24 hours?" | Names both silent gates, and says that the Hub cannot tell a silent gate from one with nothing to report. Time under 90 seconds, no help |
| 9 to 15 | **Task 2.** "Find the calls the gate refused yesterday for the `files` server and open the most recent one." | Reaches the event detail. Reads out the reason. Says the arguments are not stored. Does not read a count as an answer without opening the records |
| 15 to 20 | **Task 3.** "Can you tell whether this gate's log has been altered?" | Opens Integrity. States what the check covers and what it does not (the last records, a full rewrite). Does not answer "yes, it is fine". Reads the anchors line |
| 20 to 25 | **Task 4.** "Prepare something you could give an auditor for session 6f1c, and say how they would check it." | Finds Export. States what is omitted and the chain head. Names the offline check. Notices the format's loss line |
| 25 to 28 | **Task 5.** "Who created the enrollment token for gate-sample-03, and when?" | Finds the Administration log. Reads that the actor is not recorded, and does not guess a name |
| 28 to 30 | Debrief: what did you expect to see that was not there, and what did you trust least? | Notes only |

**Measures per task.** Completed without help (yes or no), time, number of wrong turns, the exact words used
to state what the screen does and does not show, and any moment the participant said or showed doubt. For a
participant using a screen reader or keyboard only, the same five tasks with the checklist of section 6.

**What would count as a design failure.** A participant who states a limit wrongly (says the Hub shows the log
is complete, or names an actor the screen does not show). A participant who cannot tell a silent gate from a
healthy one. A participant who treats an export as a tamper-evident copy.

## 8. Questions to ask, from the buyer-guide research

SOURCED, read 2026-11-22 by the runbook author: a vendor's buyer guide for MCP gateways, secondary and with no
independent data. **It is a list of questions and is not evidence.** Each question is paired with the
screen that would let a user answer it, and says whether the Hub can.

| Question buyers are said to ask | Where it would show | Can the Hub answer it today |
|---|---|---|
| Are audit rows timestamped in UTC with user, agent, server, tool, decision, policy and session? | Event detail | Time, server, tool, decision, manifest digest, session: yes. User and agent: **no member** (I1, I2) |
| Are the logs tamper-evident, exportable and ready for a SIEM? | Integrity, Export | Tamper-evident with limits: yes. Hub-side export: no. SIEM format: draft (8.7) |
| Are tool definitions hash-pinned with a change alert? | Gate detail | A drift event is counted. The pin itself is in the manifest, which the Hub does not hold |
| Is there retention control? | Administration | No. Planned (HUB-R15) |
| Can we leave with our data? | Export | Not yet |
| Does it support SSO and SCIM? | Administration | No, by decision: identity comes from the operator's reverse proxy |

## 9. Decisions owed

All open. None is decided here.

- Whether the Hub stores a receipt time for each batch (a second clock, option O5 in #215). Freshness, silence and
  the "last batch" column on the first screen all depend on it.
- Whether `ts` becomes an indexed column, for the time filter in Search.
- Whether the Hub records refused batches and admin actions, which Freshness and the Administration log need.
- The screen order, and whether Search and Export are one place.
- Whether to run the usability script, with whom, and who holds the recordings.

## 10. Not done

- No user was interviewed, no session was run, and no result exists. The personas are hypotheses.
- No code, no design file and no screenshot. The wireframes are ASCII, all SAMPLE.
- The accessibility checklist was not matched against WCAG text (UNVERIFIED).
- The buyer-guide material was not re-read. It is used only through the runbook's summary of it.
- Mobile and narrow layouts are named in the checklist and not drawn.
- The screens assume #222 (ingest), #243 (taint at decision) and #226 (integrity options) have merged in the places
  marked. If they do not, those cells change.

## Sources

- This repository at `develop` `b9d76a9`: `src/bawbel_gate/hub/server.py`, `hub/store.py`, `hub/fleet.py`,
  DESIGN.md 13.4 and 14.4 to 14.6, `docs/hub/EVIDENCE-MODEL.md`, `docs/hub/THREAT-MODEL.md`,
  `docs/hub/ACCOUNTABILITY-LIMITS.md`.
- Open pull requests #222, #226, #243 and #246, at their heads on 2026-11-26.
- The runbook summary of a vendor MCP gateway buyer's guide, as described in section 8.
