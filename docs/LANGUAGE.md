# LANGUAGE.md - ubiquitous language

One name per concept, everywhere: identifiers, docstrings, error strings, docs,
commit messages. If the term is not in this file and you need it, add it here in the
same PR that introduces it.

## Terms

| Term | Meaning | NEVER say instead |
|---|---|---|
| grant | a manifest entry allowing/gating a tool | permission, right, rule (alone) |
| effect | `allow` \| `approve` \| `deny` | verdict (reserve for pipeline output), action |
| lattice | the permissiveness order allow > approve > deny | hierarchy, priority |
| `lattice_min` | combine effects, least permissive wins | downgrade(), min_effect |
| manifest | a component's signed capability declaration | config, policy file, whitelist |
| condition | dotted-path predicate narrowing a grant | filter, constraint |
| argument guard | secret scan / byte cap on outbound args | sanitizer, validator |
| taint | monotone set of provenance classes seen this session | flag, dirty bit, marker |
| provenance class | origin label, e.g. `tool.response.github` | source type, tag |
| trifecta | private_data, untrusted_content, external_comms | triad, CIA (wrong concept) |
| third leg | the trifecta member whose arrival trips the human gate | last leg, final flag |
| session | one host connection's monotone state | conversation, context |
| approval | a human decision on an `approve`-effect call | confirmation, review, HITL |
| audit record | one hash-chained JSONL entry | log entry, log line, event (alone) |
| chain | the linked sequence of audit records | log, trail |
| chain head | hash of the latest record | tip, HEAD (git connotation) |
| pin | recorded integrity hash (`tool_schema_integrity` etc.) | lock, freeze |
| drift | pinned content changed after review | change, update, diff (alone) |
| suspend | withhold a drifted server's tools | disable, ban, block (alone) |
| stanza | `capability_mitigation.manifest_stanza` fragment from an AVE record | snippet, patch |
| harden | merge a record's stanza into a manifest (`harden --ave`) | apply, patch, fix |
| learning mode | observe-only recording that synthesizes draft manifests | dry run, shadow mode |
| deny burst | > N denies/min from one session | attack, brute force (unproven claims) |

## Usage rules

- `deny` is an effect; "blocked" is acceptable only in prose describing an attack
  outcome, never in identifiers or API fields.
- "approve" is the effect; "approval" is the human decision object. Do not mix.
- AVE IDs are written exactly: `AVE-2026-00042`. Never "AVE 42", never lowercase.
- Provenance classes are literal strings from the schema enum. Never invent one in
  code; extend the schema first (that is an ave repo PR, not a gate PR).
- Error strings name the reason from a closed set (`condition_failed`,
  `guard:secret_scan`, `trifecta_third_leg`, ...). Adding a reason string means
  updating the FAQ page in the same PR.
- The gate "decides"; it does not "think", "believe", or "want". No anthropomorphic
  language in code, errors, or docs.

## Casing

- Python: `snake_case` functions, `PascalCase` dataclasses (`SessionState`,
  `ToolCall`, `Decision`, `Manifest`), `SCREAMING_SNAKE` for the `Effect` enum
  members.
- Namespaced tools: `{server}__{tool}` with double underscore, e.g.
  `github__create_pull_request`.
- Schema ids: `bawbel/capability-manifest/v1`, `ave-1.2.json`. Exact strings.
