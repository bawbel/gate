# bawbel-gate DESIGN.md

**Component:** bawbel-gate (Layer 2.5, runtime enforcement)
**Status:** Draft v0.1
**Depends on:** AVE schema >= 1.2 (see Section 9), bawbel-scanner >= 1.3.0
**Package:** `bawbel-gate` (PyPI), console script `bawbel-gate`

---

## 1. Problem statement

Agent hosts (Claude Code, Cursor, any MCP client) grant flat trust to every component in
context. A tool response, a skill file, and a user message carry equal instruction authority
inside the model, because the model processes a single token sequence with no privilege
boundary. This is not fixable at the model layer. bawbel-gate fixes the consequence layer
instead: a deterministic proxy between the agent host and its MCP servers that enforces
per-component capability grants, session taint rules, and the rule-of-two trifecta invariant,
regardless of what the model decides to do.

Three enforcement primitives:

1. **Capability manifests.** Signed, default-deny, per-component declarations of what each
   MCP server is allowed to do, under which argument conditions, and how its output is
   classified (provenance class, instruction authority).
2. **Session taint tracking.** Coarse, sound, session-granularity tracking of which
   provenance classes have entered the conversation. Taint can only downgrade grants.
3. **Trifecta invariant.** A session that has touched private data and ingested untrusted
   content cannot perform external communication without a human approval, enforced outside
   the model.

Out of scope for v1: interposition on the LLM API path (user/model traffic), token-level
taint tracking, multi-agent delegation chains. See Section 10.

## 2. Threat model

### 2.1 Defended

| ID | Threat | Mechanism |
|----|--------|-----------|
| T1 | Indirect prompt injection via tool response causing unauthorized tool calls | taint rules, trifecta invariant |
| T2 | Data exfiltration through tool arguments (PR bodies, comments, URLs) | argument guards: secret scan, byte cap, arg conditions |
| T3 | Tool poisoning via mutated tool descriptions (rug pull) | `tool_schema_integrity` pinning, drift suspension |
| T4 | Over-permissioned servers (calls outside reviewed surface) | default-deny grants |
| T5 | Post-install mutation of remote content (server cards, fetched policy docs) | integrity snapshots, semantic diff, grant downgrade |
| T6 | Silent trifecta accumulation across a long session | monotone trifecta flags, mandatory approval on third leg |

### 2.2 Not defended

- Malicious agent host binary. The gate assumes the MCP client honestly routes calls.
- Model output shown directly to the user (social engineering via text, no tool call).
- A user who approves a malicious action at the approval gate. Approvals show full
  arguments and taint state; judgment remains human.
- Covert channels within a single allowed tool's legitimate argument space below the
  guard thresholds.
- Compromise of the machine running bawbel-gate itself.

### 2.3 Design commitments

- **Default deny.** Absence of a grant is a deny. Empirically, over-permissioning is the
  dominant root cause of agent incidents; default-allow re-encodes it.
- **Monotone restriction.** Taint and trifecta rules move effects down the lattice
  (`allow -> approve -> deny`), never up. This makes policy statically analyzable:
  the manifest's base grants are the permissiveness ceiling for the whole session.
- **Soundness over precision.** Session-level taint over-approximates. False positives
  (unnecessary approvals) are acceptable; false negatives (missed taint) are not.
- **The model is untrusted.** No enforcement decision consults model output. The gate is
  a JSON-RPC middleman making deterministic decisions on structured data.

## 3. Architecture

```
┌──────────────┐  MCP (stdio /   ┌──────────────────────────┐  MCP  ┌───────────────┐
│ Agent host   │  streamable ────▶  bawbel-gate             │──────▶│ github-mcp    │
│ (any MCP     │  HTTP)          │  ┌────────────────────┐  │──────▶│ filesystem-mcp│
│  client)     │◀────────────────│  │ multiplexer        │  │──────▶│ slack-mcp     │
└──────────────┘                 │  ├────────────────────┤  │       └───────────────┘
                                 │  │ manifest loader    │  │
                                 │  │ integrity verifier │  │
                                 │  │ provenance tagger  │  │
                                 │  │ policy engine      │  │
                                 │  │ taint tracker      │  │
                                 │  │ approval gate      │  │
                                 │  └────────────────────┘  │
                                 │            │             │
                                 │            ▼             │
                                 │  audit log (JSONL,       │
                                 │  hash-chained)           │
                                 └──────────────────────────┘
```

### 3.1 Deployment

The agent host is reconfigured to see exactly one MCP server.

Before:

```json
{
  "mcpServers": {
    "github": {"command": "github-mcp", "args": []},
    "filesystem": {"command": "fs-mcp", "args": ["--root", "/work"]}
  }
}
```

After:

```json
{
  "mcpServers": {
    "bawbel-gate": {
      "command": "bawbel-gate",
      "args": ["serve", "--config", "/etc/bawbel/gate.yaml"]
    }
  }
}
```

`gate.yaml` holds the upstream server definitions plus one manifest path per server:

```yaml
schema: bawbel/gate-config/v1
audit_log: /var/log/bawbel/gate.audit.jsonl
approval:
  channel: terminal          # terminal | webhook | slack
  webhook_url: null
  timeout_seconds: 120
  on_timeout: deny
servers:
  - name: github
    command: github-mcp
    args: []
    manifest: /etc/bawbel/manifests/github-mcp.cap.yaml
  - name: filesystem
    command: fs-mcp
    args: ["--root", "/work"]
    manifest: /etc/bawbel/manifests/fs-mcp.cap.yaml
```

### 3.2 Tool namespacing

Upstream tools are re-exposed as `{server}__{tool}` (`github__create_pull_request`).
The gate rewrites names in both directions. `tools/list` responses are the merge of all
upstream lists, filtered: tools whose resolved base effect is `deny` are omitted entirely.
The model cannot call what it cannot see, and cannot see what the manifest denies.

### 3.3 Request path

Every `tools/call` from the host passes through the decision pipeline (Section 6.2).
Every upstream response passes through the provenance tagger before returning to the host:
the payload is hashed, the server's `provenance_class` is recorded into session state,
taint flags update, and the audit record is appended. The response body itself is not
modified in v1 (no inline provenance markers; the host would ignore them anyway).

## 4. Capability manifest

One manifest per component. Authored in YAML, validated against the JSON Schema in 4.2.
Manifests are content-addressed: the gate records `sha256(manifest_canonical_json)` in
every audit record so a policy change is visible in the log chain.

### 4.1 Example (annotated)

```yaml
schema: bawbel/capability-manifest/v1
subject:
  kind: mcp-server                       # mcp-server | skill | subagent
  name: github-mcp
  transport: stdio
  binary_integrity: "sha256:9f2a..."     # package/binary pin, optional but recommended
  tool_schema_integrity: "sha256:c41b..."# canonicalized tools/list pin, drives T3 defense

provenance_class: tool.response.github   # label applied to everything this server emits
instruction_authority: none              # none | advisory | full; only user.direct and
                                         # operator.system are ever full

trifecta:
  private_data: true
  untrusted_content: true                # issues/PRs/comments are attacker-writable
  external_comms: true

grants:
  tools:
    - name: get_issue
      effect: allow
    - name: create_pull_request
      effect: allow
      conditions:
        args.base_repo: {pattern: "myorg/*"}
    - name: create_or_update_file
      effect: approve
    - name: "*"
      effect: deny
  argument_guards:
    - applies_to: "*"
      outbound_secret_scan: true
      max_outbound_bytes: 32768

taint_rules:
  - when:
      tainted_by_any: ["tool.response.github"]
    then:
      - tool: create_pull_request
        effect: approve
      - tool: create_issue_comment
        effect: approve
  - when:
      tainted_by_any: ["web.fetched"]
    then:
      - tools_with: external_comms
        effect: deny

integrity_watch:
  - kind: tool_schema
    on_drift: suspend                    # suspend | deny | approve
  - kind: remote_resource
    url_pattern: "https://*/server-card.json"
    snapshot_at: grant
    diff: semantic
    on_drift: suspend
```

### 4.2 JSON Schema (draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.bawbel.io/capability-manifest/v1.json",
  "title": "Bawbel Capability Manifest v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "subject", "provenance_class", "instruction_authority",
               "trifecta", "grants"],
  "properties": {
    "schema": {"const": "bawbel/capability-manifest/v1"},
    "subject": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kind", "name"],
      "properties": {
        "kind": {"enum": ["mcp-server", "skill", "subagent"]},
        "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$"},
        "transport": {"enum": ["stdio", "http", "n/a"]},
        "binary_integrity": {"$ref": "#/$defs/sha256"},
        "tool_schema_integrity": {"$ref": "#/$defs/sha256"}
      }
    },
    "provenance_class": {"$ref": "#/$defs/provenanceClass"},
    "instruction_authority": {"enum": ["none", "advisory", "full"]},
    "trifecta": {
      "type": "object",
      "additionalProperties": false,
      "required": ["private_data", "untrusted_content", "external_comms"],
      "properties": {
        "private_data": {"type": "boolean"},
        "untrusted_content": {"type": "boolean"},
        "external_comms": {"type": "boolean"}
      }
    },
    "grants": {
      "type": "object",
      "additionalProperties": false,
      "required": ["tools"],
      "properties": {
        "tools": {
          "type": "array",
          "minItems": 1,
          "items": {"$ref": "#/$defs/toolGrant"}
        },
        "argument_guards": {
          "type": "array",
          "items": {"$ref": "#/$defs/argumentGuard"}
        }
      }
    },
    "taint_rules": {
      "type": "array",
      "items": {"$ref": "#/$defs/taintRule"}
    },
    "integrity_watch": {
      "type": "array",
      "items": {"$ref": "#/$defs/integrityWatch"}
    },
    "approval": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "channel": {"enum": ["terminal", "webhook", "slack"]},
        "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 3600},
        "on_timeout": {"enum": ["deny"]}
      }
    }
  },
  "$defs": {
    "sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "provenanceClass": {
      "type": "string",
      "pattern": "^(user\\.direct|operator\\.system|skill\\.file|memory\\.persisted|model\\.generated|web\\.fetched|tool\\.response\\.[a-z0-9._-]+)$"
    },
    "effect": {"enum": ["allow", "approve", "deny"]},
    "toolGrant": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "effect"],
      "properties": {
        "name": {"type": "string", "pattern": "^([a-zA-Z0-9_]+|\\*)$"},
        "effect": {"$ref": "#/$defs/effect"},
        "conditions": {
          "type": "object",
          "propertyNames": {"pattern": "^args\\.[a-zA-Z0-9_.]+$"},
          "additionalProperties": {
            "type": "object",
            "additionalProperties": false,
            "minProperties": 1,
            "properties": {
              "pattern": {"type": "string"},
              "equals": {},
              "one_of": {"type": "array", "minItems": 1},
              "max_bytes": {"type": "integer", "minimum": 1}
            }
          }
        }
      }
    },
    "argumentGuard": {
      "type": "object",
      "additionalProperties": false,
      "required": ["applies_to"],
      "properties": {
        "applies_to": {"type": "string"},
        "outbound_secret_scan": {"type": "boolean", "default": true},
        "max_outbound_bytes": {"type": "integer", "minimum": 256}
      }
    },
    "taintRule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["when", "then"],
      "properties": {
        "when": {
          "type": "object",
          "additionalProperties": false,
          "minProperties": 1,
          "properties": {
            "tainted_by_any": {
              "type": "array", "minItems": 1,
              "items": {"type": "string"}
            },
            "tainted_by_all": {
              "type": "array", "minItems": 1,
              "items": {"type": "string"}
            }
          }
        },
        "then": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["effect"],
            "properties": {
              "tool": {"type": "string"},
              "tools_with": {"enum": ["external_comms", "private_data"]},
              "effect": {"$ref": "#/$defs/effect"}
            },
            "oneOf": [{"required": ["tool"]}, {"required": ["tools_with"]}]
          }
        }
      }
    },
    "integrityWatch": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kind", "on_drift"],
      "properties": {
        "kind": {"enum": ["tool_schema", "binary", "remote_resource"]},
        "url_pattern": {"type": "string"},
        "snapshot_at": {"enum": ["grant", "session_start"]},
        "diff": {"enum": ["hash", "semantic"]},
        "on_drift": {"enum": ["suspend", "deny", "approve"]}
      }
    },
    "manifestStanza": {
      "type": "object",
      "additionalProperties": false,
      "minProperties": 1,
      "properties": {
        "taint_rules": {
          "type": "array",
          "minItems": 1,
          "items": {"$ref": "#/$defs/taintRule"}
        },
        "integrity_watch": {
          "type": "array",
          "minItems": 1,
          "items": {"$ref": "#/$defs/integrityWatch"}
        },
        "approval": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "channel": {"enum": ["terminal", "webhook", "slack"]},
            "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 3600},
            "on_timeout": {"enum": ["deny"]}
          }
        }
      }
    }
  }
}
```

Notes on the schema:

- `taint_rules[].when.tainted_by_any` values may end in `*` for prefix match
  (`tool.response.*`). This is a match expression, not a provenance class, hence the
  looser `string` type versus `$defs/provenanceClass`.
- `on_timeout` admits only `deny`. Fail-open approval is not a supported configuration.
- `instruction_authority` is enforced indirectly in v1: it selects which default taint
  rules the gate synthesizes when a manifest omits `taint_rules` (a component with
  `none` and `untrusted_content: true` gets the standard downgrade set injected).

## 5. Policy semantics

### 5.1 Effect lattice

Effects are totally ordered by permissiveness:

```
allow (2)  >  approve (1)  >  deny (0)
```

All rule combination uses `lattice_min` (least permissive wins). Taint rules and the
trifecta invariant can only lower an effect. Consequence: the base grants in a manifest
are a static upper bound on session capability. `bawbel-gate lint` can therefore answer
"can this deployment ever exfiltrate?" without executing anything.

### 5.2 Grant resolution algorithm

For a call to `{server}__{tool}` with arguments `args`:

1. **Match.** Select the grant whose `name` matches `tool`. Exact match beats `*`.
   Two exact matches for the same name is a manifest validation error (F811 analog).
2. **No match.** Effect is `deny`. (A well-formed manifest ends with `name: "*",
   effect: deny`, but the gate does not rely on it.)
3. **Conditions.** If the matched grant has `conditions`, evaluate each against `args`
   using dotted-path lookup. Any missing path or failed predicate resolves the call to
   `deny`, not to the next grant. Conditions narrow a grant; they do not fall through.
4. **Argument guards.** Apply every guard whose `applies_to` matches. Secret scan hit or
   byte-cap breach resolves to `deny` with the guard identified in the audit record.
5. **Taint rules.** For each rule whose `when` matches current session state, apply
   `lattice_min` for matching `then` entries (`tool` exact name, or `tools_with`
   resolved via the manifest's own `trifecta` flags).
6. **Trifecta invariant.** If `session.private_touched and session.untrusted_seen` and
   the manifest declares `external_comms: true` for this server, then
   `effect = lattice_min(effect, approve)`. This step is not configurable and cannot be
   disabled by any manifest.

Reference implementation sketch:

```python
def resolve(call: ToolCall, manifest: Manifest, session: SessionState) -> Decision:
    grant = manifest.match_grant(call.tool)                    # exact > wildcard > None
    effect = grant.effect if grant else Effect.DENY
    if grant and not grant.conditions_ok(call.args):
        return Decision(Effect.DENY, reason="condition_failed")
    if (violation := manifest.guard_violation(call.tool, call.args)) is not None:
        return Decision(Effect.DENY, reason=f"guard:{violation}")
    for rule in manifest.taint_rules:
        if rule.matches(session):
            effect = lattice_min(effect, rule.effect_for(call.tool, manifest))
    if session.trifecta_third_leg(manifest, call.tool):
        effect = lattice_min(effect, Effect.APPROVE)
    return Decision(effect, reason="resolved")
```

### 5.3 Secret scanning (argument guards)

Outbound argument values are scanned with the same detector set as bawbel-scanner's
secret rules: provider-prefix patterns (AWS `AKIA`, GitLab `glpat-`, JFrog identity
tokens, Vault tokens `hvs.`), PEM blocks, JWT structure, and Shannon entropy >= 4.2
over windows >= 24 chars. Detection is a `deny`, never an `approve`: a human approving
a secret leak under time pressure is not a control.

## 6. Session state machine

### 6.1 Session state

```python
@dataclass
class SessionState:
    session_id: str                       # uuid4, minted at MCP initialize
    manifest_hashes: dict[str, str]       # server -> sha256 of manifest at load
    tainted_by: set[str]                  # provenance classes observed (monotone)
    private_touched: bool = False         # monotone
    untrusted_seen: bool = False          # monotone
    suspended: set[str] = field(default_factory=set)   # servers under drift suspension
    seq: int = 0                          # audit sequence number
```

`tainted_by`, `private_touched`, `untrusted_seen` are monotone: no event clears them
except `SESSION_CLEAR`, which requires an interactive confirmation outside the agent
loop (`bawbel-gate clear --session <id> --confirm`) and writes an audit record. The
agent cannot trigger it; there is no tool for it.

### 6.2 States and transitions

Session lifecycle:

```
            initialize            all manifests verified
  ┌──────┐ ──────────▶ ┌────────┐ ─────────────────────▶ ┌────────┐
  │ INIT │             │ VERIFY │                        │ ACTIVE │
  └──────┘             └────────┘ ──┐                    └────────┘
                                    │ any integrity drift     │ SESSION_CLEAR (human)
                                    ▼ (on_drift: suspend)     ▼
                              ┌───────────┐             taint reset,
                              │ DEGRADED  │             audit record
                              └───────────┘
```

- `VERIFY`: for each server, re-fetch `tools/list`, canonicalize (sorted keys, LF,
  UTF-8, no insignificant whitespace), hash, compare to `tool_schema_integrity`.
  Match: expose tools. Drift with `on_drift: suspend`: server enters `suspended`,
  its tools are omitted from the merged `tools/list`, and a drift report is written.
- `DEGRADED` is `ACTIVE` with one or more suspended servers. Recovery is out-of-band:
  operator reviews the diff, updates the pin, restarts (`bawbel-gate verify --accept`).

Per-call decision pipeline (within `ACTIVE`/`DEGRADED`):

```
RECEIVED ─▶ MANIFEST_RESOLVED ─▶ GUARDS_APPLIED ─▶ TAINT_APPLIED ─▶ TRIFECTA_CHECKED
                                                                          │
                        ┌────────────────────────┬────────────────────────┤
                        ▼                        ▼                        ▼
                     ALLOWED               PENDING_APPROVAL             DENIED
                        │                   │           │                 │
                        ▼              granted       denied/timeout       │
                    EXECUTED ◀──────────┘               └────────────▶ REJECTED
                        │                                                 │
                        ▼                                                 ▼
                  RESPONSE_TAGGED ────────────────────────────────▶ audit record
```

Events, exhaustively:

| Event | Source | Effect on state |
|-------|--------|-----------------|
| `SESSION_START` | MCP `initialize` | mint session, run VERIFY |
| `TOOL_LIST` | host | serve merged, filtered list |
| `CALL_RECEIVED` | host | enter decision pipeline |
| `RESPONSE_RECEIVED` | upstream | tag provenance, update taint + trifecta flags, hash payload |
| `APPROVAL_GRANTED` / `APPROVAL_DENIED` / `APPROVAL_TIMEOUT` | approval channel | resume or reject pending call |
| `DRIFT_DETECTED` | integrity verifier | suspend server per `on_drift` |
| `SESSION_CLEAR` | operator CLI | reset taint, audit |
| `SESSION_END` | transport close | final audit record, chain head printed |

Rejected calls return a JSON-RPC error with a structured, non-negotiable message:
`{"code": -32031, "message": "bawbel-gate: denied", "data": {"reason": "...", "ave": [...]}}`.
The `data.ave` field lists AVE IDs whose `capability_mitigation` produced the blocking
rule, when applicable (Section 9). The model sees why; the model cannot argue with it.

## 7. Taint tracking and the trifecta invariant

### 7.1 Granularity and soundness

Tracking is session-level and class-level. One tainted response taints the session for
that class permanently (until human clear). This over-approximates aggressively and that
is the design: token-level taint through a paraphrasing model is unsound, and unsound
taint tracking is decorative.

### 7.2 Rule-of-two as a runtime invariant

The session accumulates trifecta legs monotonically. Any two legs coexist silently.
The third leg always resolves to at least `approve`, enforced in resolution step 6,
outside manifest control. Manifest taint rules can be stricter (force `deny`); they can
never be looser.

### 7.3 Taint scoping (v1.1)

Long-lived sessions degrade toward approve-everything. Planned mitigation: task-scoped
sub-sessions. The host declares a task boundary (MCP `roots` change or an explicit
gate tool `bawbel__task_begin`, the one gate-provided tool, which itself carries no
authority); taint sets are per-task with inheritance of `private_touched`. Deferred to
v1.1 because scoping rules need field data from learning mode first.

### 7.5 Approval UX budget and learning mode

**Hard requirement, stated as a release gate:** on the benign-workload corpus
(Section 11.4), p95 of sessions produce **zero** approval prompts and p99 produce at
most one. A developer who sees routine prompts routes around the gate; a bypassed
control is worse than none, because it produces false audit confidence.

Mechanisms that keep approvals rare and meaningful:

- Approvals fire only on trifecta third-leg and explicitly `approve`-granted tools.
  Ordinary denies are silent to the human (logged, returned to the model as errors).
- Approval prompts show: tool, full arguments (secret-redacted), which taint classes
  and which rule caused the downgrade, and the AVE IDs behind the rule. One keystroke.
- Duplicate-call collapsing: an identical call (same tool, same canonical args) within
  the same task scope reuses the prior grant for `approve`-level effects.

**Learning mode** is the manifest cold-start answer and the primary onboarding path:

```
$ bawbel-gate learn --config gate.yaml --duration 7d
# proxies transparently, enforces NOTHING, records everything
$ bawbel-gate learn report
  github-mcp: 6 of 41 tools used; 3 arg-space observations attached
$ bawbel-gate learn synthesize --out manifests/
  wrote github-mcp.cap.yaml   (6 allow grants, narrowed conditions, wildcard deny)
  wrote fs-mcp.cap.yaml       (4 allow grants, path conditions from observed roots)
  NOTE: synthesized manifests set trifecta flags from server classification DB;
  review before enforcing. `learn synthesize` output is a draft, not a policy.
```

Synthesis rules: observed tools get `allow` with conditions narrowed to observed
argument patterns where a safe generalization exists (repo owner prefixes, path roots);
everything unobserved gets the wildcard `deny`; write-class tools on trifecta-complete
servers get `approve` regardless of observation. The report doubles as the first-run
demo: "everything your agents did last week that no one explicitly authorized."

## 8. Integrity pinning and drift detection

### 8.1 Tool schema pinning

`tools/list` is attacker-relevant content: tool descriptions enter the model context
verbatim, which is the tool-poisoning delivery path. Pinning binds grants to the
reviewed schema, not to a server name. Canonicalization: JSON with sorted keys, UTF-8,
LF, arrays order-preserved, then sha256.

### 8.2 Remote resource watch

`integrity_watch` entries with `kind: remote_resource` generalize the pattern to
server cards and any fetched document a deployment treats as quasi-static. Snapshot at
grant time, re-fetch per policy, diff. `diff: semantic` uses structural JSON diff with
noise suppression (timestamps, ETags); text resources fall back to hash. Drift handling
mirrors tool schema drift. This is AVE-2026-00042's behavioral class made enforceable.

### 8.3 Drift reports

```
$ bawbel-gate verify github-mcp
✗ tool schema drift: create_pull_request
  description: 47-char insertion (diff attached: drift/github-mcp.2026-07-02.patch)
  action: suspended (manifest on_drift: suspend)
  related: AVE-2026-00042
```

### 8.5 SIEM and OTel export

The hash-chained JSONL (Section 8.6) is the forensic source of truth but not an
operational feed. The gate additionally emits:

- **OpenTelemetry**: one span per decision pipeline traversal
  (`bawbel.gate.decision`), attributes: server, tool, effect, reason, taint classes,
  rule id, AVE ids, latency. OTLP/gRPC exporter, standard env config
  (`OTEL_EXPORTER_OTLP_ENDPOINT`).
- **Syslog/CEF** (v1.1): mapped subset for SIEMs without OTel ingestion.

Alertable event classes, emitted as structured log events regardless of exporter:

| Event | Default severity | SOC meaning |
|-------|------------------|-------------|
| `gate.drift.detected` | high | supply-chain mutation post-review |
| `gate.trifecta.trip` | medium | injection precondition reached, human gate engaged |
| `gate.deny.burst` (>N/min) | medium | agent probing outside granted surface |
| `gate.secretscan.hit` | high | exfiltration attempt via arguments |
| `gate.approval.timeout` | low | unattended agent hit a human gate |
| `gate.chain.gap` | critical | audit log tamper indicator |

### 8.6 Audit log

Append-only JSONL. Each record:

```json
{"seq": 1042, "ts": "2026-07-02T09:14:03.220Z", "session": "6f1c...",
 "event": "CALL_DECIDED", "server": "github", "tool": "create_pull_request",
 "effect": "approve", "reason": "trifecta_third_leg",
 "taint": ["tool.response.github"], "args_sha256": "sha256:ab12...",
 "manifest_sha256": "sha256:77e0...", "ave": ["AVE-2026-00038"],
 "prev": "sha256:e3d1...", "hash": "sha256:90fa..."}
```

`hash = sha256(canonical_json(record minus hash) || prev)`. Chain head is printed at
`SESSION_END` and can be anchored externally (git note, Vault KV, or a transparency
log later). `bawbel-gate audit verify <file>` replays the chain. Argument payloads are
hashed, not stored, by default; `--store-args` exists for regulated deployments with
their own encryption at rest.

## 9. AVE schema migration: v1.1 -> v1.2

### 9.1 New fields

Three optional objects added to the AVE record schema. Optional in v1.2, required in
v2.0. No existing field changes; this is additive and backward-compatible.

```json
{
  "provenance_vector": {
    "entry_class": "tool.response.*",
    "payload_surface": "tool_schema.description",
    "escalation": "data->instruction"
  },
  "trifecta_profile": {
    "requires": ["untrusted_content", "external_comms"],
    "private_data": "amplifies"
  },
  "capability_mitigation": {
    "manifest_stanza": {
      "taint_rules": [{
        "when": {"tainted_by_any": ["tool.response.*"]},
        "then": [{"tools_with": "external_comms", "effect": "approve"}]
      }]
    },
    "integrity_requirements": ["tool_schema_integrity"]
  }
}
```

Field semantics:

- `provenance_vector.entry_class`: where in the context supply chain the attack enters.
  Enum plus prefix wildcards, same grammar as taint match expressions:
  `user.direct | operator.system | skill.file | memory.persisted | model.generated |
  web.fetched | tool.response.* | tool.schema | server.card`.
  Note `tool.schema` and `server.card` are entry classes only (they enter at
  grant/verify time, not as session taint), which is why this enum is a superset of
  the runtime provenance classes.
- `provenance_vector.payload_surface`: the concrete field or channel carrying the
  payload (free text, controlled vocabulary grown by convention).
- `provenance_vector.escalation`: one of `data->instruction`, `instruction->capability`,
  `capability->identity`. The authority jump the class performs.
- `trifecta_profile.requires`: legs that must be present for the class to be
  exploitable. `private_data | untrusted_content | external_comms`, each valued
  implicitly `required` by membership; the optional keyed form (`"private_data":
  "amplifies"`) marks legs that worsen impact without being preconditions.
- `capability_mitigation.manifest_stanza`: a fragment that validates against the
  `manifestStanza` definition in the capability-manifest schema (`#/$defs/manifestStanza`,
  Section 4.2) and neutralizes the class when merged into a deployment's manifests.
  A stanza contains only mergeable keys (`taint_rules`, `integrity_watch`, `approval`);
  it is not a complete manifest and must not be validated against the root schema.
  This is the executable link: scanner detects the class, the record emits the policy,
  the gate enforces it, and denials cite the AVE ID back (Section 6.2).
  `bawbel-gate harden --ave AVE-2026-000XX` merges the stanza.

### 9.2 Migration of the 51 published records

Mechanics:

```
scripts/migrate_ave_v1_2.py
  --in  records/            # 51 x AVE-2026-*.json at schema 1.1
  --out records/            # in-place, git-diffable
  --schema schemas/ave-1.2.json
```

The script bumps `schema_version` to `"1.2"`, inserts the three fields as `null`, and
sets `"triage": {"provenance": "unclassified"}` in record metadata. Validation via
`jsonschema` (draft 2020-12). No classification is auto-guessed; a wrong
`provenance_vector` is worse than an absent one.

Backfill is a manual triage pass over 51 records, tractable in one sitting per batch:

| Batch | Records | Expected dominant entry classes |
|-------|---------|--------------------------------|
| 1 | tool/schema poisoning cluster (incl. AVE-2026-00041 server-card, AVE-2026-00042 dynamic fetch) | `tool.schema`, `server.card`, `web.fetched` |
| 2 | injection-via-content cluster | `tool.response.*`, `web.fetched`, `skill.file` |
| 3 | identity/credential cluster | `capability->identity` escalations |
| 4 | remainder + cross-review | mixed |

Publication sequence:

1. `schemas/ave-1.2.json` merged, CHANGELOG entry, migration script merged.
2. Migrated 51 records published with `null` fields (schema-valid immediately).
3. Batches 1-4 land as reviewed PRs; each batch updates the triage counter on
   ave.bawbel.io.
4. PiranhaDB API: `GET /records?schema=1.2` returns new fields;
   `?schema=1.1` (default until v2.0) strips them. Additive fields mean no breaking
   change for existing bawbel-scanner and VS Code extension consumers; both pin 1.1
   behavior until their own releases opt in.
5. New query surface once backfill completes:
   `GET /records?trifecta=untrusted_content,external_comms` ("every class exploitable
   in my posture") and `GET /records/{id}/mitigation` (raw manifest stanza, consumed by
   `bawbel-gate harden`).

### 9.3 Scoring interaction

`trifecta_profile` does not alter AIVSS v0.8 scores. It is a deployment-applicability
filter, orthogonal to severity. A future AIVSS revision may consume it as an
environmental modifier; out of scope here.

## 10. Limitations

Stated plainly; these go in public docs, not only here.

1. **No user/model path visibility in v1.** `user.direct` provenance is assumed, not
   attested. Full pillar-1 attestation requires LLM-API interposition (v2, Section 12).
2. **Session taint over-approximates.** One web fetch taints the session for
   `web.fetched` until human clear. Taint scoping (7.3) reduces but will not remove this.
3. **The gate trusts the host's routing.** A host that calls upstream servers directly
   bypasses everything. Deployment guidance: upstream server credentials live only in
   the gate's environment, so direct connection fails auth.
4. **Approval quality is human quality.** The gate makes the decision point explicit
   and informed; it cannot make it wise.
5. **Covert channels below guard thresholds remain.** Byte caps and secret scanning
   raise attacker cost; they are not information-flow proofs.
6. **Semantic drift diffing has false negatives.** A payload crafted to survive noise
   suppression is conceivable; `diff: hash` mode exists for zero-tolerance resources.

## 11. Deployment and operations

### 11.1 Runtime footprint

Single process, Python >= 3.11, no daemon dependencies. State is per-session and
in-memory; the audit log is the only persistent artifact. Crash recovery: sessions die
with the process; the host reconnects and a new session starts in `VERIFY`. Nothing to
replicate, no HA story required for v1 (stdio deployments are per-workstation;
HTTP deployments run one gate per agent runtime pod).

### 11.2 Latency budget

Decision pipeline is pure computation plus one optional approval wait. Budget:
p95 <= 5 ms added per tool call excluding approval waits, measured by the OTel span.
Secret scanning is the dominant cost; entropy windows run only on outbound string
arguments over 24 chars.

### 11.3 Environment promotion

Manifests are environment-specific files in git:

```
manifests/
  dev/github-mcp.cap.yaml        # wider allow set, approve on writes
  staging/github-mcp.cap.yaml
  prod/github-mcp.cap.yaml       # narrow, integrity-pinned, approve/deny heavy
```

CI gates (GitLab):

```yaml
manifest-lint:
  script:
    - bawbel-gate lint manifests/ --schema capability-manifest/v1
    - bawbel-gate lint manifests/prod --forbid-effect allow --tools-with external_comms
```

The second invocation is the static analyzability payoff from Section 5.1: prod
manifests provably cannot silently egress.

### 11.4 Benign-workload corpus

The approval budget (7.5) is measured against a recorded corpus of ordinary agent
sessions (learning-mode captures, scrubbed). The corpus ships in-repo under
`tests/corpus/` and runs in CI: a policy change that pushes p95 approvals above zero
fails the pipeline. Treat approval regressions like performance regressions.

### 11.5 Operator CLI surface

```
bawbel-gate serve --config gate.yaml
bawbel-gate learn [--duration 7d] | learn report | learn synthesize --out DIR
bawbel-gate verify [SERVER] [--accept]
bawbel-gate lint MANIFEST_DIR [--forbid-effect E --tools-with CAP]
bawbel-gate harden --ave AVE-ID [--manifest FILE] [--allow-unreviewed]
bawbel-gate audit verify FILE | audit tail [--follow]
bawbel-gate clear --session ID --confirm
```

`harden --ave` refuses to merge a stanza whose `review_status` is not `reviewed`; the
operator must pass `--allow-unreviewed` explicitly to proceed with an `llm_drafted` or
`unreviewed` stanza. Merging an unreviewed stanza into a live manifest without human
review is the failure the gate exists to prevent; the default is refusal, not a warning.
The concrete stanza source and `review_status` semantics are in
`BAWBEL_GATE_MITIGATIONS_SPEC.md` Section 3.

## 12. Roadmap and open questions

- **v1.1:** taint scoping (7.3), CEF/syslog export (8.5), approve-grant memoization
  across restarts (signed grant cache), Windows service packaging.
- **v1.2:** embedded console and Console API (Section 13); fleet ingest client behind
  a feature flag.
- **hub 1.0:** the team tier (Section 14): multi-gate ingest, fleet console, first
  paid product.
- **v1.3:** bawbel-hub team tier (Section 14): self-hosted fleet collector and console
  for 5-50 gates; first commercial product.
- **v2:** LLM-API interposition for attested `user.direct` / `model.generated`
  provenance; manifest compilation to Cedar for a formally verified evaluator;
  transparency-log anchoring of audit chain heads.
- **Open:** multi-agent delegation (does a subagent inherit the parent's taint set, or
  fork it? current position: inherit, monotone); manifest signing identity (sigstore
  keyless vs org PKI); whether `learn synthesize` should emit `trifecta` flags at all
  or always defer to a curated server classification DB.

## 13. Telemetry and Console API

The console is a projection of state the gate already maintains. No new state stores,
no polling loops against the audit file from a second process, no sync protocol to
invent: the hash-chained audit log is the transport, and everything else is a
serializer over in-memory structures.

Two modes, shipped in this order:

1. **Local (v1.2).** The gate serves the console itself:
   `bawbel-gate serve --console 127.0.0.1:7317`. Browser gets a state snapshot plus a
   live event stream. Zero infrastructure, zero sync.
2. **Fleet (platform, unscheduled).** Each gate pushes audit records to a Bawbel
   ingest endpoint; the platform rebuilds fleet state by replaying them. Event
   sourcing, with integrity properties inherited from the chain.

### 13.1 Console API endpoint contract (local mode)

All endpoints are read-only except approvals. The console can never issue tool calls,
edit manifests, or clear taint; those remain CLI-only (Sections 6.1, 11.5).

**Authentication and binding.** On startup with `--console`, the gate mints a random
bearer token and prints it once (`console: http://127.0.0.1:7317/?t=...`). Default
bind is loopback. Binding a non-loopback address without `--console-tls` and a
configured token file is a startup error, not a warning.

**`GET /v1/state`** -> `200 application/json`. Full snapshot for initial render:

```json
{
  "gate": {"version": "1.2.0", "config_sha256": "sha256:...", "started_at": "..."},
  "sessions": [{
    "session_id": "6f1c92e4", "host": "claude-code", "servers": ["github", "fs"],
    "tainted_by": ["tool.response.github", "tool.response.fs"],
    "private_touched": true, "untrusted_seen": true,
    "suspended_servers": [], "started_at": "...", "last_seq": 41205
  }],
  "approvals": [{
    "approval_id": "ap_01H...", "session_id": "6f1c92e4",
    "server": "github", "tool": "create_pull_request",
    "cause": "trifecta_third_leg", "rule_origin_ave": ["AVE-2026-00038"],
    "expires_at": "2026-07-02T09:15:27Z"
  }],
  "servers": [{
    "name": "github", "manifest_sha256": "sha256:77e0...",
    "pin_status": "drift", "trifecta": {"private_data": true,
    "untrusted_content": true, "external_comms": true},
    "grant_counts": {"allow": 6, "approve": 2, "deny_wildcard": true}
  }],
  "audit": {"head_hash": "sha256:90fa...", "records": 41208, "last_verify": "..."}
}
```

**`GET /v1/events?after_seq=N`** -> `text/event-stream`. SSE, one event per audit
record as it is written, `id:` set to `seq`, comment heartbeat every 15 s. SSE over
WebSocket deliberately: records are strictly ordered by `seq`, so reconnection is
`after_seq = last seen id` (browsers do this natively via `Last-Event-ID`), there is
no bidirectional state, and it traverses ordinary proxies. Semantics:

- `after_seq` older than the oldest retained record -> `410 Gone` with body
  `{"earliest_seq": N}`; client re-snapshots via `/v1/state` and resumes.
- `after_seq` at head -> stream stays open and waits. No error.

**`GET /v1/approvals/{id}/args`** -> full argument payload with secret-scan redaction
applied. Local mode only; in fleet mode this endpoint is never relayed centrally
unless the deployment sets an explicit `console.relay_args: true` (default false),
because centralizing argument payloads recreates the sensitive-data copy the
`args_sha256` design avoids.

**`POST /v1/approvals/{id}`** with `{"decision": "grant" | "deny", "note": "..."}`:

- `200` -> decision applied; audit record written with `channel: console`.
- `404` -> unknown or expired (timeout already resolved it to deny).
- `409` -> already decided (terminal and console raced; first writer wins).

This endpoint is the console-channel implementation of the approval gate (7.5); it
replaces nothing and bypasses nothing, it is one more `approval.channel`.

### 13.2 Fleet ingest protocol

Push-only, gate to platform. **No inbound connections to gates, ever.** This is a
hard property, not a default: gates in bank networks must not require listening
sockets reachable from outside the host.

**Transport.** `POST /v1/gates/{gate_id}/records`, mTLS with a per-gate client
certificate, `Content-Type: application/x-ndjson`, body is a batch of audit records
in ascending `seq` per `(gate_id, session_id)`. Batching: flush at 200 records or
2 s, whichever first.

**Cursor and durability.** Records are durable in the local JSONL before any send
(the JSONL is the outbound buffer; there is no second queue). The gate keeps
`~/.bawbel/ingest.cursor` mapping `session_id -> last acked seq`, updated only on
ack. Crash at any point re-sends from the cursor; the dedup key
`(gate_id, session_id, seq)` makes replays harmless.

**Responses.**

| Status | Body | Gate behavior |
|---|---|---|
| `200` | `{"acked": {"6f1c92e4": 41205, ...}}` | advance cursors |
| `409` | `{"error": "chain_mismatch", "session": "...", "expected_prev": "sha256:..."}` | re-send from indicated position; if local chain disagrees, raise `gate.chain.gap` locally and stop shipping that session |
| `422` | `{"error": "schema", "index": 3}` | quarantine record, alert, continue batch remainder |
| `429` | `Retry-After: n` | back off; JSONL keeps buffering, nothing is lost |

**Chain verification on ingest.** The platform verifies `hash` and `prev` linkage per
session on arrival. A gap or mismatch is not treated as a sync bug: it raises
`gate.chain.gap` (critical, DESIGN.md 8.5) and quarantines the batch. The sync
integrity check and the tamper-evidence control are the same code path by
construction.

**Retention interaction.** Local JSONL rotation is permitted only past the acked
cursor in fleet mode; in local-only mode, rotation policy is operator-defined and
`/v1/events` signals rotated-away history via `410`.

### 13.3 Manifest synchronization

Opposite direction, and simpler: git is the source of truth (11.3). The platform
either reads the manifest repo directly, or, with no repo access, cross-checks the
`manifest_sha256` carried in every audit record against expected values. A gate
running a manifest hash that matches no reviewed commit is flagged as config drift.
No push channel exists for manifests: the platform can observe policy, never change
it. Policy changes travel through MRs like any other change (11.3 CI gates apply).

### 13.4 Non-goals

The Console API does not execute tool calls, does not proxy MCP traffic, does not
mutate manifests or taint state, and does not expose raw secrets (redaction is
applied before any payload leaves the gate process). The fleet platform is an
observer with exactly one write path: none. Approval decisions in fleet mode remain
local to each gate's own console/terminal/webhook channels in v1.2; centralized
approval routing is a platform-era question and is explicitly deferred.

## 14. bawbel-hub: the team tier

The hub is the fleet view for a team of gates: 5 to 50 developers, one console. It is
the first paid tier, and it is deliberately small: the ingest protocol (13.2), the
console views (13.1), and the audit chain already define almost all of it. The hub is
assembly plus identity, not new invention.

### 14.1 Positioning

- **Buyer:** a team lead or security engineer who already runs gates per workstation
  and wants one place to see sessions, denies, drift, and trifecta state across the
  team.
- **Shape:** sensor/console, like EDR, with one deliberate inversion: the hub has NO
  command channel. Gates push evidence up; nothing pushes down. An EDR-style central
  write path into developer machines would itself be a lethal-trifecta component and
  a single point of compromise; the hub's write path into gates is none (13.4 holds).
- **Commercial boundary, stated plainly:** bawbel-gate is and stays Apache-2.0,
  fully functional standalone, including its embedded console. The hub (multi-gate
  ingest, fleet state, team console, posture report) is the paid product. The
  boundary is drawn at "more than one gate", which is honest and easy to explain.

### 14.2 Architecture

```
 10 x bawbel-gate (workstations)          bawbel-hub (one container)
 ┌─────────┐  audit records,   ┌───────────────────────────────────┐
 │ gate #1 │  NDJSON batches   │ ingest (13.2) ─▶ chain verify     │
 │  ...    │ ────mTLS push───▶ │      │                            │
 │ gate #10│                   │      ▼                            │
 └─────────┘                   │ replay ─▶ fleet state (Postgres   │
     ▲                         │            or SQLite)             │
     │ manifests, pins         │      │                            │
 ┌───────────┐                 │      ▼                            │
 │ git repo  │────read-only───▶│ fleet console (console views +    │
 │ manifests/│                 │ per-developer + aggregate)        │
 └───────────┘                 └───────────────────────────────────┘
```

One process, one container, on-prem first: the buyer profile (banks, fintech) will
not ship audit telemetry to a SaaS in v1, and the protocol was designed push-only and
self-hostable for exactly this reason. A hosted hub is a later packaging decision,
not an architectural one.

### 14.3 Identity and enrollment

- Each gate enrolls once: `bawbel-gate enroll --hub https://hub.internal:8443 --token <one-time>`.
  The hub issues a per-gate mTLS client certificate; the certificate CN is the
  `gate_id`. Enrollment tokens are single-use, minted by the hub CLI.
- Attribution is structural: every audit record arrives on an authenticated channel
  bound to one `gate_id`, and chains are verified per `(gate_id, session)`. There is
  no self-reported identity anywhere in the pipeline.
- Developer display names map to `gate_id` in hub config; the hub never needs
  workstation credentials, directory integration, or agents beyond the gate itself.
  (SSO for console viewers is a v1.1 hub concern, not a gate concern.)

### 14.4 Fleet state and console

Fleet state is a pure replay of verified chains: sessions, taint, trifecta flags,
suspensions, deny/approve/allow counts, drift events, per gate and aggregated. The
console is the existing two views plus a fleet dimension:

- **Fleet posture:** the four posture stats summed, plus per-gate rows (gate, active
  sessions, trifecta-locked sessions, denies last 24 h, drift, manifest hash).
- **Per-developer view:** exactly the embedded console's Console view, filtered to
  one `gate_id`.
- **Posture report:** the one-page CISO artifact (M5) generated fleet-wide.

Approvals remain local to each gate's own channels. The hub displays pending
approvals read-only; it cannot decide them. Centralized approval routing stays
deferred (13.4) because it is a command channel by another name.

### 14.5 Policy consistency

The manifest git repo is the fleet policy source. The hub cross-checks the
`manifest_sha256` carried in every audit record against the repo's reviewed commits
and flags mismatches as config drift per gate. CI lint invariants (11.3) therefore
hold fleet-wide by construction: if the repo passes
`--forbid-effect allow --tools-with external_comms`, every enrolled gate provably
runs egress-safe policy or shows up flagged.

### 14.6 Non-goals (hub)

No command channel. No approval decisions. No argument payload storage (records carry
`args_sha256`; the hub inherits this). No inbound connections to gates. No agent
deployment/update mechanism: gates are installed and updated by the team's own
tooling, and the hub merely reports version skew.

### 14.7 Sizing and operations

10 developers at realistic agent usage is on the order of 10^4-10^5 audit records per
day: trivial for SQLite, comfortable for years in Postgres. Chain verification is
sequential per session and cheap. The hub is stateless above its database; backup is
`pg_dump` or copying one file. Ships as a single OCI image plus a compose file.

## Appendix A. Compliance mapping

Mapping of gate controls to frameworks in scope for regulated deployments. Wording is
indicative; formal control narratives belong in the deployment's own compliance docs.

| Gate control | PCI DSS v4.0 | ISO/IEC 27001:2022 | NIST | NBC TCRMG |
|---|---|---|---|---|
| Default-deny capability manifests | 7.2 (least privilege, access by job function) | A.8.2, A.8.3 (privileged access, restriction) | AC-6 (least privilege); AI RMF GOVERN 1.x | access control and least-privilege provisions |
| Trifecta invariant / human approval | 7.2.4 (review of access), 6.4 (change approval analog) | A.8.2 | AC-6(1), IA-x for NHI actions; AI RMF MANAGE 2.x | operational risk controls for automated processing |
| Tool schema / remote resource pinning | 6.3.2 (inventory of bespoke and third-party components), 11.5 (change detection) | A.8.9 (configuration mgmt), A.8.32 (change mgmt) | CM-3, SI-7 (software integrity); SSDF PW.4 | third-party / outsourcing risk provisions |
| Hash-chained audit log | 10.2, 10.3 (audit trail, integrity) | A.8.15 (logging), A.8.16 (monitoring) | AU-2, AU-9 (audit protection) | audit trail requirements |
| Secret scanning on outbound args | 3.x (protect stored/transmitted account data, supporting) | A.8.24 (crypto key handling, supporting) | SC-8 supporting; SSDF PS.1 | data protection provisions |
| SIEM/OTel alert classes | 10.4 (review), 12.10 (incident response inputs) | A.5.25, A.8.16 | IR-4, SI-4 | incident management provisions |
| Learning-mode inventory report | 12.5 (inventory of system components, scoping) | A.5.9 (inventory of assets) | CM-8; AI RMF MAP 1.x | asset and risk identification |

Framework notes: SOC 2 maps through CC6 (logical access) and CC7 (system operations,
change detection) via the same rows; not tabulated separately. The AI RMF references
are to the NIST AI Risk Management Framework function/category level; agent-specific
procurement requirements emerging in 2026 map onto the manifest + signing rows.