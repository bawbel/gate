# bawbel-gate — Complete Testing Guide

Step-by-step from a clean checkout to a verified running system.
Every command is copy-paste ready. Expected output is shown inline.

---

## 1. Prerequisites

- Python 3.11 or later (`python3 --version`)
- git
- pip

---

## 2. Clone and install

```bash
git clone https://github.com/bawbel/gate
cd gate

# Editable install with all dev dependencies
pip install -e ".[dev]" --break-system-packages
```

Verify the CLI is on PATH:

```
$ bawbel-gate --version
bawbel-gate, version 0.1.0
```

---

## 3. Lint gate

Run this before every commit. All hooks must pass.

```bash
pre-commit run --all-files
```

Expected:

```
ruff.....................................................................Passed
bandit...................................................................Passed
trim trailing whitespace.................................................Passed
fix end of files.........................................................Passed
check json...............................................................Passed
check yaml...............................................................Passed
check for merge conflicts................................................Passed
```

---

## 4. Full automated test suite

```bash
pytest
```

Expected: `315 passed`

---

## 5. Test suites by layer

### 5a. Schema and migration tests

Validates JSON Schema files and the AVE 1.2 migration script.

```bash
pytest tests/test_schemas.py tests/test_migration.py -v
```

Key assertions:
- All three schemas validate correctly
- Migration script produces idempotent, schema-valid output
- `?schema=` negotiation returns 1.1 by default, 1.2 on opt-in

---

### 5b. Audit chain tests (M1)

```bash
pytest tests/test_m1_audit.py -v
```

Key assertions:
- Each appended record carries `hash = sha256(canonical(record_without_hash) || prev)`
- Genesis record uses `prev = sha256:000...000`
- Truncated last record detected by `audit verify`; prior chain intact
- Canonical JSON goes exclusively through `audit/canonical.py`

---

### 5c. Policy engine and taint tests (M2)

```bash
pytest tests/test_m2_policy.py tests/test_m2_approval.py -v
```

Key assertions:

| Class | What it verifies |
|---|---|
| `TestLatticeMin` | `deny` absorbs `allow`; `lattice_min` is commutative |
| `TestGrantResolution` | Exact match beats wildcard; no-match -> deny |
| `TestArgumentGuards` | Secret scan and byte cap produce `deny` with correct reason |
| `TestTaintRules` | Taint never raises an effect; `lattice_min` only |
| `TestTrifectaInvariant` | Third leg always fires `>= approve` regardless of grant |
| `TestDecisionJsonRpc` | Deny returns JSON-RPC `-32031` with reason field |
| `TestManifestLoader` | Invalid schema, unknown field, duplicate grant all error |

---

### 5d. Property-based invariant tests (M2, I1-I5)

These use Hypothesis to generate random inputs. Run with `-x` to stop at first failure.

```bash
pytest tests/property/ -x -v
```

Key invariants tested:

| Invariant | Hypothesis test |
|---|---|
| I1: no-match -> deny | random tool names against sparse manifests |
| I2: trifecta non-configurable | random manifest + all trifecta flags set |
| I3: taint monotone | random provenance sequences never lower the effect |
| I4: condition-fail -> deny, no fallthrough | random conditions against wrong args |
| I5: lattice_min algebraic laws | commutativity and associativity over all effect pairs |

---

### 5e. Integrity pinning tests (M3)

```bash
pytest tests/test_m3_integrity.py tests/property/test_integrity.py -v
```

Key assertions:
- Canonical hash is stable across Python versions and dict ordering
- Any field mutation (description, name, added tool) is detected as drift
- `on_drift: suspend` withholds all tools for that server
- `verify --accept` updates the pin; subsequent check passes
- `harden --ave` merges the stanza and produces a lint-clean manifest diff

---

### 5f. Replay tests — scripted attack patterns

These replay real attack chains and assert each enforcement layer independently.

```bash
pytest tests/replay/ -v
```

**GitHub MCP exfiltration (AVE-2026-00041):**

```bash
pytest tests/replay/test_github_mcp_exfil.py -v
```

| Layer | Test class | What is blocked |
|---|---|---|
| 1 | `TestLayer1PoisonedIssueRead` | `get_issue` allowed initially; taint accumulates after response |
| 2 | `TestLayer2PrivateRead` | Private file read marks `private_touched`; two trifecta legs complete |
| 3 | `TestLayer3PrToFork` | PR to fork fires third leg; result `>= approve` regardless of manifest |
| - | `TestExfilDefenceNonConfigurable` | No manifest stanza can disable trifecta enforcement |

**Tool schema rug-pull (supply-chain drift):**

```bash
pytest tests/replay/test_tool_schema_drift.py -v
```

| Layer | Test class | What is blocked |
|---|---|---|
| 1 | `TestLayer1PinComputation` | Pin is stable; hash algorithm is sha256 + canonical JSON |
| 2 | `TestLayer2DriftDetection` | Any description or name change detected |
| 3 | `TestLayer3DriftSuspension` | Server suspended; all tools withheld |
| - | `TestEndToEndRugPull` | Full chain: pin -> mutate -> detect -> suspend -> re-verify |

---

### 5g. Approval budget and latency gates (M4)

```bash
pytest tests/test_m4_corpus.py -v
```

Key assertions:
- Benign corpus (`tests/corpus/sessions/github_daily_dev.jsonl`): p95 approval prompts = 0
- p99 approval prompts <= 1
- Decision p95 latency <= 5 ms
- Static security review: no fail-open path, no inline `sort_keys=True`, trifecta in engine

---

### 5h. Operations layer (M5)

```bash
pytest tests/test_m5_ops.py -v
```

Key assertions:
- All six alert class names match `gate.*` dot-notation
- CEF output is a single line; `|` and `=` are escaped; `\n` becomes space
- `compute_posture()` counts allow/approve/deny/trifecta/drift/secret/timeout/chain-gap
- OTel functions are no-ops when `opentelemetry-sdk` is not installed (no import error)
- `bawbel-gate posture` CLI outputs text and JSON formats

---

### 5i. Embedded console (M6)

```bash
pytest tests/test_m6_console.py -v
```

Key assertions:

| Class | What it verifies |
|---|---|
| `TestBearerToken` | `mint_token()` returns 64-char hex; `verify_token` uses constant-time compare |
| `TestStateSerializer` | Snapshot is a plain dict; never mutates the original state |
| `TestApprovalRegistry` | First-writer-wins; second writer gets `False` (409); expired -> None (404) |
| `TestConsoleServer` | `/v1/state` requires Bearer; `/v1/events` accepts `?t=` param; SSE format |
| `TestReadOnlyGuarantee` | PUT/DELETE/unrecognized POST all return 404 |
| `TestConsoleCLI` | `--console HOST:PORT` starts server, prints token URL |

---

### 5j. bawbel-hub fleet manager (M7)

```bash
pytest tests/test_m7_hub.py -v
```

Key assertions:

| Class | What it verifies |
|---|---|
| `TestFleetStore` | Idempotent upsert by `(gate_id, session_id, seq)`; rebuild from records |
| `TestChainVerification` | `process_batch` raises `ChainMismatch` on tampered `prev` or `hash` |
| `TestEnrollment` | Single-use token: second `consume_token` raises `EnrollmentError` |
| `TestFleetPosture` | Per-gate allow/approve/deny/trifecta/drift aggregation |
| `TestHubServer` | Ingest 200/409; enrollment 200/403; fleet state 200; no command channel (all 404) |
| `TestIngestClient` | Cursor load/save; `build_batch` returns only unacked records |
| `TestHubCLI` | `hub serve` and `hub token new` CLI commands |

---

## 6. Manual end-to-end walkthrough

### 6a. Write a gate.yaml

```yaml
# gate.yaml
schema: bawbel/gate-config/v1

audit_log: gate.audit.jsonl

approval:
  channel: terminal
  timeout_seconds: 120

servers:
  - name: github
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    manifest: manifests/github-mcp.cap.yaml
```

### 6b. Write a capability manifest

```yaml
# manifests/github-mcp.cap.yaml
schema: bawbel/capability-manifest/v1
subject:
  kind: mcp-server
  name: github
provenance_class: tool.response.github
instruction_authority: none
trifecta:
  private_data: true
  untrusted_content: true
  external_comms: true
grants:
  tools:
    - name: get_issue
      effect: allow
    - name: create_pull_request
      effect: allow
    - name: "*"
      effect: deny
```

### 6c. Lint the manifest

```bash
bawbel-gate lint manifests/ --schema capability-manifest/v1
```

Expected: no output (clean).

### 6d. Pin tool schemas after review

```bash
# Export current tools from the server to a JSON file first, then:
bawbel-gate verify tools.json manifests/github-mcp.cap.yaml --accept
```

Expected:

```
pinned: manifests/github-mcp.cap.yaml  (hash written to tool_schema_pin)
```

### 6e. Start in learning mode

```bash
bawbel-gate serve --config gate.yaml --learn
```

Use the gate through your MCP client for a session, then:

```bash
bawbel-gate learn report
bawbel-gate learn synthesize --out manifests/
```

### 6f. Start in enforcement mode with the embedded console

```bash
bawbel-gate serve --config gate.yaml --console 127.0.0.1:7317
```

Expected output:

```
bawbel-gate: enforcement mode active
console: http://127.0.0.1:7317/?t=<token>
```

Open the URL in a browser. The console shows:
- Live session state and taint flags
- Streaming audit events via SSE
- Pending approvals (when a trifecta trip fires)

### 6g. View posture report

```bash
bawbel-gate posture --audit-log gate.audit.jsonl
bawbel-gate posture --audit-log gate.audit.jsonl --json
```

### 6h. Verify the audit chain

```bash
bawbel-gate audit verify gate.audit.jsonl
```

Expected: `chain ok  N records verified`

Tamper test — corrupt one byte and re-verify:

```bash
python3 -c "
data = open('gate.audit.jsonl', 'rb').read()
open('gate.audit.jsonl.bad', 'wb').write(data[:200] + b'X' + data[201:])
"
bawbel-gate audit verify gate.audit.jsonl.bad
```

Expected: `chain error at record <N>: hash mismatch`

---

## 7. bawbel-hub walkthrough

### 7a. Start the hub

```bash
# Terminal 1
bawbel-gate hub serve --db hub.db --host 127.0.0.1 --port 8443
```

Expected:

```
hub: listening on http://127.0.0.1:8443
  admin token: <admin-token>
```

### 7b. Mint an enrollment token

```bash
# Terminal 2
bawbel-gate hub token new --db hub.db
```

Expected:

```
enrollment token: <enrollment-token>
```

### 7c. Enroll a gate

```bash
bawbel-gate enroll --hub http://127.0.0.1:8443 --token <enrollment-token>
```

Expected:

```
enrolled: gate_id=gate-<hex>
  hub: http://127.0.0.1:8443
```

### 7d. Verify no command channel

```bash
# Hub must return 404 for any write-path not in its spec
curl -s -o /dev/null -w "%{http_code}" \
  -X PUT http://127.0.0.1:8443/v1/gates/gate-abc/manifest \
  -H "Authorization: Bearer <admin-token>"
# expected: 404

curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE http://127.0.0.1:8443/v1/gates/gate-abc/taint \
  -H "Authorization: Bearer <admin-token>"
# expected: 404
```

### 7e. Query fleet state

```bash
curl -s http://127.0.0.1:8443/v1/fleet/state \
  -H "Authorization: Bearer <admin-token>" | python3 -m json.tool
```

---

## 8. OTel export (optional)

```bash
pip install -e ".[dev,ops]" --break-system-packages

export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
bawbel-gate serve --config gate.yaml
```

Every enforcement decision emits a `bawbel.gate.decision` span. The six alertable
event classes (`gate.drift.detected`, `gate.trifecta.trip`, `gate.deny.burst`,
`gate.secretscan.hit`, `gate.approval.timeout`, `gate.chain.gap`) are emitted as
structured events on those spans.

Without `opentelemetry-sdk` installed the gate runs identically — all OTel calls
are no-ops. Verify:

```bash
pip uninstall opentelemetry-sdk -y
pytest tests/test_m5_ops.py -v -k otel
# all OTel tests must pass even with the SDK absent
```

---

## 9. Environment variables

All defaults work without any env vars set. Override for containers or CI:

| Variable | Default | Purpose |
|---|---|---|
| `BAWBEL_CONSOLE_ADDR` | `127.0.0.1:7317` | Console listen address |
| `BAWBEL_HUB_HOST` | `127.0.0.1` | Hub bind host |
| `BAWBEL_HUB_PORT` | `8443` | Hub bind port |
| `BAWBEL_HUB_DB` | `bawbel-hub.db` | Hub SQLite path |
| `BAWBEL_AUDIT_LOG` | `bawbel-audit.jsonl` | Audit log for posture/audit commands |
| `BAWBEL_SCHEMAS_DIR` | `schemas/` | Vendored JSON schema directory |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(none)_ | OTel collector endpoint |

See `.env.example` for a copy-paste template.

---

## 10. CI checklist

Before merging any PR:

```bash
pre-commit run --all-files          # must be clean
pytest                              # 315 passed
pytest tests/property/ -x          # hypothesis invariants
pytest tests/replay/                # attack replays
```

A change that adds approval prompts on the benign corpus (`tests/corpus/`) is a
regression even if all tests pass. Check `test_m4_corpus.py::TestApprovalBudget`.
