# bawbel-gate

Runtime enforcement for MCP agents: capability manifests, session taint tracking, and
a non-configurable rule-of-two trifecta invariant, with a hash-chained audit log.

## Status: design complete, implementation in progress

This repo currently ships the specification, not the enforced product. Read
[DESIGN.md](./DESIGN.md) before writing code against it or depending on it in
production. Track progress in [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md).
No stable release exists yet; do not pin this repo in a production pipeline before
v1.0.

## The problem

Agent hosts grant flat trust to everything in context. A tool response, a skill
file, and a user message carry equal instruction authority inside the model, because
the model processes one token sequence with no privilege boundary. That is not
fixable at the model layer. bawbel-gate fixes the consequence layer instead: a
deterministic proxy between the agent host and its MCP servers that enforces
per-component capability grants, session taint, and the trifecta invariant,
regardless of what the model decides to do.

## What it does

| Capability | Spec |
|---|---|
| Default-deny, signed capability manifests per MCP server | DESIGN.md §4 |
| Monotone, class-level session taint tracking | DESIGN.md §7 |
| Rule-of-two trifecta invariant, cannot be disabled by any manifest | DESIGN.md §5-7 |
| Integrity pinning against tool-schema drift and rug-pull attacks | DESIGN.md §8 |
| Hash-chained, tamper-evident audit log | DESIGN.md §8.6 |
| Learning mode: synthesize a draft manifest from observed usage | DESIGN.md §7.5 |
| Embedded console (single gate) | DESIGN.md §13 |
| Self-hosted fleet console for teams (bawbel-hub) | DESIGN.md §14 |

## How it works

```
Agent host ──MCP──▶ bawbel-gate ──MCP──▶ github-mcp, filesystem-mcp, ...
              (multiplexer, manifest loader, provenance tagger,
               policy engine, taint tracker, approval gate, audit log)
```

The agent host is configured to see exactly one MCP server. bawbel-gate holds the
real server configs, re-exposes their tools under namespaced names
(`{server}__{tool}`), and decides every call: `allow`, `approve` (human gate), or
`deny`. Effects only move down that lattice; a session that touches private data and
untrusted content cannot reach external communication without a human decision, and
no manifest field can turn that off.

Full decision pipeline, state machine, and manifest schema: [DESIGN.md](./DESIGN.md).
Where this fits among the other Bawbel projects: [ARCHITECTURE.md](./ARCHITECTURE.md).

## Non-goals

- Not a prompt filter and not model-output analysis. Every enforcement decision
  reads structured JSON-RPC only; the gate never consults what the model said.
- No fail-open mode, no configurable trifecta bypass, no "trust this server fully"
  toggle.
- No inbound connections to gates, ever, in any deployment shape.
- No argument payload storage by default. Records carry `args_sha256`, not the
  arguments themselves.

## Install (target, once packaged)

```bash
pip install bawbel-gate
```

## Quickstart (target shape, subject to change pre-1.0)

Point your MCP client at the gate instead of your servers directly:

```json
{
  "mcpServers": {
    "bawbel-gate": {
      "command": "bawbel-gate",
      "args": ["serve", "--config", "gate.yaml"]
    }
  }
}
```

Have no manifests yet? Run learning mode first and review what it observes:

```bash
bawbel-gate learn --config gate.yaml --duration 7d
bawbel-gate learn report
bawbel-gate learn synthesize --out manifests/
```

Minimal manifest shape (see DESIGN.md §4.1 for the annotated version):

```yaml
schema: bawbel/capability-manifest/v1
subject:
  kind: mcp-server
  name: github-mcp
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
      conditions:
        args.base_repo: {pattern: "myorg/*"}
    - name: "*"
      effect: deny
```

## Documentation

- [DESIGN.md](./DESIGN.md) - normative specification: threat model, manifest
  schema, policy semantics, state machine, telemetry API, compliance mapping.
- [ARCHITECTURE.md](./ARCHITECTURE.md) - where bawbel-gate sits among AVE,
  bawbel-scanner, PiranhaDB, and the rest of the Bawbel ecosystem.
- [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) - milestones and priorities.

## Related projects

- [AVE](https://ave.bawbel.io) - the behavioral vulnerability classification
  standard bawbel-gate enforces against (`bawbel-gate harden --ave`).
- [bawbel-scanner](https://pypi.org/project/bawbel-scanner/) - static detection
  for agent codebases, MCP configs, and server cards.
- [PiranhaDB](https://api.piranha.bawbel.io) - the queryable AVE corpus API.

## Security

See [SECURITY.md](./SECURITY.md) for the disclosure policy. Do not open a public
issue for a vulnerability.

## License

Apache-2.0.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Read DESIGN.md before opening a PR that
touches `policy/`, `taint/`, `audit/`, or `integrity/`: behavior that diverges from
the spec needs a DESIGN.md change first, not a larger diff.