# PRODUCT.md - bawbel-gate product context

Read this when a decision is not purely technical: naming, UX, error copy, what to
build next, what to refuse to build.

## Thesis

Software generation now scales at machine speed; trust still scales with human
attention. Bawbel builds the trust plane between them. The gate is the enforcement
layer: it does not make the model safe, it makes the model's consequences governed.

The closed loop is the product:

```
AVE class -> mitigation stanza -> harden -> manifest -> runtime deny citing the class
     ^                                                            |
     └──────────────── fleet deny patterns (evidence) ◀───────────┘
```

Taxonomy (AVE), detection (scanner), enforcement (gate). We own all three layers and
every finding, rule, and denial cites its class. A finding is a citation, never an
opinion.

## Who feels what

- **Developers** should mostly never notice the gate. The approval budget is a
  release gate: p95 sessions produce zero prompts. A routine prompt on benign work is
  a bug. Deny errors are precise (`-32031`, reason string, AVE IDs) so a blocked call
  reads as governed infrastructure, not flaky infrastructure.
- **DevOps** get a stateless-ish sidecar: one process, manifests as env-promoted git
  files, OTel spans, p95 <= 5 ms decision overhead asserted in CI.
- **DevSecOps/Security** own the loop: triage classes, `harden`, read drift diffs,
  wire alerts to the SIEM, map controls to PCI DSS v4.0 / ISO 27001 / NIST / NBC
  TCRMG (DESIGN.md Appendix A).

## Non-goals (refuse politely, cite this file)

- No prompt filtering, no model-output analysis, no "AI firewall" heuristics.
  Deterministic decisions on structured data only.
- No fail-open modes, no configurable trifecta bypass, no "trust this server fully"
  toggle.
- No centralized approval routing in v1.x (deliberately deferred, DESIGN.md 13.4).
- No inbound connections to gates, ever.
- No storing argument payloads by default. Hashes travel; payloads do not.

## Voice

Write for developers and security engineers. Precise, technical, direct. Exact
commands, file paths, env vars, data structures. Examples over prose. State
limitations plainly; the limitations page is a trust asset, not a liability. No
marketing language anywhere, including README badges and release notes.
