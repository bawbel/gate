# setup-gate-skills

Run once first.

1. Read CLAUDE.md — understand record vs finding distinction
2. Read ARCHITECTURE.md — the record/rule/fixture triangle

## Install Matt Pocock's skills

```bash
npx skills@latest add mattpocock/skills/tdd
npx skills@latest add mattpocock/skills/grill-with-docs
npx skills@latest add mattpocock/skills/to-prd
npx skills@latest add mattpocock/skills/handoff
```

## Key context

this repo is a software of Runtime enforcement for MCP agents: capability manifests, session taint tracking, and
a non-configurable rule-of-two trifecta invariant, with a hash-chained audit log.
