---
name: ave-record-authoring
description: Rules for creating, editing, migrating, or triaging AVE records and their schema-1.2 fields (provenance_vector, trifecta_profile, capability_mitigation) in the ave repo or PiranhaDB. Use this skill whenever the task involves an AVE ID (AVE-2026-*), writing or reviewing a vulnerability record, authoring a mitigation stanza, classifying provenance or trifecta applicability, running or writing the v1.2 migration, or backfilling triage batches, even if the request just says "add a new vuln" or "document this attack pattern".
---

# ave-record-authoring

AVE records are CWE-shaped: they define behavioral CLASSES, not instances. If the
draft describes one specific incident, one specific server, or one specific payload,
it is not a record yet; generalize to the class or stop.

## Checklist for every record (new or edited)

1. Validates against `schemas/ave-1.2.json` (draft 2020-12) locally before the PR.
2. `provenance_vector` is set by hand. NEVER auto-guess it; a wrong entry_class is
   worse than `"triage": {"provenance": "unclassified"}`.
3. `capability_mitigation.manifest_stanza`, if present, validates against
   `bawbel/capability-manifest/v1` AND only lowers effects (taint rules and grants in
   a stanza may introduce approve/deny, never allow).
4. Scoring is AIVSS v0.8 and is untouched by trifecta_profile; the profile filters
   applicability, it does not modify severity.
5. AVE IDs exact: `AVE-2026-000NN`. Cross-references use the ID, never a title.
6. Voice per docs/PRODUCT.md: precise, technical, examples over prose, no marketing.

## Field semantics (quick reference)

- `provenance_vector.entry_class`: where the class enters the context supply chain.
  Enum plus `tool.response.*` prefix form; `tool.schema` and `server.card` are
  entry-only classes (grant/verify time), valid here but never as runtime taint.
- `provenance_vector.escalation`: exactly one of `data->instruction`,
  `instruction->capability`, `capability->identity`. If you cannot pick one, the
  class is not understood well enough to publish.
- `trifecta_profile.requires`: legs that are preconditions. Keyed form
  (`"private_data": "amplifies"`) marks impact amplifiers that are not preconditions.
- `capability_mitigation`: the executable link. Ask of every stanza: "if
  `bawbel-gate harden --ave` merges this into a real deployment, does it neutralize
  the class without breaking the approval budget?" A stanza that approves every call
  is not a mitigation, it is alert fatigue.

## Stanza example (shape to copy)

```json
{
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

## Migration and publication rules

- Schema changes are additive within 1.x. Removing or retyping a field is v2.0 and
  needs a deprecation entry in the changelog one minor version earlier.
- Migration scripts are idempotent, git-diffable, and never classify: they insert
  nulls and `unclassified` triage markers only.
- A record is published when CI validates it and PiranhaDB serves it; `?schema=1.1`
  must strip 1.2 fields, and the contract test for both versions must stay green.
- Backfill lands as reviewed PR batches; each batch updates the triage counter on
  ave.bawbel.io.
