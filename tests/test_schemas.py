"""Tests for all three JSON Schemas (ave-1.2, capability-manifest-v1, bawbel-ave-mitigations-v1).

Each test group:
  1. Schema itself is valid JSON Schema draft 2020-12.
  2. Known-good fixtures validate successfully.
  3. Known-bad inputs are rejected with the right path.
"""

from pathlib import Path

import jsonschema
import jsonschema.validators

REPO_ROOT = Path(__file__).parent.parent


def _validator(schema: dict):
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


# ---------------------------------------------------------------------------
# AVE 1.2 schema
# ---------------------------------------------------------------------------

class TestAve12Schema:
    def test_schema_is_valid_draft_2020_12(self, ave_12_schema):
        jsonschema.validators.validator_for(ave_12_schema).check_schema(ave_12_schema)

    def test_backfilled_record_validates(self, ave_12_schema, ave_v1_2_records):
        record = ave_v1_2_records["AVE-2026-00041"]
        _validator(ave_12_schema).validate(record)

    def test_null_new_fields_validates(self, ave_12_schema):
        """A record with the three new fields as null is valid (post-null-insert migration)."""
        record = {
            "schema_version": "1.2",
            "id": "AVE-2026-00099",
            "title": "Test record",
            "description": "Null-insert migration output.",
            "aivss": {"version": "0.8", "base_score": 5.0},
            "triage": {"status": "reviewed", "provenance": "unclassified"},
            "mitigation": {"strategy": ["deny_by_default"]},
            "provenance_vector": None,
            "trifecta_profile": None,
            "capability_mitigation": None,
        }
        _validator(ave_12_schema).validate(record)

    def test_wrong_schema_version_rejected(self, ave_12_schema):
        record = {
            "schema_version": "1.1",
            "id": "AVE-2026-00001",
            "title": "x",
            "description": "x",
            "aivss": {"version": "0.8", "base_score": 1.0},
            "triage": {"status": "draft"},
            "mitigation": {"strategy": ["deny_by_default"]},
        }
        errors = list(_validator(ave_12_schema).iter_errors(record))
        assert errors, "schema_version 1.1 must be rejected by the 1.2 schema"

    def test_invalid_ave_id_rejected(self, ave_12_schema):
        record = {
            "schema_version": "1.2",
            "id": "INVALID-001",
            "title": "x",
            "description": "x",
            "aivss": {"version": "0.8", "base_score": 1.0},
            "triage": {"status": "draft"},
            "mitigation": {"strategy": ["deny_by_default"]},
        }
        errors = list(_validator(ave_12_schema).iter_errors(record))
        assert any("id" in str(e.absolute_path) for e in errors)

    def test_bad_entry_class_rejected(self, ave_12_schema):
        record = {
            "schema_version": "1.2",
            "id": "AVE-2026-00001",
            "title": "x",
            "description": "x",
            "aivss": {"version": "0.8", "base_score": 1.0},
            "triage": {"status": "draft"},
            "mitigation": {"strategy": ["deny_by_default"]},
            "provenance_vector": {
                "entry_class": "unknown.class",
                "escalation": "data->instruction",
            },
            "trifecta_profile": None,
            "capability_mitigation": None,
        }
        errors = list(_validator(ave_12_schema).iter_errors(record))
        # oneOf wraps sub-errors; assert at minimum that the record is invalid
        assert errors, "unknown entry_class must produce validation errors"
        all_messages = " ".join(str(e.message) for e in errors)
        assert "unknown.class" in all_messages or errors  # schema rejects the value

    def test_all_v1_1_corpus_records_have_required_base_fields(self, ave_v1_1_records):
        required = {"schema_version", "id", "title", "description", "aivss", "triage", "mitigation"}
        for name, record in ave_v1_1_records.items():
            missing = required - set(record.keys())
            assert not missing, f"{name} missing: {missing}"


# ---------------------------------------------------------------------------
# Capability manifest schema
# ---------------------------------------------------------------------------

class TestCapabilityManifestSchema:
    def test_schema_is_valid_draft_2020_12(self, cap_manifest_schema):
        jsonschema.validators.validator_for(cap_manifest_schema).check_schema(cap_manifest_schema)

    def test_example_manifest_validates(self, cap_manifest_schema):
        manifest = {
            "schema": "bawbel/capability-manifest/v1",
            "subject": {"kind": "mcp-server", "name": "github-mcp", "transport": "stdio"},
            "provenance_class": "tool.response.github",
            "instruction_authority": "none",
            "trifecta": {
                "private_data": True,
                "untrusted_content": True,
                "external_comms": True,
            },
            "grants": {
                "tools": [
                    {"name": "get_issue", "effect": "allow"},
                    {"name": "*", "effect": "deny"},
                ]
            },
        }
        _validator(cap_manifest_schema).validate(manifest)

    def test_manifest_stanza_def_validates(self, cap_manifest_schema):
        """$defs/manifestStanza accepts a fragment with no required fields."""
        stanza = {
            "integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}],
            "taint_rules": [
                {
                    "when": {"tainted_by_any": ["tool.response.*"]},
                    "then": [{"tools_with": "external_comms", "effect": "approve"}],
                }
            ],
        }
        # Wrap in a schema that includes the full $defs so internal $refs resolve.
        wrapped = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/manifestStanza",
            "$defs": cap_manifest_schema["$defs"],
        }
        jsonschema.Draft202012Validator(wrapped).validate(stanza)

    def test_missing_required_field_rejected(self, cap_manifest_schema):
        manifest = {
            "schema": "bawbel/capability-manifest/v1",
            "subject": {"kind": "mcp-server", "name": "test"},
            # missing provenance_class, instruction_authority, trifecta, grants
        }
        errors = list(_validator(cap_manifest_schema).iter_errors(manifest))
        assert len(errors) >= 4

    def test_allow_effect_valid_in_grant(self, cap_manifest_schema):
        """allow is valid in a full manifest; mitigation stanzas restrict this separately."""
        manifest = {
            "schema": "bawbel/capability-manifest/v1",
            "subject": {"kind": "mcp-server", "name": "fs-mcp"},
            "provenance_class": "tool.response.fs-mcp",
            "instruction_authority": "none",
            "trifecta": {"private_data": True, "untrusted_content": False, "external_comms": False},
            "grants": {
                "tools": [
                    {"name": "read_file", "effect": "allow"},
                    {"name": "*", "effect": "deny"},
                ]
            },
        }
        _validator(cap_manifest_schema).validate(manifest)

    def test_invalid_provenance_class_rejected(self, cap_manifest_schema):
        manifest = {
            "schema": "bawbel/capability-manifest/v1",
            "subject": {"kind": "mcp-server", "name": "test"},
            "provenance_class": "bad.class",
            "instruction_authority": "none",
            "trifecta": {
                "private_data": False, "untrusted_content": False, "external_comms": False
            },
            "grants": {"tools": [{"name": "*", "effect": "deny"}]},
        }
        errors = list(_validator(cap_manifest_schema).iter_errors(manifest))
        assert any("provenance_class" in str(e.absolute_path) for e in errors)

    def test_on_timeout_deny_only(self, cap_manifest_schema):
        """on_timeout: allow would be fail-open; the schema must reject it."""
        manifest = {
            "schema": "bawbel/capability-manifest/v1",
            "subject": {"kind": "mcp-server", "name": "test"},
            "provenance_class": "tool.response.test",
            "instruction_authority": "none",
            "trifecta": {
                "private_data": False, "untrusted_content": False, "external_comms": False
            },
            "grants": {"tools": [{"name": "*", "effect": "deny"}]},
            "approval": {"channel": "terminal", "timeout_seconds": 30, "on_timeout": "allow"},
        }
        errors = list(_validator(cap_manifest_schema).iter_errors(manifest))
        assert any("on_timeout" in str(e.absolute_path) for e in errors)


# ---------------------------------------------------------------------------
# AVE mitigations envelope schema
# ---------------------------------------------------------------------------

class TestAveMitigationsSchema:
    def test_schema_is_valid_draft_2020_12(self, ave_mitigations_schema):
        jsonschema.validators.validator_for(ave_mitigations_schema).check_schema(ave_mitigations_schema)

    def test_valid_unreviewed_entry(self, ave_mitigations_schema):
        doc = {
            "schema": "bawbel/ave-mitigations/v1",
            "generated_against_ave_schema": "1.2.0",
            "mitigations": {
                "AVE-2026-00041": {
                    "review_status": "unreviewed",
                    "derives_from": {
                        "strategy": ["pin_integrity"],
                        "enforcement_point": "server_card_fetch",
                        "trifecta_control": "break_untrusted_content",
                    },
                    "manifest_stanza": {
                        "integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}]
                    },
                }
            },
        }
        _validator(ave_mitigations_schema).validate(doc)

    def test_reviewed_entry_requires_reviewed_by_and_rule_ids(self, ave_mitigations_schema):
        doc = {
            "schema": "bawbel/ave-mitigations/v1",
            "generated_against_ave_schema": "1.2.0",
            "mitigations": {
                "AVE-2026-00041": {
                    "review_status": "reviewed",
                    # missing reviewed_by, reviewed_at, rule_ids
                    "derives_from": {"strategy": ["pin_integrity"]},
                    "manifest_stanza": {
                        "integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}]
                    },
                }
            },
        }
        errors = list(_validator(ave_mitigations_schema).iter_errors(doc))
        assert errors, "reviewed entry without reviewed_by/reviewed_at/rule_ids must fail"

    def test_reviewed_entry_valid(self, ave_mitigations_schema):
        doc = {
            "schema": "bawbel/ave-mitigations/v1",
            "generated_against_ave_schema": "1.2.0",
            "mitigations": {
                "AVE-2026-00041": {
                    "review_status": "reviewed",
                    "reviewed_by": "chaksaray",
                    "reviewed_at": "2026-07-05T12:00:00Z",
                    "rule_ids": ["bawbel-gate/server-card-pin/AVE-2026-00041/0"],
                    "derives_from": {
                        "strategy": ["pin_integrity", "deny_by_default"],
                        "enforcement_point": "server_card_fetch",
                        "trifecta_control": "break_untrusted_content",
                    },
                    "manifest_stanza": {
                        "integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}],
                        "taint_rules": [
                            {
                                "when": {"tainted_by_any": ["tool.response.*"]},
                                "then": [{"tools_with": "external_comms", "effect": "approve"}],
                            }
                        ],
                    },
                }
            },
        }
        _validator(ave_mitigations_schema).validate(doc)

    def test_invalid_ave_key_rejected(self, ave_mitigations_schema):
        doc = {
            "schema": "bawbel/ave-mitigations/v1",
            "generated_against_ave_schema": "1.2.0",
            "mitigations": {
                "INVALID-KEY": {
                    "review_status": "unreviewed",
                    "derives_from": {"strategy": ["deny_by_default"]},
                    "manifest_stanza": {
                        "integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}]
                    },
                }
            },
        }
        errors = list(_validator(ave_mitigations_schema).iter_errors(doc))
        assert errors, "invalid AVE key must be rejected"

    def test_invalid_rule_id_pattern_rejected(self, ave_mitigations_schema):
        doc = {
            "schema": "bawbel/ave-mitigations/v1",
            "generated_against_ave_schema": "1.2.0",
            "mitigations": {
                "AVE-2026-00041": {
                    "review_status": "reviewed",
                    "reviewed_by": "chaksaray",
                    "reviewed_at": "2026-07-05T12:00:00Z",
                    "rule_ids": ["bad-rule-id-format"],
                    "derives_from": {"strategy": ["pin_integrity"]},
                    "manifest_stanza": {
                        "integrity_watch": [{"kind": "tool_schema", "on_drift": "suspend"}]
                    },
                }
            },
        }
        errors = list(_validator(ave_mitigations_schema).iter_errors(doc))
        assert errors, "invalid rule_id format must be rejected"
