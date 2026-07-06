"""Shared constants for bawbel-gate.

Every magic string, numeric code, and ordered set lives here.
Implementation modules import from this module; they never define literals inline.
"""

# --- Schema identifiers (see DESIGN.md 4.2, 9.1; BAWBEL_GATE_MITIGATIONS_SPEC.md 3) ---
SCHEMA_CAPABILITY_MANIFEST_V1 = "bawbel/capability-manifest/v1"
SCHEMA_AVE_MITIGATIONS_V1 = "bawbel/ave-mitigations/v1"
SCHEMA_GATE_CONFIG_V1 = "bawbel/gate-config/v1"
SCHEMA_AVE_VERSION_SUPPORTED = "1.2"

# Schema file names (relative to schemas/ directory)
SCHEMA_FILE_CAPABILITY_MANIFEST = "capability-manifest-v1.json"
SCHEMA_FILE_AVE_12 = "ave-1.2.json"
SCHEMA_FILE_AVE_MITIGATIONS = "bawbel-ave-mitigations-v1.json"

# --- Effect lattice (see DESIGN.md 5.1) ---
EFFECT_ALLOW = "allow"
EFFECT_APPROVE = "approve"
EFFECT_DENY = "deny"

# Permissiveness order: higher = more permissive. Used by lattice_min.
EFFECT_ORDER: dict[str, int] = {
    EFFECT_ALLOW:   2,
    EFFECT_APPROVE: 1,
    EFFECT_DENY:    0,
}

# --- Provenance classes (see DESIGN.md 4.2 provenanceClass $def) ---
PROVENANCE_USER_DIRECT = "user.direct"
PROVENANCE_OPERATOR_SYSTEM = "operator.system"
PROVENANCE_SKILL_FILE = "skill.file"
PROVENANCE_MEMORY_PERSISTED = "memory.persisted"
PROVENANCE_MODEL_GENERATED = "model.generated"
PROVENANCE_WEB_FETCHED = "web.fetched"
PROVENANCE_TOOL_RESPONSE_PREFIX = "tool.response."

# Entry classes that exist only at grant/verify time (not runtime taint classes)
ENTRY_CLASS_TOOL_SCHEMA = "tool.schema"
ENTRY_CLASS_SERVER_CARD = "server.card"

# --- Trifecta leg names (see DESIGN.md 5.2 step 6, 7.2) ---
TRIFECTA_PRIVATE_DATA = "private_data"
TRIFECTA_UNTRUSTED_CONTENT = "untrusted_content"
TRIFECTA_EXTERNAL_COMMS = "external_comms"

TRIFECTA_LEGS: tuple[str, ...] = (
    TRIFECTA_PRIVATE_DATA,
    TRIFECTA_UNTRUSTED_CONTENT,
    TRIFECTA_EXTERNAL_COMMS,
)

# --- JSON-RPC error codes (see DESIGN.md 6.2) ---
JSONRPC_DENY_CODE = -32031

# --- Deny reasons: closed set (see DESIGN.md 6.2, docs/LANGUAGE.md) ---
REASON_NO_GRANT = "no_grant"
REASON_CONDITION_FAILED = "condition_failed"
REASON_TRIFECTA_THIRD_LEG = "trifecta_third_leg"
REASON_GUARD_SECRET_SCAN = "guard:secret_scan"  # nosec B105 # noqa: S105 -- deny reason code, not a password
REASON_GUARD_BYTE_CAP = "guard:byte_cap"
REASON_APPROVAL_TIMEOUT = "approval_timeout"
REASON_APPROVAL_DENIED = "approval_denied"
REASON_DRIFT_SUSPENDED = "drift:suspended"
REASON_PARSE_ERROR = "parse_error"

# --- AVE record identifiers ---
AVE_ID_PATTERN = r"^AVE-\d{4}-\d{5}$"

# --- Tool namespace separator (see DESIGN.md 3.2) ---
TOOL_NS_SEP = "__"

# --- Audit chain constants (see DESIGN.md 8.6) ---
AUDIT_CHAIN_GENESIS = "sha256:" + "0" * 64  # prev for the first record
AUDIT_HASH_PREFIX = "sha256:"
ARGS_SHA256_DEFAULT = None  # args hashed, not stored, by default

# --- Approval (see DESIGN.md 7.5) ---
APPROVAL_TIMEOUT_DEFAULT_S = 120
APPROVAL_ON_TIMEOUT = EFFECT_DENY  # fail-closed; not configurable

# --- Latency budget (see DESIGN.md 11.2, IMPLEMENTATION_PLAN.md M4) ---
LATENCY_P95_MAX_MS = 5

# --- Approval budget (see DESIGN.md 7.5, IMPLEMENTATION_PLAN.md M4) ---
APPROVAL_BUDGET_P95 = 0   # zero prompts at p95 on benign corpus
APPROVAL_BUDGET_P99 = 1   # at most one prompt at p99

# --- Instruction authority levels (see DESIGN.md 4.2) ---
INSTRUCTION_AUTHORITY_NONE = "none"
INSTRUCTION_AUTHORITY_ADVISORY = "advisory"
INSTRUCTION_AUTHORITY_FULL = "full"

# --- AVE mitigation review states (see BAWBEL_GATE_MITIGATIONS_SPEC.md 2) ---
REVIEW_STATUS_UNREVIEWED = "unreviewed"
REVIEW_STATUS_LLM_DRAFTED = "llm_drafted"
REVIEW_STATUS_REVIEWED = "reviewed"

# --- Rule ID format for stanza-to-rule provenance (see BAWBEL_GATE_MITIGATIONS_SPEC.md 4) ---
RULE_ID_PREFIX = "bawbel-gate"
RULE_ID_PATTERN = r"^bawbel-gate/[a-z0-9-]+/AVE-\d{4}-\d{5}/\d+$"

# --- Session state events (see DESIGN.md 6.2) ---
EVENT_SESSION_START = "SESSION_START"
EVENT_TOOL_LIST = "TOOL_LIST"
EVENT_CALL_RECEIVED = "CALL_RECEIVED"
EVENT_CALL_DECIDED = "CALL_DECIDED"
EVENT_RESPONSE_RECEIVED = "RESPONSE_RECEIVED"
EVENT_APPROVAL_GRANTED = "APPROVAL_GRANTED"
EVENT_APPROVAL_DENIED = "APPROVAL_DENIED"
EVENT_APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT"
EVENT_DRIFT_DETECTED = "DRIFT_DETECTED"
EVENT_SESSION_CLEAR = "SESSION_CLEAR"
EVENT_SESSION_END = "SESSION_END"

# --- Integrity / drift (see DESIGN.md 8.1, 8.2) ---
ON_DRIFT_SUSPEND = "suspend"
ON_DRIFT_DENY = "deny"
ON_DRIFT_APPROVE = "approve"

INTEGRITY_KIND_TOOL_SCHEMA = "tool_schema"
INTEGRITY_KIND_BINARY = "binary"
INTEGRITY_KIND_REMOTE_RESOURCE = "remote_resource"
