"""Shared type aliases used across bawbel-gate modules."""

from typing import Any

# Raw JSON-RPC message (decoded from wire)
JsonRpcMessage = dict[str, Any]

# Provenance class string, e.g. "tool.response.github"
ProvenanceClass = str

# Effect string: "allow" | "approve" | "deny"
Effect = str

# AVE ID string, e.g. "AVE-2026-00041"
AveId = str

# Tool name as exposed to the host (namespaced: "{server}__{tool}")
NamespacedTool = str

# Tool name as known to the upstream server (bare: "{tool}")
BareTool = str
