"""Tool namespace utilities per DESIGN.md 3.2.

Upstream tools are re-exposed as {server}__{tool} (double underscore).
The gate rewrites names in both directions before routing.
"""

from bawbel_gate._const import TOOL_NS_SEP
from bawbel_gate._types import BareTool, NamespacedTool


def to_namespaced(server: str, tool: str) -> NamespacedTool:
    return f"{server}{TOOL_NS_SEP}{tool}"


def from_namespaced(namespaced: NamespacedTool) -> tuple[str, BareTool]:
    """Return (server_name, bare_tool). Raises ValueError if not namespaced."""
    parts = namespaced.split(TOOL_NS_SEP, maxsplit=1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"not a namespaced tool: {namespaced!r}")
    return parts[0], parts[1]


def is_namespaced(tool: str) -> bool:
    return TOOL_NS_SEP in tool
