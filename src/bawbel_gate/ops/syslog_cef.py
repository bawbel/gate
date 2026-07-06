"""CEF/syslog formatter for the six alertable event classes.

See DESIGN.md 8.5 — SIEMs without OTel ingestion.

CEF format: CEF:Version|Device Vendor|Device Product|Device Version|
            Device Event Class ID|Name|Severity|[Extension]

Extension key=value pairs: pipe, equals, and backslash in values must be escaped.
Newlines are stripped (CEF is one record per line).
"""

from __future__ import annotations

from bawbel_gate._const import (
    ALERT_DEFAULT_SEVERITIES,
    CEF_DEV_VERSION,
    CEF_PRODUCT,
    CEF_SEVERITY,
    CEF_VENDOR,
    CEF_VERSION,
)


def _escape_header(value: str) -> str:
    """Escape pipe and backslash in CEF header fields."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_ext_value(value: str) -> str:
    """Escape equals, pipe, backslash, and newlines in CEF extension values."""
    value = value.replace("\\", "\\\\")
    value = value.replace("|", "\\|")
    value = value.replace("=", "\\=")
    value = value.replace("\n", " ").replace("\r", " ")
    return value


def _sev_int(event_class: str) -> int:
    """Map event class to CEF severity integer (0-10)."""
    sev_name = ALERT_DEFAULT_SEVERITIES.get(event_class, "medium")
    return CEF_SEVERITY.get(sev_name, 5)


def format_cef_record(event_class: str, attrs: dict[str, object]) -> str:
    """Return a single-line CEF record for the given alertable event class.

    attrs values are cast to str before encoding.
    """
    sev = _sev_int(event_class)
    event_id = _escape_header(event_class)
    name = _escape_header(event_class)

    header = (
        f"CEF:{CEF_VERSION}"
        f"|{_escape_header(CEF_VENDOR)}"
        f"|{_escape_header(CEF_PRODUCT)}"
        f"|{_escape_header(CEF_DEV_VERSION)}"
        f"|{event_id}"
        f"|{name}"
        f"|{sev}"
    )

    if not attrs:
        return header

    ext_parts = []
    for key, val in attrs.items():
        safe_key = str(key).replace(" ", "_")
        safe_val = _escape_ext_value(str(val))
        ext_parts.append(f"{safe_key}={safe_val}")

    return header + "|" + " ".join(ext_parts)
