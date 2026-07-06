"""OTel span emission for the gate decision pipeline.

See DESIGN.md 8.5 and 11.2.

opentelemetry-sdk is an optional dependency. When absent, all functions are no-ops
so the gate runs without any observability stack installed. Enable with:
  pip install 'bawbel-gate[ops]'
and set OTEL_EXPORTER_OTLP_ENDPOINT.
"""

from __future__ import annotations

import os
from typing import Any

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

from bawbel_gate._const import OTEL_SPAN_DECISION

_tracer: Any = None


def setup_otel(endpoint: str | None = None) -> None:
    """Configure a TracerProvider if OTel SDK is installed and endpoint is set.

    Reads OTEL_EXPORTER_OTLP_ENDPOINT when endpoint is None.
    """
    global _tracer  # noqa: PLW0603 -- module-level singleton; intentional
    if not OTEL_AVAILABLE:
        return

    resolved = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not resolved:
        return

    try:  # nosec B110 -- best-effort OTel setup; gate continues on failure
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # noqa: F401
        resource = Resource.create({"service.name": "bawbel-gate"})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=resolved)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("bawbel.gate")
    except Exception:  # noqa: BLE001 -- OTel failure must not break the gate
        _tracer = None


def record_decision_span(
    tool: str,
    server: str,
    decision: Any,
    taint_classes: list[str],
    latency_ms: float,
) -> None:
    """Emit a bawbel.gate.decision OTel span if a tracer is configured.

    Attributes per DESIGN.md 8.5: server, tool, effect, reason, taint, latency.
    """
    if _tracer is None or not OTEL_AVAILABLE:
        return

    with _tracer.start_as_current_span(OTEL_SPAN_DECISION) as span:
        span.set_attribute("gate.server", server)
        span.set_attribute("gate.tool", tool)
        span.set_attribute("gate.effect", decision.effect)
        span.set_attribute("gate.reason", decision.reason or "")
        span.set_attribute("gate.taint_classes", ",".join(sorted(taint_classes)))
        span.set_attribute("gate.latency_ms", latency_ms)
        if decision.ave:
            span.set_attribute("gate.ave_ids", ",".join(decision.ave))


def emit_alert_event(event_class: str, attrs: dict[str, object]) -> None:
    """Emit an alertable event as an OTel log event if a tracer is configured.

    When OTel is absent, this is a deliberate no-op: the audit JSONL is the
    forensic record; OTel is an operational feed.
    """
    if _tracer is None or not OTEL_AVAILABLE:
        return

    with _tracer.start_as_current_span(event_class) as span:
        for key, val in attrs.items():
            span.set_attribute(f"gate.{key}", str(val))
