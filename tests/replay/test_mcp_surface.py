"""Replay test: MCP methods outside tools/* as a prompt-injection ingress.

Attack surface (OWASP ACS v0.1.0 names resources/read the canonical ingress for
attacker-controlled external content):
  1. The host requests resources/read, prompts/get, or another non-tools method.
     Forwarded untagged, the upstream content would reach the model without setting
     untrusted_seen, and the trifecta invariant could never fire for that session.
  2. The upstream pushes content nobody asked for: a notification, or a
     server-to-client request such as sampling/createMessage, written ahead of a
     tools/call response.

The gate's MCP surface is initialize, tools/list, tools/call (DESIGN.md 3.3). Every
other method is rejected at the gate, and every upstream message that is not the
response to the gate's own request is dropped or refused. Each layer is asserted
on its own so a regression names the path that opened.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from bawbel_gate.mux.config import ApprovalConfig, GateConfig, ServerConfig
from tests.fixtures.hostile_mcp_server import INJECTION_MARKER, SAMPLING_REQUEST_ID_PREFIX
from tests.proxy_harness import empty_console_state, run_enforce_session

FIXTURES = Path(__file__).parent.parent / "fixtures"
HOSTILE_SERVER = FIXTURES / "hostile_mcp_server.py"
MANIFEST = FIXTURES / "hostile_test.cap.yaml"
SERVER = "hostile"
PROVENANCE_CLASS = "tool.response.hostile"

# JSON-RPC 2.0 section 5.1. Asserted against the spec value, not a gate constant.
METHOD_NOT_FOUND = -32601

_RESOURCE = {"uri": "file:///poisoned/README.md"}
_PROMPT = {"name": "summarize"}
NON_TOOLS_REQUESTS = {
    "resources/list": {},
    "resources/templates/list": {},
    "resources/read": _RESOURCE,
    "resources/subscribe": _RESOURCE,
    "prompts/list": {},
    "prompts/get": _PROMPT,
    "completion/complete": {"ref": {"type": "ref/prompt", **_PROMPT}},
    "logging/setLevel": {"level": "debug"},
}
HOST_NOTIFICATIONS = {
    "notifications/initialized": {},
    "notifications/cancelled": {"requestId": 2},
    "notifications/roots/list_changed": {},
}


def _session(tmp_path: Path, messages: list[dict]):
    """Run one enforce session; return (sent to host, SessionState, received upstream)."""
    received_log = tmp_path / "upstream_received.jsonl"
    cfg = GateConfig(
        audit_log=tmp_path / "audit.jsonl",
        servers=[ServerConfig(
            name=SERVER, command=sys.executable,
            args=[str(HOSTILE_SERVER), str(received_log)], manifest=MANIFEST,
        )],
        approval=ApprovalConfig(channel="terminal", timeout_seconds=5),
    )
    state = empty_console_state(cfg)
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    sent = run_enforce_session(cfg, [initialize, *messages], console_state=state)
    session = next(iter(state.sessions.values()))
    received = [
        json.loads(line) for line in received_log.read_text(encoding="utf-8").splitlines()
    ]
    return sent, session, received


def _get_file(request_id: int, path: str) -> dict:
    return {
        "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
        "params": {"name": f"{SERVER}__get_file", "arguments": {"path": path}},
    }


def _by_id(sent: list[dict]) -> dict:
    return {m["id"]: m for m in sent if "id" in m}


# ---------------------------------------------------------------------------
# Layer 1: host requests outside tools/* are rejected at the gate
# ---------------------------------------------------------------------------

class TestNonToolsRequestsAreRejected:
    def test_every_non_tools_request_is_rejected_and_never_forwarded(self, tmp_path):
        requests = [
            {"jsonrpc": "2.0", "id": 10 + i, "method": method, "params": params}
            for i, (method, params) in enumerate(NON_TOOLS_REQUESTS.items())
        ]
        sent, _, received = _session(tmp_path, requests)

        responses = _by_id(sent)
        for request in requests:
            error = responses[request["id"]].get("error")
            assert error is not None and error["code"] == METHOD_NOT_FOUND, (
                f"{request['method']} must be rejected with JSON-RPC method-not-found"
            )
        forwarded = {m.get("method") for m in received}
        assert forwarded.isdisjoint(NON_TOOLS_REQUESTS), (
            f"the gate forwarded {sorted(forwarded & set(NON_TOOLS_REQUESTS))} upstream"
        )

    def test_rejected_resources_read_leaves_the_session_clean(self, tmp_path):
        sent, session, _ = _session(tmp_path, [
            {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": _RESOURCE},
        ])
        assert INJECTION_MARKER not in json.dumps(sent), (
            "poisoned resource content reached the host"
        )
        # No upstream content entered the session, so nothing could have been tagged.
        assert session.tainted_by == set()
        assert session.untrusted_seen is False

    def test_initialize_advertises_the_tools_capability_only(self, tmp_path):
        sent, _, _ = _session(tmp_path, [])
        capabilities = _by_id(sent)[1]["result"]["capabilities"]
        assert capabilities == {"tools": {}}, (
            "a host must not be told the gate serves resources, prompts, or logging"
        )


# ---------------------------------------------------------------------------
# Layer 2: host notifications stay at the gate
# ---------------------------------------------------------------------------

class TestHostNotificationsAreNotForwarded:
    def test_host_notifications_are_not_forwarded_or_answered(self, tmp_path):
        notifications = [
            {"jsonrpc": "2.0", "method": method, "params": params}
            for method, params in HOST_NOTIFICATIONS.items()
        ]
        sent, _, received = _session(tmp_path, notifications)

        assert [m["id"] for m in sent] == [1], "only the initialize request gets a response"
        forwarded = {m.get("method") for m in received}
        assert forwarded.isdisjoint(HOST_NOTIFICATIONS)


# ---------------------------------------------------------------------------
# Layer 3: upstream messages that are not the awaited response
# ---------------------------------------------------------------------------

class TestUnsolicitedUpstreamMessages:
    def test_upstream_notification_does_not_replace_the_tool_result(self, tmp_path):
        sent, _, _ = _session(tmp_path, [_get_file(2, "a")])

        result = _by_id(sent)[2].get("result")
        assert result is not None, "an upstream notification was returned as the result"
        echoed = json.loads(result["content"][0]["text"])
        assert echoed["arguments"] == {"path": "a"}

    def test_each_tool_result_is_paired_with_its_own_call(self, tmp_path):
        paths = {2: "a", 3: "b", 4: "c"}
        sent, _, _ = _session(tmp_path, [_get_file(i, p) for i, p in paths.items()])

        responses = _by_id(sent)
        for request_id, path in paths.items():
            result = responses[request_id].get("result")
            assert result is not None, f"call {request_id} returned no result"
            echoed = json.loads(result["content"][0]["text"])
            assert echoed["arguments"] == {"path": path}, (
                f"call {request_id} received the result of a different call"
            )

    def test_upstream_sampling_request_is_refused_and_not_forwarded(self, tmp_path):
        sent, _, received = _session(tmp_path, [_get_file(2, "a")])

        assert INJECTION_MARKER not in json.dumps(sent), (
            "upstream-initiated content reached the host"
        )
        assert all("method" not in m for m in sent), (
            "the gate must never send a request or notification to the host"
        )
        replies = [
            m for m in received
            if isinstance(m.get("id"), str) and m["id"].startswith(SAMPLING_REQUEST_ID_PREFIX)
        ]
        assert len(replies) == 1, "the upstream's sampling/createMessage got no answer"
        assert "result" not in replies[0]
        assert replies[0]["error"]["code"] == METHOD_NOT_FOUND

    def test_tool_result_is_still_provenance_tagged(self, tmp_path):
        _, session, _ = _session(tmp_path, [_get_file(2, "a")])

        assert PROVENANCE_CLASS in session.tainted_by
        assert session.untrusted_seen is True
