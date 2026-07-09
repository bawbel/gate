"""The MCP multiplexer request loop. See DESIGN.md 3.3, 6.2.

run_enforce() and run_learn() are the two blocking entry points cli.py's `serve`
command drives. Both spawn every configured upstream server, do the tools/list
handshake, then loop reading JSON-RPC from the host: run_enforce() routes every
tools/call through the policy decision pipeline (policy/engine.py) before ever
forwarding upstream; run_learn() forwards everything unconditionally and records
observations for `learn report` / `learn synthesize`.

Deliberately out of scope for this pass (DESIGN.md features not yet wired here):
console-driven approval (webhook/slack channels; terminal only), integrity_watch
kind=remote_resource (only tool_schema VERIFY runs), task-scoped sub-sessions and
duplicate-call collapsing (both already deferred to v1.1 in DESIGN.md 7.3/7.5).
One call is in flight per server at a time; DESIGN.md does not mandate pipelining.
"""

from __future__ import annotations

import contextlib
import hashlib
import itertools
import subprocess  # nosec B404 # noqa: S404 -- only .wait()/.terminate(), spawn is transport.py
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version as _pkg_version
from pathlib import Path
from types import SimpleNamespace
from typing import IO, Callable

from bawbel_gate._const import (
    ALERT_DRIFT_DETECTED,
    AUDIT_HASH_PREFIX,
    EFFECT_ALLOW,
    EFFECT_APPROVE,
    EFFECT_DENY,
    EVENT_CALL_DECIDED,
    EVENT_DRIFT_DETECTED,
    EVENT_SESSION_END,
    EVENT_SESSION_START,
    REASON_DRIFT_SUSPENDED,
    REASON_NO_GRANT,
    TRIFECTA_PRIVATE_DATA,
    TRIFECTA_UNTRUSTED_CONTENT,
)
from bawbel_gate.audit.canonical import canonical_bytes
from bawbel_gate.audit.writer import AuditWriter
from bawbel_gate.console.state import ConsoleState
from bawbel_gate.integrity.pinning import detect_drift
from bawbel_gate.learn.recorder import LearnRecorder
from bawbel_gate.mux.config import GateConfig
from bawbel_gate.mux.namespace import from_namespaced, to_namespaced
from bawbel_gate.mux.session import SessionState
from bawbel_gate.mux.transport import read_messages, spawn_server, write_message
from bawbel_gate.ops.otel import emit_alert_event, record_decision_span
from bawbel_gate.policy.approval import request_approval
from bawbel_gate.policy.engine import Decision, resolve
from bawbel_gate.policy.manifest import Manifest, load_manifest


@dataclass
class _ProxyContext:
    session: SessionState
    manifests: dict[str, Manifest]
    procs: dict[str, subprocess.Popen]
    call_ids: dict[str, "itertools.count[int]"]
    merged_tools: list[dict]
    writer: AuditWriter


def run_enforce(
    cfg: GateConfig,
    *,
    console_state: ConsoleState | None = None,
    host_in: IO[str] | None = None,
    host_out: IO[str] | None = None,
    approval_input_fn: Callable[[], str] | None = None,
) -> None:
    """Full enforcement proxy: every tools/call passes through resolve() first."""
    host_in = host_in or sys.stdin
    host_out = host_out or sys.stdout
    ctx = _bootstrap(cfg, console_state, enforce=True)
    try:
        for message in read_messages(host_in):
            response = _dispatch_enforce(message, ctx, cfg, approval_input_fn)
            if response is not None:
                write_message(host_out, response)
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown(ctx)


def run_learn(
    cfg: GateConfig,
    *,
    console_state: ConsoleState | None = None,
    host_in: IO[str] | None = None,
    host_out: IO[str] | None = None,
    obs_path: Path = Path("learn.observations.jsonl"),
) -> None:
    """Transparent proxy: enforces nothing, records every call for synthesis."""
    host_in = host_in or sys.stdin
    host_out = host_out or sys.stdout
    ctx = _bootstrap(cfg, console_state, enforce=False)
    recorder = LearnRecorder()
    try:
        for message in read_messages(host_in):
            response = _dispatch_learn(message, ctx, recorder)
            if response is not None:
                write_message(host_out, response)
    except KeyboardInterrupt:
        pass
    finally:
        recorder.flush(obs_path)
        _shutdown(ctx)


# ---------------------------------------------------------------------------
# Bootstrap: spawn servers, handshake, VERIFY, merge tools/list
# ---------------------------------------------------------------------------

def _bootstrap(cfg: GateConfig, console_state: ConsoleState | None, *, enforce: bool):
    session = SessionState()
    manifests: dict[str, Manifest] = {}
    procs: dict[str, subprocess.Popen] = {}
    call_ids: dict[str, "itertools.count[int]"] = {}
    merged_tools: list[dict] = []
    writer = AuditWriter.from_existing(cfg.audit_log)

    for server_cfg in cfg.servers:
        manifest = load_manifest(server_cfg.manifest, server_cfg.name)
        manifests[server_cfg.name] = manifest
        session.manifest_hashes[server_cfg.name] = manifest.manifest_sha256

        proc = spawn_server(server_cfg.command, server_cfg.args)
        procs[server_cfg.name] = proc
        call_ids[server_cfg.name] = itertools.count(3)

        _send_and_recv(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        tools_resp = _send_and_recv(
            proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        live_tools = tools_resp.get("result", {}).get("tools", [])

        if enforce and manifest.tool_schema_integrity:
            _check_drift(manifest, server_cfg.name, live_tools, session, writer)

        if console_state is not None:
            console_state.manifests[server_cfg.name] = manifest

        if session.is_suspended(server_cfg.name):
            continue

        for tool in live_tools:
            if enforce:
                grant = manifest.match_grant(tool["name"])
                if grant is None or grant.effect == EFFECT_DENY:
                    continue
            namespaced_tool = dict(tool)
            namespaced_tool["name"] = to_namespaced(server_cfg.name, tool["name"])
            merged_tools.append(namespaced_tool)

    if console_state is not None:
        console_state.sessions[session.session_id] = session

    writer.append({
        "ts": _now_iso(),
        "session": session.session_id,
        "event": EVENT_SESSION_START,
        "manifest_hashes": dict(session.manifest_hashes),
    })

    return _ProxyContext(
        session=session, manifests=manifests, procs=procs, call_ids=call_ids,
        merged_tools=merged_tools, writer=writer,
    )


def _check_drift(
    manifest: Manifest, server: str, live_tools: list[dict],
    session: SessionState, writer: AuditWriter,
) -> None:
    drift = detect_drift(live_tools, manifest.tool_schema_integrity)
    if not drift.drifted:
        return
    session.suspend_server(server)
    writer.append({
        "ts": _now_iso(),
        "session": session.session_id,
        "event": EVENT_DRIFT_DETECTED,
        "server": server,
        "stored_hash": drift.stored_hash,
        "current_hash": drift.current_hash,
    })
    emit_alert_event(ALERT_DRIFT_DETECTED, {
        "server": server, "stored": drift.stored_hash, "current": drift.current_hash,
    })


def _send_and_recv(proc: subprocess.Popen, message: dict) -> dict:
    write_message(proc.stdin, message)
    return next(read_messages(proc.stdout))


def _shutdown(ctx: _ProxyContext) -> None:
    for proc in ctx.procs.values():
        with contextlib.suppress(BrokenPipeError, OSError):
            proc.stdin.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)
        if proc.poll() is None:
            proc.terminate()
    head = ctx.writer.append({
        "ts": _now_iso(),
        "session": ctx.session.session_id,
        "event": EVENT_SESSION_END,
    })
    sys.stderr.write(f"bawbel-gate: session end -- chain head {head}\n")


# ---------------------------------------------------------------------------
# Enforce-mode dispatch
# ---------------------------------------------------------------------------

def _dispatch_enforce(
    message: dict, ctx: _ProxyContext, cfg: GateConfig,
    approval_input_fn: Callable[[], str] | None,
) -> dict | None:
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None  # notification, no response
    if method == "initialize":
        return _initialize_result(request_id)
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": ctx.merged_tools}}
    if method == "tools/call":
        params = message.get("params", {})
        return _handle_tools_call(
            request_id, params, ctx, cfg.approval.timeout_seconds, approval_input_fn,
        )
    return _method_not_found(request_id, method)


def _handle_tools_call(
    request_id, params: dict, ctx: _ProxyContext,
    timeout_s: int, approval_input_fn: Callable[[], str] | None,
) -> dict:
    namespaced = params.get("name", "")
    args = params.get("arguments", {})

    try:
        server, bare_tool = from_namespaced(namespaced)
    except ValueError:
        decision = Decision(effect=EFFECT_DENY, reason=REASON_NO_GRANT)
        _audit_call(ctx, "", namespaced, decision, args, None)
        return decision.to_jsonrpc_error(request_id)

    manifest = ctx.manifests.get(server)
    if manifest is None or ctx.session.is_suspended(server):
        decision = Decision(effect=EFFECT_DENY, reason=REASON_DRIFT_SUSPENDED)
        _audit_call(ctx, server, bare_tool, decision, args, manifest)
        return decision.to_jsonrpc_error(request_id)

    start = time.monotonic()
    decision = resolve(bare_tool, args, manifest, ctx.session)
    final_effect, final_reason, executed = decision.effect, decision.reason, False

    if decision.effect == EFFECT_APPROVE:
        outcome = request_approval(
            bare_tool, args, ctx.session.tainted_by, decision.reason, decision.ave,
            timeout_s=timeout_s, input_fn=approval_input_fn,
        )
        if outcome == "":
            final_effect, executed = EFFECT_APPROVE, True
        else:
            final_effect, final_reason = EFFECT_DENY, outcome
    elif decision.effect == EFFECT_ALLOW:
        executed = True

    if executed:
        response = _forward_and_tag(request_id, server, bare_tool, args, ctx)
    else:
        response = Decision(
            effect=final_effect, reason=final_reason, ave=decision.ave,
        ).to_jsonrpc_error(request_id)

    final_decision = SimpleNamespace(effect=final_effect, reason=final_reason, ave=decision.ave)
    _audit_call(ctx, server, bare_tool, final_decision, args, manifest)
    record_decision_span(
        bare_tool, server, final_decision, list(ctx.session.tainted_by),
        (time.monotonic() - start) * 1000,
    )
    return response


def _forward_and_tag(request_id, server: str, bare_tool: str, args: dict, ctx: _ProxyContext):
    proc = ctx.procs[server]
    upstream_id = next(ctx.call_ids[server])
    upstream_req = {
        "jsonrpc": "2.0", "id": upstream_id, "method": "tools/call",
        "params": {"name": bare_tool, "arguments": args},
    }
    upstream_resp = _send_and_recv(proc, upstream_req)

    manifest = ctx.manifests[server]
    ctx.session.add_taint(manifest.provenance_class)
    if manifest.trifecta.get(TRIFECTA_UNTRUSTED_CONTENT, False):
        ctx.session.mark_untrusted_seen()
    if manifest.trifecta.get(TRIFECTA_PRIVATE_DATA, False):
        ctx.session.mark_private_touched()

    out: dict = {"jsonrpc": "2.0", "id": request_id}
    if "error" in upstream_resp:
        out["error"] = upstream_resp["error"]
    else:
        out["result"] = upstream_resp.get("result")
    return out


# ---------------------------------------------------------------------------
# Learn-mode dispatch
# ---------------------------------------------------------------------------

def _dispatch_learn(message: dict, ctx: _ProxyContext, recorder: LearnRecorder) -> dict | None:
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None
    if method == "initialize":
        return _initialize_result(request_id)
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": ctx.merged_tools}}
    if method == "tools/call":
        params = message.get("params", {})
        namespaced = params.get("name", "")
        args = params.get("arguments", {})
        try:
            server, bare_tool = from_namespaced(namespaced)
        except ValueError:
            return _method_not_found(request_id, "tools/call")
        recorder.record_call(server, bare_tool, args)
        response = _forward_and_tag(request_id, server, bare_tool, args, ctx)
        decision = SimpleNamespace(effect=EFFECT_ALLOW, reason="resolved", ave=[])
        _audit_call(ctx, server, bare_tool, decision, args, ctx.manifests.get(server))
        return response
    return _method_not_found(request_id, method)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _initialize_result(request_id) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "bawbel-gate", "version": _pkg_version("bawbel-gate")},
            "capabilities": {"tools": {}},
        },
    }


def _method_not_found(request_id, method: str) -> dict:
    return {
        "jsonrpc": "2.0", "id": request_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _audit_call(ctx: _ProxyContext, server: str, tool: str, decision, args: dict, manifest) -> None:
    ctx.writer.append({
        "ts": _now_iso(),
        "session": ctx.session.session_id,
        "event": EVENT_CALL_DECIDED,
        "server": server,
        "tool": tool,
        "effect": decision.effect,
        "reason": decision.reason,
        "taint": sorted(ctx.session.tainted_by),
        "args_sha256": _hash_args(args),
        "manifest_sha256": manifest.manifest_sha256 if manifest else None,
        "ave": list(decision.ave),
    })


def _hash_args(args: dict) -> str:
    return AUDIT_HASH_PREFIX + hashlib.sha256(canonical_bytes(args)).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
