"""Console HTTP server. See DESIGN.md 13.1.

Endpoints:
  GET  /v1/state                    -- full state snapshot
  GET  /v1/events                   -- SSE stream of audit records
  POST /v1/approvals/{id}           -- console approval channel
  GET  /v1/approvals/{id}/args      -- redacted args (P1, local mode only)
  GET  /                            -- embedded UI bundle (index.html)

All read-only endpoints reject POST/PUT/DELETE. The approval endpoint is the only
mutation path and it can only resolve a pending approval, never issue a tool call,
clear taint, or modify a manifest.

Authentication: all endpoints require Authorization: Bearer <token>. 401 is returned
without a WWW-Authenticate challenge (avoids browser pop-ups on loopback; token is
printed once at startup).
"""

from __future__ import annotations

import http.server
import json
import re
import threading
from pathlib import Path
from typing import Any

from bawbel_gate._const import (
    CONSOLE_DEFAULT_HOST,
    CONSOLE_DEFAULT_PORT,
    HTTP_POLL_INTERVAL_S,
    HTTP_SERVER_POLL_S,
    HTTP_SHUTDOWN_TIMEOUT_S,
    SSE_HEARTBEAT_INTERVAL_S,
)
from bawbel_gate.console.auth import mint_token, verify_token
from bawbel_gate.console.approvals import ApprovalDecision, ApprovalRegistry
from bawbel_gate.console.state import ConsoleState, serialize_state

_UI_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>bawbel-gate console</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --fg: #c9d1d9; --muted: #8b949e;
    --allow: #3fb950; --approve: #d29922; --deny: #f85149; --accent: #58a6ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px; background: var(--bg); color: var(--fg);
    font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 14px; line-height: 1.5;
  }
  h1 { font-size: 18px; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 12px; margin-bottom: 20px; }
  .status { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: var(--muted); margin-right: 6px; }
  .status.live { background: var(--allow); }
  .status.down { background: var(--deny); }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 6px;
    padding: 14px 16px; }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em;
    color: var(--muted); margin: 0 0 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 4px 8px 4px 0; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .chip { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px;
    margin: 1px 3px 1px 0; border: 1px solid var(--border); color: var(--muted); }
  .chip.on { color: var(--fg); border-color: var(--accent); }
  .effect { font-weight: 600; }
  .effect.allow { color: var(--allow); }
  .effect.approve { color: var(--approve); }
  .effect.deny { color: var(--deny); }
  .empty { color: var(--muted); font-style: italic; }
  .feed { max-height: 360px; overflow-y: auto; }
  .feed table { table-layout: fixed; }
  .feed td { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  button { background: var(--panel); border: 1px solid var(--border); color: var(--fg);
    border-radius: 4px; padding: 3px 10px; font-size: 12px; cursor: pointer; margin-right: 4px; }
  button.grant { border-color: var(--allow); color: var(--allow); }
  button.deny { border-color: var(--deny); color: var(--deny); }
  button:hover { filter: brightness(1.3); }
</style>
</head>
<body>
<h1><span id="dot" class="status"></span>bawbel-gate console</h1>
<div class="sub" id="gatemeta">connecting...</div>

<div class="panel" id="approvals-panel" style="margin-bottom:16px;">
  <h2>Pending approvals</h2>
  <div id="approvals"><span class="empty">none</span></div>
</div>

<div class="grid">
  <div class="panel">
    <h2>Sessions</h2>
    <div id="sessions"><span class="empty">none yet</span></div>
  </div>
  <div class="panel">
    <h2>Servers</h2>
    <div id="servers"><span class="empty">none</span></div>
  </div>
</div>

<div class="panel">
  <h2>Audit feed (live via SSE)</h2>
  <div class="feed">
    <table>
      <thead><tr><th style="width:90px">time</th><th style="width:70px">event</th>
        <th style="width:70px">server</th><th style="width:140px">tool</th>
        <th style="width:70px">effect</th><th>reason</th></tr></thead>
      <tbody id="feed-body"></tbody>
    </table>
  </div>
</div>

<script>
const token = new URLSearchParams(location.search).get('t') || '';
const authHeaders = {'Authorization': 'Bearer ' + token};

function short(h, head, tail) {
  if (!h) return '';
  head = head || 7; tail = tail || 4;
  return h.length > head + tail + 3 ? h.slice(0, head) + '...' + h.slice(-tail) : h;
}
function esc(s) {
  return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
}

function renderSessions(sessions) {
  const el = document.getElementById('sessions');
  if (!sessions.length) { el.innerHTML = '<span class="empty">none yet</span>'; return; }
  el.innerHTML = '<table><thead><tr><th>session</th><th>taint</th><th>trifecta</th>' +
    '<th>suspended</th></tr></thead><tbody>' + sessions.map(s => {
      const legs = ['private_touched', 'untrusted_seen'].map(k =>
        '<span class="chip' + (s[k] ? ' on' : '') + '">' + k.replace('_', ' ') + '</span>'
      ).join('');
      const taint = s.tainted_by.length
        ? s.tainted_by.map(t => '<span class="chip on">' + esc(t) + '</span>').join('')
        : '<span class="empty">none</span>';
      const susp = s.suspended_servers.length ? esc(s.suspended_servers.join(', ')) : '-';
      return '<tr><td class="mono">' + short(s.session_id, 8, 0) + '</td><td>' + taint +
        '</td><td>' + legs + '</td><td>' + susp + '</td></tr>';
    }).join('') + '</tbody></table>';
}

function renderServers(servers) {
  const el = document.getElementById('servers');
  if (!servers.length) { el.innerHTML = '<span class="empty">none</span>'; return; }
  el.innerHTML = '<table><thead><tr><th>server</th><th>manifest</th><th>trifecta</th>' +
    '</thead></tr><tbody>' + servers.map(s => {
      const tri = Object.entries(s.trifecta || {}).filter(([, v]) => v)
        .map(([k]) => '<span class="chip on">' + k.replace('_', ' ') + '</span>').join('');
      return '<tr><td>' + esc(s.name) + '</td><td class="mono">' +
        short(s.manifest_sha256) + '</td><td>' + (tri || '-') + '</td></tr>';
    }).join('') + '</tbody></table>';
}

function renderApprovals(approvals) {
  const el = document.getElementById('approvals');
  if (!approvals.length) { el.innerHTML = '<span class="empty">none</span>'; return; }
  el.innerHTML = approvals.map(a =>
    '<div style="margin-bottom:6px;">' +
    '<span class="mono">' + esc(a.server) + '__' + esc(a.tool) + '</span> ' +
    '<span class="chip">' + esc(a.cause) + '</span> ' +
    '<button class="grant" data-id="' + a.approval_id + '" data-decision="grant">grant</button>' +
    '<button class="deny" data-id="' + a.approval_id + '" data-decision="deny">deny</button>' +
    '</div>'
  ).join('');
}
document.getElementById('approvals').addEventListener('click', e => {
  const id = e.target.getAttribute('data-id');
  const decision = e.target.getAttribute('data-decision');
  if (id && decision) decide(id, decision);
});

async function decide(id, decision) {
  await fetch('/v1/approvals/' + id, {
    method: 'POST',
    headers: Object.assign({'Content-Type': 'application/json'}, authHeaders),
    body: JSON.stringify({decision: decision}),
  });
  refresh();
}

async function refresh() {
  const r = await fetch('/v1/state', {headers: authHeaders});
  if (!r.ok) return;
  const state = await r.json();
  document.getElementById('gatemeta').textContent =
    'started ' + state.gate.started_at + '  |  config ' + short(state.gate.config_sha256) +
    '  |  audit ' + state.audit.records + ' records, head ' + short(state.audit.head_hash);
  renderSessions(state.sessions);
  renderServers(state.servers);
  renderApprovals(state.approvals);
}

function addFeedRow(rec) {
  const tbody = document.getElementById('feed-body');
  const tr = document.createElement('tr');
  const effect = rec.effect || '';
  tr.innerHTML = '<td class="mono">' + esc((rec.ts || '').split('T')[1] || rec.ts || '') +
    '</td><td>' + esc(rec.event || '') + '</td><td>' + esc(rec.server || '') +
    '</td><td class="mono">' + esc(rec.tool || '') + '</td>' +
    '<td class="effect ' + esc(effect) + '">' + esc(effect) + '</td>' +
    '<td>' + esc(rec.reason || '') + '</td>';
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
}

const dot = document.getElementById('dot');
const src = new EventSource('/v1/events?t=' + encodeURIComponent(token));
src.onopen = () => dot.className = 'status live';
src.onerror = () => dot.className = 'status down';
src.onmessage = e => {
  try {
    const rec = JSON.parse(e.data);
    addFeedRow(rec);
    refresh();
  } catch (err) { /* heartbeat comments do not reach onmessage */ }
};

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""

_RE_APPROVAL = re.compile(r"^/v1/approvals/([^/]+)$")
_RE_APPROVAL_ARGS = re.compile(r"^/v1/approvals/([^/]+)/args$")


class _Handler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the console API."""

    server_state: ConsoleState
    console_token: str
    approvals: ApprovalRegistry

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # silence access log; audit log is the forensic record

    def _send_json(self, code: int, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, code: int, message: str) -> None:
        self._send_json(code, {"error": message})

    def _check_auth(self) -> bool:
        """Return True if the request carries the correct bearer token."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return verify_token(auth[7:], self.console_token)
        # SSE clients may pass token as query param ?t=... (browsers cannot set headers
        # for EventSource).
        import urllib.parse
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        provided = params.get("t", [""])[0]
        return verify_token(provided, self.console_token)

    def _clean_path(self) -> str:
        import urllib.parse
        return urllib.parse.urlparse(self.path).path

    def do_GET(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler naming convention
        if not self._check_auth():
            self._send_error(401, "unauthorized")
            return
        path = self._clean_path()

        if path in ("/", "/index.html"):
            body = _UI_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/v1/state":
            self._send_json(200, serialize_state(self.server_state))
            return

        if path == "/v1/events":
            self._handle_sse()
            return

        m = _RE_APPROVAL_ARGS.match(path)
        if m:
            self._send_error(404, "not found")  # P1 stub; full impl in a later PR
            return

        self._send_error(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_auth():
            self._send_error(401, "unauthorized")
            return
        path = self._clean_path()

        m = _RE_APPROVAL.match(path)
        if m:
            ap_id = m.group(1)
            length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(body_bytes)
            except json.JSONDecodeError:
                self._send_error(400, "invalid JSON")
                return

            raw_decision = body.get("decision", "")
            try:
                decision = ApprovalDecision(raw_decision)
            except ValueError:
                self._send_error(400, f"unknown decision: {raw_decision!r}")
                return

            result = self.approvals.decide(ap_id, decision)
            if result is None:
                self._send_error(404, "approval not found or expired")
            elif result is False:
                self._send_error(409, "already decided")
            else:
                self._send_json(200, {"status": "ok", "decision": raw_decision})
            return

        self._send_error(404, "not found")

    def do_PUT(self) -> None:  # noqa: N802
        if not self._check_auth():
            self._send_error(401, "unauthorized")
            return
        self._send_error(404, "not found")

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._check_auth():
            self._send_error(401, "unauthorized")
            return
        self._send_error(404, "not found")

    def do_PATCH(self) -> None:  # noqa: N802
        if not self._check_auth():
            self._send_error(401, "unauthorized")
            return
        self._send_error(404, "not found")

    def _handle_sse(self) -> None:
        """Tail the audit log and stream records as SSE events."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        # Stream existing records first, then wait for new ones.
        audit_log: Path = self.server_state.audit_log
        last_pos = 0
        heartbeat_interval = SSE_HEARTBEAT_INTERVAL_S
        last_heartbeat = 0.0

        try:
            import time as _time
            while True:
                if audit_log.exists():
                    with audit_log.open(encoding="utf-8") as fh:
                        fh.seek(last_pos)
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                record = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            seq = record.get("seq", "")
                            payload = json.dumps(record)
                            msg = f"id:{seq}\ndata:{payload}\n\n"
                            self.wfile.write(msg.encode())
                            self.wfile.flush()
                        last_pos = fh.tell()

                now = _time.monotonic()
                if now - last_heartbeat >= heartbeat_interval:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                    last_heartbeat = now

                _time.sleep(HTTP_POLL_INTERVAL_S)
        except (BrokenPipeError, ConnectionResetError):
            pass


class ConsoleServer:
    """Wraps the stdlib HTTPServer to serve the console API on a background thread."""

    def __init__(
        self,
        state: ConsoleState,
        host: str = CONSOLE_DEFAULT_HOST,
        port: int = CONSOLE_DEFAULT_PORT,
    ) -> None:
        self.token = mint_token()
        self._state = state
        self._approvals = ApprovalRegistry()
        # ThreadingHTTPServer: /v1/events is a long-lived SSE stream (_handle_sse
        # blocks in a loop). A plain HTTPServer handles one request at a time, so
        # a single open SSE connection would starve every other request -- state
        # polls, the approval endpoint, even the page itself -- until it closed.
        # Port 0 lets the OS pick a free port (useful in tests).
        self._httpd = http.server.ThreadingHTTPServer((host, port), _Handler)
        self._httpd.daemon_threads = True
        self._httpd.timeout = HTTP_SERVER_POLL_S

        # Inject server-level state into handler instances via class attributes.
        handler_cls = self._httpd.RequestHandlerClass
        handler_cls.server_state = state
        handler_cls.console_token = self.token
        handler_cls.approvals = self._approvals

        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start_background(self) -> None:
        """Start serving in a daemon thread."""
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        import time
        time.sleep(0.05)  # let the thread bind before tests hit it

    def _serve(self) -> None:
        self._httpd.serve_forever()

    def stop(self) -> None:
        self._httpd.shutdown()
        if self._thread:
            self._thread.join(timeout=HTTP_SHUTDOWN_TIMEOUT_S)
