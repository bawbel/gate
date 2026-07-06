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

from bawbel_gate.console.auth import mint_token, verify_token
from bawbel_gate.console.approvals import ApprovalDecision, ApprovalRegistry
from bawbel_gate.console.state import ConsoleState, serialize_state

_UI_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>bawbel-gate console</title></head>
<body>
<h1>bawbel-gate console</h1>
<pre id="state">Loading...</pre>
<script>
async function load() {
  const t = new URLSearchParams(location.search).get('t') || '';
  const r = await fetch('/v1/state', {headers: {'Authorization': 'Bearer ' + t}});
  document.getElementById('state').textContent = JSON.stringify(await r.json(), null, 2);
}
load();
const src = new EventSource('/v1/events?t=' + new URLSearchParams(location.search).get('t'));
src.onmessage = e => console.log('event', e.data);
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
        heartbeat_interval = 15.0
        last_heartbeat = 0.0

        try:
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

                now = threading.get_ident()  # dummy; just track time
                import time
                now = time.monotonic()
                if now - last_heartbeat >= heartbeat_interval:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                    last_heartbeat = now

                import time as _time
                _time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError):
            pass


class ConsoleServer:
    """Wraps the stdlib HTTPServer to serve the console API on a background thread."""

    def __init__(
        self,
        state: ConsoleState,
        host: str = "127.0.0.1",
        port: int = 7317,
    ) -> None:
        self.token = mint_token()
        self._state = state
        self._approvals = ApprovalRegistry()
        # Port 0 lets the OS pick a free port (useful in tests).
        self._httpd = http.server.HTTPServer((host, port), _Handler)
        self._httpd.timeout = 0.5

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
            self._thread.join(timeout=2)
