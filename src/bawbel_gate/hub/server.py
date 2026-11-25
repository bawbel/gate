"""Hub HTTP server: fleet ingest + fleet console endpoints. See DESIGN.md 14.

Endpoints:
  POST /v1/gates/{gate_id}/records  -- NDJSON audit record ingest
  GET  /v1/fleet/state              -- fleet posture snapshot
  GET  /v1/fleet/gates/{gate_id}    -- per-gate state
  POST /v1/enrollment/tokens        -- mint a new enrollment token (admin)
  POST /v1/enroll                   -- consume token, get gate credentials

No command channel: there is no endpoint that can issue tool calls, push
manifests, or clear taint (DESIGN.md 14.6). All such paths return 404.
"""

from __future__ import annotations

import http.server
import json
import re
import socket
import threading
import time
from dataclasses import asdict
from typing import Any

from bawbel_gate._const import (
    HUB_DEFAULT_HOST,
    HUB_DEFAULT_PORT,
    HUB_LINGER_MAX_BYTES,
    HUB_LINGER_S,
    HUB_MAX_BODY_BYTES,
    HUB_REQUEST_TIMEOUT_S,
    HTTP_SERVER_POLL_S,
    HTTP_SHUTDOWN_TIMEOUT_S,
)
from bawbel_gate.hub.enroll import EnrollmentRegistry, EnrollmentError
from bawbel_gate.hub.fleet import compute_fleet_posture
from bawbel_gate.hub.ingest import process_batch, ChainMismatch, IngestSchemaError
from bawbel_gate.hub.store import FleetStore

_RE_GATE_RECORDS = re.compile(r"^/v1/gates/([^/]+)/records$")
_RE_FLEET_GATE = re.compile(r"^/v1/fleet/gates/([^/]+)$")

_UI_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>bawbel-hub fleet console</title></head>
<body>
<h1>bawbel-hub fleet console</h1>
<p>Per-gate allow/approve/deny counts, trifecta trips, and drift events
(DESIGN.md 14.4). Refreshes every 5s.</p>
<pre id="state">Loading...</pre>
<script>
async function load() {
  const t = new URLSearchParams(location.search).get('t') || '';
  const r = await fetch('/v1/fleet/state', {headers: {'Authorization': 'Bearer ' + t}});
  document.getElementById('state').textContent = JSON.stringify(await r.json(), null, 2);
}
load();
setInterval(load, 5000);
</script>
</body>
</html>
"""


_READ_CHUNK = 65536


class _HubHandler(http.server.BaseHTTPRequestHandler):
    hub_store:   FleetStore
    hub_enroll:  EnrollmentRegistry
    admin_token: str
    max_body_bytes: int = HUB_MAX_BODY_BYTES
    # Socket timeout for each read while the request line and headers arrive
    # (socketserver.StreamRequestHandler.timeout). The body has its own total deadline.
    timeout: float = HUB_REQUEST_TIMEOUT_S

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _json(self, code: int, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, code: int, msg: str) -> None:
        self._json(code, {"error": msg})

    def _refuse(self, code: int, msg: str, **extra: Any) -> None:
        """Answer an early refusal, before the body was read, and close the connection.

        Closing with unread request bytes makes the kernel reset the connection, and the client
        may lose the answer. So stop sending, then read and drop what it still sends for a
        short, bounded while.
        """
        self.close_connection = True
        try:
            self._json(code, {"error": msg, **extra})
            self.connection.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + HUB_LINGER_S
            dropped = 0
            while dropped < HUB_LINGER_MAX_BYTES and time.monotonic() < deadline:
                self.connection.settimeout(max(deadline - time.monotonic(), 0.01))
                chunk = self.connection.recv(_READ_CHUNK)
                if not chunk:
                    break
                dropped += len(chunk)
        except OSError:
            pass

    def _read_body(self) -> bytes | None:
        """Read the request body within the size cap and a total deadline.

        Returns None when it has already answered (411, 400, 413, 408). It never reads more than
        `max_body_bytes`, and an oversize Content-Length is refused before any of the body is read.
        """
        if self.headers.get("Transfer-Encoding") is not None:
            self._refuse(411, "length_required")
            return None
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b""
        if not (raw.isascii() and raw.isdigit()):
            self._refuse(400, "bad_content_length")
            return None
        length = int(raw)
        if length > self.max_body_bytes:
            self._refuse(413, "too_large", max_bytes=self.max_body_bytes)
            return None

        deadline = time.monotonic() + self.timeout
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            left = deadline - time.monotonic()
            if left <= 0:
                self._refuse(408, "request_timeout")
                return None
            try:
                self.connection.settimeout(left)
                chunk = self.rfile.read1(min(remaining, _READ_CHUNK))
            except OSError:  # includes the socket timeout
                self._refuse(408, "request_timeout")
                return None
            if not chunk:
                self._refuse(400, "incomplete_body")
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return self.hub_enroll.is_admin_token(auth[7:])
        # Browsers cannot set a custom header on plain navigation, so the fleet
        # console page (served below) is reached via ?t=<admin_token> instead.
        import urllib.parse
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return self.hub_enroll.is_admin_token(params.get("t", [""])[0])

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth():
            self._error(401, "unauthorized")
            return
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            body = _UI_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/v1/fleet/state":
            rows = compute_fleet_posture(self.hub_store)
            self._json(200, {
                "gates": [asdict(r) for r in rows],
            })
            return

        m = _RE_FLEET_GATE.match(path)
        if m:
            gate_id = m.group(1)
            agg = self.hub_store.get_aggregate_state(gate_id)
            self._json(200, {"gate_id": gate_id, **agg})
            return

        self._error(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]

        # /v1/enroll is the bootstrap path for a gate that has no admin token yet:
        # the single-use enrollment token itself is the credential (DESIGN.md 14.3).
        # consume_token() rejects invalid/reused tokens with EnrollmentError -> 403.
        if path == "/v1/enroll":
            body = self._read_body()
            if body is None:
                return
            try:
                payload = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._error(400, "invalid JSON")
                return
            enroll_token = payload.get("token", "")
            try:
                gate_id = self.hub_enroll.consume_token(enroll_token)
            except EnrollmentError as exc:
                self._error(403, str(exc))
                return
            self._json(200, {"gate_id": gate_id})
            return

        if not self._auth():
            self._error(401, "unauthorized")
            return

        m = _RE_GATE_RECORDS.match(path)
        if m:
            gate_id = m.group(1)
            body = self._read_body()
            if body is None:
                return
            records = []
            for line in body.decode(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    self._error(422, "invalid NDJSON")
                    return

            try:
                result = process_batch(gate_id, records, self.hub_store)
            except IngestSchemaError as exc:
                self._json(422, {"error": "schema", "index": exc.index, "reason": exc.reason})
                return
            except ChainMismatch as exc:
                self._json(409, {
                    "error":         "chain_mismatch",
                    "reason":        exc.reason,
                    "session":       exc.session_id,
                    "expected_prev": exc.expected_prev,
                    "expected_seq":  exc.expected_seq,
                })
                return
            self._json(200, {"acked": result.acked})
            return

        if path == "/v1/enrollment/tokens":
            token = self.hub_enroll.mint_token()
            self._json(200, {"token": token})
            return

        self._error(404, "not found")

    def do_PUT(self) -> None:  # noqa: N802
        self._error(404, "not found")

    def do_DELETE(self) -> None:  # noqa: N802
        self._error(404, "not found")


class HubServer:
    """Wraps ThreadingHTTPServer to serve the hub API on a background thread.

    One thread per connection, so a client that stalls holds its own thread and no one else's.
    Ingest serialises verify-then-store under FleetStore.ingest_lock (hub/ingest.py).
    """

    def __init__(
        self,
        store: FleetStore,
        enroll: EnrollmentRegistry,
        host: str = HUB_DEFAULT_HOST,
        port: int = HUB_DEFAULT_PORT,
        *,
        max_body_bytes: int = HUB_MAX_BODY_BYTES,
        request_timeout_s: float = HUB_REQUEST_TIMEOUT_S,
    ) -> None:
        if not isinstance(max_body_bytes, int) or isinstance(max_body_bytes, bool) or max_body_bytes < 1:
            raise ValueError("max_body_bytes must be a positive integer")
        if not isinstance(request_timeout_s, (int, float)) or isinstance(request_timeout_s, bool) \
                or request_timeout_s <= 0:
            raise ValueError("request_timeout_s must be a positive number")
        self._store = store
        self._enroll = enroll
        admin_token = enroll.mint_admin_token()

        # One handler class per server: the settings are class attributes, so two servers in one
        # process must not share a class.
        handler_cls = type("_BoundHubHandler", (_HubHandler,), {
            "hub_store": store,
            "hub_enroll": enroll,
            "admin_token": admin_token,
            "max_body_bytes": max_body_bytes,
            "timeout": float(request_timeout_s),
        })
        self._httpd = http.server.ThreadingHTTPServer((host, port), handler_cls)
        self._httpd.daemon_threads = True
        self._httpd.timeout = HTTP_SERVER_POLL_S

        self._admin_token = admin_token
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def admin_token(self) -> str:
        return self._admin_token

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        import time
        time.sleep(0.05)

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=HTTP_SHUTDOWN_TIMEOUT_S)
