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
import threading
from dataclasses import asdict
from typing import Any

from bawbel_gate._const import (
    HUB_DEFAULT_HOST,
    HUB_DEFAULT_PORT,
    HTTP_SERVER_POLL_S,
    HTTP_SHUTDOWN_TIMEOUT_S,
)
from bawbel_gate.hub.enroll import EnrollmentRegistry, EnrollmentError
from bawbel_gate.hub.fleet import compute_fleet_posture
from bawbel_gate.hub.ingest import process_batch, ChainMismatch
from bawbel_gate.hub.store import FleetStore

_RE_GATE_RECORDS = re.compile(r"^/v1/gates/([^/]+)/records$")
_RE_FLEET_GATE = re.compile(r"^/v1/fleet/gates/([^/]+)$")


class _HubHandler(http.server.BaseHTTPRequestHandler):
    hub_store:   FleetStore
    hub_enroll:  EnrollmentRegistry
    admin_token: str

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

    def _auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return self.hub_enroll.is_admin_token(auth[7:])
        return False

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth():
            self._error(401, "unauthorized")
            return
        path = self.path.split("?")[0]

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
        if not self._auth():
            self._error(401, "unauthorized")
            return
        path = self.path.split("?")[0]

        m = _RE_GATE_RECORDS.match(path)
        if m:
            gate_id = m.group(1)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
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
            except ChainMismatch as exc:
                self._json(409, {
                    "error":         "chain_mismatch",
                    "session":       exc.session_id,
                    "expected_prev": exc.expected_prev,
                })
                return
            self._json(200, {"acked": result.acked})
            return

        if path == "/v1/enrollment/tokens":
            token = self.hub_enroll.mint_token()
            self._json(200, {"token": token})
            return

        if path == "/v1/enroll":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(body)
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

        self._error(404, "not found")

    def do_PUT(self) -> None:  # noqa: N802
        self._error(404, "not found")

    def do_DELETE(self) -> None:  # noqa: N802
        self._error(404, "not found")


class HubServer:
    """Wraps HTTPServer to serve the hub API on a background thread."""

    def __init__(
        self,
        store: FleetStore,
        enroll: EnrollmentRegistry,
        host: str = HUB_DEFAULT_HOST,
        port: int = HUB_DEFAULT_PORT,
    ) -> None:
        self._store = store
        self._enroll = enroll
        admin_token = enroll.mint_admin_token()

        self._httpd = http.server.HTTPServer((host, port), _HubHandler)
        self._httpd.timeout = HTTP_SERVER_POLL_S

        handler_cls = self._httpd.RequestHandlerClass
        handler_cls.hub_store = store
        handler_cls.hub_enroll = enroll
        handler_cls.admin_token = admin_token

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
        if self._thread:
            self._thread.join(timeout=HTTP_SHUTDOWN_TIMEOUT_S)
