#!/usr/bin/env python3
"""OT-zone control gateway (audit F-02 remediation).

Purpose
-------
Move *write* authority over the PLC OUT of the analytics tier and into the OT
zone, where control legitimately belongs. This small service runs INSIDE
container-ot (local to the PLC) and is the only thing that issues Modbus writes
for operator actions (start / stop / e-stop / reset / slow mode). The analytics
service (``score_service.py``) becomes a read-only relay: it forwards the
operator's *intent* here over an authenticated call instead of writing Modbus
itself.

It is OFF by default so the demo is unaffected: ``score_service`` only forwards
to this gateway when ``LAB_CONTROL_GATEWAY_URL`` is set. Until you set that env
var (and test), the existing direct-write path runs exactly as before.

Security
--------
* Requires a matching ``X-API-Key`` header (the lab's ``LAB_API_KEY``). If no key
  is configured it fails closed (refuses every request), mirroring
  ``score_service._require_api_key``.
* Writes only to the LOCAL PLC (127.0.0.1) on the production (502) and safety
  (503) Modbus ports — it never reaches across zones.

Run (started by entrypoint_ot.sh; harmless to run standalone):
    python3 control_gateway.py --port 8002
"""
from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pymodbus.client import ModbusTcpClient

LOG = logging.getLogger("control_gateway")
logging.basicConfig(
    level=os.environ.get("LAB_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

API_KEY = os.environ.get("LAB_API_KEY", "")
PLC_HOST = os.environ.get("LAB_GATEWAY_PLC_HOST", "127.0.0.1")
PROD_PORT = int(os.environ.get("LAB_GATEWAY_PROD_PORT", "502"))
SAFETY_PORT = int(os.environ.get("LAB_GATEWAY_SAFETY_PORT", "503"))

VALID_ACTIONS = {
    "start", "stop", "pause", "estop", "reset", "reset_estop",
    "enable_slow_mode", "disable_slow_mode",
}


def _apply_action(action: str) -> dict:
    """Perform the Modbus writes for one control action on the local PLC.

    The register/coil map is identical to the previous in-line implementation in
    score_service.hmi_control, so behaviour is unchanged when the gateway is
    enabled. Coils: 5=e_stop_active, 6=request_safe_state, 8=remote_start,
    9=remote_stop. Holding reg 1028=%MW4 slow-mode, 1034=%MW10, 1036=%MW12.
    Safety supervisor (:503) holding reg 2: 1=E-stop request, 9=admin reset.
    """
    action = action.lower()
    if action not in VALID_ACTIONS:
        return {"status": "error", "message": f"Unknown control action '{action}'", "code": 400}

    client = ModbusTcpClient(PLC_HOST, port=PROD_PORT, timeout=1.0)
    try:
        if not client.connect():
            return {"status": "error", "message": "Could not connect to Production PLC", "code": 503}

        if action == "start":
            res = client.write_coil(8, True)
            if res.isError():
                return {"status": "error", "message": "write remote_start_btn failed", "code": 500}
            return {"status": "ok", "message": "Momentary start command written to PLC"}

        if action in ("stop", "pause"):
            res = client.write_coil(9, True)
            if res.isError():
                return {"status": "error", "message": "write remote_stop_btn failed", "code": 500}
            return {"status": "ok", "message": "Momentary stop/pause command written to PLC"}

        if action == "estop":
            safety = ModbusTcpClient(PLC_HOST, port=SAFETY_PORT, timeout=1.0)
            try:
                if safety.connect():
                    if safety.write_register(2, 1).isError():
                        LOG.error("failed to write E-stop code 1 to safety PLC")
                else:
                    LOG.error("could not connect to safety PLC on %d for E-stop", SAFETY_PORT)
            finally:
                try:
                    safety.close()
                except Exception:
                    pass
            if client.write_coil(5, True).isError():
                return {"status": "error", "message": "write e_stop_active failed", "code": 500}
            return {"status": "ok", "message": "Emergency Stop asserted to Production and Safety PLCs"}

        if action in ("reset", "reset_estop"):
            safety = ModbusTcpClient(PLC_HOST, port=SAFETY_PORT, timeout=1.0)
            try:
                if safety.connect():
                    if safety.write_register(2, 9).isError():
                        LOG.error("failed to write reset code 9 to safety PLC")
                else:
                    LOG.error("could not connect to safety PLC on %d", SAFETY_PORT)
            finally:
                try:
                    safety.close()
                except Exception:
                    pass
            client.write_coil(5, False)
            client.write_coil(6, False)
            client.write_coil(8, False)
            client.write_coil(9, False)
            client.write_register(1028, 0)
            client.write_register(1034, 0)
            client.write_register(1036, 0)
            return {"status": "ok", "message": "System safety reset command written to PLC"}

        if action == "enable_slow_mode":
            if client.write_register(1028, 1).isError():
                return {"status": "error", "message": "write slow_mode failed", "code": 500}
            return {"status": "ok", "message": "Slow mode enabled on Production PLC"}

        if action == "disable_slow_mode":
            if client.write_register(1028, 0).isError():
                return {"status": "error", "message": "write slow_mode failed", "code": 500}
            return {"status": "ok", "message": "Slow mode disabled on Production PLC"}

        return {"status": "error", "message": f"Unhandled action '{action}'", "code": 400}
    finally:
        try:
            client.close()
        except Exception:
            pass


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # health check
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"status": "error", "message": "not found"})

    def do_POST(self) -> None:
        if self.path != "/control":
            self._send(404, {"status": "error", "message": "not found"})
            return
        # Fail closed: refuse if no key configured, then require a matching key.
        if not API_KEY:
            self._send(503, {"status": "error", "message": "gateway API key not configured"})
            return
        if not hmac.compare_digest(self.headers.get("X-API-Key", ""), API_KEY):
            self._send(401, {"status": "error", "message": "invalid or missing API key"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            action = str(data.get("action", ""))
        except Exception as exc:
            self._send(400, {"status": "error", "message": f"bad request: {exc}"})
            return
        result = _apply_action(action)
        code = result.pop("code", 200 if result.get("status") == "ok" else 500)
        self._send(code, result)

    def log_message(self, *_a) -> None:  # quiet default access logging
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default=os.environ.get("LAB_GATEWAY_BIND", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("LAB_GATEWAY_PORT", "8002")))
    args = ap.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    LOG.info("OT control gateway listening on %s:%d (PLC=%s prod=%d safety=%d)",
             args.host, args.port, PLC_HOST, PROD_PORT, SAFETY_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
