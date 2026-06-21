#!/usr/bin/env python3
"""
L7 Modbus/TCP read-only proxy for the IDMZ (runs in the OT zone, in front of the PLC).

The analytics tier (AI) connects HERE instead of to the PLC directly. The router
firewall denies AI->PLC:502 and allows AI->proxy:5020 only. This proxy parses every
Modbus/TCP frame and forwards ONLY read function codes to the PLC; any write FC gets
a Modbus 'illegal function' (0x01) exception and never reaches the controller.

Why this exists: the L3/L4 router cannot read Modbus function codes, so "AI is
read-only to OT" cannot be enforced by the firewall alone. This proxy enforces it at
L7. Operator writes take a separate, authenticated path through the OT control gateway
(control_gateway.py). Net effect: even a fully compromised AI container can only READ
the PLC.

Stdlib only (socket + threading) so it runs in any of the OT container's interpreters.

Env:
  LAB_MBPROXY_HOST (default 0.0.0.0)   LAB_MBPROXY_PORT (default 5020)
  LAB_PLC_HOST     (default 127.0.0.1) LAB_PLC_PORT     (default 502)
"""
from __future__ import annotations

import logging
import os
import socket
import struct
import sys
import threading

LISTEN_HOST = os.environ.get("LAB_MBPROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LAB_MBPROXY_PORT", "5020"))
PLC_HOST = os.environ.get("LAB_PLC_HOST", "127.0.0.1")
PLC_PORT = int(os.environ.get("LAB_PLC_PORT", "502"))

# Read / diagnostic function codes that are allowed through.
READ_FCS = frozenset({1, 2, 3, 4, 7, 11, 12, 17, 20, 24, 43})
# Everything else (writes 5,6,15,16,22,23 and the rest) is denied.

LOG = logging.getLogger("modbus_read_proxy")


def _recv_exact(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_frame(sock: socket.socket):
    """Read one Modbus/TCP frame. Returns (mbap, tid, pid, uid, pdu) or None."""
    mbap = _recv_exact(sock, 7)   # transaction(2) protocol(2) length(2) unit(1)
    if not mbap:
        return None
    tid, pid, length, uid = struct.unpack(">HHHB", mbap)
    pdu = _recv_exact(sock, length - 1) if length >= 1 else b""   # length counts unit + PDU
    if pdu is None:
        return None
    return mbap, tid, pid, uid, pdu


def _exception(tid: int, pid: int, uid: int, fc: int, code: int = 0x01) -> bytes:
    pdu = struct.pack(">BB", fc | 0x80, code)            # FC|0x80, exception code
    return struct.pack(">HHHB", tid, pid, len(pdu) + 1, uid) + pdu


def _handle(client: socket.socket, addr) -> None:
    plc = None
    try:
        while True:
            frame = _recv_frame(client)
            if frame is None:
                break
            mbap, tid, pid, uid, pdu = frame
            if not pdu:
                break
            fc = pdu[0]
            if fc not in READ_FCS:
                LOG.warning("DENY write/illegal FC=%d from %s", fc, addr)
                client.sendall(_exception(tid, pid, uid, fc, 0x01))
                continue
            if plc is None:
                plc = socket.create_connection((PLC_HOST, PLC_PORT), timeout=3)
            plc.sendall(mbap + pdu)
            resp = _recv_frame(plc)
            if resp is None:
                break
            r_mbap, _, _, _, r_pdu = resp
            client.sendall(r_mbap + r_pdu)
    except Exception as exc:  # noqa: BLE001
        LOG.debug("session %s ended: %s", addr, exc)
    finally:
        for s in (client, plc):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(16)
    LOG.info("modbus_read_proxy listening on %s:%d -> PLC %s:%d (read FCs %s only)",
             LISTEN_HOST, LISTEN_PORT, PLC_HOST, PLC_PORT, sorted(READ_FCS))
    try:
        while True:
            c, a = srv.accept()
            threading.Thread(target=_handle, args=(c, a), daemon=True).start()
    except KeyboardInterrupt:
        return 0
    finally:
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
