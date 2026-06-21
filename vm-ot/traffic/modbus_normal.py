#!/usr/bin/env python3
"""
Baseline Modbus/TCP traffic generator.

Acts as an authorized HMI client: reads a small set of holding registers
from the production OpenPLC at a steady rate. The traffic profile is what
Zeek's modbus parser sees during normal plant operation, and what Stage 2's
ML models will use to learn "normal."

Why a separate generator and not just Gazebo's own writes:
  * OpenPLC by itself does not generate outbound Modbus traffic; without
    a client, Zeek sees nothing on the wire.
  * The generator's read pattern (fixed registers, fixed rate) is the
    well-defined baseline. Attack replays in this directory deliberately
    deviate from that baseline.

Run:
    python3 modbus_normal.py --host 192.168.10.10 --port 502 --rate-hz 5
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from dataclasses import dataclass
from typing import List

try:
    from pymodbus.client import ModbusTcpClient
except ImportError as exc:  # pragma: no cover
    print(
        f'pymodbus not installed in this Python: {exc}. '
        'Activate /opt/lab/venv-traffic.',
        file=sys.stderr,
    )
    sys.exit(2)

LOG = logging.getLogger('modbus_normal')

# Holding registers exposed by production.st (see vm-ot/openplc/production.st).
# Reading these is benign and idempotent.
DEFAULT_REGISTERS: List[int] = [0, 1, 2, 3]   # cycle_step, cycle_count, e-stop trips, last_cycle_ms
DEFAULT_UNIT_ID = 1


@dataclass
class Args:
    host: str
    port: int
    rate_hz: float
    registers: List[int]
    unit_id: int
    duration_s: float    # 0 = run until SIGINT


def _parse_args(argv: List[str]) -> Args:
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--host', required=True, help='Modbus server IP')
    p.add_argument('--port', type=int, default=502)
    p.add_argument('--rate-hz', type=float, default=5.0,
                   help='Read polls per second')
    p.add_argument('--registers', default='0,1,2,3',
                   help='Comma-separated holding register addresses')
    p.add_argument('--unit-id', type=int, default=DEFAULT_UNIT_ID)
    p.add_argument('--duration-s', type=float, default=0.0,
                   help='Stop after N seconds; 0 = run forever')
    p.add_argument('--log-level', default='INFO',
                   choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    ns = p.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, ns.log_level),
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )

    try:
        regs = [int(x.strip()) for x in ns.registers.split(',') if x.strip()]
    except ValueError as exc:
        p.error(f'invalid --registers: {exc}')
    if not regs:
        p.error('--registers must contain at least one address')

    if ns.rate_hz <= 0 or ns.rate_hz > 100:
        p.error('--rate-hz must be in (0, 100]')

    return Args(
        host=ns.host,
        port=ns.port,
        rate_hz=ns.rate_hz,
        registers=regs,
        unit_id=ns.unit_id,
        duration_s=ns.duration_s,
    )


_SHOULD_EXIT = False


def _sigterm(*_args) -> None:
    global _SHOULD_EXIT  # noqa: PLW0603
    _SHOULD_EXIT = True


def main(argv: List[str]) -> int:
    args = _parse_args(argv)
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)

    # A real HMI/SCADA station refreshes its register reads several times a second,
    # not once. Model that: poll at a steady HMI scan rate, treating --rate-hz as a
    # FLOOR. This denser, even stream fills the 5-second scoring windows uniformly,
    # so a brief OS/PLC stall no longer leaves a half-empty window (which used to make
    # the PCA/TF z-scores dip). Same valid register block (read-only) — only the
    # cadence changes. NOTE: re-run the live AE threshold calibration after changing
    # this, since the per-window message volume changes.
    HMI_SCAN_HZ = 4.0
    scan_hz = max(args.rate_hz, HMI_SCAN_HZ)
    period = 1.0 / scan_hz
    LOG.info(
        'connecting to modbus tcp://%s:%d unit=%d steady HMI scan=%.1f Hz',
        args.host, args.port, args.unit_id, scan_hz,
    )

    client = ModbusTcpClient(host=args.host, port=args.port, timeout=2.0)
    if not client.connect():
        LOG.error('initial connect failed')
        return 1

    started = time.monotonic()
    next_tick = started
    polls_ok = 0
    polls_err = 0
    next_log = started + 10.0
    try:
        while not _SHOULD_EXIT:
            t0 = time.monotonic()
            try:
                # FC=03 Read Holding Registers, count = max addr + 1
                count = max(args.registers) + 1
                rr = client.read_holding_registers(
                    address=0, count=count, slave=args.unit_id,
                )
                if rr.isError():
                    polls_err += 1
                    LOG.warning('read returned error: %s', rr)
                else:
                    polls_ok += 1
                    LOG.debug(
                        'regs[%s] = %s',
                        ','.join(str(r) for r in args.registers),
                        [rr.registers[i] for i in args.registers],
                    )
            except Exception as exc:  # noqa: BLE001
                polls_err += 1
                LOG.warning('exception during read: %s', exc)
                # auto-reconnect
                try:
                    client.close()
                    client.connect()
                except Exception:  # noqa: BLE001
                    pass

            now = time.monotonic()
            if now >= next_log:
                LOG.info('ok=%d err=%d elapsed=%.0fs',
                         polls_ok, polls_err, now - started)
                next_log = now + 10.0

            if args.duration_s and (now - started) >= args.duration_s:
                break

            # Steady absolute-schedule cadence. If a transient stall (slow PLC reply
            # or CPU contention) made this cycle run long, resume ON schedule rather
            # than bursting to catch up — bursts would themselves unbalance the
            # windows. Only re-baseline the clock if we fell more than one tick behind.
            next_tick += period
            delay = next_tick - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            elif delay < -period:
                next_tick = time.monotonic()
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass

    LOG.info('exiting: ok=%d err=%d elapsed=%.0fs',
             polls_ok, polls_err, time.monotonic() - started)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
