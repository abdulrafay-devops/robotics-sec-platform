#!/usr/bin/env python3
"""
Stage 3 — production-side safety heartbeat sender.

Runs on vm-ot under the `/lab/production_plc` SROS2 enclave. Performs
two jobs concurrently:

  1. **Modbus TCP client to 192.168.10.11:503** (the safety supervisor).
     Every `--hb-period` seconds (default 0.2 s = 5 Hz), writes
     three holding registers:
       HR[0] hb_counter   (monotonic, wraps at 2**16)
       HR[1] prod_state   (currently always 1 = RUN; Stage 4 will source
                          this from the real OpenPLC's /api/v1/state)
       HR[2] remote_estop (always 0; remote E-stops are signed and travel
                          over the SROS2 path below, not via Modbus)

  2. **SROS2 publisher of /safety/request**. Idle by default (no publish);
     when invoked with `--request-estop` for testing, publishes a single
     authenticated E-stop request and exits.

Why a separate process from the safety supervisor:

- The supervisor's SROS2 enclave (/lab/safety_supervisor) ONLY allows
  subscription to /safety/request. Production must run in a different
  enclave (/lab/production_plc) which is granted publish rights to that
  topic. DDS enforces this cryptographically; we cannot fake it from
  inside the supervisor.

- A real second OpenPLC at 192.168.10.10 (production) would write the
  Modbus heartbeat to the safety controller across the wire — this
  process is the lab equivalent.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from typing import Optional

from pymodbus.client import ModbusTcpClient

import rclpy
from rclpy.node import Node
from std_msgs.msg import UInt8

LOG = logging.getLogger("safety_heartbeat")


class _HeartbeatLoop:
    def __init__(self, host: str, port: int, period_s: float) -> None:
        self._host = host
        self._port = port
        self._period = period_s
        self._counter = 0
        self._client: Optional[ModbusTcpClient] = None
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def _connect(self) -> bool:
        try:
            self._client = ModbusTcpClient(self._host, port=self._port, timeout=2.0)
            ok = self._client.connect()
            if ok:
                LOG.info("heartbeat client connected to %s:%d", self._host, self._port)
            return ok
        except Exception as exc:  # noqa: BLE001
            LOG.warning("heartbeat connect failed: %s", exc)
            return False

    def run(self) -> int:
        backoff = 1.0
        while not self._stop:
            if self._client is None or not self._client.is_socket_open():
                if not self._connect():
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10.0)
                    continue
                backoff = 1.0
            self._counter = (self._counter + 1) & 0xFFFF
            try:
                self._client.write_registers(0, [self._counter, 1, 0])
            except Exception as exc:  # noqa: BLE001
                LOG.warning("heartbeat write failed: %s", exc)
                try:
                    self._client.close()
                except Exception:  # noqa: BLE001
                    pass
                self._client = None
                continue
            time.sleep(self._period)
        if self._client:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
        return 0


class _RequestPublisher(Node):
    def __init__(self) -> None:
        super().__init__("safety_heartbeat")
        self._pub = self.create_publisher(UInt8, "/safety/request", 10)
        # Periodically publish to overcome DDS discovery handshake latency
        self._timer = self.create_timer(0.25, self._publish_periodic)

    def _publish_periodic(self) -> None:
        msg = UInt8()
        msg.data = 1
        self._pub.publish(msg)
        self.get_logger().warning("authenticated /safety/request published (value=1)")


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--safety-host", default=os.environ.get("LAB_SAFETY_HOST", "192.168.10.11"))
    p.add_argument("--safety-port", type=int, default=int(os.environ.get("LAB_SAFETY_PORT", "503")))
    p.add_argument("--hb-period", type=float, default=0.2,
                   help="Heartbeat period in seconds (default 0.2 = 5 Hz).")
    p.add_argument("--request-estop", action="store_true",
                   help="Publish a single authenticated /safety/request E-stop and exit.")
    p.add_argument("--log-level", default=os.environ.get("LAB_LOG_LEVEL", "INFO"))
    args = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if args.request_estop:
        rclpy.init(args=sys.argv)
        node = _RequestPublisher()
        try:
            # Spin for ~2 s; one publish is enough.
            end = time.monotonic() + 2.0
            while time.monotonic() < end and rclpy.ok():
                rclpy.spin_once(node, timeout_sec=0.1)
        finally:
            node.destroy_node()
            if rclpy.ok():
                rclpy.shutdown()
        return 0

    loop = _HeartbeatLoop(args.safety_host, args.safety_port, args.hb_period)
    signal.signal(signal.SIGINT, lambda *_: loop.stop())
    signal.signal(signal.SIGTERM, lambda *_: loop.stop())
    return loop.run()


if __name__ == "__main__":
    sys.exit(main())
