#!/usr/bin/env python3
"""Stage 3 — safety-loop timing test.

Runs *inside* vm-ot (so the SROS2 keystore is on the local filesystem).
Publishes an authenticated /safety/request, then measures how long until
the supervisor flips /safety/state to EMERGENCY. Must be <= 200 ms.

Usage on the host:
    vagrant ssh vm-ot -c \
      'sudo /opt/lab/bin/run-stage3-safety-loop.sh' -- -q
"""
from __future__ import annotations

import os
import sys
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import (
    QoSDurabilityPolicy, QoSHistoryPolicy, QoSProfile, QoSReliabilityPolicy,
)
from std_msgs.msg import UInt8

DEADLINE_MS = float(os.environ.get('STAGE3_DEADLINE_MS', '200'))
EMERGENCY = 2


class _Probe(Node):
    def __init__(self) -> None:
        super().__init__('stage3_safety_probe')
        qos = QoSProfile(
            history=QoSHistoryPolicy.KEEP_LAST, depth=10,
            reliability=QoSReliabilityPolicy.RELIABLE,
            durability=QoSDurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._sub = self.create_subscription(
            UInt8, '/safety/state', self._on_state, qos)
        self._pub = self.create_publisher(UInt8, '/safety/request', 10)
        self.t_request = 0.0
        self.t_emergency = 0.0
        self.sent = False
        # Poll at 50 ms: as soon as the supervisor's subscriber is matched
        # (DDS-Security handshake done), publish exactly once and record t0.
        # Under SROS2/Enforce the discovery handshake can take 1–3 s.
        self.create_timer(0.05, self._tick)

    def _tick(self) -> None:
        if self.sent:
            return
        if self._pub.get_subscription_count() < 1 or self.count_publishers('/safety/state') < 1:
            return
        msg = UInt8(); msg.data = 1
        self._pub.publish(msg)
        self.t_request = time.monotonic()
        self.sent = True
        self.get_logger().info(
            'published authenticated /safety/request=1 '
            f'(matched_subs={self._pub.get_subscription_count()})'
        )

    def _on_state(self, msg: UInt8) -> None:
        if msg.data >= EMERGENCY and self.t_emergency == 0.0 and self.sent:
            self.t_emergency = time.monotonic()


def _emit_and_exit(line: str, rc: int) -> None:
    # rclpy.shutdown() under SROS2 Enforce has been observed to block
    # indefinitely on this lab (only-peer + DDS-Security finalization).
    # The test outcome is fully determined by the time we get here, so we
    # print the verdict, flush, and short-circuit the runtime with os._exit
    # to guarantee the wrapper script returns to the shell.
    print(line, flush=True)
    sys.stdout.flush()
    os._exit(rc)


def main() -> int:
    rclpy.init()
    node = _Probe()
    # Allow up to 10 s for DDS-Security discovery to complete; the actual
    # safety-loop deadline (DEADLINE_MS) is measured from t_request, so
    # this only relaxes the overall test wall-clock budget.
    end = time.monotonic() + 10.0
    while time.monotonic() < end and rclpy.ok():
        rclpy.spin_once(node, timeout_sec=0.05)
        if node.t_emergency > 0.0:
            break
    if node.t_request == 0.0:
        _emit_and_exit(
            'STAGE 3 SAFETY LOOP: FAIL (no matched supervisor subscriber within 10 s)',
            1,
        )
    if node.t_emergency == 0.0:
        _emit_and_exit('STAGE 3 SAFETY LOOP: FAIL (EMERGENCY never received within 5s)', 1)
    elapsed_ms = (node.t_emergency - node.t_request) * 1000.0
    if elapsed_ms > DEADLINE_MS:
        _emit_and_exit(f'STAGE 3 SAFETY LOOP: FAIL ({elapsed_ms:.1f}ms > {DEADLINE_MS}ms)', 1)
    _emit_and_exit(f'STAGE 3 SAFETY LOOP: PASS ({elapsed_ms:.1f}ms <= {DEADLINE_MS}ms)', 0)
    return 0  # unreachable; satisfies type checker


if __name__ == '__main__':
    sys.exit(main())
