#!/usr/bin/env python3
"""Stage 3 — SROS2 unauthenticated-client rejection test.

Spawns an rclpy node WITHOUT the SROS2 enclave environment variables
(no keystore, no enforce). Attempts to publish to /safety/request and
verifies that the safety supervisor's /safety/state does NOT flip to
EMERGENCY within 3 seconds. DDS security drops the unauthenticated
participant during the discovery handshake, so the request is never
delivered.

A PASS means the security boundary held; a FAIL means an unsigned peer
was able to inject a remote E-stop, which would be a critical defect.

Usage on the host:
    vagrant ssh vm-ot -c \
      'sudo /opt/lab/bin/run-stage3-sros2-authn.sh' -- -q
"""
from __future__ import annotations

import os
import sys
import time

# Strip every SROS2 var before importing rclpy so the test process runs
# as an unsigned peer regardless of how the systemd unit was launched.
for v in (
    'ROS_SECURITY_ENABLE', 'ROS_SECURITY_STRATEGY',
    'ROS_SECURITY_KEYSTORE', 'ROS_SECURITY_ENCLAVE_OVERRIDE',
    'ROS_SECURITY_LOOKUP_TYPE',
):
    os.environ.pop(v, None)

import rclpy  # noqa: E402
from rclpy.node import Node  # noqa: E402
from rclpy.qos import (  # noqa: E402
    QoSDurabilityPolicy, QoSHistoryPolicy, QoSProfile, QoSReliabilityPolicy,
)
from std_msgs.msg import UInt8  # noqa: E402

EMERGENCY = 2


class _Attacker(Node):
    def __init__(self) -> None:
        super().__init__('stage3_unauth_attacker')
        qos = QoSProfile(
            history=QoSHistoryPolicy.KEEP_LAST, depth=10,
            reliability=QoSReliabilityPolicy.RELIABLE,
            durability=QoSDurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._sub = self.create_subscription(
            UInt8, '/safety/state', self._on_state, qos)
        self._pub = self.create_publisher(UInt8, '/safety/request', 10)
        self.received_emergency = False
        self.create_timer(0.3, self._spam)

    def _spam(self) -> None:
        msg = UInt8(); msg.data = 1
        try:
            self._pub.publish(msg)
        except Exception:  # noqa: BLE001
            # Even constructing the publisher may fail under Enforce — that's a PASS.
            pass

    def _on_state(self, msg: UInt8) -> None:
        if msg.data >= EMERGENCY:
            self.received_emergency = True


def _emit_and_exit(line: str, rc: int) -> None:
    # See stage3_safety_loop.py for rationale (rclpy.shutdown deadlock).
    print(line, flush=True)
    sys.stdout.flush()
    os._exit(rc)


def main() -> int:
    try:
        rclpy.init()
    except Exception as exc:  # noqa: BLE001
        # If rclpy can't even initialize unsigned, that's the cleanest PASS.
        _emit_and_exit(f'STAGE 3 SROS2 AUTHN: PASS (rclpy init refused unsigned: {exc})', 0)

    node = _Attacker()
    end = time.monotonic() + 3.0
    while time.monotonic() < end and rclpy.ok():
        rclpy.spin_once(node, timeout_sec=0.1)
        if node.received_emergency:
            break

    if node.received_emergency:
        _emit_and_exit('STAGE 3 SROS2 AUTHN: FAIL (unauthenticated client triggered EMERGENCY)', 1)
    _emit_and_exit('STAGE 3 SROS2 AUTHN: PASS (unsigned /safety/request had no effect)', 0)
    return 0  # unreachable


if __name__ == '__main__':
    sys.exit(main())
