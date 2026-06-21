#!/usr/bin/env python3
"""
Passive joint-telemetry tap for the robot-behavior anomaly plane.

Subscribes to ``/lab_arm/joint_states`` (published by cyclic_motion.py under
Gazebo or the headless fallback), decimates to ~10 Hz, and maintains a small
rolling-window file on the shared lab-state volume:

    /var/lab/state/robot/joint_stream.jsonl   (last ROLL_N samples, atomically replaced)

container-ai's ``robot_consumer.py`` reads that file and scores it with the LSTM
autoencoder.  This node is **passive** — a read-only observer of the joint topic,
completely separate from the safety-critical ``cyclic_motion`` publisher, exactly
like Zeek passively taps the network.  If it dies the robot is unaffected.

It emits RAW joint angles only; all feature logic lives in
``vm-ai/model/robot_features.py`` so there is nothing here that can drift from the
model (anti-drift).
"""
from __future__ import annotations

import json
import os
import time
from collections import deque

import rclpy
from rclpy.node import Node
from sensor_msgs.msg import JointState

JOINT_NAMES = ["j1", "j2", "j3", "j4", "j5", "j6"]

OUT_DIR = os.environ.get("LAB_ROBOT_STREAM_DIR", "/var/lab/state/robot")
OUT_FILE = os.path.join(OUT_DIR, "joint_stream.jsonl")
TOPIC = os.environ.get("LAB_ROBOT_JOINT_TOPIC", "/lab_arm/joint_states")
SAMPLE_HZ = float(os.environ.get("LAB_ROBOT_SAMPLE_HZ", "10.0"))
ROLL_N = int(os.environ.get("LAB_ROBOT_ROLL_N", "256"))     # ~25 s of history at 10 Hz
WRITE_PERIOD = float(os.environ.get("LAB_ROBOT_WRITE_PERIOD", "0.3"))


class JointTelemetryBridge(Node):
    def __init__(self) -> None:
        super().__init__("joint_telemetry_bridge")
        os.makedirs(OUT_DIR, exist_ok=True)
        try:
            os.chmod(OUT_DIR, 0o777)
        except Exception:
            pass
        self._buf: deque = deque(maxlen=ROLL_N)
        self._last_sample = 0.0
        self._min_dt = 1.0 / SAMPLE_HZ - 0.005
        # Default QoS (depth 10, RELIABLE) matches cyclic_motion's publisher.
        self.create_subscription(JointState, TOPIC, self._on_js, 10)
        self.create_timer(WRITE_PERIOD, self._flush)
        self.get_logger().info(
            f"joint_telemetry_bridge: tap {TOPIC} -> {OUT_FILE} @ ~{SAMPLE_HZ:.0f} Hz"
        )

    def _ordered(self, msg: JointState):
        """Return (pos, vel, eff) reordered to canonical j1..j6 regardless of
        the publisher's name ordering."""
        idx = {n: i for i, n in enumerate(msg.name)}

        def pick(arr, j):
            i = idx.get(j)
            return float(arr[i]) if (i is not None and i < len(arr)) else 0.0

        pos = [pick(msg.position, j) for j in JOINT_NAMES]
        vel = [pick(msg.velocity, j) for j in JOINT_NAMES]
        eff = [pick(msg.effort, j) for j in JOINT_NAMES]
        return pos, vel, eff

    def _on_js(self, msg: JointState) -> None:
        now = time.time()
        if now - self._last_sample < self._min_dt:
            return   # decimate to ~SAMPLE_HZ
        self._last_sample = now
        pos, vel, eff = self._ordered(msg)
        self._buf.append({"ts": now, "position": pos, "velocity": vel, "effort": eff})

    def _flush(self) -> None:
        if not self._buf:
            return
        try:
            tmp = OUT_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                for row in list(self._buf):
                    fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            os.replace(tmp, OUT_FILE)   # atomic — reader never sees a partial file
            try:
                os.chmod(OUT_FILE, 0o666)
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001
            self.get_logger().debug(f"flush failed: {exc}")


def main() -> int:
    rclpy.init()
    node = JointTelemetryBridge()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
