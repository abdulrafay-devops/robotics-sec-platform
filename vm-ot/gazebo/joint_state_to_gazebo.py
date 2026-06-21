#!/usr/bin/env python3
"""
Bridge /lab_arm/joint_states into Gazebo's joint trajectory topic.

The security platform keeps the robot motion generator intentionally simple:
`cyclic_motion.py` publishes sensor-style JointState telemetry for the AI
pipeline. Gazebo Classic does not automatically move spawned URDF joints from
that topic, so this bridge applies those positions to the `lab_arm` model for
operator demos in the remote GUI by publishing JointTrajectory points.
"""
from __future__ import annotations

import logging
import sys
from typing import Dict

import rclpy
from rclpy.node import Node
from sensor_msgs.msg import JointState
from trajectory_msgs.msg import JointTrajectory, JointTrajectoryPoint
from builtin_interfaces.msg import Duration

LOG = logging.getLogger("joint_state_to_gazebo")


class JointStateToGazebo(Node):
    def __init__(self) -> None:
        super().__init__("joint_state_to_gazebo")
        self.declare_parameter("model_name", "lab_arm")
        self.declare_parameter("joint_state_topic", "/lab_arm/joint_states")
        self.declare_parameter("joint_trajectory_topic", "/lab_arm/joint_trajectory")
        self.declare_parameter("max_update_hz", 20.0)

        self._model_name = str(self.get_parameter("model_name").value)
        topic = str(self.get_parameter("joint_state_topic").value)
        traj_topic = str(self.get_parameter("joint_trajectory_topic").value)
        
        self._min_period = 1.0 / max(
            float(self.get_parameter("max_update_hz").value), 1.0
        )
        self._last_call = 0.0
        self._latest: JointState | None = None

        self._pub = self.create_publisher(JointTrajectory, traj_topic, 10)
        self.create_subscription(JointState, topic, self._on_joint_state, 10)
        self.create_timer(0.05, self._tick)
        self.get_logger().info(
            f"bridging {topic} -> JointTrajectory topic {traj_topic} (model {self._model_name})"
        )

    def _on_joint_state(self, msg: JointState) -> None:
        self._latest = msg

    def _tick(self) -> None:
        if self._latest is None:
            return
        now = self.get_clock().now().nanoseconds / 1e9
        if (now - self._last_call) < self._min_period:
            return

        msg = self._latest
        joint_map: Dict[str, float] = dict(zip(msg.name, msg.position))
        names = [name for name in ("j1", "j2", "j3", "j4", "j5", "j6")
                 if name in joint_map]
        if not names:
            return

        traj = JointTrajectory()
        # Set stamp to 0 to execute the trajectory immediately in Gazebo Classic
        traj.header.stamp.sec = 0
        traj.header.stamp.nanosec = 0
        traj.header.frame_id = "base_link"
        traj.joint_names = [f"{self._model_name}::{name}" for name in names]

        point = JointTrajectoryPoint()
        point.positions = [float(joint_map[name]) for name in names]
        point.time_from_start = Duration(sec=0, nanosec=10000000) # 10 ms

        traj.points = [point]
        self._pub.publish(traj)
        self._last_call = now
        self.get_logger().info(f"Published JointTrajectory point: {traj.joint_names} -> {point.positions}", throttle_duration_sec=2.0)



def main() -> int:
    logging.basicConfig(level=logging.INFO)
    rclpy.init(args=sys.argv)
    node = JointStateToGazebo()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

