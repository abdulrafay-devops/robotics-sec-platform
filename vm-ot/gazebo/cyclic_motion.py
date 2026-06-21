#!/usr/bin/env python3
"""
Cyclic pick-and-place trajectory publisher for the lab arm.

A standalone rclpy node (no colcon package required). Publishes joint
position commands at a configurable rate that drive the 6-DoF arm along
a deterministic recorded trajectory:

    waypoint A: home pose
    waypoint B: above pick zone
    waypoint C: at pick zone
    waypoint D: above drop zone
    waypoint E: at drop zone

Each waypoint is held for a fraction of the cycle. The trajectory is
intentionally smooth (cosine interpolation) so the robot-behavior LSTM
autoencoder (trained by vm-ai/model/train_robot_lstm.py) sees coherent
dynamics it can learn.

The /lab_arm/joint_states stream this node publishes is passively tapped by
joint_telemetry_bridge.py and scored live by vm-ai/robot_consumer.py
(LSTM autoencoder + physical-envelope rules) — the robot-behavior anomaly plane.

Run directly:
    source /opt/ros/humble/setup.bash
    python3 /vagrant/vm-ot/gazebo/cyclic_motion.py
"""
from __future__ import annotations

import logging
import math
import signal
import sys
from typing import List

import rclpy
from rclpy.node import Node
from rclpy.qos import (
    QoSDurabilityPolicy,
    QoSHistoryPolicy,
    QoSProfile,
    QoSReliabilityPolicy,
)
from sensor_msgs.msg import JointState
from std_msgs.msg import UInt8

LOG = logging.getLogger('cyclic_motion')
JOINT_NAMES = ['j1', 'j2', 'j3', 'j4', 'j5', 'j6']

# Mirrors vm-ot/sros2/safety_supervisor.py.
SAFETY_NORMAL = 0
SAFETY_DEGRADED = 1
SAFETY_EMERGENCY = 2

# Recorded trajectory: 5 waypoints, joint angles in radians.
# Calibrated to keep the end-effector inside the cell volume.
WAYPOINTS: List[List[float]] = [
    # j1 = waist rotation around Z-axis.
    # At j1=0  the arm faces +X (East).
    # At j1=+π/2 (+1.5708) the arm faces +Y (North) → pick zone on conveyor.
    # At j1=-π/2 (-1.5708) the arm faces -Y (South) → drop bin.
    [0.0,      0.0,   0.0,  0.0,  0.0, 0.0],   # home (facing East, safe neutral)
    [1.5708,  -0.5,  -1.0,  0.0,  0.5, 0.0],   # above pick  (arm faces North/+Y)
    [1.5708,  -0.7,  -1.4,  0.0,  0.7, 0.0],   # pick        (reach down to pick zone)
    [-1.5708, -0.5,  -1.0,  0.0,  0.5, 0.0],   # above drop  (arm faces South/-Y)
    [-1.5708, -0.7,  -1.4,  0.0,  0.7, 0.0],   # drop        (reach down into bin)
]


def smooth_interp(a: List[float], b: List[float], t: float) -> List[float]:
    """Cosine interpolation in [0,1] -> [a,b]; matches a real arm's
    velocity profile better than linear, and gives a feature-rich
    /joint_states stream for the LSTM autoencoder."""
    s = 0.5 - 0.5 * math.cos(math.pi * max(0.0, min(1.0, t)))
    return [ai + (bi - ai) * s for ai, bi in zip(a, b)]


class CyclicMotion(Node):
    def __init__(self) -> None:
        super().__init__('cyclic_motion')

        self.declare_parameter('rate_hz', 20.0)
        self.declare_parameter('cycle_seconds', 8.0)
        rate_hz: float = float(self.get_parameter('rate_hz').value)
        cycle_seconds: float = float(self.get_parameter('cycle_seconds').value)
        if rate_hz <= 0:
            raise ValueError('rate_hz must be > 0')
        if cycle_seconds <= 0:
            raise ValueError('cycle_seconds must be > 0')

        self._period = 1.0 / rate_hz
        self._cycle_s = cycle_seconds
        self._t = 0.0
        self._cycles = 0
        self._prev_positions: List[float] | None = None
        # Stage 3: latched safety flag. Once flipped to True the trajectory
        # publisher freezes the arm at the most recent waypoint until the
        # process is restarted (matching the supervisor's latch semantics).
        self._estop_active = False
        self._motor_disabled = True
        self._frozen_positions: List[float] | None = None
        self._estop_first_seen: float | None = None
        # Guard: only honour EMERGENCY after we have first seen NORMAL.
        # This prevents a stale TRANSIENT_LOCAL EMERGENCY (published before
        # this process started) from immediately freezing the arm on startup.
        self._safety_initialized = False

        # Initialize Modbus safety fallback channel (bridges cryptographic ROS2 isolation)
        self.declare_parameter('modbus_host', '127.0.0.1')
        self.declare_parameter('modbus_port', 502)
        self.mb_host = str(self.get_parameter('modbus_host').value)
        self.mb_port = int(self.get_parameter('modbus_port').value)
        self._mb_client = None
        try:
            try:
                from pymodbus.client.sync import ModbusTcpClient
            except ImportError:
                from pymodbus.client import ModbusTcpClient
            self._mb_client = ModbusTcpClient(self.mb_host, port=self.mb_port, timeout=0.5)
            self.get_logger().info(f'Modbus safety polling channel initialized targeting {self.mb_host}:{self.mb_port}')
        except Exception as exc:
            self.get_logger().warning(f'Could not initialize Modbus safety client: {exc}')

        # Stage 1 design: publish directly to joint_states (the canonical
        # sensor topic). Stage 2's ML pipeline subscribes to this exact name.
        self._state_pub = self.create_publisher(
            JointState, 'joint_states', 10
        )

        # Stage 3: subscribe to /safety/state. RELIABLE + TRANSIENT_LOCAL
        # matches the publisher's QoS in safety_supervisor.py so a
        # late-joining cyclic_motion still receives the current state.
        safety_qos = QoSProfile(
            history=QoSHistoryPolicy.KEEP_LAST,
            depth=10,
            reliability=QoSReliabilityPolicy.RELIABLE,
            durability=QoSDurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._safety_sub = self.create_subscription(
            UInt8, '/safety/state', self._on_safety_state, safety_qos
        )

        self.create_timer(self._period, self._tick)
        self.get_logger().info(
            f'cyclic_motion started: {rate_hz:.1f} Hz, {cycle_seconds:.1f}s/cycle'
            ' (subscribed to /safety/state and polling Modbus for E-stop)'
        )

    def _check_modbus_safety(self) -> None:
        if self._mb_client is None:
            return
        try:
            if not self._mb_client.is_socket_open():
                self._mb_client.connect()
            
            # Read coils starting at address 0 (read 10 coils) from Production PLC
            res = self._mb_client.read_coils(0, count=10)
            if res is not None and not res.isError() and len(res.bits) >= 6:
                motor_enable = res.bits[0]
                estop_coil = res.bits[5]
                
                # Update E-Stop flag
                if estop_coil:
                    if not self._estop_active:
                        self._estop_active = True
                        self.get_logger().warning('EMERGENCY E-Stop active coil (5) detected on Production PLC — halting robot!')
                else:
                    if self._estop_active:
                        self._estop_active = False
                        self.get_logger().info('EMERGENCY E-Stop coil cleared — resuming motion.')
                
                # Update Motor Disabled flag (only if not E-stopped)
                if not motor_enable:
                    if not self._motor_disabled:
                        self._motor_disabled = True
                        self.get_logger().info('Robotic arm motor disabled (cycle stopped/idle) — freezing motion.')
                else:
                    if self._motor_disabled:
                        self._motor_disabled = False
                        self.get_logger().info('Robotic arm motor enabled (cycle active) — resuming motion.')
        except Exception as exc:
            self.get_logger().debug(f'Modbus safety polling exception: {exc}')

    def _on_safety_state(self, msg: UInt8) -> None:
        if msg.data == SAFETY_NORMAL:
            # Mark that we have seen at least one NORMAL message. Only now
            # will subsequent EMERGENCY messages be acted upon.
            if not self._safety_initialized:
                self.get_logger().info(
                    'Safety state NORMAL received — arm motion monitoring active'
                )
            self._safety_initialized = True
            if self._estop_active:
                self._estop_active = False
                self.get_logger().info(
                    'Safety state NORMAL received — unfreezing robotic arm motion'
                )
        elif msg.data >= SAFETY_EMERGENCY:
            if not self._safety_initialized:
                # Ignore stale EMERGENCY from before this node started.
                self.get_logger().warning(
                    'Ignoring EMERGENCY on /safety/state received before first NORMAL '
                    '(stale TRANSIENT_LOCAL message — will monitor after NORMAL is seen)'
                )
                return
            if not self._estop_active:
                now = self.get_clock().now().nanoseconds / 1e9
                self._estop_active = True
                self._estop_first_seen = now
                self.get_logger().warning(
                    'EMERGENCY received on /safety/state — freezing motion at last waypoint'
                )

    def _tick(self) -> None:
        # Check Modbus safety state every 4 ticks (approx 100ms / 10 Hz at 40 Hz update rate)
        self._tick_count = getattr(self, '_tick_count', 0) + 1
        if self._tick_count % 4 == 0:
            self._check_modbus_safety()

        # Stage 3 — if E-stop latched or motor disabled, keep republishing the last position
        # so subscribers see a stable (frozen) trajectory.
        should_freeze = self._estop_active or self._motor_disabled
        if should_freeze and self._frozen_positions is not None:
            msg = JointState()
            msg.header.stamp = self.get_clock().now().to_msg()
            msg.name = JOINT_NAMES
            msg.position = self._frozen_positions
            msg.velocity = [0.0] * len(JOINT_NAMES)
            msg.effort   = [0.0] * len(JOINT_NAMES)
            self._state_pub.publish(msg)
            return

        self._t = (self._t + self._period) % self._cycle_s
        n_seg = len(WAYPOINTS)
        seg_t = self._t / self._cycle_s * n_seg
        i = int(seg_t)
        frac = seg_t - i
        a = WAYPOINTS[i % n_seg]
        b = WAYPOINTS[(i + 1) % n_seg]
        positions = smooth_interp(a, b, frac)

        # Capture the freeze frame BEFORE checking estop_active in case the
        # callback fires between this assignment and publish().
        self._frozen_positions = positions

        # Finite-difference velocity (rad/s) — used by Stage 2 ML features.
        if self._prev_positions is not None:
            velocities = [
                (p - pp) / self._period
                for p, pp in zip(positions, self._prev_positions)
            ]
        else:
            velocities = [0.0] * len(JOINT_NAMES)
        self._prev_positions = list(positions)

        # Estimated effort (torque proxy): proportional to |velocity| * link_mass
        EFFORT_SCALE = [2.0, 2.5, 1.8, 1.2, 0.8, 0.5]
        efforts = [abs(v) * s for v, s in zip(velocities, EFFORT_SCALE)]

        msg = JointState()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.name = JOINT_NAMES
        msg.position = positions
        msg.velocity = velocities
        msg.effort   = efforts

        self._state_pub.publish(msg)

        if self._t < self._period:
            self._cycles += 1
            self.get_logger().info(f'cycle {self._cycles} complete')


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    rclpy.init(args=sys.argv)
    node: CyclicMotion | None = None

    def _on_sigint(*_unused) -> None:
        if node is not None:
            node.get_logger().info('SIGINT received, shutting down')
        rclpy.shutdown()

    signal.signal(signal.SIGINT, _on_sigint)
    try:
        node = CyclicMotion()
        rclpy.spin(node)
    except Exception as exc:  # noqa: BLE001
        LOG.error('cyclic_motion crashed: %s', exc, exc_info=True)
        return 1
    finally:
        if node is not None:
            node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main())
