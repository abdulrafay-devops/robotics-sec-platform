#!/usr/bin/env python3
"""
Animate the workpiece in Gazebo to follow the robot arm's pick-and-place motion.

This version drives the workpiece position purely from the arm's j1 (waist) and
j2 (shoulder) joint angles using a bulletproof coordinate state machine.

We only transition to CARRY when the arm is facing the pick zone (j1 <= -1.45) AND
has actually descended to touch the table surface (j2 <= -0.65). This ensures the
gripper physically contacts the box before picking it, rather than it sticking
magnetically in mid-air.

Similarly, we only transition to DROP when the arm has descended into the drop bin
(j1 >= 1.45 and j2 <= -0.65), ensuring a perfect physical release on the bin floor.

SDF Mapping ground truth:
  - j1 = -1.5708 (negative) points to North (Y = +0.62), where the conveyor pick zone is.
  - j1 = +1.5708 (positive) points to South (Y = -0.62), where the drop bin is.
"""
import sys
import math
import logging
import rclpy
from rclpy.node import Node
from gazebo_msgs.srv import SetEntityState
from gazebo_msgs.msg import LinkStates
from sensor_msgs.msg import JointState
from geometry_msgs.msg import Pose
from rclpy.qos import QoSProfile, QoSReliabilityPolicy

try:
    from pymodbus.client.sync import ModbusTcpClient
    _MODBUS_OK = True
except ImportError:
    _MODBUS_OK = False

LOG = logging.getLogger("workpiece_animator")

# State machine thresholds (calibrated to SDF mapping and vertical descent)
PICK_J1       = -1.45   # j1 threshold to enter CARRY (near North pick zone)
DROP_J1       =  1.45   # j1 threshold to enter DROP (near South drop zone)
DESCENT_J2    = -0.65   # j2 threshold confirming vertical contact/descent
RESET_J1      =  1.40   # j1 threshold to enter CONVEYOR (when leaving South drop zone)

# World positions
PICK_Y   =  0.62   # Y of pick zone (South end of conveyor, close to robot)
START_Y  =  1.45   # Y where workpiece starts on conveyor (North end)
BIN_Y    = -0.62   # Y of drop bin (South of robot)
BIN_Z    =  0.53   # Z of drop bin floor
BELT_Z   =  0.565  # Z of conveyor surface


class WorkpieceAnimator(Node):
    def __init__(self) -> None:
        super().__init__("workpiece_animator")
        self.declare_parameter("modbus_host", "127.0.0.1")
        self.declare_parameter("modbus_port", 502)
        self.declare_parameter("workpiece_name", "02b_work_piece")

        self.host    = str(self.get_parameter("modbus_host").value)
        self.port    = int(self.get_parameter("modbus_port").value)
        self.wp_name = str(self.get_parameter("workpiece_name").value)

        # Optional Modbus client (best-effort — failures are tolerated)
        self._client = None
        if _MODBUS_OK:
            try:
                self._client = ModbusTcpClient(self.host, port=self.port)
                self._client.connect()
            except Exception as exc:
                self.get_logger().warning(f"Modbus optional connect failed: {exc}")
                self._client = None

        # Gazebo set-state service
        self.set_state_client = self.create_client(
            SetEntityState, "/gazebo/set_entity_state"
        )

        # Arm joint states
        self.j1 = 0.0
        self.j2 = 0.0
        self.create_subscription(
            JointState, "/lab_arm/joint_states", self._on_joint_state, 10
        )

        # Gripper real-time link pose (used for zero-lag high-precision CARRY tracking)
        self.gripper_pose = None
        qos = QoSProfile(depth=10, reliability=QoSReliabilityPolicy.BEST_EFFORT)
        self.create_subscription(
            LinkStates, "/gazebo/link_states", self._on_link_states, qos
        )

        # State machine
        self._state = "CONVEYOR"  # CONVEYOR, CARRY, or DROP
        self.wp_y   = START_Y

        self.create_timer(0.025, self._tick)   # 40 Hz for ultra-smooth rendering
        self.get_logger().info(
            "WorkpieceAnimator ready — high-precision j1/j2 state machine with dynamic link-tracking"
        )

    # ------------------------------------------------------------------ #
    def _on_joint_state(self, msg: JointState) -> None:
        if "j1" in msg.name:
            self.j1 = msg.position[msg.name.index("j1")]
        if "j2" in msg.name:
            self.j2 = msg.position[msg.name.index("j2")]

    # ------------------------------------------------------------------ #
    def _on_link_states(self, msg: LinkStates) -> None:
        if "lab_arm::link6" in msg.name:
            idx = msg.name.index("lab_arm::link6")
            self.gripper_pose = msg.pose[idx]

    # ------------------------------------------------------------------ #
    def _tick(self) -> None:
        # ── State machine transitions ────────────────────────────────────
        if self._state == "CONVEYOR":
            # Transition to CARRY only if facing pick zone AND shoulder descends for contact
            if self.j1 <= PICK_J1 and self.j2 <= DESCENT_J2:
                self._state = "CARRY"
                self.get_logger().info("State → CARRY (gripper contacted and picked workpiece)")

        elif self._state == "CARRY":
            # Transition to DROP only if facing drop zone AND shoulder descends to drop floor
            if self.j1 >= DROP_J1 and self.j2 <= DESCENT_J2:
                self._state = "DROP"
                self.get_logger().info("State → DROP (workpiece released on drop bin floor)")

        elif self._state == "DROP":
            # Transition back to CONVEYOR once the arm lifts and leaves the drop bin
            if self.j1 < RESET_J1:
                self._state = "CONVEYOR"
                self.wp_y = START_Y
                self.get_logger().info("State → CONVEYOR (new cycle, workpiece reset)")

        # ── Compute target pose ──────────────────────────────────────────
        target_pose = Pose()
        target_pose.orientation.w = 1.0

        if self._state == "CARRY" and self.gripper_pose is not None:
            # DYNAMIC LINK TRACKING: Lock the workpiece perfectly to the gripper's fingertip gap
            # Rotate offset vector (0, 0, -0.175) by the gripper's real-time quaternion
            qw = self.gripper_pose.orientation.w
            qx = self.gripper_pose.orientation.x
            qy = self.gripper_pose.orientation.y
            qz = self.gripper_pose.orientation.z
            
            # Local offset along gripper Z-axis to position it exactly between parallel fingertips
            oz = 0.135
            
            # Rotated offset vector
            rx = 2 * (qx * qz + qw * qy) * oz
            ry = 2 * (qy * qz - qw * qx) * oz
            rz = (qw * qw - qx * qx - qy * qy + qz * qz) * oz
            
            target_pose.position.x = self.gripper_pose.position.x + rx
            target_pose.position.y = self.gripper_pose.position.y + ry
            target_pose.position.z = self.gripper_pose.position.z + rz
            target_pose.orientation = self.gripper_pose.orientation

        elif self._state == "DROP":
            # Workpiece sits in drop bin
            target_pose.position.x = 0.0
            target_pose.position.y = BIN_Y
            target_pose.position.z = BIN_Z

        else:  # CONVEYOR
            # Conveyor: j1 goes 0 → -π/2, workpiece moves START_Y (1.45) → PICK_Y (0.62)
            if self.j1 <= 0.0:
                t = max(0.0, min(1.0, self.j1 / -1.5708))
                self.wp_y = START_Y + t * (PICK_Y - START_Y)
            else:
                self.wp_y = START_Y
            target_pose.position.x = 0.0
            target_pose.position.y = self.wp_y
            target_pose.position.z = BELT_Z

        # ── Send to Gazebo ───────────────────────────────────────────────
        if not self.set_state_client.service_is_ready():
            return

        req = SetEntityState.Request()
        req.state.name            = self.wp_name
        req.state.pose            = target_pose
        req.state.reference_frame = "world"
        self.set_state_client.call_async(req)

        # ── Optional Modbus read (best-effort for cycle counting) ────────
        if self._client is not None:
            try:
                if not self._client.is_socket_open():
                    self._client.connect()
                self._client.read_coils(0, 8)           # just keep the conn alive
            except Exception:
                pass   # non-fatal


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    rclpy.init(args=sys.argv)
    node = WorkpieceAnimator()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        if node._client is not None:
            node._client.close()
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
