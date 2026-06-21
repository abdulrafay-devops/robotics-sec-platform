"""
ROS2 launch file for the Gazebo lab cell.

Boots:
  * gzserver (headless Gazebo physics) with `world.sdf`
  * robot_state_publisher fed by `robot.urdf`
  * spawn_entity to insert the arm at fixed pose
  * a simple cyclic_motion node that drives j1..j6 along a recorded
    pick-and-place trajectory at ~10 Hz, mirroring the OpenPLC step machine

Why no gzclient here: the server runs headless for determinism. Operators open
the GUI through Apache Guacamole/RDP, which starts gzclient separately.

Usage (from VM-OT):
    source /opt/ros/humble/setup.bash
    ros2 launch /vagrant/vm-ot/gazebo/launch.py
"""
from __future__ import annotations

import os
from pathlib import Path

from launch import LaunchDescription
from launch.actions import ExecuteProcess
from launch_ros.actions import Node


def _read_urdf() -> str:
    gazebo_dir = Path(os.environ.get('LAB_GAZEBO_DIR', '/opt/lab/vm-ot/gazebo'))
    urdf_path = gazebo_dir / 'robot.urdf'
    if not urdf_path.exists():
        raise FileNotFoundError(
            f'URDF not found: {urdf_path}. The /vagrant share must be mounted.'
        )
    return urdf_path.read_text(encoding='utf-8')


def generate_launch_description() -> LaunchDescription:
    gazebo_dir = Path(os.environ.get('LAB_GAZEBO_DIR', '/opt/lab/vm-ot/gazebo'))
    world_path = str(gazebo_dir / 'world.sdf')
    urdf_xml = _read_urdf()

    # gzserver only -- headless. -r runs simulation immediately, -v 1 limits verbosity.
    gzserver = ExecuteProcess(
        cmd=[
            'gzserver',
            '--verbose',
            '-r',
            '-s', 'libgazebo_ros_init.so',
            '-s', 'libgazebo_ros_factory.so',
            world_path,
        ],
        output='screen',
        env={
            **os.environ,
            'GAZEBO_PLUGIN_PATH': os.environ.get(
                'GAZEBO_PLUGIN_PATH', '/opt/ros/humble/lib'
            ),
            # Ensure DDS runs without SROS2 for Gazebo so service calls from the
            # joint bridge succeed consistently in this lab environment.
            'ROS_SECURITY_ENABLE': 'false',
        },
    )

    rsp = Node(
        package='robot_state_publisher',
        executable='robot_state_publisher',
        name='robot_state_publisher',
        namespace='lab_arm',
        output='screen',
        parameters=[{'robot_description': urdf_xml}],
        additional_env={'ROS_SECURITY_ENABLE': 'false'},
    )

    spawn = Node(
        package='gazebo_ros',
        executable='spawn_entity.py',
        name='spawn_lab_arm',
        arguments=[
            '-entity', 'lab_arm',
            '-file', str(gazebo_dir / 'robot.urdf'),
            '-x', '0', '-y', '0', '-z', '0.0',
        ],
        output='screen',
        additional_env={'ROS_SECURITY_ENABLE': 'false'},
    )

    # Run the standalone rclpy script; no colcon package required.
    cyclic_motion = ExecuteProcess(
        cmd=['python3', str(gazebo_dir / 'cyclic_motion.py'),
             '--ros-args', '-p', 'rate_hz:=40.0', '-p', 'cycle_seconds:=8.0',
             '-r', '__ns:=/lab_arm'],
        output='screen',
        env={**os.environ, 'ROS_SECURITY_ENABLE': 'false'}
    )

    # Disable SROS2 just for the Gazebo model configuration bridge to avoid
    # permission conflicts with the Gazebo API service. All other nodes remain
    # under the default SROS2 settings from the container environment.
    joint_state_bridge = ExecuteProcess(
        cmd=['python3', str(gazebo_dir / 'joint_state_to_gazebo.py'),
             '--ros-args', '-p', 'max_update_hz:=40.0'],
        output='screen',
        env={**os.environ, 'ROS_SECURITY_ENABLE': 'false'}
    )

    workpiece_animator = ExecuteProcess(
        cmd=['python3', str(gazebo_dir / 'workpiece_animator.py')],
        output='screen',
        env={**os.environ, 'ROS_SECURITY_ENABLE': 'false'}
    )

    # Passive joint-telemetry tap for the robot-behavior anomaly plane. Runs in the
    # same security-disabled group as cyclic_motion so it always sees
    # /lab_arm/joint_states; writes a rolling window file on the shared lab-state
    # volume that container-ai's robot_consumer.py scores with the LSTM AE.
    joint_telemetry_bridge = ExecuteProcess(
        cmd=['python3', str(gazebo_dir / 'joint_telemetry_bridge.py')],
        output='screen',
        env={**os.environ, 'ROS_SECURITY_ENABLE': 'false'}
    )

    # Safety reset: publish NORMAL (0) to /safety/state with TRANSIENT_LOCAL
    # so any late-joining cyclic_motion node sees NORMAL before stale EMERGENCY.
    # This prevents the arm from starting frozen after every Gazebo restart.
    safety_reset = ExecuteProcess(
        cmd=[
            'ros2', 'topic', 'pub', '--once',
            '/safety/state', 'std_msgs/msg/UInt8', '{data: 0}',
            '--qos-reliability', 'reliable',
            '--qos-durability', 'transient_local',
        ],
        output='screen',
        env={**os.environ, 'ROS_SECURITY_ENABLE': 'false'}
    )

    return LaunchDescription([
        gzserver,
        rsp,
        spawn,
        safety_reset,
        cyclic_motion,
        joint_state_bridge,
        workpiece_animator,
        joint_telemetry_bridge,
    ])
