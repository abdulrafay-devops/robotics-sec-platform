#!/usr/bin/env bash
export ROS_SECURITY_ENABLE=false
unset CYCLONEDDS_URI
unset RMW_IMPLEMENTATION
source /opt/ros/humble/setup.bash

echo "Calling service /gazebo/set_model_configuration..."
ros2 service call /gazebo/set_model_configuration gazebo_msgs/srv/SetModelConfiguration "{model_name: 'lab_arm', urdf_param_name: '', joint_names: ['j1', 'j2', 'j3', 'j4', 'j5', 'j6'], joint_positions: [0.5, -0.5, 0.5, -0.5, 0.5, -0.5]}"
