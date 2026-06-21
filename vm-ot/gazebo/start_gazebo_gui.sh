#!/usr/bin/env bash
# Start the Gazebo Classic client inside an RDP/Xfce session.
set -euo pipefail

export GAZEBO_MASTER_URI="${GAZEBO_MASTER_URI:-http://127.0.0.1:11345}"
export LIBGL_ALWAYS_SOFTWARE="${LIBGL_ALWAYS_SOFTWARE:-1}"
export QT_X11_NO_MITSHM="${QT_X11_NO_MITSHM:-1}"

set +u
source /opt/ros/humble/setup.bash
set -u

exec gzclient --verbose
