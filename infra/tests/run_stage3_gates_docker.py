#!/usr/bin/env python3
"""
Stage 3 SROS2 Gate Runner (Docker version).

Restarts the secured nodes inside container-ot to clear the EMERGENCY latch,
then executes:
- Gate 1: safety loop timing test (must respond in <= 200 ms).
- Gate 2: unsigned peer authn rejection (unsigned request must be dropped).

Usage:
    python infra/tests/run_stage3_gates_docker.py
"""
import os
import sys
import time
import subprocess
import logging

LOG = logging.getLogger('stage3-gates-docker')

def _run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)

def _restart_secured_nodes():
    LOG.info("Stopping safety supervisor and heartbeat nodes in container-ot...")
    _run_cmd(["docker", "exec", "container-ot", "pkill", "-9", "-f", "safety_bridge.py"])
    _run_cmd(["docker", "exec", "container-ot", "pkill", "-9", "-f", "safety_heartbeat.py"])
    time.sleep(2)
    
    LOG.info("Starting safety supervisor node...")
    cmd_sup = [
        "docker", "exec", "-d", "container-ot", "bash", "-c",
        "export HOME=/root && "
        "export ROS_LOG_DIR=/var/lab/log/ros && "
        "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp && "
        "export ROS_DOMAIN_ID=0 && "
        "export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore && "
        "export ROS_SECURITY_ENABLE=true && "
        "export ROS_SECURITY_STRATEGY=Enforce && "
        "export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml && "
        "source /opt/ros/humble/setup.bash && "
        "export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/safety_supervisor && "
        "/opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_bridge.py --plc-host 127.0.0.1 --plc-port 503 > /var/lab/log/lab-safety-supervisor.log 2>&1"
    ]
    _run_cmd(cmd_sup)

    LOG.info("Starting safety heartbeat node...")
    cmd_hb = [
        "docker", "exec", "-d", "container-ot", "bash", "-c",
        "export HOME=/root && "
        "export ROS_LOG_DIR=/var/lab/log/ros && "
        "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp && "
        "export ROS_DOMAIN_ID=0 && "
        "export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore && "
        "export ROS_SECURITY_ENABLE=true && "
        "export ROS_SECURITY_STRATEGY=Enforce && "
        "export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml && "
        "source /opt/ros/humble/setup.bash && "
        "export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/production_plc && "
        "/opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_heartbeat.py > /var/lab/log/lab-safety-heartbeat.log 2>&1"
    ]
    _run_cmd(cmd_hb)
    
    LOG.info("Waiting 4 seconds for DDS-Security enclaves to discover and bind...")
    time.sleep(4)

def main() -> int:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    
    # 0. Check container
    res = _run_cmd(["docker", "ps", "--filter", "name=container-ot", "--filter", "status=running", "-q"])
    if not res.stdout.strip():
        LOG.error("container-ot is not running!")
        return 1

    # 1. Restart nodes (Clear EMERGENCY latch)
    _restart_secured_nodes()
    
    # 2. Run Gate 1: Safety timing loop
    LOG.info("=== GATE 1: Safety loop timing test ===")
    cmd_gate1 = [
        "docker", "exec", "container-ot", "bash", "-c",
        "export HOME=/root && "
        "export ROS_LOG_DIR=/var/lab/log/ros && "
        "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp && "
        "export ROS_DOMAIN_ID=0 && "
        "export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore && "
        "export ROS_SECURITY_ENABLE=true && "
        "export ROS_SECURITY_STRATEGY=Enforce && "
        "export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/production_plc && "
        "export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml && "
        "source /opt/ros/humble/setup.bash && "
        "/opt/lab/venv-traffic/bin/python /vagrant/infra/tests/stage3_safety_loop.py"
    ]
    LOG.info("Executing timing probe inside container-ot...")
    res_gate1 = subprocess.run(cmd_gate1, capture_output=True, text=True, timeout=30)
    print(res_gate1.stdout)
    if res_gate1.returncode != 0:
        LOG.error(f"Gate 1 failed! Stderr: {res_gate1.stderr}")
        return 1

    # 3. Restart nodes again to clear the latch triggered by Gate 1
    _restart_secured_nodes()
    
    # 4. Run Gate 2: Unsigned peer authn rejection
    LOG.info("=== GATE 2: SROS2 authn rejection ===")
    cmd_gate2 = [
        "docker", "exec", "container-ot", "bash", "-c",
        "export HOME=/root && "
        "export ROS_LOG_DIR=/var/lab/log/ros && "
        "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp && "
        "export ROS_DOMAIN_ID=0 && "
        "export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml && "
        "source /opt/ros/humble/setup.bash && "
        "/opt/lab/venv-traffic/bin/python /vagrant/infra/tests/stage3_sros2_authn.py"
    ]
    LOG.info("Executing unsigned attack probe inside container-ot...")
    res_gate2 = subprocess.run(cmd_gate2, capture_output=True, text=True, timeout=30)
    print(res_gate2.stdout)
    if res_gate2.returncode != 0:
        LOG.error(f"Gate 2 failed! Stderr: {res_gate2.stderr}")
        return 1

    print("\nSTAGE 3 OVERALL: PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
