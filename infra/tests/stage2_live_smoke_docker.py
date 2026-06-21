#!/usr/bin/env python3
"""
Stage 2 live smoke gate (Docker version).

Drives a 30-second replay attack from container-sec, then asserts that
/var/lab/log/ai-alerts.json on container-ai grew and contains at least one
AI-shaped alert with category='modbus-write-anomaly' or 'modbus-baseline-deviation'.

Usage:
    python infra/tests/stage2_live_smoke_docker.py
"""
import os
import sys
import time
import subprocess
import logging

LOG = logging.getLogger('stage2-live-smoke-docker')

OT_TARGET = "192.168.10.10"
DURATION_S = 30
MULTIPLIER = 5
ALERT_FILE = "/var/lab/log/ai-alerts.json"

def _run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)

def main() -> int:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    
    # Check if containers are active
    LOG.info("Checking if Docker containers are running...")
    res = _run_cmd(["docker", "ps", "--filter", "name=container-ai", "--filter", "status=running", "-q"])
    if not res.stdout.strip():
        LOG.error("container-ai is not running!")
        return 1
        
    res = _run_cmd(["docker", "ps", "--filter", "name=container-sec", "--filter", "status=running", "-q"])
    if not res.stdout.strip():
        LOG.error("container-sec is not running!")
        return 1

    # Snapshot current alert file size inside container-ai
    LOG.info("Snapshotting current ai-alerts.json size in container-ai...")
    res = _run_cmd(["docker", "exec", "container-ai", "bash", "-c", f"[ -f {ALERT_FILE} ] && wc -c < {ALERT_FILE} || echo 0"])
    before_str = res.stdout.strip()
    try:
        before = int(before_str)
    except ValueError:
        before = 0
    LOG.info(f"Size before attack: {before} bytes")

    # Drive the replay attack from container-sec
    LOG.info(f"Replaying Modbus packets from container-sec for {DURATION_S}s to {OT_TARGET}...")
    # The attack generator script is located in /opt/lab/vm-ot/traffic/attack_modbus_replay.py
    # Since we mounted ./vm-ot to /opt/lab/vm-ot, it is directly available!
    attack_cmd = [
        "docker", "exec", "container-sec", 
        "/opt/lab/venv-shipper/bin/python", 
        "/opt/lab/vm-ot/traffic/attack_modbus_replay.py",
        "--host", OT_TARGET, 
        "--duration-s", str(DURATION_S), 
        "--multiplier", str(MULTIPLIER)
    ]
    res = subprocess.run(attack_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        LOG.warning(f"Replay attack driver exited with code {res.returncode}. Stderr: {res.stderr}")
    else:
        LOG.info("Replay attack driver completed successfully.")

    # Wait for pipeline to drain
    LOG.info("Waiting 15 seconds for the security pipeline to process and drain alerts...")
    time.sleep(15)

    # Compare sizes and inspect content
    res = _run_cmd(["docker", "exec", "container-ai", "bash", "-c", f"[ -f {ALERT_FILE} ] && wc -c < {ALERT_FILE} || echo 0"])
    after_str = res.stdout.strip()
    try:
        after = int(after_str)
    except ValueError:
        after = 0
    LOG.info(f"Size after attack: {after} bytes")

    if after <= before:
        LOG.error(f"FAIL: ai-alerts.json did not grow! before={before}, after={after}")
        return 1

    # Extract the new portion and check for anomaly keywords
    new_bytes = after - before
    # Read the tail of the alert file inside container-ai
    res = _run_cmd(["docker", "exec", "container-ai", "bash", "-c", f"tail -c {new_bytes} {ALERT_FILE}"])
    new_content = res.stdout
    
    LOG.info(f"Read {new_bytes} new bytes of alerts.")
    if "modbus-write-anomaly" in new_content or "modbus-baseline-deviation" in new_content:
        LOG.info("Found matching anomaly alert in the captured log window!")
        print("STAGE 2 LIVE SMOKE: PASS")
        return 0
    else:
        LOG.error("FAIL: Did not find modbus-write-anomaly or modbus-baseline-deviation in the new alerts!")
        LOG.debug(f"New alert content: {new_content}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
