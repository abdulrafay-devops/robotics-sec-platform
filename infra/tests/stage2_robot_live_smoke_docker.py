#!/usr/bin/env python3
"""
Stage 2 ROBOT live smoke gate (Docker).

Injects a robot-behavior attack through the dashboard API (nginx injects the API
key), then asserts that /var/lab/log/ai-alerts.json on container-ai gained a
`robot-behavior-anomaly` alert — i.e. the live path
OT joint tap -> robot_consumer (LSTM + envelope) -> alert_bridge worked end to end.

Usage:
    python infra/tests/stage2_robot_live_smoke_docker.py
"""
import json
import logging
import subprocess
import sys
import time
import urllib.request

LOG = logging.getLogger("stage2-robot-live-smoke")
ALERT_FILE = "/var/lab/log/ai-alerts.json"
DASH = "http://localhost:8888"
ATTACK = "joint_speed_violation"
DURATION_S = 10


def _exec(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _robot_alert_count() -> int:
    res = _exec(["docker", "exec", "container-ai", "bash", "-c",
                 f"grep -c robot-behavior-anomaly {ALERT_FILE} 2>/dev/null || echo 0"])
    try:
        return int(res.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    res = _exec(["docker", "ps", "--filter", "name=container-ai", "--filter", "status=running", "-q"])
    if not res.stdout.strip():
        LOG.error("container-ai is not running!")
        return 1

    before = _robot_alert_count()
    LOG.info("robot-behavior-anomaly alerts before: %d", before)

    LOG.info("Injecting robot attack '%s' (%ds) via dashboard API...", ATTACK, DURATION_S)
    payload = json.dumps({"attack_type": ATTACK, "duration_s": DURATION_S, "rate_hz": 5}).encode()
    try:
        req = urllib.request.Request(f"{DASH}/api/demo/inject-attack", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            LOG.info("inject response: %s", r.read().decode()[:200])
    except Exception as exc:  # noqa: BLE001
        LOG.error("injection request failed: %s", exc)
        return 1

    LOG.info("Waiting %ds for detection + alert to drain...", DURATION_S + 8)
    time.sleep(DURATION_S + 8)

    after = _robot_alert_count()
    LOG.info("robot-behavior-anomaly alerts after: %d", after)

    if after > before:
        print(f"STAGE 2 ROBOT LIVE SMOKE: PASS (alerts {before} -> {after})")
        return 0
    print(f"STAGE 2 ROBOT LIVE SMOKE: FAIL (no new robot-behavior-anomaly; {before} -> {after})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
