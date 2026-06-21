"""
Stage 2 alert bridge.

Pops anomaly events from Redis (`lab.anomaly.events`), reshapes them into
Suricata `eve.json`-compatible records, and appends them to
`/var/lab/log/ai-alerts.json` so Stage 6 dashboards can mix native
Suricata alerts with AI-generated ones on a single timeline.

Output schema (one JSON object per line):

    {
        "timestamp": "2026-05-18T08:30:21.123456Z",
        "event_type": "alert",
        "src_ip": "192.168.20.10",
        "dest_ip": "192.168.10.10",
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 9000,
            "signature_id": 9001001,            # AI-namespace: 9001000-9001999
            "rev": 1,
            "signature": "AI: modbus write-burst anomaly",
            "category": "modbus-write-anomaly",
            "severity": 2
        },
        "lab": {
            "source": "lab-ai-score",
            "model_version": "v1",
            "iforest_score": 0.31,
            "pca_z": 4.7,
            "top_features": ["msg_rate", "n_writes", "ot_origin"]
        }
    }
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import redis

LOG = logging.getLogger("alert_bridge")
logging.basicConfig(
    level=os.environ.get("LAB_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

REDIS_HOST = os.environ.get("LAB_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("LAB_REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ.get("LAB_REDIS_PASSWORD", "")
ANOMALY_LIST = os.environ.get("LAB_REDIS_ANOMALY_LIST", "lab.anomaly.events")
ALERT_FILE = os.environ.get("LAB_AI_ALERT_FILE", "/var/lab/log/ai-alerts.json")
SIG_ID_BASE = 9001000
GID = 9000

# Minimum seconds between writing alerts for the same category (dedup gate).
# 60s collapses a burst/sustained event of one category into a single alert so
# the IR engine opens one incident, not a stream. Lower via LAB_BRIDGE_COOLDOWN_S
# only for back-to-back demo injections of the same attack type.
ALERT_COOLDOWN_S = float(os.environ.get("LAB_BRIDGE_COOLDOWN_S", "60.0"))
_last_written_ts: dict = {}  # category → last write timestamp

_should_exit = False


def _sigterm(*_a) -> None:
    global _should_exit  # noqa: PLW0603
    _should_exit = True


def _classify(ev: dict) -> tuple[int, str, str, int]:
    """Map an event to (signature_id, signature, category, severity).

    Canonical categories emitted by this function:
      modbus-external-anomaly  — anomalous traffic from outside the OT zone (192.168.10.0/24)
      modbus-baseline-deviation — anomalous traffic from inside the OT zone
      robot-behavior-anomaly   — anomalous robot joint dynamics (robot plane)
    Playbooks in vm-ai/ir/playbooks/ must reference one of these exact strings.
    """
    # Robot plane (robot_consumer.py): the event carries its own signature and
    # severity already; pass them through under a dedicated category + sig-id range.
    if ev.get("plane") == "robot":
        sev = int(ev.get("severity", 2) or 2)
        sig = ev.get("signature") or "AI: robot joint-dynamics anomaly"
        return (SIG_ID_BASE + 10, sig, "robot-behavior-anomaly", sev)

    src = ev.get("src_ip") or ""
    pca = ev.get("pca_z") or 0
    ifs = ev.get("iforest_score") or 0
    # 9001001: write-burst from outside OT zone (highest severity)
    if src and not src.startswith("192.168.10."):
        # Score-based severity: worse score = higher priority
        sev = 1 if (pca >= 5.0 or ifs >= 0.25) else 2
        return (
            SIG_ID_BASE + 1,
            "AI: modbus write-burst from outside OT zone",
            "modbus-external-anomaly",
            sev,
        )
    # 9001002: anomalous behaviour from inside OT (score-based severity)
    sev = 2 if (pca >= 3.5 or ifs >= 0.20) else 3
    return (
        SIG_ID_BASE + 2,
        "AI: anomalous Modbus behaviour from OT host",
        "modbus-baseline-deviation",
        sev,
    )


def _eve(ev: dict) -> dict:
    sig_id, sig_text, category, severity = _classify(ev)
    is_robot = ev.get("plane") == "robot"
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event_type": "alert",
        "anomaly": True,  # always True — only anomalies reach this bridge
        "src_ip": ev.get("src_ip"),
        "dest_ip": ev.get("dst_ip"),
        "proto": "ROS2" if is_robot else "TCP",
        "alert": {
            "action": "allowed",
            "gid": GID,
            "signature_id": sig_id,
            "rev": 1,
            "signature": sig_text,
            "category": category,
            "severity": severity,
        },
        "lab": {
            "source": "lab-ai-robot" if is_robot else "lab-ai-score",
            "model_version": ev.get("model_version"),
            "iforest_score": ev.get("iforest_score"),
            "pca_z": ev.get("pca_z"),
            "tf_z": ev.get("tf_z"),
            "robot_z": ev.get("robot_z"),
            "envelope_hits": ev.get("envelope_hits"),
            "top_features": ev.get("top_features") or ev.get("top_joints", []),
            "window_start": ev.get("window_start"),
            "n_msgs": ev.get("n_msgs"),
        },
    }


def main() -> int:
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
    LOG.info("alert_bridge starting: redis=%s:%d list=%s out=%s",
             REDIS_HOST, REDIS_PORT, ANOMALY_LIST, ALERT_FILE)

    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                    password=REDIS_PASSWORD or None, decode_responses=True)
    for _ in range(30):
        try:
            r.ping()
            break
        except redis.ConnectionError:
            time.sleep(1.0)
    else:
        LOG.error("Redis unreachable at %s:%d", REDIS_HOST, REDIS_PORT)
        return 1

    fh = open(ALERT_FILE, "a", buffering=1, encoding="utf-8")
    try:
        while not _should_exit:
            try:
                item = r.blpop(ANOMALY_LIST, timeout=1)
            except redis.RedisError as exc:
                LOG.warning("redis BLPOP failed: %s; backoff 1s", exc)
                time.sleep(1.0)
                continue
            if item is None:
                continue
            _, payload = item
            try:
                ev = json.loads(payload)
            except ValueError:
                LOG.warning("bad json on anomaly list: %r", payload[:120])
                continue

            # Deduplicate: skip writing if the same category was written recently.
            record = _eve(ev)
            category = record["alert"]["category"]
            now_t = time.time()
            if now_t - _last_written_ts.get(category, 0.0) < ALERT_COOLDOWN_S:
                LOG.debug(
                    "alert suppressed by cooldown (cat=%s, remaining=%.0fs)",
                    category,
                    ALERT_COOLDOWN_S - (now_t - _last_written_ts.get(category, 0.0)),
                )
                continue
            _last_written_ts[category] = now_t

            line = json.dumps(record, separators=(",", ":"))
            fh.write(line + "\n")
            fh.flush()
            LOG.info("alert -> %s", line[:200])
    finally:
        try:
            fh.close()
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
