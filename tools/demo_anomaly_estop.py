#!/usr/bin/env python3
"""Create Grafana-visible AI anomalies and optionally trigger the lab E-stop.

This is a safe examiner/demo helper. It does not modify dashboards directly.
Instead, it pushes anomaly events into the same Redis list consumed by
`vm-ai/alert_bridge.py`, so Prometheus/Grafana see the normal platform metrics.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request

import redis


def _push_anomalies(count: int, redis_host: str, redis_port: int) -> None:
    r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
    r.ping()
    now = time.time()
    for i in range(count):
        event = {
            "src_ip": "192.168.20.77",
            "dst_ip": "192.168.10.10",
            "window_start": now + i,
            "n_msgs": 180 + (i * 7),
            "feature_version": "v1",
            "model_version": "v1",
            "iforest_score": 0.42 + (i * 0.01),
            "pca_z": 8.5 + (i * 0.25),
            "anomaly": True,
            "top_features": ["msg_rate", "n_writes", "ot_origin"],
            "demo": "examiner_modbus_write_burst",
        }
        r.rpush("lab.anomaly.events", json.dumps(event, separators=(",", ":")))


def _trigger_estop(api_base: str) -> str:
    req = urllib.request.Request(
        api_base.rstrip("/") + "/api/hmi/trigger-sros2-estop",
        data=b"",
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"E-stop API call failed: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=8,
                        help="number of anomaly events to create")
    parser.add_argument("--redis-host", default="127.0.0.1")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--no-estop", action="store_true",
                        help="only create anomalies; do not trigger E-stop")
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")

    _push_anomalies(args.count, args.redis_host, args.redis_port)
    print(f"created {args.count} AI anomaly events via Redis")

    if not args.no_estop:
        response = _trigger_estop(args.api_base)
        print(f"triggered SROS2/OpenPLC E-stop: {response}")

    print("Grafana should update on the next Prometheus scrape/refresh.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
