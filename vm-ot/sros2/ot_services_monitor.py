#!/usr/bin/env python3
"""
Background daemon to monitor local safety-critical processes on container-ot.
Writes active process status to a shared JSON file in /var/lab/state/.ot_services.json.
"""

import json
import os
import time
from pathlib import Path

OUT = Path("/var/lab/state/.ot_services.json")

def _proc_running(name: str) -> bool:
    try:
        # Scan /proc for running processes matching name in cmdline
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "r", errors="replace") as fh:
                    cmd = fh.read()
            except Exception:
                continue
            if name in cmd:
                return True
    except Exception:
        return False
    return False

def main() -> None:
    print("Starting OT Services Monitor...", flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            data = {
                "safety_supervisor": _proc_running("safety_bridge.py"),
                "safety_heartbeat": _proc_running("safety_heartbeat.py"),
                "openplc": _proc_running("openplc") or _proc_running("OpenPLC")
            }
            # Write atomically using a temporary file
            tmp = OUT.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
            tmp.replace(OUT)
        except Exception as exc:
            print(f"[ot_services_monitor] Error: {exc}", flush=True)
        time.sleep(2)

if __name__ == "__main__":
    main()
