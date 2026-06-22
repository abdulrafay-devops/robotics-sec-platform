#!/usr/bin/env python3
"""
AI validation harness — the anti-churn SAFETY NET (Step 1 of AI-UPGRADE-PLAN.md).

Runs against the LIVE pipeline (what the demo actually uses) and asserts:
  (a) the steady BASELINE stays calm  -> no false alarms / fake incidents
  (b) EVERY attack in the library is DETECTED (anomaly=true)
and prints a PASS/FAIL table. Rule: never promote a model change unless this PASSES.

Usage (host):  python infra/tests/validate_ai.py
Exit code 0 = PASS, 1 = FAIL.
"""
from __future__ import annotations
import json
import subprocess
import sys
import time

# Windows consoles default to cp1252; force UTF-8 so the report never crashes on output.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

AI = "container-ai"
SEC = "container-sec"
PLC = "192.168.10.10"
PY = "/opt/lab/venv-shipper/bin/python"
TRAFFIC = "/opt/lab/vm-ot/traffic"

# Attack library (~6-8), each tagged with MITRE ATT&CK for ICS. "trigger" attacks go
# through SEC's attack-watcher (attack_trigger.json); "extra" attacks run the
# parameterised attack_modbus_extra.py directly. (dur, rate) in seconds / Hz.
ATTACKS = [
    ("Command injection (T0855)",       "trigger", "modbus_command_injection", 18, 10),
    ("Replay (T0831)",                  "trigger", "modbus_replay",            18, 5),
    ("Coil/register flood / DoS (T0814)", "trigger", "coil_flood",             18, 40),
    ("Recon scan (T0846)",              "extra",   "recon",                    18, 12),
    ("Safety / E-stop tampering (T0880)", "extra", "estop",                    18, 8),
    ("Stealthy setpoint drift (T0836)", "extra",   "drift",                    22, 2),
    ("Unauthorized bulk write (T0843)", "extra",   "bulk",                     18, 8),
]

BASELINE_READS = 8
BASELINE_INTERVAL = 5
ATTACK_POLLS = 7
ATTACK_POLL_INTERVAL = 5
CLEAR_WAIT = 22


def _dexec(container, cmd, timeout=30, detach=False):
    args = ["docker", "exec"] + (["-d"] if detach else []) + [container, "sh", "-c", cmd]
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _score() -> dict:
    r = _dexec(AI, "cat /var/lab/state/latest_scores.json")
    if not r or not r.stdout.strip():
        return {}
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {}


def _launch(method, key, dur, rate):
    if method == "trigger":
        payload = '{"attack_type":"%s","duration_s":%d,"rate_hz":%d}' % (key, dur, rate)
        _dexec(SEC, "echo '%s' > /var/lab/state/attack_trigger.json" % payload)
    else:  # extra
        _dexec(SEC, "%s %s/attack_modbus_extra.py --host %s --mode %s --duration-s %d --rate-hz %d"
               % (PY, TRAFFIC, PLC, key, dur, rate), detach=True)


def main() -> int:
    print("=" * 70)
    print(" AI VALIDATION HARNESS - live baseline-calm + attack-detection gate")
    print("=" * 70)

    print("\n[1] BASELINE - expect calm (anomaly=false, scores >= 0):")
    false_alarms = neg = 0
    for _ in range(BASELINE_READS):
        s = _score()
        anom = bool(s.get("anomaly"))
        pca, tf = s.get("pca_z", 0) or 0, s.get("tf_z", 0) or 0
        false_alarms += anom
        neg += (pca < 0 or tf < 0)
        print("    if=%.3f pca=%.2f tf=%.2f  anomaly=%s" % (s.get("iforest_score", 0) or 0, pca, tf, anom))
        time.sleep(BASELINE_INTERVAL)
    baseline_ok = (false_alarms == 0 and neg == 0)
    print("    -> %s (%d false alarm(s), %d negative score(s))"
          % ("CALM" if baseline_ok else "PROBLEM", false_alarms, neg))

    print("\n[2] ATTACKS - expect each DETECTED (anomaly=true):")
    results = []
    for name, method, key, dur, rate in ATTACKS:
        _launch(method, key, dur, rate)
        detected, peak = False, {}
        for _ in range(ATTACK_POLLS):
            time.sleep(ATTACK_POLL_INTERVAL)
            s = _score()
            if s.get("anomaly"):
                detected, peak = True, s
                break
        tag = ("DETECTED  (pca=%.0f tf=%.0f if=%.2f)"
               % (peak.get("pca_z", 0) or 0, peak.get("tf_z", 0) or 0, peak.get("iforest_score", 0) or 0)
               ) if detected else "MISSED"
        print("    %-36s %s" % (name, tag))
        results.append((name, detected))
        time.sleep(CLEAR_WAIT)

    print("\n" + "=" * 70 + "\n RESULT\n" + "=" * 70)
    detected_n = sum(1 for _, d in results if d)
    print("  baseline calm + non-negative: %s (%d false alarms, %d negatives)"
          % ("PASS" if baseline_ok else "FAIL", false_alarms, neg))
    print("  attacks detected:             %d / %d" % (detected_n, len(results)))
    for name, d in results:
        print("      %-36s %s" % (name, "OK" if d else "MISS"))
    overall = baseline_ok and detected_n == len(results)
    print("\n  OVERALL: %s" % ("PASS - safe to promote models" if overall else "FAIL - do NOT promote"))
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
