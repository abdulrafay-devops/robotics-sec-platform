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

# Attack library — name (with MITRE ATT&CK for ICS id) -> SEC attack-watcher params.
# (Expanded to the full ~6-8 set in Step 2; these 3 are wired today.)
ATTACKS = [
    ("Command injection (T0855)",      "modbus_command_injection", 25, 10),
    ("Replay (T0831)",                 "modbus_replay",            22, 5),
    ("Coil/register flood / DoS (T0814)", "coil_flood",            22, 40),
]

BASELINE_READS = 8        # ~40s of steady baseline
BASELINE_INTERVAL = 5
ATTACK_POLLS = 7          # ~35s window to catch the attack
ATTACK_POLL_INTERVAL = 5
CLEAR_WAIT = 25           # let the attack finish + baseline return before the next


def _dexec(container: str, cmd: str, timeout: int = 30):
    try:
        return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                              capture_output=True, text=True, timeout=timeout)
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


def _trigger(attack_type: str, dur: int, rate: int) -> None:
    payload = '{"attack_type":"%s","duration_s":%d,"rate_hz":%d}' % (attack_type, dur, rate)
    _dexec(SEC, "echo '%s' > /var/lab/state/attack_trigger.json" % payload)


def main() -> int:
    print("=" * 70)
    print(" AI VALIDATION HARNESS — live baseline-calm + attack-detection gate")
    print("=" * 70)

    # ---- 1. Baseline must be calm (no false alarms) ----
    print("\n[1] BASELINE — expect calm (anomaly=false every read):")
    false_alarms = 0
    for _ in range(BASELINE_READS):
        s = _score()
        anom = bool(s.get("anomaly"))
        false_alarms += anom
        print("    if=%.3f pca=%.2f tf=%.2f  anomaly=%s"
              % (s.get("iforest_score", 0) or 0, s.get("pca_z", 0) or 0,
                 s.get("tf_z", 0) or 0, anom))
        time.sleep(BASELINE_INTERVAL)
    baseline_ok = (false_alarms == 0)
    print("    -> baseline %s (%d false alarm(s))" % ("CALM" if baseline_ok else "NOISY", false_alarms))

    # ---- 2. Every attack must be detected ----
    print("\n[2] ATTACKS — expect each DETECTED (anomaly=true):")
    results = []
    for name, atype, dur, rate in ATTACKS:
        _trigger(atype, dur, rate)
        detected, peak = False, {}
        for _ in range(ATTACK_POLLS):
            time.sleep(ATTACK_POLL_INTERVAL)
            s = _score()
            if s.get("anomaly"):
                detected, peak = True, s
                break
        if detected:
            print("    %-34s DETECTED  (pca=%.0f tf=%.0f if=%.2f)"
                  % (name, peak.get("pca_z", 0) or 0, peak.get("tf_z", 0) or 0,
                     peak.get("iforest_score", 0) or 0))
        else:
            print("    %-34s MISSED" % name)
        results.append((name, detected))
        time.sleep(CLEAR_WAIT)  # let it finish + clear before the next attack

    # ---- 3. Verdict ----
    print("\n" + "=" * 70)
    print(" RESULT")
    print("=" * 70)
    print("  baseline calm:        %s (%d false alarms)"
          % ("PASS" if baseline_ok else "FAIL", false_alarms))
    detected_n = sum(1 for _, d in results if d)
    print("  attacks detected:     %d / %d" % (detected_n, len(results)))
    for name, d in results:
        print("      %-34s %s" % (name, "OK" if d else "MISS"))
    overall = baseline_ok and detected_n == len(results)
    print("\n  OVERALL: %s" % ("PASS - safe to promote models" if overall
                               else "FAIL - do NOT promote"))
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
