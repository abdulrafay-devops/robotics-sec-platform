#!/usr/bin/env python3
"""
IR validation harness — the Step 4 (SOC response) anti-churn SAFETY NET.

Two layers:

  [A] OFFLINE classifier gate (always runs, no infra):
      Feeds the 7 attacks' protocol fingerprints to ir.attack_classifier and
      asserts each maps to the EXPECTED attack_type + MITRE technique. This is the
      deterministic gate — if classification logic regresses, this fails instantly.

  [B] LIVE end-to-end gate (--live):
      Resets IR state + restarts container-ai for a clean slate, launches each of
      the 7 attacks, and asserts a correctly-classified, MITRE-tagged INCIDENT is
      opened by the playbook engine with the right per-attack playbook.

Usage:
    python infra/tests/validate_ir.py          # offline gate only
    python infra/tests/validate_ir.py --live    # offline + live end-to-end
Exit 0 = PASS, 1 = FAIL.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Make ir.attack_classifier importable when run from the repo root.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "vm-ai"))

AI = "container-ai"
SEC = "container-sec"
PLC = "192.168.10.10"
PY = "/opt/lab/venv-shipper/bin/python"
TRAFFIC = "/opt/lab/vm-ot/traffic"
INCIDENTS = "/var/lab/state/ir/incidents.jsonl"

# (name, expected_attack_type, expected_mitre, launch_method, key, dur, rate)
# All 7 launch via the trigger file (the EXACT path the dashboard inject buttons use):
# score_service writes attack_trigger.json -> SEC's watcher runs the real attack ->
# Zeek -> feature_consumer -> the IR classifier. `key` is the attack_type the SEC
# watcher maps to a script; `expected` is what the classifier derives from the traffic.
ATTACKS = [
    ("Command injection", "modbus_command_injection", "T0855", "trigger", "modbus_command_injection", 18, 10),
    ("Replay",            "modbus_replay",            "T0831", "trigger", "modbus_replay",            18, 5),
    ("Coil flood / DoS",  "coil_flood",               "T0814", "trigger", "coil_flood",               18, 40),
    ("Recon scan",        "recon_scan",               "T0846", "trigger", "register_scan",            18, 12),
    ("E-stop tampering",  "safety_tamper",            "T0880", "trigger", "safety_tamper",            18, 8),
    ("Setpoint drift",    "setpoint_drift",           "T0836", "trigger", "setpoint_drift",           22, 2),
    ("Bulk write",        "bulk_write",               "T0843", "trigger", "bulk_write",               18, 8),
]

# Synthetic per-attack fingerprints for the OFFLINE gate — taken from REAL captured
# live signatures (Zeek decoder: FC16 addr/qty unparsed; spurious addr-0 per write).
OFFLINE_FP = {
    "modbus_command_injection": {"n_read": 70, "n_write": 90, "n_coil_write": 56, "n_reg_write": 34, "write_fcs": [5, 6], "coil_addrs": [0, 2], "reg_addrs": [0], "max_reg_addr": 0, "write_rate": 18},
    "modbus_replay":            {"n_read": 34, "n_write": 126, "n_coil_write": 0, "n_reg_write": 126, "write_fcs": [6], "reg_addrs": [0, 10, 11, 12, 13], "max_reg_addr": 13, "write_rate": 25},
    "coil_flood":               {"n_read": 28, "n_write": 132, "n_coil_write": 132, "n_reg_write": 0, "write_fcs": [5], "coil_addrs": [0, 5], "max_coil_addr": 5, "write_rate": 26},
    "recon_scan":               {"n_read": 148, "n_write": 0},
    "safety_tamper":            {"n_read": 52, "n_write": 108, "n_coil_write": 54, "n_reg_write": 54, "write_fcs": [5, 6], "coil_addrs": [0, 1], "reg_addrs": [0, 2], "max_reg_addr": 2, "write_rate": 21},
    "setpoint_drift":           {"n_read": 124, "n_write": 36, "n_coil_write": 0, "n_reg_write": 36, "write_fcs": [6], "reg_addrs": [0, 4], "max_reg_addr": 4, "write_rate": 7},
    "bulk_write":               {"n_read": 96, "n_write": 48, "n_coil_write": 0, "n_reg_write": 48, "write_fcs": [16], "has_block_write": True, "reg_addrs": [0], "max_reg_addr": 0, "write_rate": 9.6},
}

ATTACK_POLLS = 11
ATTACK_POLL_INTERVAL = 5
# The consumer applies a 45s per-source alert cooldown and every attack shares
# src 192.168.10.20, so we must leave a clear gap between detections or the next
# attack is suppressed at the consumer. Launch each attack only once >COOLDOWN_GAP
# seconds have elapsed since the previous detection.
COOLDOWN_GAP = 52


def _dexec(container, cmd, timeout=60, detach=False):
    args = ["docker", "exec"] + (["-d"] if detach else []) + [container, "sh", "-c", cmd]
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _launch(method, key, dur, rate):
    if method == "trigger":
        payload = '{"attack_type":"%s","duration_s":%d,"rate_hz":%d}' % (key, dur, rate)
        _dexec(SEC, "echo '%s' > /var/lab/state/attack_trigger.json" % payload)
    else:
        _dexec(SEC, "%s %s/attack_modbus_extra.py --host %s --mode %s --duration-s %d --rate-hz %d"
               % (PY, TRAFFIC, PLC, key, dur, rate), detach=True)


def _read_incidents() -> list:
    r = _dexec(AI, "cat %s 2>/dev/null" % INCIDENTS)
    out = []
    if r and r.stdout:
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def offline_gate() -> bool:
    print("=" * 72)
    print(" [A] OFFLINE CLASSIFIER GATE — 7 attack fingerprints -> attack_type + MITRE")
    print("=" * 72)
    try:
        from ir.attack_classifier import classify
    except Exception as exc:
        print("  CANNOT IMPORT ir.attack_classifier: %s" % exc)
        return False
    ok = 0
    for name, atype, mitre, *_ in ATTACKS:
        res = classify({"fingerprint": OFFLINE_FP[atype]})
        good = (res["attack_type"] == atype and res["mitre_id"] == mitre)
        ok += good
        print("  %-20s -> %-26s %-6s %s" % (
            name, res["attack_type"], res["mitre_id"], "OK" if good else "MISMATCH (exp %s/%s)" % (atype, mitre)))
    print("  -> %d / %d correctly classified" % (ok, len(ATTACKS)))
    return ok == len(ATTACKS)


def _reset_and_restart() -> None:
    print("\n  resetting IR state + restarting container-ai for a clean slate...")
    _dexec(AI, "rm -f /var/lab/state/ir/incidents.jsonl /var/lab/state/ir/pending_approvals.json "
               "/var/lab/state/ir/drift_seen.json /var/lab/state/ir/ir_engine_offset.json "
               "/var/lab/log/ai-alerts.json")
    subprocess.run(["docker", "restart", AI], capture_output=True, text=True, timeout=120)
    # Wait until the baseline pipeline is genuinely FLOWING again, not just until a
    # (possibly stale) score file exists: require the score timestamp to be recent
    # AND to advance across reads, so the very first attack lands on a warm pipeline.
    fresh_seen = 0
    last_ts = 0.0
    for _ in range(30):
        time.sleep(5)
        r = _dexec(AI, "cat /var/lab/state/latest_scores.json 2>/dev/null")
        try:
            ts = float(json.loads(r.stdout).get("ts", 0))
        except (ValueError, AttributeError, TypeError):
            ts = 0.0
        if ts and (time.time() - ts) < 12 and ts != last_ts:
            fresh_seen += 1
            last_ts = ts
            if fresh_seen >= 3:  # 3 advancing fresh windows == pipeline flowing
                print("  consumer back online + baseline flowing; warming up 15s...")
                time.sleep(15)  # extra warm-up so the first attack isn't cold
                return
    print("  (proceeding; consumer health probe inconclusive)")


def live_gate() -> bool:
    print("\n" + "=" * 72)
    print(" [B] LIVE END-TO-END GATE — each attack -> classified, MITRE-tagged incident")
    print("=" * 72)
    _reset_and_restart()
    seen: set = set()
    results = []
    last_detect = 0.0
    for name, atype, mitre, method, key, dur, rate in ATTACKS:
        # Respect the consumer's per-source alert cooldown between attacks.
        wait = COOLDOWN_GAP - (time.time() - last_detect)
        if last_detect and wait > 0:
            print("  (waiting %.0fs for the per-source alert cooldown to clear)" % wait)
            time.sleep(wait)
        before = {i.get("incident_id") for i in _read_incidents()}
        _launch(method, key, dur, rate)
        match = None
        for _ in range(ATTACK_POLLS):
            time.sleep(ATTACK_POLL_INTERVAL)
            for inc in _read_incidents():
                iid = inc.get("incident_id")
                if iid in before or iid in seen:
                    continue
                if inc.get("blocked") or inc.get("merged"):
                    continue
                # A real, classified incident for this technique.
                if inc.get("attack_type") == atype:
                    match = inc
                    seen.add(iid)
                    break
            if match:
                break
        last_detect = time.time()
        if match:
            mid = (match.get("mitre") or {}).get("id", "")
            good = (mid == mitre)
            print("  %-20s -> incident %s  playbook=%s  %s %s" % (
                name, match.get("incident_id", "?"), match.get("playbook", "?"),
                mid, "OK" if good else "(MITRE mismatch exp %s)" % mitre))
            results.append((name, good))
        else:
            print("  %-20s -> NO MATCHING INCIDENT" % name)
            results.append((name, False))
    passed = sum(1 for _, g in results if g)
    print("  -> %d / %d attacks produced a correctly-classified incident" % (passed, len(results)))
    return passed == len(results)


def main() -> int:
    live = "--live" in sys.argv
    a = offline_gate()
    b = True
    if live:
        b = live_gate()
    print("\n" + "=" * 72)
    print(" RESULT")
    print("=" * 72)
    print("  offline classifier gate: %s" % ("PASS" if a else "FAIL"))
    if live:
        print("  live end-to-end gate:    %s" % ("PASS" if b else "FAIL"))
    overall = a and b
    print("\n  OVERALL: %s" % ("PASS - safe to promote IR changes" if overall else "FAIL - do NOT promote"))
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
