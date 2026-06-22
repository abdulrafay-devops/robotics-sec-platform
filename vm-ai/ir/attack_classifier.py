#!/usr/bin/env python3
"""
Attack classifier — turns a generic AI anomaly into a NAMED, MITRE ATT&CK for ICS
tagged finding with a plain-English "why it fired" rationale.

This is the SOC-grade response layer (Step 4 of AI-UPGRADE-PLAN.md). The detection
plane (feature_consumer) decides *whether* a 5-second window is anomalous; this
module decides *what* it is, so the right playbook runs and the analyst sees the
technique + the evidence behind it.

It classifies from the OBSERVED Modbus protocol fields (function code, target
address, write quantity, rate) — the same fields a SOC analyst or an OT-IDS would
read off the wire — NOT from the attacker's self-declared intent. The preferred
signal is `event["fingerprint"]`, an exact per-window protocol summary attached by
feature_consumer. If it is absent (e.g. an older alert) we fall back to a coarse
classification from the 20-dim feature vector.

Design rules:
  * Pure + total: classify() NEVER raises and ALWAYS returns a dict — a bad input
    yields the honest "unclassified" finding, never a crash in the alert path.
  * Additive: this does not change any model, threshold, or the anomaly decision.
    It only labels an anomaly that the detection plane already raised.

Live attack signatures it separates (all from SEC 192.168.10.20 -> PLC .10):

  recon          FC3+FC1 read sweep 0..56, no writes          -> T0846
  bulk_write     FC16 multi-register write (qty>=2)            -> T0843
  coil_flood     FC5 single coil, very high write rate         -> T0814
  modbus_replay  FC6 to scratch regs 10-13 (no coils)          -> T0831
  setpoint_drift FC6 to one setpoint reg 4, low & slow         -> T0836
  safety_tamper  FC5 coil 1 + FC6 reg 2 (safety path, addr>=1) -> T0880
  cmd_injection  FC5 coils 0/2 + FC6 cycle reg 0 (touches 0)   -> T0855
"""
from __future__ import annotations

from typing import Any, Optional

# --- MITRE ATT&CK for ICS catalog ------------------------------------------
# attack_type -> presentation + classification metadata. `category` is one of the
# three canonical alert_bridge categories, kept so the legacy category-triggered
# playbooks still work as a fallback.
CATALOG: dict[str, dict[str, str]] = {
    "modbus_command_injection": dict(
        label="Modbus Command Injection",
        mitre_id="T0855", mitre_technique="Unauthorized Command Message",
        tactic="Impair Process Control", severity="critical",
        category="modbus-external-anomaly"),
    "modbus_replay": dict(
        label="Modbus Replay Attack",
        mitre_id="T0831", mitre_technique="Manipulation of Control",
        tactic="Impair Process Control", severity="high",
        category="modbus-baseline-deviation"),
    "coil_flood": dict(
        label="Modbus Coil Flood / DoS",
        mitre_id="T0814", mitre_technique="Denial of Service",
        tactic="Inhibit Response Function", severity="high",
        category="modbus-baseline-deviation"),
    "recon_scan": dict(
        label="OT Reconnaissance Scan",
        mitre_id="T0846", mitre_technique="Remote System Discovery",
        tactic="Discovery", severity="medium",
        category="modbus-baseline-deviation"),
    "safety_tamper": dict(
        label="Safety / E-Stop Tampering",
        mitre_id="T0880", mitre_technique="Loss of Safety",
        tactic="Impact", severity="critical",
        category="modbus-baseline-deviation"),
    "setpoint_drift": dict(
        label="Stealthy Setpoint Drift",
        mitre_id="T0836", mitre_technique="Modify Parameter",
        tactic="Impair Process Control", severity="high",
        category="modbus-baseline-deviation"),
    "bulk_write": dict(
        label="Unauthorized Bulk Register Write",
        mitre_id="T0843", mitre_technique="Program Download",
        tactic="Lateral Movement", severity="critical",
        category="modbus-baseline-deviation"),
    "robot_behavior": dict(
        label="Robot Joint-Dynamics Anomaly",
        mitre_id="T0831", mitre_technique="Manipulation of Control",
        tactic="Impair Process Control", severity="high",
        category="robot-behavior-anomaly"),
    # Honest fallbacks when the signature does not match a known pattern.
    "unknown_write": dict(
        label="Unauthorized Control Write (unclassified)",
        mitre_id="T0836", mitre_technique="Modify Parameter",
        tactic="Impair Process Control", severity="high",
        category="modbus-baseline-deviation"),
    "unknown": dict(
        label="Unclassified Modbus Anomaly",
        mitre_id="", mitre_technique="Anomalous Modbus Behaviour",
        tactic="Unknown", severity="medium",
        category="modbus-baseline-deviation"),
}

# Modbus write function codes.
_COIL_WRITE = {5, 15}     # FC5 write_coil, FC15 write_coils
_REG_WRITE = {6, 16}      # FC6 write_register, FC16 write_registers
_MULTI_WRITE = {15, 16}   # block writes


def _f(fp: dict, key: str, default: float = 0.0) -> float:
    try:
        v = fp.get(key, default)
        return float(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _nz(addrs) -> list:
    """Non-zero write addresses (Zeek emits a spurious addr-0 companion per write)."""
    return sorted({int(a) for a in (addrs or []) if int(a) != 0})


def _classify_from_fingerprint(fp: dict) -> tuple[str, str, list[str]]:
    """Return (attack_type, confidence, why[]) from the exact protocol fingerprint.

    Ordered most-specific first; each test removes one attack from contention. The
    baseline poller shares the source IP, so a window mixes baseline READS with the
    attack's writes — every test keys off the WRITE side (or its absence), which the
    baseline never produces, so baseline noise cannot misclassify. Robust to the
    decoder quirks: keys on coil-vs-register split, function codes, and the SET of
    write addresses (max register address separates e-stop from injection), never on
    the unparsed write quantity.
    """
    n_write = _f(fp, "n_write")
    n_read = _f(fp, "n_read")
    n_coil_write = _f(fp, "n_coil_write")
    n_reg_write = _f(fp, "n_reg_write")
    write_fcs = set(int(x) for x in fp.get("write_fcs", []) if x is not None)
    has_block = bool(fp.get("has_block_write")) or bool(write_fcs & _MULTI_WRITE)
    coil_nz = _nz(fp.get("coil_addrs"))
    reg_nz = _nz(fp.get("reg_addrs"))
    max_reg = _f(fp, "max_reg_addr", -1)
    wrate = _f(fp, "write_rate")
    why: list[str] = []

    # 1) Read-only anomaly -> reconnaissance. The baseline reads too, but never
    #    triggers an anomaly; a read burst broad enough to fire IS a scan.
    if n_write == 0 and n_read > 0:
        why.append(f"read-only burst: {int(n_read)} reads, 0 writes — enumerating, not operating")
        why.append("breadth of registers/coils read far exceeds the narrow HMI baseline")
        return "recon_scan", "high", why

    # 2) Block (multi-register) write -> bulk write / program-style overwrite.
    if has_block:
        why.append("multi-register block write (FC16) — pushing a block of crafted values at once")
        why.append("the baseline only ever writes single values, never blocks")
        return "bulk_write", "high", why

    # 3) Coil-only writes -> flood / DoS (the only coil-exclusive attack).
    if n_coil_write > 0 and n_reg_write == 0:
        tgt = f" to coil {coil_nz}" if coil_nz else ""
        why.append(f"~{wrate:.0f} coil writes/sec{tgt} with no register writes — flooding the PLC scan cycle (DoS)")
        return "coil_flood", "high", why

    # 4) Pure register writes (no coils): replay (scratch regs >=8) vs drift (<=7).
    if n_coil_write == 0 and n_reg_write > 0:
        if max_reg >= 8:
            why.append(f"repeating register-write sequence to scratch regs {reg_nz or ['10-13']} — replayed control commands")
            why.append("no coil writes; an off-baseline write cadence on otherwise-valid registers")
            return "modbus_replay", "high", why
        why.append(f"slow, small writes to a single setpoint register (addr {reg_nz or ['4']}) — low-and-slow parameter drift")
        why.append("write volume stays just above the read-only baseline to evade rate alarms")
        return "setpoint_drift", "medium", why

    # 5) Coil + register writes. The safety register (reg 2) separates e-stop from
    #    injection, which only ever writes the cycle register (reg 0).
    if n_coil_write > 0 and n_reg_write > 0:
        if max_reg >= 1:
            why.append(f"writes to the safety path — coil {coil_nz or ['1']} + safety register {reg_nz or ['2']} — e-stop / safety-state tampering")
            why.append("the safety registers are operator-read-only in normal operation")
            return "safety_tamper", "high", why
        why.append(f"unauthorized control writes — coils {coil_nz or ['0','2']} + the cycle register — forcing commands at ~{wrate:.0f}/s")
        why.append("a non-HMI source is driving control points the baseline only reads")
        return "modbus_command_injection", "high", why

    return "unknown_write", "medium", ["write activity that does not match a known attack signature"]


# Feature-vector indices for the coarse fallback (must match model.features.FEATURE_NAMES).
_FV = {
    "n_writes": 2, "n_reads": 3, "n_exceptions": 4, "max_quantity": 8,
    "n_unique_addresses": 9, "msg_rate": 10, "write_ratio": 12,
    "n_external_writes": 14, "bulk_write_ratio": 18,
}


def _classify_from_vector(vec: list) -> tuple[str, str, list[str]]:
    """Coarse fallback when no fingerprint is present (older alerts)."""
    def g(name: str) -> float:
        i = _FV.get(name, -1)
        try:
            return float(vec[i]) if 0 <= i < len(vec) else 0.0
        except (TypeError, ValueError):
            return 0.0
    why = ["classified from aggregate window features (no protocol fingerprint available)"]
    if g("write_ratio") < 0.02 and g("n_reads") > 0:
        return "recon_scan", "medium", why + ["read-heavy, near-zero writes"]
    if g("bulk_write_ratio") > 0.0 or g("max_quantity") >= 2:
        return "bulk_write", "medium", why + ["multi-register write ratio elevated"]
    if g("msg_rate") >= 25:
        return "coil_flood", "medium", why + [f"very high message rate (~{g('msg_rate'):.0f}/s)"]
    if g("n_writes") > 0:
        return "unknown_write", "low", why + ["writes present but signature ambiguous from aggregates"]
    return "unknown", "low", why


def classify(event: dict) -> dict:
    """Classify an anomaly event into a MITRE-tagged finding. Never raises."""
    try:
        # Robot plane events carry their own identity — pass them through.
        if event.get("plane") == "robot":
            meta = dict(CATALOG["robot_behavior"])
            joints = event.get("top_joints") or event.get("top_features") or []
            hits = event.get("envelope_hits") or []
            why = []
            if hits:
                why.append(f"physical-envelope breach: {', '.join(map(str, hits))[:160]}")
            if joints:
                why.append(f"LSTM flagged abnormal dynamics on joint(s): {', '.join(map(str, joints))[:120]}")
            if not why:
                why.append("robot joint dynamics deviated from the learned pick-and-place cycle")
            return _finalize("robot_behavior", meta, "high", why)

        fp = event.get("fingerprint")
        if isinstance(fp, dict) and fp:
            atype, conf, why = _classify_from_fingerprint(fp)
        else:
            vec = event.get("features") or []
            atype, conf, why = _classify_from_vector(vec)

        meta = dict(CATALOG.get(atype, CATALOG["unknown"]))
        # Add the live model evidence to the rationale.
        pca = event.get("pca_z")
        tf = event.get("tf_z")
        ifs = event.get("iforest_score")
        bits = []
        if ifs is not None:
            bits.append(f"IsolationForest={float(ifs):.2f}")
        if pca is not None:
            bits.append(f"PCA-AE z={float(pca):.0f}")
        if tf is not None:
            bits.append(f"TF-AE z={float(tf):.0f}")
        if bits:
            why.append("model scores: " + ", ".join(bits))
        return _finalize(atype, meta, conf, why)
    except Exception as exc:  # never break the alert path
        meta = dict(CATALOG["unknown"])
        return _finalize("unknown", meta, "low", [f"classifier error: {exc}"])


def _finalize(atype: str, meta: dict, confidence: str, why: list) -> dict:
    return {
        "attack_type": atype,
        "label": meta["label"],
        "mitre_id": meta["mitre_id"],
        "mitre_technique": meta["mitre_technique"],
        "tactic": meta["tactic"],
        "severity": meta["severity"],
        "category": meta["category"],
        "confidence": confidence,
        "why": why,
    }


if __name__ == "__main__":
    # Tiny self-test with synthetic fingerprints (no infra needed).
    import json
    # Real captured signatures (Zeek decoder: FC16 addr/qty unparsed, spurious
    # addr-0 companion per write). expected attack_type alongside.
    samples = {
        "recon_scan":               {"n_read": 148, "n_write": 0},
        "bulk_write":               {"n_write": 48, "n_coil_write": 0, "n_reg_write": 48, "write_fcs": [16], "has_block_write": True, "reg_addrs": [0], "max_reg_addr": 0, "write_rate": 9.6},
        "coil_flood":               {"n_write": 132, "n_coil_write": 132, "n_reg_write": 0, "write_fcs": [5], "coil_addrs": [0, 5], "max_coil_addr": 5, "write_rate": 26},
        "modbus_replay":            {"n_write": 126, "n_coil_write": 0, "n_reg_write": 126, "write_fcs": [6], "reg_addrs": [0, 10, 11, 12, 13], "max_reg_addr": 13, "write_rate": 25},
        "setpoint_drift":           {"n_write": 36, "n_coil_write": 0, "n_reg_write": 36, "write_fcs": [6], "reg_addrs": [0, 4], "max_reg_addr": 4, "write_rate": 7},
        "safety_tamper":            {"n_write": 108, "n_coil_write": 54, "n_reg_write": 54, "write_fcs": [5, 6], "coil_addrs": [0, 1], "reg_addrs": [0, 2], "max_reg_addr": 2, "write_rate": 21},
        "modbus_command_injection": {"n_write": 90, "n_coil_write": 56, "n_reg_write": 34, "write_fcs": [5, 6], "coil_addrs": [0, 2], "reg_addrs": [0], "max_reg_addr": 0, "write_rate": 18},
    }
    for expected, fp in samples.items():
        r = classify({"fingerprint": fp, "n_read": fp.get("n_read", 20)})
        ok = r["attack_type"] == expected
        print(f"{expected:26s} -> {r['attack_type']:26s} {r['mitre_id']:6s} {'OK' if ok else 'MISMATCH'}")
        assert ok, f"{expected} misclassified as {r['attack_type']}"
    print("self-test OK")
    print(json.dumps(classify({"fingerprint": samples["modbus_command_injection"], "iforest_score": 0.41, "pca_z": 42000, "tf_z": 120000}), indent=2))
