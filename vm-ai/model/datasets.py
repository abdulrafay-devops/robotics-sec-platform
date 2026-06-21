"""
Production-grade synthetic dataset generator for Stage 2 AI engine (v2).

Generates realistic ICS/OT Modbus traffic for training and evaluation.

Baseline patterns (normal):
  - Periodic register polling (FC=3) from multiple OT hosts
  - Coil status monitoring (FC=1) from SCADA HMI
  - Discrete input reads (FC=2) from safety monitors
  - Occasional operator writes (FC=6) from HMI
  - Holding register bulk reads (FC=4) from historian

Attack patterns (for test/eval only — NEVER used in IF/PCA training):
  1. modbus_command_injection  — high-rate writes from IT zone
  2. modbus_replay             — repeated FC=6 write sequences from outside OT
  3. coil_flood                — FC=5 coil write DoS at high rate
  4. register_scan             — sequential address scan (reconnaissance)
  5. bulk_write_attack         — FC=15/16 multiple-register writes (sabotage)
"""
from __future__ import annotations

import csv
import logging
import math
import os
import random
from typing import Iterable, List, Optional, Tuple

import numpy as np

from .features import FEATURE_NAMES, N_FEATURES, RawRow, aggregate_rows

LOG = logging.getLogger(__name__)

DEFAULT_DATASET_DIR = "/var/lab/datasets"

# Realistic IP topology
OT_PLCS   = ["192.168.10.10", "192.168.10.11", "192.168.10.12"]
SCADA_HMI = "192.168.10.20"
HISTORIAN = "192.168.10.30"
SAFETY    = "192.168.10.40"
IT_ATTACKER  = "192.168.20.99"
IT_ATTACKER2 = "192.168.20.88"
IT_ATTACKER3 = "192.168.20.77"
OT_DST    = "192.168.10.10"


def _is_ot(ip: str) -> bool:
    return ip.startswith("192.168.10.")


# ─── Normal traffic generators ─────────────────────────────────────────────

def _plc_polling_minute(t0: float, src: str, dst: str = OT_DST) -> List[RawRow]:
    """Realistic PLC polling: FC=3 reads at ~1Hz, occasional FC=6 writes."""
    rows: List[RawRow] = []
    t = t0
    rng = random.Random(int(t0 * 1000) ^ hash(src))
    end = t0 + 60.0
    # Different PLCs poll at slightly different rates
    base_rate = rng.uniform(0.7, 1.3)
    while t < end:
        # FC=3: read holding registers (primary polling)
        addr = rng.choice([0, 4, 8, 16, 1024])
        qty  = rng.choice([1, 2, 4, 8])
        rows.append(RawRow(ts=t, src_ip=src, dst_ip=dst, func_code=3,
                           is_request=True, address=addr, quantity=qty,
                           exception=False, ot_origin=_is_ot(src)))
        rows.append(RawRow(ts=t+0.002, src_ip=src, dst_ip=dst, func_code=3,
                           is_request=False, address=addr, quantity=qty,
                           exception=False, ot_origin=_is_ot(src)))
        t += rng.gauss(base_rate, base_rate * 0.1)
        # Occasional FC=6 write from operator (2% probability per poll)
        if rng.random() < 0.02:
            write_addr = rng.choice([10, 11, 12, 13, 1028])
            rows.append(RawRow(ts=t, src_ip=src, dst_ip=dst, func_code=6,
                               is_request=True, address=write_addr, quantity=1,
                               exception=False, ot_origin=_is_ot(src)))
            rows.append(RawRow(ts=t+0.003, src_ip=src, dst_ip=dst, func_code=6,
                               is_request=False, address=write_addr, quantity=1,
                               exception=False, ot_origin=_is_ot(src)))
            t += 0.05
    return rows


def _hmi_monitoring_minute(t0: float) -> List[RawRow]:
    """SCADA HMI: mixed FC=1 coil reads + FC=3 register reads at ~2Hz."""
    rows: List[RawRow] = []
    rng = random.Random(int(t0 * 997))
    t = t0
    end = t0 + 60.0
    while t < end:
        fc = rng.choice([1, 1, 3, 3, 3, 4])   # weighted toward reads
        addr = rng.choice([0, 1, 2, 3, 100, 200])
        qty  = rng.choice([1, 4, 8])
        rows.append(RawRow(ts=t, src_ip=SCADA_HMI, dst_ip=OT_DST, func_code=fc,
                           is_request=True, address=addr, quantity=qty,
                           exception=False, ot_origin=True))
        t += rng.gauss(0.5, 0.05)
    return rows


def _historian_minute(t0: float) -> List[RawRow]:
    """Historian: bulk FC=3 reads at ~0.2Hz, occasionally FC=4."""
    rows: List[RawRow] = []
    rng = random.Random(int(t0 * 503))
    t = t0
    end = t0 + 60.0
    while t < end:
        fc = rng.choice([3, 3, 3, 4])
        qty = rng.choice([8, 16, 32])
        rows.append(RawRow(ts=t, src_ip=HISTORIAN, dst_ip=OT_DST, func_code=fc,
                           is_request=True, address=0, quantity=qty,
                           exception=False, ot_origin=True))
        t += rng.gauss(5.0, 0.5)
    return rows


def _safety_monitor_minute(t0: float) -> List[RawRow]:
    """Safety monitor: FC=2 discrete input reads at ~0.5Hz."""
    rows: List[RawRow] = []
    rng = random.Random(int(t0 * 251))
    t = t0
    end = t0 + 60.0
    while t < end:
        rows.append(RawRow(ts=t, src_ip=SAFETY, dst_ip=OT_DST, func_code=2,
                           is_request=True, address=rng.choice([0, 1, 2]),
                           quantity=rng.choice([1, 2]),
                           exception=False, ot_origin=True))
        t += rng.gauss(2.0, 0.2)
    return rows


def synthetic_baseline(minutes: int = 120) -> List[RawRow]:
    """Generate realistic baseline traffic from all OT network participants."""
    rows: List[RawRow] = []
    t = 1_700_000_000.0
    for m in range(minutes):
        t_min = t + m * 60.0
        for plc_ip in OT_PLCS:
            rows.extend(_plc_polling_minute(t_min, src=plc_ip))
        rows.extend(_hmi_monitoring_minute(t_min))
        if m % 3 == 0:          # historian archives every 3 minutes
            rows.extend(_historian_minute(t_min))
        rows.extend(_safety_monitor_minute(t_min))
    return rows


# ─── Attack traffic generators ──────────────────────────────────────────────

def _attack_command_injection(t0: float, duration_s: float = 20.0,
                               rate_hz: float = 10.0) -> List[RawRow]:
    """High-rate FC=6 writes from IT attacker targeting PLC registers."""
    rows: List[RawRow] = []
    rng = random.Random(int(t0))
    t, i = t0, 0
    while t < t0 + duration_s:
        addr = rng.choice([1024, 1025, 1026, 1028, 2048])
        rows.append(RawRow(ts=t, src_ip=IT_ATTACKER, dst_ip=OT_DST, func_code=6,
                           is_request=True, address=addr, quantity=1,
                           exception=False, ot_origin=False))
        t += 1.0 / rate_hz + rng.gauss(0, 0.005)
        i += 1
    return rows


def _attack_replay(t0: float, duration_s: float = 15.0) -> List[RawRow]:
    """Replay attack: repeated identical FC=6 write sequences from IT."""
    rows: List[RawRow] = []
    rng = random.Random(int(t0 * 3))
    t = t0
    pattern_addrs = [10, 11, 12, 13]
    while t < t0 + duration_s:
        for addr in pattern_addrs:
            rows.append(RawRow(ts=t, src_ip=IT_ATTACKER2, dst_ip=OT_DST, func_code=6,
                               is_request=True, address=addr, quantity=1,
                               exception=False, ot_origin=False))
            t += rng.gauss(0.18, 0.01)
    return rows


def _attack_coil_flood(t0: float, duration_s: float = 10.0,
                        rate_hz: float = 40.0) -> List[RawRow]:
    """Coil DoS: extremely rapid FC=5 coil writes to starve PLC scan cycle."""
    rows: List[RawRow] = []
    rng = random.Random(int(t0 * 7))
    t = t0
    while t < t0 + duration_s:
        rows.append(RawRow(ts=t, src_ip=IT_ATTACKER3, dst_ip=OT_DST, func_code=5,
                           is_request=True, address=rng.choice([0, 1, 2, 3]),
                           quantity=1, exception=False, ot_origin=False))
        t += 1.0 / rate_hz + rng.gauss(0, 0.002)
    return rows


def _attack_register_scan(t0: float, duration_s: float = 20.0) -> List[RawRow]:
    """Reconnaissance: sequential address scan across register space."""
    rows: List[RawRow] = []
    t = t0
    for addr in range(0, min(1000, int(duration_s * 5))):
        rows.append(RawRow(ts=t, src_ip=IT_ATTACKER, dst_ip=OT_DST, func_code=3,
                           is_request=True, address=addr, quantity=1,
                           exception=(addr % 20 == 0),
                           ot_origin=False))
        t += 0.2
    return rows


def _attack_bulk_write(t0: float, duration_s: float = 15.0) -> List[RawRow]:
    """Sabotage: FC=16 multi-register writes overwriting PLC memory."""
    rows: List[RawRow] = []
    rng = random.Random(int(t0 * 11))
    t = t0
    while t < t0 + duration_s:
        qty = rng.choice([8, 16, 32, 64])
        rows.append(RawRow(ts=t, src_ip=IT_ATTACKER2, dst_ip=OT_DST, func_code=16,
                           is_request=True, address=rng.choice([0, 100, 1024]),
                           quantity=qty, exception=False, ot_origin=False))
        t += rng.gauss(0.8, 0.05)
    return rows


# ─── Dataset builders ────────────────────────────────────────────────────────

def synthetic_dataset(
    *,
    baseline_minutes: int = 120,
    attack_episodes: int = 0,
) -> Tuple[np.ndarray, np.ndarray]:
    """Returns (X, y) feature matrix.

    For production IsolationForest/PCA training, always use attack_episodes=0.
    For evaluation / threshold calibration, pass attack_episodes > 0.
    """
    # Live-baseline override: when LAB_LIVE_BASELINE_NPY points at a matrix captured
    # from REAL traffic (capture_live_baseline.py), train on that instead of the
    # synthetic generator — this is the "train on real data" path that removes the
    # train/serve skew. Only applies to pure-baseline training (attack_episodes==0);
    # attack evaluation below still uses the synthetic attack generators.
    _live = os.environ.get("LAB_LIVE_BASELINE_NPY")
    if _live and attack_episodes == 0 and os.path.exists(_live):
        X_live = np.load(_live).astype(np.float64)
        return X_live, np.zeros(len(X_live), dtype=np.int8)

    rows = synthetic_baseline(minutes=baseline_minutes)

    if attack_episodes > 0:
        rng = random.Random(42)
        base_t0  = rows[0].ts
        base_end = rows[-1].ts
        span     = base_end - base_t0
        attack_generators = [
            _attack_command_injection,
            _attack_replay,
            _attack_coil_flood,
            _attack_register_scan,
            _attack_bulk_write,
        ]
        for i in range(attack_episodes):
            t0  = base_t0 + rng.uniform(0.1 * span, 0.9 * span)
            gen = attack_generators[i % len(attack_generators)]
            rows.extend(gen(t0))

    rows.sort(key=lambda r: r.ts)
    buckets = aggregate_rows(rows)

    X = np.zeros((len(buckets), N_FEATURES), dtype=np.float64)
    y = np.zeros(len(buckets), dtype=np.int8)
    for i, b in enumerate(buckets):
        X[i] = b.feature_vector()
        if attack_episodes > 0:
            # Label: any non-OT write OR high exception rate = attack
            has_ext_write = any(
                r.func_code in {5, 6, 15, 16} and not r.ot_origin
                for r in b.rows
            )
            has_exc_storm = sum(1 for r in b.rows if r.exception) > 3
            y[i] = int(has_ext_write or has_exc_storm)
    return X, y


def synthetic_attack_only(n_episodes: int = 20) -> Tuple[np.ndarray, np.ndarray]:
    """Returns a labelled attack-only dataset for threshold calibration."""
    rng = random.Random(99)
    t0  = 1_700_100_000.0
    all_rows: List[RawRow] = []
    gens = [_attack_command_injection, _attack_replay, _attack_coil_flood,
            _attack_register_scan, _attack_bulk_write]
    for i in range(n_episodes):
        all_rows.extend(gens[i % len(gens)](t0 + i * 120.0))
    all_rows.sort(key=lambda r: r.ts)
    buckets = aggregate_rows(all_rows)
    X = np.array([b.feature_vector() for b in buckets], dtype=np.float64)
    y = np.ones(len(buckets), dtype=np.int8)
    return X, y


def load_external(path: str = DEFAULT_DATASET_DIR) -> Optional[Tuple[np.ndarray, np.ndarray]]:
    """Load operator-supplied CSV dataset (HAI/SWaT slices)."""
    if not os.path.isdir(path):
        return None
    candidates = [f for f in os.listdir(path) if f.endswith(".csv")]
    if not candidates:
        return None
    rows_data: List[List[float]] = []
    labels: List[int] = []
    expected = list(FEATURE_NAMES) + ["label"]
    for fname in candidates:
        full = os.path.join(path, fname)
        try:
            with open(full, "r", newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                if reader.fieldnames is None or sorted(reader.fieldnames) != sorted(expected):
                    LOG.warning("skipping %s: schema mismatch (expected v2 features)", full)
                    continue
                for row in reader:
                    rows_data.append([float(row[f]) for f in FEATURE_NAMES])
                    labels.append(int(float(row["label"])))
        except OSError as exc:
            LOG.warning("could not read %s: %s", full, exc)
    if not rows_data:
        return None
    return np.array(rows_data, dtype=np.float64), np.array(labels, dtype=np.int8)
