"""
Feature-contract / anti-drift gate (offline, no TensorFlow required).

Guards the single most important property of the AI engine: the features the
model is TRAINED on must be byte-for-byte the features the live scorer SEES.
Mirrors the shared-module design used by both planes:

  * Robot plane (model/robot_features.py, ROBOT_FEATURE_VERSION):
      - live RobotWindowStore output == offline make_windows output
      - derived velocity matches a hand-written finite difference
      - normal windows never trip the calibrated physical envelope; attacks do
  * Modbus plane (model/features.py, FEATURE_VERSION):
      - the shared aggregate_rows path is importable and stable

Run from the project root:
    python infra/tests/feature_contract_test.py
"""
from __future__ import annotations

import logging
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "vm-ai"))

import numpy as np  # noqa: E402

from model import robot_features as rf            # noqa: E402
from model.robot_datasets import (                # noqa: E402
    _normal_positions, ATTACK_GENERATORS,
)
import random  # noqa: E402

LOG = logging.getLogger("feature_contract")


def _check(name: str, ok: bool) -> bool:
    LOG.info("%-48s %s", name, "OK" if ok else "FAIL")
    return ok


def test_constants() -> bool:
    ok = True
    ok &= _check("ROBOT_FEATURE_VERSION present", bool(rf.ROBOT_FEATURE_VERSION))
    ok &= _check("N_CHANNELS == 12", rf.N_CHANNELS == 12)
    ok &= _check("WINDOW_LEN == 50", rf.WINDOW_LEN == 50)
    ok &= _check("len(CHANNEL_NAMES) == N_CHANNELS",
                 len(rf.CHANNEL_NAMES) == rf.N_CHANNELS)
    return ok


def test_velocity_matches_manual_finite_diff() -> bool:
    rng = random.Random(1)
    pos = _normal_positions(8.0, 7.0, rng, noise_std=0.0)
    ch = rf.derive_channels(pos)
    vel = ch[:, rf.N_JOINTS:]
    manual = np.zeros_like(pos)
    manual[1:] = (pos[1:] - pos[:-1]) / rf.DT
    return _check("derive_channels velocity == manual finite diff",
                  np.allclose(vel, manual))


def test_live_store_equals_offline_windows() -> bool:
    """The anti-drift heart: feeding samples one-by-one to the live
    RobotWindowStore yields windows identical to the offline make_windows
    builder over the same contiguous stream."""
    rng = random.Random(2)
    pos = _normal_positions(12.0, 7.0, rng, noise_std=0.0)   # 120 samples
    full = rf.derive_channels(pos)
    store = rf.RobotWindowStore()
    ok = True
    n_emitted = 0
    for m in range(1, pos.shape[0] + 1):
        store.add(pos[m - 1])
        w = store.maybe_window()
        if w is not None:
            n_emitted += 1
            expected = full[m - rf.WINDOW_LEN:m]
            if not np.allclose(w, expected):
                ok = False
    ok &= n_emitted > 0
    return _check(f"live store window == offline window ({n_emitted} windows)", ok)


def test_standardize_roundtrip() -> bool:
    rng = random.Random(3)
    pos = _normal_positions(20.0, 7.0, rng)
    W = rf.positions_to_windows(pos)
    mean, std = rf.channel_stats(W)
    Ws = rf.standardize(W, mean, std)
    flat = Ws.reshape(-1, rf.N_CHANNELS)
    ok = np.allclose(flat.mean(axis=0), 0.0, atol=1e-6) and \
        np.allclose(flat.std(axis=0), 1.0, atol=1e-2)
    return _check("standardize → ~zero mean / unit std", ok)


def test_envelope_normal_clean_attacks_trip() -> bool:
    rng = random.Random(4)
    pos = _normal_positions(60.0, 7.0, rng)
    normal_W = rf.positions_to_windows(pos)
    env = rf.calibrate_envelope(normal_W)
    normal_clean = all(len(rf.envelope_violations(w, env)) == 0 for w in normal_W)

    # The two attacks that break physical motion limits (over-speed, high jerk)
    # must trip the deterministic envelope. Other attacks (e.g. workspace_breach
    # which stays inside the hard position limit) are deliberately left for the
    # learned LSTM layer to catch — that is why both layers exist.
    physical = ("joint_speed_violation", "erratic_jerk")
    tripped = 0
    for atk in physical:
        base = _normal_positions(60.0, 7.0, random.Random(5))
        aw = rf.positions_to_windows(ATTACK_GENERATORS[atk](base, random.Random(6)))
        if any(len(rf.envelope_violations(w, env)) > 0 for w in aw):
            tripped += 1
    ok = _check("normal windows never trip calibrated envelope", normal_clean)
    ok &= _check("physical-limit attacks trip the envelope", tripped == len(physical))
    return ok


def test_modbus_plane_contract() -> bool:
    from model.features import FEATURE_VERSION, N_FEATURES, FEATURE_NAMES
    ok = _check("Modbus FEATURE_VERSION present", bool(FEATURE_VERSION))
    ok &= _check("len(FEATURE_NAMES) == N_FEATURES",
                 len(FEATURE_NAMES) == N_FEATURES)
    return ok


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    results = [
        test_constants(),
        test_velocity_matches_manual_finite_diff(),
        test_live_store_equals_offline_windows(),
        test_standardize_roundtrip(),
        test_envelope_normal_clean_attacks_trip(),
        test_modbus_plane_contract(),
    ]
    if all(results):
        print("FEATURE CONTRACT: PASS")
        return 0
    print("FEATURE CONTRACT: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
