"""
Synthetic robot-dynamics dataset generator for the robot-behavior anomaly plane.
Version ``r1``.  The robot-plane twin of ``model/datasets.py``.

Generates realistic 6-DoF pick-and-place joint trajectories for training and
evaluation.  Normal motion is produced with the **exact same** 5 waypoints and
cosine interpolation as ``vm-ot/gazebo/cyclic_motion.py`` so the model trains on
the same dynamics the live robot exhibits.  Cycle time is randomised in the
6–8 s range so the model generalises across the Gazebo (8 s) and headless
fallback (6 s) paths.

Normal:
  - 5-waypoint pick-and-place loop, cosine-interpolated, small sensor noise.

Behavioral attacks (label=1; eval/calibration only — NEVER in training):
  1. joint_speed_violation  — one joint driven far faster than normal
  2. trajectory_deviation   — one joint pushed outside its normal range
  3. frozen_joint           — one joint stuck (sensor freeze / actuator fault)
  4. erratic_jerk           — high-frequency position noise (control instability)
  5. workspace_breach       — j1 driven toward the closed fence side (envelope)

All feature math is delegated to ``model.robot_features`` (positions →
windows) so this module owns NO feature logic — anti-drift.
"""
from __future__ import annotations

import logging
import math
import random
from typing import List, Tuple

import numpy as np

from .robot_features import (
    N_JOINTS,
    SAMPLE_HZ,
    WINDOW_STRIDE,
    positions_to_windows,
)

LOG = logging.getLogger(__name__)

# ── trajectory definition — MUST stay in sync with cyclic_motion.py ───────────
# (kept as a local copy because cyclic_motion imports rclpy, which is not present
#  in the AI container; if the waypoints there change, mirror them here and bump
#  ROBOT_FEATURE_VERSION.)
WAYPOINTS: List[List[float]] = [
    [0.0,      0.0,   0.0,  0.0,  0.0, 0.0],   # home
    [1.5708,  -0.5,  -1.0,  0.0,  0.5, 0.0],   # above pick
    [1.5708,  -0.7,  -1.4,  0.0,  0.7, 0.0],   # pick
    [-1.5708, -0.5,  -1.0,  0.0,  0.5, 0.0],   # above drop
    [-1.5708, -0.7,  -1.4,  0.0,  0.7, 0.0],   # drop
]
N_SEG = len(WAYPOINTS)
POS_NOISE_STD = 0.004   # rad — gentle joint-encoder noise
# The live tap decimates by wall clock (not a perfect 10 Hz), so the finite-
# difference velocity/jerk carry timing jitter. Model the same jitter here so the
# calibrated envelope and the LSTM reflect real acquisition conditions (anti-drift).
JITTER_FRAC = 0.15


def _smooth_interp(a: List[float], b: List[float], t: float) -> List[float]:
    """Cosine interpolation in [0,1] — identical to cyclic_motion.smooth_interp."""
    s = 0.5 - 0.5 * math.cos(math.pi * max(0.0, min(1.0, t)))
    return [ai + (bi - ai) * s for ai, bi in zip(a, b)]


def _normal_positions(seconds: float, cycle_s: float, rng: random.Random,
                      noise_std: float = POS_NOISE_STD) -> np.ndarray:
    """Generate a contiguous (N, 6) normal joint-angle stream at SAMPLE_HZ."""
    n = int(round(seconds * SAMPLE_HZ))
    out = np.zeros((n, N_JOINTS), dtype=np.float64)
    t = 0.0
    period = 1.0 / SAMPLE_HZ
    for k in range(n):
        seg_t = (t % cycle_s) / cycle_s * N_SEG
        i = int(seg_t)
        frac = seg_t - i
        a = WAYPOINTS[i % N_SEG]
        b = WAYPOINTS[(i + 1) % N_SEG]
        out[k] = _smooth_interp(a, b, frac)
        # advance by a jittered interval (the consumer derives velocity assuming a
        # fixed DT, so jittered advance ⇒ realistic velocity/jerk noise)
        t += period * max(0.3, 1.0 + rng.gauss(0.0, JITTER_FRAC))
    if noise_std > 0:
        out += rng_normal(rng, noise_std, out.shape)
    return out


def rng_normal(rng: random.Random, std: float, shape) -> np.ndarray:
    """Gaussian noise from a seeded ``random.Random`` (keeps everything seeded)."""
    n = int(np.prod(shape))
    vals = np.array([rng.gauss(0.0, std) for _ in range(n)], dtype=np.float64)
    return vals.reshape(shape)


# ─── attack perturbations (operate on a normal positions stream) ─────────────

def _attack_joint_speed_violation(pos: np.ndarray, rng: random.Random) -> np.ndarray:
    """Drive one joint ~3x faster (sharp triangle sweeps) → velocity far above normal."""
    p = pos.copy()
    j = rng.randrange(N_JOINTS)
    n = p.shape[0]
    amp = rng.uniform(1.2, 2.0)
    freq = rng.uniform(1.2, 2.2)   # Hz — well above the ~0.15 Hz normal cycle
    t = np.arange(n) / SAMPLE_HZ
    p[:, j] = amp * np.sin(2 * math.pi * freq * t)
    return p


def _attack_trajectory_deviation(pos: np.ndarray, rng: random.Random) -> np.ndarray:
    """Add a sustained offset that pushes one joint outside its normal range."""
    p = pos.copy()
    j = rng.randrange(N_JOINTS)
    offset = rng.choice([-1.0, 1.0]) * rng.uniform(1.2, 2.2)
    p[:, j] = p[:, j] + offset
    return p


def _attack_frozen_joint(pos: np.ndarray, rng: random.Random) -> np.ndarray:
    """Freeze one normally-moving joint while the others keep moving.

    j4 (idx 3) and j6 (idx 5) are always 0 in the trajectory, so freezing them
    would be a no-op — pick from the joints that actually move (j1,j2,j3,j5)."""
    p = pos.copy()
    j = rng.choice([0, 1, 2, 4])
    p[:, j] = p[0, j]
    return p


def _attack_erratic_jerk(pos: np.ndarray, rng: random.Random) -> np.ndarray:
    """Inject high-frequency position noise on one joint → large jerk / unstable."""
    p = pos.copy()
    j = rng.randrange(N_JOINTS)
    p[:, j] = p[:, j] + rng_normal(rng, rng.uniform(0.10, 0.20), p.shape[0])
    return p


def _attack_workspace_breach(pos: np.ndarray, rng: random.Random) -> np.ndarray:
    """Drive j1 toward the closed (south) fence side, near the physical limit."""
    p = pos.copy()
    target = rng.uniform(2.7, 3.0)   # approaching the +3.14 URDF limit
    p[:, 0] = target
    return p


ATTACK_GENERATORS = {
    "joint_speed_violation": _attack_joint_speed_violation,
    "trajectory_deviation": _attack_trajectory_deviation,
    "frozen_joint": _attack_frozen_joint,
    "erratic_jerk": _attack_erratic_jerk,
    "workspace_breach": _attack_workspace_breach,
}
ATTACK_TYPES: Tuple[str, ...] = tuple(ATTACK_GENERATORS.keys())


# ─── dataset builders (mirror datasets.py API) ───────────────────────────────

def robot_synthetic_dataset(*, baseline_minutes: int = 20,
                            attack_episodes: int = 0,
                            seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Returns (X, y) where X is (n_windows, WINDOW_LEN, N_CHANNELS).

    For production LSTM training always use attack_episodes=0 (pure normal)."""
    rng = random.Random(seed)
    episode_s = 60.0
    n_normal_eps = max(1, int(round(baseline_minutes * 60.0 / episode_s)))

    windows: List[np.ndarray] = []
    labels: List[int] = []

    for _ in range(n_normal_eps):
        cycle_s = rng.uniform(6.0, 8.0)
        pos = _normal_positions(episode_s, cycle_s, rng)
        w = positions_to_windows(pos, stride=WINDOW_STRIDE)
        windows.append(w)
        labels.extend([0] * len(w))

    if attack_episodes > 0:
        for i in range(attack_episodes):
            atk = ATTACK_TYPES[i % len(ATTACK_TYPES)]
            cycle_s = rng.uniform(6.0, 8.0)
            base = _normal_positions(episode_s, cycle_s, rng)
            pos = ATTACK_GENERATORS[atk](base, rng)
            w = positions_to_windows(pos, stride=WINDOW_STRIDE)
            windows.append(w)
            labels.extend([1] * len(w))

    X = np.concatenate(windows, axis=0)
    y = np.array(labels, dtype=np.int8)
    return X, y


def robot_attack_only(n_episodes: int = 20,
                      seed: int = 99) -> Tuple[np.ndarray, np.ndarray]:
    """Labelled attack-only windows for AUC evaluation / threshold calibration."""
    rng = random.Random(seed)
    episode_s = 60.0
    windows: List[np.ndarray] = []
    for i in range(n_episodes):
        atk = ATTACK_TYPES[i % len(ATTACK_TYPES)]
        cycle_s = rng.uniform(6.0, 8.0)
        base = _normal_positions(episode_s, cycle_s, rng)
        pos = ATTACK_GENERATORS[atk](base, rng)
        windows.append(positions_to_windows(pos, stride=WINDOW_STRIDE))
    X = np.concatenate(windows, axis=0)
    y = np.ones(len(X), dtype=np.int8)
    return X, y
