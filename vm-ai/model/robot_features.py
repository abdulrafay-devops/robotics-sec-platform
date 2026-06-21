"""
Canonical robot-dynamics feature engineering for the robot-behavior anomaly
plane.  Version ``r1``.

This is the robot-plane twin of ``model/features.py``.  It is the SINGLE place
that turns a raw joint-position stream into the ``(WINDOW_LEN, N_CHANNELS)``
tensors the LSTM autoencoder consumes.  Both the trainer
(``model/train_robot_lstm.py``) and the live scorer (``robot_consumer.py``)
import these symbols, so the model and the live scorer can never disagree on the
feature space.  Any change here REQUIRES retraining and bumping
``ROBOT_FEATURE_VERSION``.

Anti-drift design (mirrors the proven Modbus plane in ``features.py``):
  * **Positions are the only raw input.**  Joint *velocities* are DERIVED here by
    finite difference at ``SAMPLE_HZ`` so training and inference compute them with
    identical code.  The OT-side telemetry tap therefore emits raw joint angles
    only and carries no feature logic that could drift from the model.
  * A fixed ``SAMPLE_HZ`` (the tap decimates to it) means a 40 Hz Gazebo stream and
    a 10 Hz headless-fallback stream yield identical windows.
  * Channel layout, window length, scaling helpers and the physical-envelope rules
    all live here behind ``ROBOT_FEATURE_VERSION``.

Channels (``N_CHANNELS = 12``):
    j1_pos .. j6_pos   joint angle (rad)
    j1_vel .. j6_vel   joint angular velocity (rad/s) — finite diff of position
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

ROBOT_FEATURE_VERSION = "r1"

JOINT_NAMES: Tuple[str, ...] = ("j1", "j2", "j3", "j4", "j5", "j6")
N_JOINTS = len(JOINT_NAMES)

SAMPLE_HZ = 10.0
DT = 1.0 / SAMPLE_HZ
WINDOW_LEN = 50          # 5.0 s at 10 Hz — roughly one motion phase
WINDOW_STRIDE = 10       # 1.0 s hop between consecutive windows

CHANNEL_NAMES: Tuple[str, ...] = tuple(
    [f"{j}_pos" for j in JOINT_NAMES] + [f"{j}_vel" for j in JOINT_NAMES]
)
N_CHANNELS = len(CHANNEL_NAMES)   # 12

# URDF joint limits (vm-ot/gazebo/robot.urdf <limit>).  Position limits are HARD
# physical ceilings — the scripted normal trajectory stays well inside them, so a
# position outside this band is unambiguously a fault.  Velocity limits are kept
# for reference only: the cosine trajectory can momentarily exceed the URDF
# velocity limit on the big j1 swing, so the live velocity envelope is CALIBRATED
# from normal data at train time (see ``calibrate_envelope``), not taken here.
URDF_POS_LIMIT = np.array([3.14, 1.8, 2.6, 3.14, 1.9, 3.14], dtype=np.float64)
URDF_VEL_LIMIT = np.array([2.0, 2.0, 2.5, 3.0, 3.0, 3.5], dtype=np.float64)

# Frozen-joint detection (a sensor-freeze / actuator-fault leaves one joint static
# while the arm is otherwise moving — a "too simple" anomaly the reconstruction AE
# does not catch).  A joint is flagged frozen only when the arm is active.
MOTION_ACTIVE_THRESH = 0.10   # rad — arm is "moving" if any joint's window std exceeds this
FROZEN_MIN_TYPICAL = 0.05     # rad — only joints that NORMALLY move are frozen-checked (exempts j4/j6)
FROZEN_RATIO = 0.10           # flag if current window std < 10% of the joint's typical std


# ─── raw input ───────────────────────────────────────────────────────────────

@dataclass
class RawJointRow:
    """One decimated joint sample emitted by the OT telemetry tap.

    Only ``position`` is consumed for features — velocity/effort published by the
    robot are intentionally ignored and re-derived in ``derive_channels`` so the
    train and serve paths use one code path (anti-drift)."""

    ts: float
    position: List[float]

    @classmethod
    def from_dict(cls, d: Dict) -> "RawJointRow":
        pos = d.get("position") or d.get("positions") or []
        return cls(
            ts=float(d.get("ts", 0.0) or 0.0),
            position=[float(x) for x in list(pos)[:N_JOINTS]],
        )


# ─── feature construction (the single source of truth) ───────────────────────

def derive_channels(positions: np.ndarray) -> np.ndarray:
    """``(N, 6)`` joint angles → ``(N, 12)`` [position | velocity] channel matrix.

    Velocity is a finite difference at ``SAMPLE_HZ``; the first sample's velocity
    is 0 (matches ``cyclic_motion.py`` which seeds velocities at 0 on its first
    tick).  Computing velocity over a *contiguous* stream before windowing is what
    keeps live windows identical to training windows."""
    positions = np.asarray(positions, dtype=np.float64)
    if positions.ndim != 2 or positions.shape[1] != N_JOINTS:
        raise ValueError(f"positions must be (N,{N_JOINTS}); got {positions.shape}")
    vel = np.zeros_like(positions)
    if positions.shape[0] > 1:
        vel[1:] = (positions[1:] - positions[:-1]) / DT
    return np.concatenate([positions, vel], axis=1)


def make_windows(channels: np.ndarray,
                 window_len: int = WINDOW_LEN,
                 stride: int = WINDOW_STRIDE) -> np.ndarray:
    """``(N, C)`` channel matrix → ``(n_windows, window_len, C)`` tensor."""
    channels = np.asarray(channels, dtype=np.float64)
    n, c = channels.shape
    if n < window_len:
        return np.empty((0, window_len, c), dtype=np.float64)
    starts = range(0, n - window_len + 1, stride)
    return np.stack([channels[i:i + window_len] for i in starts], axis=0)


def positions_to_windows(positions: np.ndarray,
                         stride: int = WINDOW_STRIDE) -> np.ndarray:
    """Convenience: raw ``(N,6)`` positions → ``(n_windows, WINDOW_LEN, 12)``."""
    return make_windows(derive_channels(positions), WINDOW_LEN, stride)


class RobotWindowStore:
    """Online windowing for the live scorer (``robot_consumer.py``).

    Keeps a short rolling buffer of raw positions and emits a finished
    ``(WINDOW_LEN, N_CHANNELS)`` window every ``stride`` new samples.  Velocity is
    derived over the *whole buffer* and the last ``WINDOW_LEN`` rows are returned,
    so the emitted window's leading velocity uses the prior sample exactly as an
    interior ``make_windows`` window would — i.e. the live window is byte-for-byte
    what training saw (anti-drift)."""

    def __init__(self, window_len: int = WINDOW_LEN, stride: int = WINDOW_STRIDE) -> None:
        self.window_len = window_len
        self.stride = stride
        # +1 extra sample of history so the window's first velocity is real.
        self._buf: deque = deque(maxlen=window_len + stride + 1)
        self._new = 0

    def add(self, position: Sequence[float]) -> None:
        self._buf.append([float(x) for x in list(position)[:N_JOINTS]])
        self._new += 1

    def maybe_window(self) -> Optional[np.ndarray]:
        if len(self._buf) >= self.window_len and self._new >= self.stride:
            self._new = 0
            ch = derive_channels(np.asarray(self._buf, dtype=np.float64))
            return ch[-self.window_len:].copy()
        return None


# ─── scaling (per-channel; stored in robot_threshold.json, no pickle needed) ──

def channel_stats(windows: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Per-channel mean/std over all timesteps of all windows."""
    flat = np.asarray(windows, dtype=np.float64).reshape(-1, N_CHANNELS)
    mean = flat.mean(axis=0)
    std = flat.std(axis=0) + 1e-8
    return mean, std


def standardize(window: np.ndarray, mean, std) -> np.ndarray:
    """Apply stored per-channel mean/std. Same code on train and serve paths."""
    return (np.asarray(window, dtype=np.float64) - np.asarray(mean, dtype=np.float64)) \
        / np.asarray(std, dtype=np.float64)


# ─── reconstruction scoring helpers ──────────────────────────────────────────

def recon_error(x: np.ndarray, recon: np.ndarray) -> float:
    """Mean squared reconstruction error over a (T, C) window."""
    x = np.asarray(x, dtype=np.float64)
    recon = np.asarray(recon, dtype=np.float64)
    return float(np.mean((x - recon) ** 2))


def top_channels(x: np.ndarray, recon: np.ndarray, k: int = 3) -> List[str]:
    """Names of the channels with the largest reconstruction error (explainability)."""
    x = np.asarray(x, dtype=np.float64)
    recon = np.asarray(recon, dtype=np.float64)
    per = np.mean((x - recon) ** 2, axis=0)   # (C,)
    idx = np.argsort(-per)[:k]
    return [CHANNEL_NAMES[i] for i in idx]


# ─── physical-envelope rule layer (deterministic, explainable) ───────────────

def calibrate_envelope(normal_windows: np.ndarray,
                       vel_margin: float = 2.0,
                       accel_margin: float = 3.0) -> Dict[str, list]:
    """Derive per-joint envelope thresholds from NORMAL training windows.

    Position bounds are the URDF hard limits (normal stays well inside them).
    Velocity/acceleration bounds are calibrated from observed normal motion times
    a safety margin, because the scripted normal trajectory itself runs fast — so
    a fixed URDF velocity limit would false-positive.  Stored in
    robot_threshold.json and consumed by ``envelope_violations``."""
    W = np.asarray(normal_windows, dtype=np.float64)
    vel = W[..., N_JOINTS:2 * N_JOINTS].reshape(-1, N_JOINTS)
    accel_seq = np.diff(W[..., N_JOINTS:2 * N_JOINTS], axis=1) / DT
    accel = accel_seq.reshape(-1, N_JOINTS) if accel_seq.size else np.zeros((1, N_JOINTS))
    vel_abs = np.max(np.abs(vel), axis=0) * vel_margin
    accel_abs = np.max(np.abs(accel), axis=0) * accel_margin
    # Typical per-window position spread for each joint (median over normal
    # windows) — the baseline the frozen-joint check compares against.
    per_window_pos_std = np.std(W[..., :N_JOINTS], axis=1)   # (n_windows, N_JOINTS)
    pos_std_typical = np.median(per_window_pos_std, axis=0)
    return {
        "pos_lo": (-URDF_POS_LIMIT).tolist(),
        "pos_hi": (URDF_POS_LIMIT).tolist(),
        "vel_abs": vel_abs.tolist(),
        "accel_abs": accel_abs.tolist(),
        "pos_std_typical": pos_std_typical.tolist(),
    }


def envelope_violations(window: np.ndarray, env: Dict[str, list]) -> List[str]:
    """Deterministic physical-limit checks on a (T, C) window.

    Returns a list of human-readable violation tags (empty == within envelope)."""
    W = np.asarray(window, dtype=np.float64)
    pos = W[:, :N_JOINTS]
    vel = W[:, N_JOINTS:2 * N_JOINTS]
    accel = np.diff(vel, axis=0) / DT if W.shape[0] > 1 else np.zeros((1, N_JOINTS))
    pos_lo = np.asarray(env["pos_lo"], dtype=np.float64)
    pos_hi = np.asarray(env["pos_hi"], dtype=np.float64)
    vel_abs = np.asarray(env["vel_abs"], dtype=np.float64)
    accel_abs = np.asarray(env["accel_abs"], dtype=np.float64)
    out: List[str] = []
    for j, name in enumerate(JOINT_NAMES):
        if np.any(pos[:, j] < pos_lo[j]) or np.any(pos[:, j] > pos_hi[j]):
            out.append(f"{name}_pos_out_of_range")
        if np.any(np.abs(vel[:, j]) > vel_abs[j]):
            out.append(f"{name}_vel_over_limit")
        if accel.size and np.any(np.abs(accel[:, j]) > accel_abs[j]):
            out.append(f"{name}_jerk_spike")

    # Frozen-joint check: a normally-moving joint that goes nearly static while
    # the arm is otherwise active. Skipped when the whole arm is static, so a
    # legitimate halt / E-stop does not raise a false alarm.
    typical = env.get("pos_std_typical")
    if typical is not None:
        typical = np.asarray(typical, dtype=np.float64)
        cur_std = np.std(pos, axis=0)   # (N_JOINTS,)
        if float(np.max(cur_std)) > MOTION_ACTIVE_THRESH:   # arm is moving
            for j, name in enumerate(JOINT_NAMES):
                if typical[j] > FROZEN_MIN_TYPICAL and cur_std[j] < FROZEN_RATIO * typical[j]:
                    out.append(f"{name}_frozen")
    return out
