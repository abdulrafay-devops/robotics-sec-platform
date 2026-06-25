#!/usr/bin/env python3
"""Re-baseline the robot-behavior LSTM anomaly threshold against the LIVE arm.

The robot LSTM autoencoder + its z threshold were calibrated once at training
time. If the live joint motion drifts from that baseline — e.g. after a host
sleep/resume the Gazebo sim runs slightly differently, or the joint-stream tap
timing changes — the reconstruction error on NORMAL motion rises and the
(too-tight) z threshold trips false anomalies with no attack present.

This replays recent LIVE *normal* robot windows through the SAME resampling
windowing + LSTM the consumer uses (robot_consumer._read_positions /
_latest_window / RobotScorer.score), measures the reconstruction-error
distribution on clean (active, no envelope breach) motion, and rewrites
baseline_recon_mean / baseline_recon_std / p99 / z_alert_threshold so a normal
window stays comfortably below the alert line while a real attack still fires.

This is the robot-plane mirror of model.recalibrate_live_thresholds (network
plane) and uses the identical z_alert convention: above the worst normal window
by a margin, never below 4 sigma.

Run inside container-ai:
  PYTHONPATH=/opt/lab/vm-ai /opt/lab/venv-ai/bin/python \
      -m model.recalibrate_robot_threshold [--seconds 90]
Then restart robot_consumer to load the new threshold.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time

import numpy as np

sys.path.insert(0, "/opt/lab/vm-ai")
import robot_consumer as rc  # noqa: E402
from model.robot_features import (  # noqa: E402
    FROZEN_MIN_TYPICAL, FROZEN_RATIO, N_JOINTS,
)

MODELS_DIR = os.environ.get("LAB_MODELS_DIR", "/opt/lab/models")
THR_PATH = os.path.join(MODELS_DIR, "robot_threshold.json")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--seconds", type=float, default=90.0,
                    help="how long to sample live normal motion")
    ap.add_argument("--min-windows", type=int, default=20)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    scorer = rc.RobotScorer(MODELS_DIR)
    if not scorer.ready:
        print("ERROR: robot model/threshold not loaded")
        return 2

    print(f"sampling live normal robot motion for ~{a.seconds:.0f}s "
          f"(current z_alert={scorer.z_alert:.2f}) ...")
    errs: list[float] = []
    stds: list[np.ndarray] = []
    t_end = time.time() + a.seconds
    while time.time() < t_end:
        pos, ts, mtime = rc._read_positions(rc.STREAM_FILE)
        win = rc._latest_window(pos, ts) if pos is not None else None
        if win is not None:
            res = scorer.score(win)
            if not res.get("idle"):
                # Per-joint position std of every ACTIVE window (incl. ones that
                # currently trip the frozen rule) — this captures how low a
                # normally-moving joint's std legitimately dips at turnarounds,
                # so we can set the frozen floor below the true normal minimum.
                w = np.asarray(win, dtype=np.float64)
                stds.append(np.std(w[:, :N_JOINTS], axis=0))
                # LSTM recon baseline: clean windows only (exclude physical
                # envelope breaches — those are genuine, not baseline drift).
                if not res.get("envelope_hits"):
                    errs.append(float(res["recon_error"]))
        time.sleep(1.0)

    e = np.asarray(errs, dtype=float)
    print(f"clean active normal windows collected: {e.size}")
    if e.size < a.min_windows:
        print("ERROR: too few clean windows; let the arm run longer and retry.")
        return 2

    mean = float(e.mean())
    std = float(max(e.std(), 1e-9))
    z = (e - mean) / std
    # Alert line: above the worst normal window by a 1-sigma margin, never below
    # 4 sigma — identical rule to recalibrate_live_thresholds.py.
    z_alert = float(max(4.0, math.ceil(z.max()) + 1.0))
    print(f"recon err mean={mean:.6f} std={std:.6f} "
          f"max_baseline_z={z.max():.2f} -> z_alert={z_alert:.2f}")
    if a.dry_run:
        print("dry-run: threshold NOT written.")
        return 0

    with open(THR_PATH, "r", encoding="utf-8") as fh:
        thr = json.load(fh)
    thr["baseline_recon_mean"] = mean
    thr["baseline_recon_std"] = std
    thr["p99_threshold"] = float(np.percentile(e, 99))
    thr["z_alert_threshold"] = z_alert
    thr["recalibrated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    thr["recalibrated_on"] = f"live-robot-baseline:{e.size}w"

    # Re-baseline the frozen-joint envelope floor to the LIVE arm. The frozen
    # check flags a joint when its window std drops below FROZEN_RATIO*typical;
    # if a normally-moving joint legitimately dwells at a turnaround the trained
    # `typical` (a mean) makes that floor too high and trips a false "frozen".
    # We lower `pos_std_typical` only where needed so the floor sits safely below
    # the joint's true normal minimum std (a real freeze drives std -> 0, well
    # under the floor, and the LSTM also flags it).
    env = thr.get("envelope") or {}
    old_typ = env.get("pos_std_typical")
    if old_typ is not None and stds:
        S = np.asarray(stds, dtype=np.float64)            # (n_windows, N_JOINTS)
        min_std = S.min(axis=0)                            # natural per-joint min
        old_typ = np.asarray(old_typ, dtype=np.float64)
        desired = (0.6 * min_std) / max(FROZEN_RATIO, 1e-9)  # floor = 0.6*min
        new_typ = np.minimum(old_typ, desired)
        # never raise the floor for already-exempt joints (typical < min)
        new_typ = np.where(old_typ < FROZEN_MIN_TYPICAL, old_typ, new_typ)
        env["pos_std_typical"] = [float(x) for x in new_typ]
        thr["envelope"] = env
        lowered = [JN for JN, a_, b_ in
                   zip(range(N_JOINTS), old_typ, new_typ) if b_ < a_ - 1e-9]
        print(f"  frozen floor re-baselined (lowered joints idx={lowered}); "
              f"new pos_std_typical={[round(float(x),3) for x in new_typ]}")

    with open(THR_PATH, "w", encoding="utf-8") as fh:
        json.dump(thr, fh, indent=2)
    print(f"  -> robot_threshold.json: mean={mean:.6f} std={std:.6f} "
          f"z_alert={z_alert:.2f}")
    print("done. restart robot_consumer to load the new threshold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
