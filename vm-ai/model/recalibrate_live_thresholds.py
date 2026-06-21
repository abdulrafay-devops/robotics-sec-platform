#!/usr/bin/env python3
"""
Recalibrate the autoencoder anomaly thresholds against the LIVE baseline.

The PCA/TF autoencoders were calibrated on the *synthetic* dataset, whose Modbus
message shape (volume, multi-row-per-transaction, inter-arrival burstiness) does
not match what the live Zeek pipeline emits. Result: the autoencoders reconstruct
normal live traffic poorly, so tf_z/pca_z sit high on a normal baseline and trip
false anomalies. The IsolationForest is robust and is left untouched.

This tool replays recent live baseline windows through the SAME feature code,
scaler, and AE models the consumer uses, measures each AE's reconstruction-error
distribution on *normal* traffic, and rewrites baseline_recon_mean/std + p99 +
z_alert_threshold so:
  * a normal window stays comfortably below the alert line (no false positive), and
  * a real attack (reconstruction error 1000x+ higher) still fires hard.

Run inside container-ai (needs model.features on PYTHONPATH + the AI venv):
  PYTHONPATH=/opt/lab/vm-ai /opt/lab/venv-ai/bin/python \
      -m model.recalibrate_live_thresholds --log /var/lab/sec-log/zeek/current/modbus_features.log
"""
from __future__ import annotations

import argparse
import json
import os
import time

import joblib
import numpy as np

from model.features import FEATURE_NAMES, RawRow, WindowStore

MODELS_DIR = os.environ.get("LAB_MODELS_DIR", "/opt/lab/models")


def _load_windows(log_path: str, recent_s: float, min_msgs: int):
    with open(log_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()[-20000:]
    rows = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(RawRow.from_dict(json.loads(ln)))
        except Exception:  # noqa: BLE001
            pass
    if not rows:
        return []
    # keep only the most recent `recent_s` of traffic (post rate-revert, clean)
    tmax = max(r.ts for r in rows)
    rows = [r for r in rows if r.ts >= tmax - recent_s]
    store = WindowStore(grace_seconds=2.0)
    for r in rows:
        store.add(r)
    buckets = list(store.flush_until(time.time() + 3600))
    return [b for b in buckets if len(b.rows) >= min_msgs]


def _is_clean(vec: np.ndarray) -> bool:
    """Drop any window that looks attack-ish, so calibration uses normal traffic only."""
    f = {n: vec[i] for i, n in enumerate(FEATURE_NAMES)}
    if f.get("n_writes", 0) > 1:            return False   # baseline is read-only
    if f.get("n_exceptions", 0) > 0:        return False
    if f.get("n_external_writes", 0) > 0:   return False
    if f.get("write_ratio", 0) > 0.05:      return False
    if f.get("msg_rate", 0) > 30:           return False   # flood
    return True


def _pca_errs(scaler, pca, vecs):
    out = []
    for v in vecs:
        xs = scaler.transform(v.reshape(1, -1))
        recon = pca.inverse_transform(pca.transform(xs))
        out.append(float(((xs - recon) ** 2).mean()))
    return np.asarray(out)


def _tf_errs(scaler, tf_model, vecs):
    out = []
    for v in vecs:
        xs = scaler.transform(v.reshape(1, -1)).astype(np.float32)
        recon = tf_model(xs, training=False).numpy()
        out.append(float(np.mean((xs - recon) ** 2)))
    return np.asarray(out)


def _rewrite(path: str, errs: np.ndarray, n_windows: int) -> None:
    with open(path, "r", encoding="utf-8") as fh:
        thr = json.load(fh)
    mean = float(errs.mean())
    std = float(max(errs.std(), 1e-6))
    z = (errs - mean) / std
    # alert line: above the worst normal window by a margin, but never below 4 sigma
    z_alert = float(max(4.0, np.ceil(z.max()) + 1.0))
    thr["baseline_recon_mean"] = mean
    thr["baseline_recon_std"] = std
    thr["p99_threshold"] = float(np.percentile(errs, 99))
    thr["z_alert_threshold"] = z_alert
    thr["recalibrated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    thr["recalibrated_on"] = f"live-baseline:{n_windows}w"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(thr, fh, indent=2)
    print(f"  -> {os.path.basename(path)}: mean={mean:.5f} std={std:.5f} "
          f"max_baseline_z={z.max():.2f} z_alert={z_alert:.2f}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--log", default="/var/lab/sec-log/zeek/current/modbus_features.log")
    ap.add_argument("--recent-s", type=float, default=180.0)
    ap.add_argument("--min-msgs", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    buckets = _load_windows(a.log, a.recent_s, a.min_msgs)
    vecs = [np.asarray(b.feature_vector(), dtype=float) for b in buckets]
    vecs = [v for v in vecs if _is_clean(v)]
    print(f"clean baseline windows for calibration: {len(vecs)} (from {len(buckets)} total)")
    if len(vecs) < 10:
        print("ERROR: too few clean windows; let the baseline run longer and retry.")
        return 2

    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    pca = joblib.load(os.path.join(MODELS_DIR, "pca.pkl"))
    import tensorflow as tf
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
    tf_model = tf.keras.models.load_model(os.path.join(MODELS_DIR, "autoencoder.h5"), compile=False)

    pca_e = _pca_errs(scaler, pca, vecs)
    tf_e = _tf_errs(scaler, tf_model, vecs)
    print(f"PCA recon err: mean={pca_e.mean():.5f} max={pca_e.max():.5f}")
    print(f"TF  recon err: mean={tf_e.mean():.5f} max={tf_e.max():.5f}")
    if a.dry_run:
        print("dry-run: thresholds NOT written.")
        return 0

    print("rewriting thresholds:")
    _rewrite(os.path.join(MODELS_DIR, "pca_threshold.json"), pca_e, len(vecs))
    _rewrite(os.path.join(MODELS_DIR, "tf_threshold.json"), tf_e, len(vecs))
    print("done. restart the feature_consumer to load the new thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
