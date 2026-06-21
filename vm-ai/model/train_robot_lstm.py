"""
LSTM autoencoder trainer for the robot-behavior anomaly plane.  Version ``r1``.
The robot-plane twin of ``model/train_autoencoder_tf.py``.

Architecture (WINDOW_LEN × N_CHANNELS sequence input):
  Input(T,12) → LSTM(32,seq) → LSTM(16) [latent] → RepeatVector(T)
              → LSTM(16,seq) → LSTM(32,seq) → TimeDistributed(Dense(12))

Trains on PURE-NORMAL joint dynamics only; calibrates the alert threshold as the
99th percentile of normal reconstruction error; evaluates ROC-AUC / AP on the
held-out synthetic behavioral attacks.  Also calibrates the physical-envelope
thresholds from normal data (see robot_features.calibrate_envelope).

Output artefacts (→ /opt/lab/models):
  robot_lstm.h5         the Keras LSTM autoencoder
  robot_threshold.json  channel mean/std, recon stats, p99/z thresholds, envelope
  robot_meta.json       version, architecture, ROC-AUC/AP, training provenance

All feature math is delegated to ``model.robot_features`` (anti-drift).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import numpy as np

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

from .robot_features import (
    N_CHANNELS,
    ROBOT_FEATURE_VERSION,
    SAMPLE_HZ,
    WINDOW_LEN,
    CHANNEL_NAMES,
    calibrate_envelope,
    channel_stats,
    envelope_violations,
    standardize,
)
from .robot_datasets import robot_synthetic_dataset, robot_attack_only

LOG = logging.getLogger("train_robot_lstm")
DEFAULT_MODELS_DIR = "/opt/lab/models"


def build_lstm_autoencoder(timesteps: int, channels: int, latent: int, seed: int):
    """Sequence-to-sequence LSTM autoencoder."""
    import tensorflow as tf
    from tensorflow.keras import layers, models

    tf.random.set_seed(seed)
    inp = layers.Input(shape=(timesteps, channels), name="input")
    x = layers.LSTM(32, return_sequences=True, name="enc_1")(inp)
    x = layers.LSTM(latent, return_sequences=False, name="bottleneck")(x)
    x = layers.RepeatVector(timesteps, name="repeat")(x)
    x = layers.LSTM(latent, return_sequences=True, name="dec_1")(x)
    x = layers.LSTM(32, return_sequences=True, name="dec_2")(x)
    out = layers.TimeDistributed(layers.Dense(channels), name="output")(x)
    ae = models.Model(inp, out, name="robot_lstm_autoencoder")
    ae.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3), loss="mse")
    return ae


def train_and_eval(*, baseline_minutes: int = 20, epochs: int = 60,
                   batch_size: int = 32, latent: int = 16, seed: int = 42,
                   models_dir: Optional[str] = None, save: bool = True,
                   log: logging.Logger = LOG) -> dict:
    """Train the LSTM AE on pure-normal data, calibrate, evaluate.

    Returns the meta dict (also written to robot_meta.json when ``save``).  The
    offline smoke gate calls this with ``save=False`` and small params."""
    import tensorflow as tf
    from tensorflow.keras import callbacks
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import roc_auc_score, average_precision_score

    np.random.seed(seed)
    tf.random.set_seed(seed)

    # ── 1. Pure-normal windows ───────────────────────────────────────────────
    log.info("Generating %d-min synthetic robot baseline (pure normal)...", baseline_minutes)
    X, _ = robot_synthetic_dataset(baseline_minutes=baseline_minutes,
                                   attack_episodes=0, seed=seed)
    log.info("Baseline windows: %s", X.shape)

    X_train, X_calib = train_test_split(X, test_size=0.20, random_state=seed)
    X_train, X_val = train_test_split(X_train, test_size=0.10, random_state=seed)
    log.info("Train=%d  Val=%d  Calib=%d", len(X_train), len(X_val), len(X_calib))

    # ── 2. Per-channel standardization (fit on train only) ───────────────────
    mean, std = channel_stats(X_train)
    Xtr = standardize(X_train, mean, std).astype(np.float32)
    Xva = standardize(X_val, mean, std).astype(np.float32)
    Xca = standardize(X_calib, mean, std).astype(np.float32)

    # ── 3. Build + train ─────────────────────────────────────────────────────
    ae = build_lstm_autoencoder(WINDOW_LEN, N_CHANNELS, latent, seed)
    cb = [
        callbacks.EarlyStopping(monitor="val_loss", patience=8,
                                restore_best_weights=True, verbose=0),
        callbacks.ReduceLROnPlateau(monitor="val_loss", factor=0.5,
                                    patience=4, min_lr=1e-5, verbose=0),
    ]
    hist = ae.fit(Xtr, Xtr, validation_data=(Xva, Xva), epochs=epochs,
                  batch_size=batch_size, callbacks=cb, shuffle=True, verbose=0)
    epochs_run = len(hist.history["loss"])
    best_val = float(min(hist.history["val_loss"]))
    log.info("Training complete: %d epochs, best val_loss=%.6f", epochs_run, best_val)

    def recon_err(Xs: np.ndarray) -> np.ndarray:
        pred = ae.predict(Xs, verbose=0, batch_size=128)
        return np.mean((Xs - pred) ** 2, axis=(1, 2))

    # ── 4. Calibrate threshold on held-out normal ────────────────────────────
    calib_err = recon_err(Xca)
    mean_err = float(np.mean(calib_err))
    std_err = float(np.std(calib_err) + 1e-9)
    p99_err = float(np.percentile(calib_err, 99))
    z_at_p99 = (p99_err - mean_err) / std_err
    log.info("Calib recon error: mean=%.6f std=%.6f p99=%.6f z@p99=%.2f",
             mean_err, std_err, p99_err, z_at_p99)

    # ── 5. Evaluate AUC on synthetic behavioral attacks ──────────────────────
    X_atk, y_atk = robot_attack_only(n_episodes=30, seed=seed + 1)
    Xatk = standardize(X_atk, mean, std).astype(np.float32)
    atk_err = recon_err(Xatk)
    y_eval = np.concatenate([np.zeros(len(calib_err)), y_atk])
    sc_eval = np.concatenate([(calib_err - mean_err) / std_err,
                              (atk_err - mean_err) / std_err])
    auc = float(roc_auc_score(y_eval, sc_eval))
    ap = float(average_precision_score(y_eval, sc_eval))
    detected = int((atk_err >= p99_err).sum())
    log.info("Robot LSTM eval  ROC-AUC=%.4f  AP=%.4f  LSTM-detection=%.1f%%",
             auc, ap, 100.0 * detected / max(len(atk_err), 1))

    # ── 6. Calibrate physical envelope from RAW normal train windows ─────────
    envelope = calibrate_envelope(X_train)

    # Full-system detection (LSTM OR physical envelope). The envelope adds
    # deterministic coverage for "too simple" anomalies (e.g. a frozen joint) that
    # the reconstruction AE alone misses — this is why both layers exist.
    atk_z = (atk_err - mean_err) / std_err
    combined = sum(
        1 for i in range(len(X_atk))
        if atk_z[i] >= z_at_p99 or len(envelope_violations(X_atk[i], envelope)) > 0
    )
    combined_rate = round(100.0 * combined / max(len(X_atk), 1), 1)
    log.info("Full-system detection (LSTM OR envelope) = %.1f%%", combined_rate)

    meta = {
        "feature_version": ROBOT_FEATURE_VERSION,
        "model": "LSTM-Autoencoder",
        "architecture": f"{WINDOW_LEN}x{N_CHANNELS}->32->{latent}->{latent}->32->{N_CHANNELS}",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "window_len": WINDOW_LEN,
        "n_channels": N_CHANNELS,
        "sample_hz": SAMPLE_HZ,
        "epochs_run": epochs_run,
        "best_val_loss": round(best_val, 6),
        "roc_auc": round(auc, 4),
        "average_precision": round(ap, 4),
        "detection_rate_pct": round(100.0 * detected / max(len(atk_err), 1), 1),
        "combined_detection_rate_pct": combined_rate,
        "n_train": len(X_train),
        "n_calib": len(X_calib),
        "seed": seed,
        "scoring_convention": "z = (mean_window_recon_mse - baseline_mean) / baseline_std",
    }

    if save:
        models_dir = models_dir or DEFAULT_MODELS_DIR
        os.makedirs(models_dir, exist_ok=True)
        ae.save(os.path.join(models_dir, "robot_lstm.h5"))
        threshold = {
            "feature_version": ROBOT_FEATURE_VERSION,
            "window_len": WINDOW_LEN,
            "n_channels": N_CHANNELS,
            "sample_hz": SAMPLE_HZ,
            "channels": list(CHANNEL_NAMES),
            "channel_mean": mean.tolist(),
            "channel_std": std.tolist(),
            "baseline_recon_mean": mean_err,
            "baseline_recon_std": std_err,
            "p99_threshold": p99_err,
            "z_alert_threshold": round(float(z_at_p99), 2),
            "envelope": envelope,
        }
        with open(os.path.join(models_dir, "robot_threshold.json"), "w") as fh:
            json.dump(threshold, fh, indent=2)
        with open(os.path.join(models_dir, "robot_meta.json"), "w") as fh:
            json.dump(meta, fh, indent=2)
        log.info("Saved robot_lstm.h5, robot_threshold.json, robot_meta.json → %s", models_dir)

    return meta


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--models-dir", default=DEFAULT_MODELS_DIR)
    p.add_argument("--baseline-minutes", type=int, default=20)
    p.add_argument("--epochs", type=int, default=60)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--latent", type=int, default=16)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    train_and_eval(baseline_minutes=args.baseline_minutes, epochs=args.epochs,
                   batch_size=args.batch_size, latent=args.latent, seed=args.seed,
                   models_dir=args.models_dir, save=True)
    LOG.info("Robot LSTM training complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
