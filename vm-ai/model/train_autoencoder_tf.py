"""
Production-grade TensorFlow Dense Autoencoder for Stage 2 OT anomaly detection.

Architecture (20-feature input):
  Input(20) → Dense(32,relu)+BN → Dense(16,relu)+BN → Bottleneck Dense(6,relu)
            → Dense(16,relu)+BN → Dense(32,relu)+BN → Output Dense(20,linear)

Improvements over v1:
  - Deeper encoder/decoder with BatchNormalization for stable training
  - Dropout(0.05) on encoder to prevent feature memorization
  - EarlyStopping(patience=15) + ReduceLROnPlateau for automatic convergence
  - 200 epochs max (stops early, typically at ~60-80)
  - Threshold = 99th-percentile of calibration reconstruction error
  - AUC evaluated on synthetic attacks

Output artefacts: autoencoder.h5, tf_threshold.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import tensorflow as tf
from tensorflow.keras import layers, models, callbacks, regularizers

from .datasets import synthetic_dataset, synthetic_attack_only
from .features import FEATURE_NAMES, FEATURE_VERSION, N_FEATURES

LOG = logging.getLogger("train_autoencoder_tf")
DEFAULT_MODELS_DIR = "/opt/lab/models"


def build_autoencoder(input_dim: int, bottleneck: int, seed: int) -> models.Model:
    """Production deep autoencoder with BatchNorm and Dropout."""
    tf.random.set_seed(seed)

    inp = layers.Input(shape=(input_dim,), name="input")

    # Encoder
    x = layers.Dense(32, kernel_regularizer=regularizers.l2(1e-4),
                      name="enc_1")(inp)
    x = layers.BatchNormalization(name="bn_1")(x)
    x = layers.Activation("relu")(x)
    x = layers.Dropout(0.05, name="drop_1")(x)

    x = layers.Dense(16, kernel_regularizer=regularizers.l2(1e-4),
                      name="enc_2")(x)
    x = layers.BatchNormalization(name="bn_2")(x)
    x = layers.Activation("relu")(x)

    # Bottleneck
    z = layers.Dense(bottleneck, activation="relu", name="bottleneck")(x)

    # Decoder
    x = layers.Dense(16, kernel_regularizer=regularizers.l2(1e-4),
                      name="dec_1")(z)
    x = layers.BatchNormalization(name="bn_3")(x)
    x = layers.Activation("relu")(x)

    x = layers.Dense(32, kernel_regularizer=regularizers.l2(1e-4),
                      name="dec_2")(x)
    x = layers.BatchNormalization(name="bn_4")(x)
    x = layers.Activation("relu")(x)

    out = layers.Dense(input_dim, activation="linear", name="output")(x)

    ae = models.Model(inp, out, name="deep_autoencoder")
    ae.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="mse",
    )
    return ae


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--models-dir",       default=DEFAULT_MODELS_DIR)
    p.add_argument("--baseline-minutes", type=int, default=120)
    p.add_argument("--epochs",           type=int, default=200)
    p.add_argument("--batch-size",       type=int, default=64)
    p.add_argument("--bottleneck",       type=int, default=6)
    p.add_argument("--seed",             type=int, default=42)
    p.add_argument("--log-level",        default="INFO")
    args = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    os.makedirs(args.models_dir, exist_ok=True)
    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)

    # ── 1. Pure-normal training data ────────────────────────────────────────
    LOG.info("Generating %d-min baseline for TF AE...", args.baseline_minutes)
    X, _ = synthetic_dataset(baseline_minutes=args.baseline_minutes, attack_episodes=0)

    from sklearn.model_selection import train_test_split
    X_train, X_calib = train_test_split(X, test_size=0.15, random_state=args.seed)
    X_train, X_val   = train_test_split(X_train, test_size=0.10, random_state=args.seed)
    LOG.info("Train=%d  Val=%d  Calib=%d", len(X_train), len(X_val), len(X_calib))

    # ── 2. Scaler ────────────────────────────────────────────────────────────
    scaler_path = os.path.join(args.models_dir, "scaler.pkl")
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
        LOG.info("Re-using scaler from %s", scaler_path)
    else:
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler().fit(X_train)
        joblib.dump(scaler, scaler_path)
        LOG.info("Fit fresh scaler → %s", scaler_path)

    X_train_s = scaler.transform(X_train).astype(np.float32)
    X_val_s   = scaler.transform(X_val).astype(np.float32)
    X_calib_s = scaler.transform(X_calib).astype(np.float32)

    # ── 3. Build and train ───────────────────────────────────────────────────
    ae = build_autoencoder(N_FEATURES, args.bottleneck, args.seed)
    ae.summary(print_fn=LOG.info)

    cb = [
        callbacks.EarlyStopping(
            monitor="val_loss", patience=15,
            restore_best_weights=True, verbose=1,
        ),
        callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5,
            patience=7, min_lr=1e-5, verbose=1,
        ),
    ]
    history = ae.fit(
        X_train_s, X_train_s,
        validation_data=(X_val_s, X_val_s),
        epochs=args.epochs,
        batch_size=args.batch_size,
        callbacks=cb,
        shuffle=True,
        verbose=0,
    )
    epochs_run = len(history.history["loss"])
    best_val   = float(min(history.history["val_loss"]))
    LOG.info("Training complete: %d epochs, best val_loss=%.6f", epochs_run, best_val)

    # ── 4. Calibrate threshold ───────────────────────────────────────────────
    def recon_err(Xs: np.ndarray) -> np.ndarray:
        pred = ae.predict(Xs, verbose=0, batch_size=256)
        return np.mean((Xs - pred) ** 2, axis=1)

    calib_err = recon_err(X_calib_s)
    mean_err  = float(np.mean(calib_err))
    std_err   = float(np.std(calib_err) + 1e-9)
    p99_err   = float(np.percentile(calib_err, 99))
    z_at_p99  = (p99_err - mean_err) / std_err
    LOG.info("Calib recon error: mean=%.6f  std=%.6f  p99=%.6f  z@p99=%.2f",
             mean_err, std_err, p99_err, z_at_p99)

    # ── 5. Evaluate AUC ──────────────────────────────────────────────────────
    from sklearn.metrics import roc_auc_score, average_precision_score
    X_atk, y_atk = synthetic_attack_only(n_episodes=30)
    X_atk_s      = scaler.transform(X_atk).astype(np.float32)
    atk_err      = recon_err(X_atk_s)

    y_eval  = np.concatenate([np.zeros(len(calib_err)), y_atk])
    sc_eval = np.concatenate([(calib_err - mean_err) / std_err,
                               (atk_err  - mean_err) / std_err])
    auc = float(roc_auc_score(y_eval, sc_eval))
    ap  = float(average_precision_score(y_eval, sc_eval))
    detected = int((atk_err >= p99_err).sum())
    LOG.info("TF AE evaluation  ROC-AUC=%.4f  AP=%.4f  detection=%.1f%%",
             auc, ap, 100.0 * detected / max(len(atk_err), 1))

    # ── 6. Save artefacts ───────────────────────────────────────────────────
    model_path = os.path.join(args.models_dir, "autoencoder.h5")
    ae.save(model_path)
    LOG.info("Saved TF model → %s", model_path)

    thr = {
        "feature_version":      FEATURE_VERSION,
        "feature_names":        list(FEATURE_NAMES),
        "n_features":           N_FEATURES,
        "trained_at":           datetime.now(timezone.utc).isoformat(),
        "model":                "TF-DeepAutoencoder",
        "architecture":         "20→32→16→6→16→32→20",
        "epochs_run":           epochs_run,
        "best_val_loss":        round(best_val, 6),
        "baseline_recon_mean":  mean_err,
        "baseline_recon_std":   std_err,
        "p99_threshold":        p99_err,
        "z_alert_threshold":    round(z_at_p99, 2),
        "roc_auc":              round(auc, 4),
        "average_precision":    round(ap, 4),
        "seed":                 args.seed,
    }
    with open(os.path.join(args.models_dir, "tf_threshold.json"), "w") as fh:
        json.dump(thr, fh, indent=2)

    LOG.info("Saved tf_threshold.json → %s", args.models_dir)
    LOG.info("TF Autoencoder training complete. ROC-AUC=%.4f", auc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
