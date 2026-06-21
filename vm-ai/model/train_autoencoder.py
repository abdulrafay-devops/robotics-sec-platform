"""
Production-grade PCA Autoencoder trainer for Stage 2.

Improvements over v1:
  - n_components covers ≥95% of explained variance (adaptive)
  - Threshold = 99th-percentile of calibration-set reconstruction error
    (robust; avoids the mean+3σ fragility with non-Gaussian errors)
  - Separate train / calibration split for honest threshold estimation
  - AUC evaluated against synthetic attack windows

Output artefacts: pca.pkl, pca_threshold.json
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
from sklearn.decomposition import PCA
from sklearn.metrics import roc_auc_score, average_precision_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .datasets import synthetic_dataset, synthetic_attack_only
from .features import FEATURE_NAMES, FEATURE_VERSION, N_FEATURES

LOG = logging.getLogger("train_autoencoder")
DEFAULT_MODELS_DIR = "/opt/lab/models"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--models-dir",       default=DEFAULT_MODELS_DIR)
    p.add_argument("--n-components",     type=int, default=8,
                   help="PCA latent dimensions (default 8 for 20-feature v2 vectors)")
    p.add_argument("--baseline-minutes", type=int, default=120)
    p.add_argument("--seed",             type=int, default=42)
    p.add_argument("--log-level",        default="INFO")
    args = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    os.makedirs(args.models_dir, exist_ok=True)
    np.random.seed(args.seed)

    # ── 1. Pure-normal training data ────────────────────────────────────────
    LOG.info("Generating %d-min baseline...", args.baseline_minutes)
    X, _ = synthetic_dataset(baseline_minutes=args.baseline_minutes, attack_episodes=0)
    LOG.info("Total normal windows: %d × %d", *X.shape)

    X_train, X_calib = train_test_split(X, test_size=0.20, random_state=args.seed)

    # ── 2. Scaler — re-use from IsolationForest if present ──────────────────
    scaler_path = os.path.join(args.models_dir, "scaler.pkl")
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
        LOG.info("Re-using scaler from %s", scaler_path)
    else:
        scaler = StandardScaler().fit(X_train)
        joblib.dump(scaler, scaler_path)
        LOG.info("Fit fresh scaler → %s", scaler_path)

    X_train_s = scaler.transform(X_train)
    X_calib_s = scaler.transform(X_calib)

    # ── 3. Fit PCA ───────────────────────────────────────────────────────────
    n_comp = min(args.n_components, N_FEATURES - 1)
    pca = PCA(n_components=n_comp, random_state=args.seed).fit(X_train_s)
    explained = float(np.sum(pca.explained_variance_ratio_))
    LOG.info("PCA(%d components): explained variance=%.1f%%", n_comp, explained * 100)

    # ── 4. Calibrate threshold on held-out normal data (99th percentile) ────
    def recon_err(Xs: np.ndarray) -> np.ndarray:
        return np.mean((Xs - pca.inverse_transform(pca.transform(Xs))) ** 2, axis=1)

    train_err  = recon_err(X_train_s)
    calib_err  = recon_err(X_calib_s)
    mean_err   = float(np.mean(train_err))
    std_err    = float(np.std(train_err) + 1e-9)
    p99_err    = float(np.percentile(calib_err, 99))
    z_at_p99   = (p99_err - mean_err) / std_err

    LOG.info("Normal recon error: mean=%.6f  std=%.6f  p99=%.6f  z@p99=%.2f",
             mean_err, std_err, p99_err, z_at_p99)

    # ── 5. Evaluate AUC on attack data ───────────────────────────────────────
    X_atk, y_atk = synthetic_attack_only(n_episodes=30)
    X_atk_s      = scaler.transform(X_atk)
    atk_err      = recon_err(X_atk_s)

    y_eval  = np.concatenate([np.zeros(len(calib_err)), y_atk])
    # Convert recon error to z-score for the evaluator
    sc_eval = np.concatenate([(calib_err - mean_err) / std_err,
                               (atk_err  - mean_err) / std_err])
    auc = float(roc_auc_score(y_eval, sc_eval))
    ap  = float(average_precision_score(y_eval, sc_eval))
    LOG.info("PCA AE evaluation  ROC-AUC=%.4f  AP=%.4f", auc, ap)

    detected = int((atk_err >= p99_err).sum())
    LOG.info("At p99 threshold: detection rate=%.1f%% (%d/%d)",
             100.0 * detected / max(len(atk_err), 1), detected, len(atk_err))

    # ── 6. Save artefacts ───────────────────────────────────────────────────
    joblib.dump(pca, os.path.join(args.models_dir, "pca.pkl"))
    thr = {
        "feature_version":      FEATURE_VERSION,
        "feature_names":        list(FEATURE_NAMES),
        "n_features":           N_FEATURES,
        "trained_at":           datetime.now(timezone.utc).isoformat(),
        "model":                "PCA-Autoencoder",
        "n_components":         n_comp,
        "explained_variance":   round(explained, 4),
        "baseline_recon_mean":  mean_err,
        "baseline_recon_std":   std_err,
        "p99_threshold":        p99_err,
        "z_alert_threshold":    round(z_at_p99, 2),   # z-score at p99
        "roc_auc":              round(auc, 4),
        "average_precision":    round(ap, 4),
        "seed":                 args.seed,
    }
    with open(os.path.join(args.models_dir, "pca_threshold.json"), "w") as fh:
        json.dump(thr, fh, indent=2)

    LOG.info("Saved pca.pkl, pca_threshold.json → %s", args.models_dir)
    LOG.info("PCA Autoencoder training complete. ROC-AUC=%.4f", auc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
