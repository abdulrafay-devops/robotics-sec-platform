"""
Production-grade IsolationForest trainer for Stage 2 OT anomaly detection.

Best practices applied:
  - Train on PURE NORMAL data only (attack_episodes=0)
  - contamination='auto' (unsupervised; avoids biasing the decision boundary)
  - n_estimators=300 for stable, low-variance scoring
  - max_samples=256 (standard IsolationForest recommendation)
  - Threshold calibrated as 99th-percentile of normal training scores
  - AUC evaluated on held-out attack data so performance is quantified
  - Scoring convention: max(0, -decision_function) — always non-negative

Output artefacts:
  iforest.pkl, scaler.pkl, model_meta.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, precision_recall_curve, average_precision_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .datasets import load_external, synthetic_dataset, synthetic_attack_only
from .features import FEATURE_NAMES, FEATURE_VERSION, N_FEATURES

LOG = logging.getLogger("train_iforest")
DEFAULT_MODELS_DIR = "/opt/lab/models"


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--models-dir",       default=DEFAULT_MODELS_DIR)
    p.add_argument("--external-dir",     default="/var/lab/datasets")
    p.add_argument("--baseline-minutes", type=int, default=120)
    p.add_argument("--attack-episodes",  type=int, default=0,
                   help="keep at 0 for production; >0 contaminates the training set")
    p.add_argument("--n-estimators",     type=int, default=300)
    p.add_argument("--max-samples",      type=int, default=256)
    p.add_argument("--seed",             type=int, default=42)
    p.add_argument("--log-level",        default="INFO")
    args = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    os.makedirs(args.models_dir, exist_ok=True)
    np.random.seed(args.seed)

    # ── 1. Build training corpus (pure normal) ──────────────────────────────
    LOG.info("Generating %d-minute synthetic baseline (pure normal)...", args.baseline_minutes)
    X_normal, _ = synthetic_dataset(
        baseline_minutes=args.baseline_minutes,
        attack_episodes=0,
    )
    LOG.info("Baseline corpus: %d windows × %d features", *X_normal.shape)

    # Merge with external dataset if available
    ext = load_external(args.external_dir)
    X_ext_atk = None
    if ext is not None:
        X_ext, y_ext = ext
        X_normal_ext = X_ext[y_ext == 0]
        X_ext_atk = X_ext[y_ext == 1]
        LOG.info("External dataset: +%d normal windows, %d attack windows",
                 len(X_normal_ext), len(X_ext_atk))
        X_normal = np.vstack([X_normal, X_normal_ext])

    # Hold out 20% for threshold calibration
    X_train, X_calib = train_test_split(X_normal, test_size=0.20,
                                        random_state=args.seed)
    LOG.info("Training: %d  |  Calibration: %d", len(X_train), len(X_calib))

    # ── 2. Fit scaler on training split only ────────────────────────────────
    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_calib_s = scaler.transform(X_calib)

    # ── 3. Fit IsolationForest on pure normal data ───────────────────────────
    # contamination='auto' → offset_ set at -0.5 (sklearn default for unsupervised)
    # max_samples=256 is the canonical recommendation from the IF paper
    LOG.info("Fitting IsolationForest(n_estimators=%d, max_samples=%d)...",
             args.n_estimators, args.max_samples)
    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples=min(args.max_samples, len(X_train_s)),
        contamination="auto",
        random_state=args.seed,
        n_jobs=-1,
    ).fit(X_train_s)

    # ── 4. Calibrate threshold on held-out normal data ─────────────────────
    # Scoring: max(0, -decision_function). Normal traffic → 0.0.
    # The 99th-percentile of calibration scores is our false-positive gate:
    # at most 1% of normal traffic should trigger an alert.
    calib_scores = np.maximum(0.0, -model.decision_function(X_calib_s))
    train_scores = np.maximum(0.0, -model.decision_function(X_train_s))
    # A p99 gate fires ~1% of NORMAL windows; on a continuous 5s-window stream that
    # is a fake incident every few minutes. Calibrate ABOVE the normal maximum with a
    # margin so steady normal traffic never trips it. On an ultra-regular single-arm
    # baseline the IsolationForest is a gross-outlier backstop — the autoencoders
    # carry the fine-grained sensitivity — so a conservative gate is correct here.
    normal_max   = float(max(np.max(calib_scores), np.max(train_scores)))
    fp_threshold = round(max(float(np.percentile(calib_scores, 99)), normal_max) * 1.25, 4)
    LOG.info("Calibration normal score: p50=%.4f  p95=%.4f  p99=%.4f  max=%.4f (→ threshold=%.4f)",
             np.percentile(calib_scores, 50),
             np.percentile(calib_scores, 95),
             np.percentile(calib_scores, 99),
             normal_max, fp_threshold)

    # ── 5. Evaluate AUC on synthetic attack data ────────────────────────────
    X_atk, y_atk = synthetic_attack_only(n_episodes=30)
    X_atk_s      = scaler.transform(X_atk)
    atk_scores   = np.maximum(0.0, -model.decision_function(X_atk_s))

    # Build combined eval set: calibration normal + all attacks
    y_eval   = np.concatenate([np.zeros(len(X_calib_s)), y_atk])
    sc_eval  = np.concatenate([calib_scores, atk_scores])
    auc      = float(roc_auc_score(y_eval, sc_eval))
    ap       = float(average_precision_score(y_eval, sc_eval))
    LOG.info("Evaluation  ROC-AUC=%.4f  AP=%.4f  "
             "(n_normal=%d  n_attack=%d)",
             auc, ap, len(X_calib_s), len(X_atk))

    # Log detection rate at calibrated threshold
    detected = int((atk_scores >= fp_threshold).sum())
    LOG.info("At p99 threshold=%.4f: detection rate=%.1f%%  (%d/%d attacks)",
             fp_threshold, 100.0 * detected / max(len(atk_scores), 1),
             detected, len(atk_scores))

    # ── 5b. Honest AUC on REAL held-out attacks, if a labelled external dataset
    # is present (model.convert_public_dataset → /var/lab/datasets). This is the
    # non-circular number to quote: synthetic-trained model vs real attack traffic.
    external_auc = None
    if X_ext_atk is not None and len(X_ext_atk) > 0:
        ext_atk_scores = np.maximum(0.0, -model.decision_function(scaler.transform(X_ext_atk)))
        y_ext_eval = np.concatenate([np.zeros(len(X_calib_s)), np.ones(len(X_ext_atk))])
        sc_ext_eval = np.concatenate([calib_scores, ext_atk_scores])
        external_auc = float(roc_auc_score(y_ext_eval, sc_ext_eval))
        LOG.info("External (REAL-data) ROC-AUC=%.4f on %d held-out attack windows",
                 external_auc, len(X_ext_atk))

    # ── 6. Save artefacts ───────────────────────────────────────────────────
    joblib.dump(model,  os.path.join(args.models_dir, "iforest.pkl"))
    joblib.dump(scaler, os.path.join(args.models_dir, "scaler.pkl"))

    meta = {
        "feature_version":       FEATURE_VERSION,
        "feature_names":         list(FEATURE_NAMES),
        "n_features":            N_FEATURES,
        "trained_at":            datetime.now(timezone.utc).isoformat(),
        "model":                 "IsolationForest",
        "n_estimators":          args.n_estimators,
        "max_samples":           min(args.max_samples, len(X_train_s)),
        "contamination":         "auto",
        "seed":                  args.seed,
        "n_train":               len(X_train),
        "n_calib":               len(X_calib),
        "roc_auc":               round(auc, 4),
        "external_roc_auc":      round(external_auc, 4) if external_auc is not None else None,
        "average_precision":     round(ap, 4),
        "calibrated_threshold":  round(fp_threshold, 6),
        "detection_rate_pct":    round(100.0 * detected / max(len(atk_scores), 1), 1),
        "attack_episodes_used":  0,
        "scoring_convention":    "max(0, -decision_function)",
    }
    with open(os.path.join(args.models_dir, "model_meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)

    LOG.info("Saved iforest.pkl, scaler.pkl, model_meta.json → %s", args.models_dir)
    LOG.info("IsolationForest training complete. ROC-AUC=%.4f", auc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
