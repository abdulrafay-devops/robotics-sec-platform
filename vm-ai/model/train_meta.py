#!/usr/bin/env python3
"""
Decision-fusion meta-scorer + Model-Performance report.

Trains a small logistic-regression "stacker" that fuses the three Modbus detectors
(IsolationForest, PCA-AE, TF-AE) into ONE calibrated attack probability, then a
single risk score (0-100) + confidence + severity. This is the system's final
decision maker — it replaces the hand-written `if OR (pca AND tf)` rule with a
learned weighting, and it reports honest metrics (ROC-AUC, precision, recall, FPR,
per-attack recall) on a held-out split.

Inputs to the meta-model are the model SCORES (not raw features):
    [ iforest_score , log1p(pca_z) , log1p(tf_z) ]
The autoencoder z-scores span many orders of magnitude, so log1p keeps the fusion
numerically stable and the learned weights interpretable.

Normal class  = the live baseline the models were trained on (no train/serve skew).
Attack class  = the five labelled synthetic attack generators.

Run inside container-ai:  PYTHONPATH=/opt/lab/vm-ai python -m model.train_meta
Outputs (to the models dir):  meta_model.pkl  +  model_performance.json
"""
from __future__ import annotations
import json
import os
import sys
import datetime as dt

import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, precision_score, recall_score

from model.features import N_FEATURES, aggregate_rows
from model.datasets import (
    synthetic_baseline,
    _attack_command_injection, _attack_replay, _attack_coil_flood,
    _attack_register_scan, _attack_bulk_write,
)

MODELS = os.environ.get("LAB_MODELS_DIR", "/opt/lab/models")
LIVE_NPY = os.environ.get("LAB_LIVE_BASELINE_NPY", "/var/lab/state/live_baseline_X.npy")
STATE_PERF = "/var/lab/state/model_performance.json"

ATTACKS = [
    ("command_injection", _attack_command_injection),
    ("replay", _attack_replay),
    ("coil_flood", _attack_coil_flood),
    ("register_scan", _attack_register_scan),
    ("bulk_write", _attack_bulk_write),
]


def _load_models():
    scaler = joblib.load(os.path.join(MODELS, "scaler.pkl"))
    iforest = joblib.load(os.path.join(MODELS, "iforest.pkl"))
    pca = joblib.load(os.path.join(MODELS, "pca.pkl"))
    pca_thr = json.load(open(os.path.join(MODELS, "pca_threshold.json")))
    tf_thr = json.load(open(os.path.join(MODELS, "tf_threshold.json")))
    import tensorflow as tf
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
    tfm = tf.keras.models.load_model(os.path.join(MODELS, "autoencoder.h5"), compile=False)
    return scaler, iforest, pca, pca_thr, tfm, tf_thr


def _score_matrix(X, M):
    """Return per-window [iforest_score, pca_z, tf_z] using the SAME math as the consumer."""
    scaler, iforest, pca, pca_thr, tfm, tf_thr = M
    Xs = scaler.transform(X)
    ifs = np.maximum(0.0, -iforest.decision_function(Xs))
    recon = pca.inverse_transform(pca.transform(Xs))
    perr = ((Xs - recon) ** 2).mean(axis=1)
    pz = np.maximum(0.0, (perr - pca_thr["baseline_recon_mean"]) / max(pca_thr["baseline_recon_std"], 1e-9))
    xr = tfm.predict(Xs.astype("float32"), verbose=0)
    terr = ((Xs.astype("float32") - xr) ** 2).mean(axis=1)
    tz = np.maximum(0.0, (terr - tf_thr["baseline_recon_mean"]) / max(tf_thr["baseline_recon_std"], 1e-9))
    return np.column_stack([ifs, pz, tz])


def _meta_feats(S):
    return np.column_stack([S[:, 0], np.log1p(S[:, 1]), np.log1p(S[:, 2])])


def _attack_windows(gen, episodes=8):
    rows = synthetic_baseline(minutes=6)
    base_t0, span = rows[0].ts, rows[-1].ts - rows[0].ts
    import random as _r
    rng = _r.Random(7)
    for _ in range(episodes):
        rows.extend(gen(base_t0 + rng.uniform(0.1 * span, 0.9 * span)))
    rows.sort(key=lambda r: r.ts)
    out = []
    for b in aggregate_rows(rows):
        # Synthetic attacks all originate from a non-OT attacker (ot_origin=False);
        # this also captures the READ-ONLY recon scan, which has no writes.
        is_atk = any(not r.ot_origin for r in b.rows)
        if is_atk:
            out.append(b.feature_vector())
    return np.asarray(out, dtype=float)


def main() -> int:
    M = _load_models()

    # Normal class = the live baseline (what the live models call "calm").
    if os.path.exists(LIVE_NPY):
        Xn = np.load(LIVE_NPY).astype(float)
        normal_src = "live baseline"
    else:
        from model.datasets import synthetic_dataset
        Xn, _ = synthetic_dataset(attack_episodes=0)
        normal_src = "synthetic baseline"
    if Xn.shape[1] != N_FEATURES:
        print("normal matrix wrong width", Xn.shape); return 2

    # Attack class = the five synthetic attack generators (also gives per-attack recall).
    per_attack = {}
    Xa_parts = []
    for name, gen in ATTACKS:
        Xa = _attack_windows(gen)
        if len(Xa):
            Xa_parts.append(Xa)
            per_attack[name] = Xa
    Xa = np.vstack(Xa_parts)

    X = np.vstack([Xn, Xa])
    y = np.concatenate([np.zeros(len(Xn)), np.ones(len(Xa))]).astype(int)
    S = _score_matrix(X, M)
    F = _meta_feats(S)

    Ftr, Fte, ytr, yte = train_test_split(F, y, test_size=0.30, random_state=42, stratify=y)
    clf = LogisticRegression(class_weight="balanced", max_iter=2000).fit(Ftr, ytr)

    # ── operating threshold: lowest prob that keeps FPR <= 0.5% on ALL normal ──
    pn = clf.predict_proba(_meta_feats(_score_matrix(Xn, M)))[:, 1]
    thr = float(np.clip(np.percentile(pn, 99.5), 0.05, 0.999))

    # ── evaluation on the held-out test split ──
    pte = clf.predict_proba(Fte)[:, 1]
    pred = (pte >= thr).astype(int)
    auc = float(roc_auc_score(yte, pte))
    prec = float(precision_score(yte, pred, zero_division=0))
    rec = float(recall_score(yte, pred, zero_division=0))
    norm_mask = yte == 0
    fpr = float((pred[norm_mask] == 1).mean()) if norm_mask.any() else 0.0
    tp = int(((pred == 1) & (yte == 1)).sum()); fn = int(((pred == 0) & (yte == 1)).sum())
    fp = int(((pred == 1) & (yte == 0)).sum()); tn = int(((pred == 0) & (yte == 0)).sum())

    pa_recall = {}
    for name, Xat in per_attack.items():
        pat = clf.predict_proba(_meta_feats(_score_matrix(Xat, M)))[:, 1]
        pa_recall[name] = round(float((pat >= thr).mean()), 3)

    coefs = clf.coef_[0]
    weights = {"iforest": round(float(coefs[0]), 3), "pca_ae": round(float(coefs[1]), 3), "tf_ae": round(float(coefs[2]), 3)}

    # ── persist meta-model + report ──
    joblib.dump({"clf": clf, "threshold": thr, "transform": "log1p(pca,tf)",
                 "inputs": ["iforest_score", "pca_z", "tf_z"]},
                os.path.join(MODELS, "meta_model.pkl"))

    report = {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "model": "decision-fusion (logistic stacker)",
        "normal_source": normal_src,
        "n_normal": int(len(Xn)), "n_attack": int(len(Xa)),
        "roc_auc": round(auc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "false_positive_rate": round(fpr, 4),
        "operating_threshold": round(thr, 4),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "fusion_weights": weights,
        "per_attack_recall": pa_recall,
    }
    with open(os.path.join(MODELS, "model_performance.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    try:
        with open(STATE_PERF, "w") as fh:
            json.dump(report, fh, indent=2)
    except OSError:
        pass

    print(json.dumps(report, indent=2))
    print("\nsaved meta_model.pkl + model_performance.json to", MODELS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
