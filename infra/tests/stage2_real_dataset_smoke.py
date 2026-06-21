"""
Stage 2 REAL-dataset smoke gate (offline).

If a labelled external ICS dataset (v2 feature CSV, produced by
model.convert_public_dataset) is present, this trains an IsolationForest on the
real NORMAL windows and asserts ROC-AUC on the held-out real ATTACK windows is
above a floor — the honest, non-circular accuracy number. If no external dataset
is present, it SKIPS cleanly (exit 0) so CI is never blocked on data that must be
downloaded manually (SWaT/HAI/Morris require registration).

Dataset search dir: $LAB_DATASETS_DIR, else /var/lab/datasets, else ./datasets.

Run from the project root:
    python infra/tests/stage2_real_dataset_smoke.py
"""
from __future__ import annotations

import logging
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "vm-ai"))

import numpy as np  # noqa: E402

from model.datasets import load_external  # noqa: E402

LOG = logging.getLogger("stage2_real_dataset_smoke")
AUC_FLOOR = 0.75   # real data is messier than synthetic; modest, honest floor


def _dataset_dir() -> str:
    for d in (os.environ.get("LAB_DATASETS_DIR"), "/var/lab/datasets",
              os.path.join(ROOT, "datasets")):
        if d and os.path.isdir(d):
            return d
    return ""


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    d = _dataset_dir()
    ext = load_external(d) if d else None
    if ext is None:
        print("STAGE 2 REAL DATASET SMOKE: SKIP (no external v2 dataset present — "
              "convert one with model.convert_public_dataset and drop it in /var/lab/datasets)")
        return 0

    X, y = ext
    n_atk = int((y == 1).sum())
    n_norm = int((y == 0).sum())
    LOG.info("external dataset: %d normal, %d attack windows", n_norm, n_atk)
    if n_atk < 5 or n_norm < 20:
        print(f"STAGE 2 REAL DATASET SMOKE: SKIP (too few labelled windows: "
              f"{n_norm} normal / {n_atk} attack)")
        return 0

    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    X_norm = X[y == 0]
    X_atk = X[y == 1]
    X_tr, X_cal = train_test_split(X_norm, test_size=0.3, random_state=42)
    scaler = StandardScaler().fit(X_tr)
    model = IsolationForest(n_estimators=200, random_state=42, n_jobs=1).fit(scaler.transform(X_tr))
    cal_scores = np.maximum(0.0, -model.decision_function(scaler.transform(X_cal)))
    atk_scores = np.maximum(0.0, -model.decision_function(scaler.transform(X_atk)))
    y_eval = np.concatenate([np.zeros(len(cal_scores)), np.ones(len(atk_scores))])
    sc = np.concatenate([cal_scores, atk_scores])
    auc = float(roc_auc_score(y_eval, sc))
    LOG.info("REAL-data hold-out ROC-AUC = %.4f (floor %.2f)", auc, AUC_FLOOR)

    if auc >= AUC_FLOOR:
        print(f"STAGE 2 REAL DATASET SMOKE: PASS (real-data AUC={auc:.4f})")
        return 0
    print(f"STAGE 2 REAL DATASET SMOKE: FAIL (real-data AUC={auc:.4f} < {AUC_FLOOR})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
