"""
Stage 2 dataset smoke gate.

Builds a small synthetic dataset (deterministic seed), trains an
IsolationForest on a labelled subset, and asserts ROC-AUC > 0.85 on the
held-out portion. Runs offline; no Vagrant / no VMs required.

Run from the project root:
    python infra/tests/stage2_dataset_smoke.py
"""
from __future__ import annotations

import logging
import os
import sys

# Allow running without an installed package: prepend vm-ai/ to sys.path.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "vm-ai"))

from sklearn.ensemble import IsolationForest                # noqa: E402
from sklearn.metrics import roc_auc_score                  # noqa: E402
from sklearn.model_selection import train_test_split        # noqa: E402
from sklearn.preprocessing import StandardScaler            # noqa: E402

from model.datasets import synthetic_dataset                # noqa: E402

LOG = logging.getLogger("stage2_dataset_smoke")
AUC_THRESHOLD = 0.85


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    X, y = synthetic_dataset(baseline_minutes=20, attack_episodes=5)
    n_attack = int(y.sum())
    LOG.info("dataset: n=%d  attack=%d  benign=%d", len(X), n_attack, len(X) - n_attack)
    if n_attack < 5:
        LOG.error("not enough attack labels in synthetic data (got %d)", n_attack)
        return 2

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y,
    )
    scaler = StandardScaler().fit(X_tr)
    Xt = scaler.transform(X_tr)
    Xe = scaler.transform(X_te)
    model = IsolationForest(n_estimators=200, random_state=42, n_jobs=1).fit(Xt)
    scores = -model.decision_function(Xe)
    auc = float(roc_auc_score(y_te, scores))
    LOG.info("hold-out ROC-AUC = %.4f (threshold %.2f)", auc, AUC_THRESHOLD)

    if auc >= AUC_THRESHOLD:
        print(f"STAGE 2 DATASET SMOKE: PASS (AUC={auc:.4f})")
        return 0
    print(f"STAGE 2 DATASET SMOKE: FAIL (AUC={auc:.4f} < {AUC_THRESHOLD})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
