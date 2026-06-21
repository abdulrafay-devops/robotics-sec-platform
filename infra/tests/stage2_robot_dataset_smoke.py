"""
Stage 2 ROBOT dataset smoke gate (offline).

The robot-plane twin of stage2_dataset_smoke.py.  Trains the LSTM autoencoder on
pure-normal synthetic joint dynamics and asserts ROC-AUC on the held-out
behavioral attacks is above a floor.  Uses small params so it runs in ~1-2 min on
CPU.  Skips cleanly (exit 0) if TensorFlow is unavailable so a TF-less CI host is
not blocked — the in-container boot training is the authoritative run.

Run from the project root:
    python infra/tests/stage2_robot_dataset_smoke.py
"""
from __future__ import annotations

import logging
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "vm-ai"))

LOG = logging.getLogger("stage2_robot_dataset_smoke")
AUC_THRESHOLD = 0.85


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        import tensorflow  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        print(f"STAGE 2 ROBOT DATASET SMOKE: SKIP (TensorFlow unavailable: {exc})")
        return 0

    from model.train_robot_lstm import train_and_eval

    meta = train_and_eval(baseline_minutes=8, epochs=25, batch_size=32,
                          latent=16, seed=42, save=False, log=LOG)
    auc = float(meta["roc_auc"])
    LOG.info("robot LSTM hold-out ROC-AUC = %.4f (threshold %.2f)", auc, AUC_THRESHOLD)

    if auc >= AUC_THRESHOLD:
        print(f"STAGE 2 ROBOT DATASET SMOKE: PASS (AUC={auc:.4f}, AP={meta['average_precision']})")
        return 0
    print(f"STAGE 2 ROBOT DATASET SMOKE: FAIL (AUC={auc:.4f} < {AUC_THRESHOLD})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
