"""
Stage 2 feature consumer.

Reads raw Modbus feature rows pushed by `vm-sec/log_shipper/feature_pusher.py`
from a Redis list, accumulates them into 5-second windows, scores each
finalised window via the in-process model, and pushes detected anomalies
to a downstream Redis list consumed by `alert_bridge.py`.

Why in-process scoring (not HTTP to score_service):
  * One fewer hop = lower latency
  * Avoids a runtime dependency on the FastAPI service for the data plane
  * The same code path is exercised by `infra/tests/stage2_live_smoke.sh`

Redis layout:
    LIST  lab.modbus.features.raw    (RPUSH from vm-sec, BLPOP here)
    LIST  lab.anomaly.events         (RPUSH here, BLPOP from alert_bridge)
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from typing import Optional

import joblib
import numpy as np
import redis

from model.features import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    RawRow,
    WindowStore,
    resolve_if_threshold,
)

LOG = logging.getLogger("feature_consumer")
logging.basicConfig(
    level=os.environ.get("LAB_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

REDIS_HOST = os.environ.get("LAB_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("LAB_REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ.get("LAB_REDIS_PASSWORD", "")
RAW_LIST = os.environ.get("LAB_REDIS_RAW_LIST", "lab.modbus.features.raw")
ANOMALY_LIST = os.environ.get("LAB_REDIS_ANOMALY_LIST", "lab.anomaly.events")
MODELS_DIR = os.environ.get("LAB_MODELS_DIR", "/opt/lab/models")
FLUSH_PERIOD_S = float(os.environ.get("LAB_FLUSH_PERIOD_S", "1.0"))

# Anomaly gate parameters — tunable via env vars.
# IsolationForest alert threshold resolution (see _Scorer._resolve_if_threshold):
#   1. LAB_IF_ANOMALY_THRESHOLD env var, if set, always wins (explicit override).
#   2. Otherwise the model's *calibrated* threshold — the 99th-percentile of
#      normal training scores that train_iforest.py writes to model_meta.json as
#      "calibrated_threshold" (target: <=1% false positives on normal traffic),
#      clamped to a small floor.
#   3. Otherwise a conservative fallback of 0.15.
# The previous code hard-coded 0.15 and ignored the calibration entirely, which
# was the main driver of spurious incidents on benign OT traffic.
IF_THRESHOLD_ENV = os.environ.get("LAB_IF_ANOMALY_THRESHOLD")  # None unless set
IF_THRESHOLD_FLOOR = float(os.environ.get("LAB_IF_THRESHOLD_FLOOR", "0.10"))
IF_THRESHOLD_FALLBACK = 0.15
# Require N consecutive anomalous windows before pushing to Redis (debounce).
# A real attack persists across the 5s windows; a false positive is an isolated
# blip. Requiring 2 consecutive windows removes the vast majority of sporadic
# FPs while still catching any sustained (>=~10s) attack. Override with
# LAB_ANOMALY_CONSECUTIVE (set 3+ for very noisy production links).
ANOMALY_CONSECUTIVE_REQUIRED = int(os.environ.get("LAB_ANOMALY_CONSECUTIVE", "2"))
# Minimum seconds between alerts for the same source host (cooldown).
ALERT_COOLDOWN_S = float(os.environ.get("LAB_ALERT_COOLDOWN_S", "45.0"))
# Decision-rule hardening (false-positive control):
#  * REQUIRE_AE_CONSENSUS: the calibrated IsolationForest (per-model p99 thresh,
#    AUC ~0.99) may alert on its own, but an IF-negative window must trip BOTH
#    autoencoders (PCA and TF) to alert. This stops single-autoencoder false
#    positives - e.g. the SEC zone's periodic Modbus read-probe that only raises
#    tf_z while the IsolationForest correctly says "normal". Real attacks trip
#    the IsolationForest outright, so detection is preserved. Set
#    LAB_REQUIRE_AE_CONSENSUS=0 to revert to the old "any single model" rule.
#  * MIN_WINDOW_MSGS: tiny windows produce unstable autoencoder z-scores; an
#    autoencoder-only anomaly on a window with fewer messages than this is
#    ignored (the IsolationForest may still fire on small windows).
REQUIRE_AE_CONSENSUS = os.environ.get("LAB_REQUIRE_AE_CONSENSUS", "1") != "0"
MIN_WINDOW_MSGS = int(os.environ.get("LAB_MIN_WINDOW_MSGS", "5"))

_should_exit = False


def _sigterm(*_a) -> None:
    global _should_exit  # noqa: PLW0603
    _should_exit = True


class _Scorer:
    """In-process scorer: IsolationForest + PCA AE + TF Deep AE (all three)."""

    def __init__(self, models_dir: str) -> None:
        self.iforest  = self._maybe(joblib.load,     os.path.join(models_dir, "iforest.pkl"))
        self.pca      = self._maybe(joblib.load,     os.path.join(models_dir, "pca.pkl"))
        self.scaler   = self._maybe(joblib.load,     os.path.join(models_dir, "scaler.pkl"))
        self.pca_thr  = self._maybe(self._load_json, os.path.join(models_dir, "pca_threshold.json"))
        self.meta     = self._maybe(self._load_json, os.path.join(models_dir, "model_meta.json"))
        self.if_threshold = self._resolve_if_threshold()
        self.tf_model = None
        self.tf_thr   = None
        self._tf_lock = __import__("threading").Lock()
        self._load_tf(models_dir)

    def _resolve_if_threshold(self) -> float:
        """Pick the IsolationForest alert threshold via the shared resolver
        (env > calibrated p99 > fallback) so the data plane and the API agree.
        (audit F-14 — was previously re-implemented separately here.)"""
        thr, reason = resolve_if_threshold(
            self.meta, env_val=IF_THRESHOLD_ENV,
            floor=IF_THRESHOLD_FLOOR, fallback=IF_THRESHOLD_FALLBACK)
        LOG.info("IsolationForest threshold = %.4f (%s)", thr, reason)
        return thr

    def _load_tf(self, models_dir: str) -> None:
        tf_path  = os.path.join(models_dir, "autoencoder.h5")
        thr_path = os.path.join(models_dir, "tf_threshold.json")
        if not os.path.exists(tf_path):
            LOG.warning("TF model not found at %s — tf_z will be None", tf_path)
            return
        try:
            import tensorflow as tf
            os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
            with self._tf_lock:
                self.tf_model = tf.keras.models.load_model(tf_path, compile=False)
            LOG.info("Loaded TF autoencoder from %s", tf_path)
        except Exception as exc:
            LOG.warning("Could not load TF model (%s) — tf_z will be None", exc)
        if os.path.exists(thr_path):
            self.tf_thr = self._maybe(self._load_json, thr_path)

    @staticmethod
    def _maybe(fn, path):
        try:
            return fn(path) if os.path.exists(path) else None
        except Exception as exc:  # noqa: BLE001
            LOG.warning("could not load %s: %s", path, exc)
            return None

    @staticmethod
    def _load_json(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @property
    def ready(self) -> bool:
        return self.scaler is not None and (self.iforest is not None or self.pca is not None)

    def score(self, x: np.ndarray) -> dict:
        xs = self.scaler.transform(x.reshape(1, -1))

        # ── IsolationForest ────────────────────────────────────────────────
        if_score: Optional[float] = None
        if self.iforest is not None:
            if_score = max(0.0, float(-self.iforest.decision_function(xs)[0]))

        # ── PCA Autoencoder z-score ────────────────────────────────────────
        pca_z: Optional[float] = None
        if self.pca is not None and self.pca_thr is not None:
            recon = self.pca.inverse_transform(self.pca.transform(xs))
            err   = float(((xs - recon) ** 2).mean())
            pca_z = (err - self.pca_thr["baseline_recon_mean"]) / max(
                self.pca_thr["baseline_recon_std"], 1e-9
            )

        # ── TF Deep Autoencoder z-score ────────────────────────────────────
        tf_z: Optional[float] = None
        if self.tf_model is not None and self.tf_thr is not None:
            try:
                xs_f32 = xs.astype(np.float32)
                with self._tf_lock:
                    recon_tf = self.tf_model(xs_f32, training=False).numpy()
                err_tf = float(np.mean((xs_f32 - recon_tf) ** 2))
                tf_z = (err_tf - self.tf_thr["baseline_recon_mean"]) / max(
                    self.tf_thr["baseline_recon_std"], 1e-9
                )
            except Exception as exc:
                LOG.debug("TF scoring error: %s", exc)

        # ── Anomaly decision ───────────────────────────────────────────────
        # Which models fired?
        if_fired  = if_score is not None and if_score > self.if_threshold
        pca_fired = (pca_z is not None and self.pca_thr is not None
                     and pca_z >= self.pca_thr.get("z_alert_threshold", 3.0))
        tf_fired  = (tf_z is not None and self.tf_thr is not None
                     and tf_z >= self.tf_thr.get("z_alert_threshold", 3.0))
        # Trust the calibrated IsolationForest alone; otherwise require BOTH
        # autoencoders to agree (consensus) so a single noisy AE z-score cannot
        # raise an alert by itself. See REQUIRE_AE_CONSENSUS note above.
        if REQUIRE_AE_CONSENSUS:
            anomaly = if_fired or (pca_fired and tf_fired)
        else:
            anomaly = if_fired or pca_fired or tf_fired

        idx = np.argsort(-np.abs(xs.ravel()))[:3]
        top = [FEATURE_NAMES[i] for i in idx]
        # Emit NON-NEGATIVE scores. A z-score below 0 just means "reconstructs better
        # than the calibration average" = perfectly normal, so we floor it to 0. This
        # gives a clean convention everywhere (0 = normal/better, higher = more
        # anomalous — same as the IsolationForest). Firing decisions above used the raw
        # z (clamping negatives can't change a >= positive-threshold test), so detection
        # sensitivity is unchanged.
        return {
            "iforest_score": if_score,
            "pca_z":         (max(0.0, pca_z) if pca_z is not None else None),
            "tf_z":          (max(0.0, tf_z) if tf_z is not None else None),
            "anomaly":       anomaly,
            "top_features":  top,
            "model_version": FEATURE_VERSION,
        }


def main() -> int:
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)
    LOG.info(
        "feature_consumer starting: redis=%s:%d raw=%s anomaly=%s models=%s",
        REDIS_HOST, REDIS_PORT, RAW_LIST, ANOMALY_LIST, MODELS_DIR,
    )

    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                    password=REDIS_PASSWORD or None, decode_responses=True)
    # Wait for Redis (it might come up after us at boot).
    for _ in range(30):
        try:
            r.ping()
            break
        except redis.ConnectionError:
            time.sleep(1.0)
    else:
        LOG.error("Redis unreachable at %s:%d", REDIS_HOST, REDIS_PORT)
        return 1

    scorer = _Scorer(MODELS_DIR)
    if not scorer.ready:
        LOG.warning(
            "models not yet present in %s; running in pass-through (no scoring)",
            MODELS_DIR,
        )

    store = WindowStore(grace_seconds=2.0)
    last_flush = time.monotonic()
    # Debounce state: consecutive anomaly count and last-alert timestamp per src_ip.
    _consecutive: dict = {}
    _last_alert_ts: dict = {}

    while not _should_exit:
        try:
            # BLPOP with 1s timeout so we can periodically flush windows.
            item = r.blpop(RAW_LIST, timeout=1)
        except redis.RedisError as exc:
            LOG.warning("redis BLPOP failed: %s; reconnecting", exc)
            time.sleep(1.0)
            continue
        if item is not None:
            _, payload = item
            try:
                d = json.loads(payload)
                row = RawRow.from_dict(d)
                store.add(row)
            except (ValueError, KeyError) as exc:
                LOG.warning("could not parse raw row: %s", exc)

        now = time.time()
        if (time.monotonic() - last_flush) >= FLUSH_PERIOD_S:
            last_flush = time.monotonic()
            for bucket in store.flush_until(now):
                vec = bucket.feature_vector()
                event = {
                    "src_ip": bucket.src_ip,
                    "window_start": bucket.window_start,
                    "n_msgs": len(bucket.rows),
                    "feature_version": FEATURE_VERSION,
                    "features": vec.tolist(),
                }
                if scorer.ready:
                    event.update(scorer.score(vec))
                else:
                    event.update({"iforest_score": None, "pca_z": None, "anomaly": False})

                # Tiny windows yield unstable autoencoder z-scores. Suppress an
                # anomaly on a sub-threshold-size window UNLESS the calibrated
                # IsolationForest itself fired (it is robust on small windows).
                if (event.get("anomaly") and len(bucket.rows) < MIN_WINDOW_MSGS
                        and not (event.get("iforest_score") is not None
                                 and event["iforest_score"] > scorer.if_threshold)):
                    event["anomaly"] = False

                # Always persist the latest score to a state file so Grafana /
                # lab_exporter can display live scores even without active attacks.
                # This is the primary fix for scores showing -1 or "waiting".
                _if_s  = event.get("iforest_score")
                _pca_s = event.get("pca_z")
                _tf_s  = event.get("tf_z")
                if _if_s is not None or _pca_s is not None or _tf_s is not None:
                    try:
                        import pathlib
                        _score_path = pathlib.Path("/var/lab/state/latest_scores.json")
                        _score_path.parent.mkdir(parents=True, exist_ok=True)
                        _score_path.write_text(json.dumps({
                            "ts":            time.time(),
                            "iforest_score": _if_s,
                            "pca_z":         _pca_s,
                            "tf_z":          _tf_s,
                            "src_ip":        bucket.src_ip,
                            "anomaly":       bool(event.get("anomaly", False)),
                        }))
                    except Exception:
                        pass

                src = bucket.src_ip or "unknown"
                now_t = time.time()

                if event.get("anomaly"):
                    # Increment consecutive anomaly counter for this host.
                    _consecutive[src] = _consecutive.get(src, 0) + 1
                    # Only push to Redis if we have N consecutive anomalies
                    # AND the cooldown for this host has expired.
                    if (_consecutive[src] >= ANOMALY_CONSECUTIVE_REQUIRED
                            and now_t - _last_alert_ts.get(src, 0.0) >= ALERT_COOLDOWN_S):
                        _last_alert_ts[src] = now_t
                        _consecutive[src] = 0  # reset after alerting
                        event["dst_ip"] = bucket.rows[0].dst_ip if bucket.rows else None
                        r.rpush(ANOMALY_LIST, json.dumps(event))
                        LOG.info(
                            "ANOMALY src=%s win=%.1f if=%.4f pcaZ=%s top=%s",
                            bucket.src_ip,
                            bucket.window_start,
                            event.get("iforest_score") or 0.0,
                            event.get("pca_z"),
                            event.get("top_features"),
                        )
                    else:
                        LOG.debug(
                            "anomaly suppressed (consec=%d cooldown=%.0fs) src=%s if=%.4f",
                            _consecutive.get(src, 0),
                            ALERT_COOLDOWN_S - (now_t - _last_alert_ts.get(src, 0.0)),
                            src,
                            event.get("iforest_score") or 0.0,
                        )
                else:
                    # Normal window — reset the consecutive counter so debounce
                    # restarts from zero for this host.
                    _consecutive[src] = 0

    LOG.info("feature_consumer exiting")
    return 0


if __name__ == "__main__":
    sys.exit(main())
