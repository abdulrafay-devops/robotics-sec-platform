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
    WindowBucket,
    WindowStore,
    WINDOW_SECONDS,
    resolve_if_threshold,
)
from collections import deque

LOG = logging.getLogger("feature_consumer")
logging.basicConfig(
    level=os.environ.get("LAB_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

# Modbus write function codes (for the per-alert protocol fingerprint below).
_COIL_WRITE_FC = {5, 15}
_REG_WRITE_FC = {6, 16}
_READ_FC = {1, 2, 3, 4}


def _fingerprint(rows, window_s: float = 5.0) -> dict:
    """Exact per-window Modbus protocol summary, attached to anomaly alerts.

    This is ADDITIVE metadata only — it never touches scoring, thresholds, or the
    anomaly decision. The IR attack_classifier reads it to name the technique and
    explain *why* an alert fired from the observed function codes / addresses, the
    same fields a SOC analyst would read off the wire. Guarded by the caller; this
    helper itself is total and returns a best-effort dict.

    Note on the wire: this Zeek Modbus decoder does NOT parse the write *payload*
    (FC16 logs address/quantity as 0) and emits a spurious address-0 companion row
    per write. So the classifier keys on robust signals — coil-vs-register split,
    the function codes, and the *set* of write addresses (where addr 0 is treated
    as low-information) — never on quantity or a single min address.
    """
    reqs = [r for r in rows if getattr(r, "is_request", True)]
    coil_w = [r for r in reqs if r.func_code in _COIL_WRITE_FC]
    reg_w = [r for r in reqs if r.func_code in _REG_WRITE_FC]
    writes = coil_w + reg_w
    reads = [r for r in reqs if r.func_code in _READ_FC]
    coil_addrs = sorted({int(r.address) for r in coil_w})
    reg_addrs = sorted({int(r.address) for r in reg_w})
    write_fcs = sorted({int(r.func_code) for r in writes})
    return {
        "n_req": len(reqs),
        "n_read": len(reads),
        "n_write": len(writes),
        "n_coil_write": len(coil_w),
        "n_reg_write": len(reg_w),
        "fcs": sorted({int(r.func_code) for r in reqs}),
        "write_fcs": write_fcs,
        "coil_addrs": coil_addrs[:16],
        "reg_addrs": reg_addrs[:16],
        "max_coil_addr": max(coil_addrs, default=-1),
        "max_reg_addr": max(reg_addrs, default=-1),
        "has_block_write": bool({15, 16} & set(write_fcs)),
        "write_rate": round(len(writes) / window_s, 2),
        "read_rate": round(len(reads) / window_s, 2),
    }

REDIS_HOST = os.environ.get("LAB_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("LAB_REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ.get("LAB_REDIS_PASSWORD", "")
RAW_LIST = os.environ.get("LAB_REDIS_RAW_LIST", "lab.modbus.features.raw")
ANOMALY_LIST = os.environ.get("LAB_REDIS_ANOMALY_LIST", "lab.anomaly.events")
MODELS_DIR = os.environ.get("LAB_MODELS_DIR", "/opt/lab/models")
FLUSH_PERIOD_S = float(os.environ.get("LAB_FLUSH_PERIOD_S", "1.0"))
# Fast live-display path: every DISPLAY_PERIOD_S the consumer scores a SLIDING
# trailing window and writes positive "activity" telemetry to LIVE_ACTIVITY_FILE,
# so the dashboard gauges move every ~2s. This is display-only and completely
# separate from the 5s tumbling-window path that drives anomaly alerts/incidents.
DISPLAY_PERIOD_S = float(os.environ.get("LAB_DISPLAY_PERIOD_S", "2.0"))
LIVE_ACTIVITY_FILE = os.environ.get("LAB_LIVE_ACTIVITY_FILE", "/var/lab/state/live_activity.json")

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
        # Decision-fusion meta-scorer (logistic stacker) — the final decision maker.
        self.fusion   = self._maybe(joblib.load,     os.path.join(models_dir, "meta_model.pkl"))
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

        # Always-positive "activity" telemetry for the live dashboard (separate from
        # the floored detection scores below). These are the RAW model outputs, so
        # they show a small positive baseline that jitters every window and spikes on
        # an attack — nothing fabricated. if_activity centres ~0.4 (boundary 0.5);
        # the AE activities are reconstruction-error "x normal" (≈1.0 on baseline).
        if_activity: Optional[float] = None
        pca_activity: Optional[float] = None
        tf_activity: Optional[float] = None

        # ── IsolationForest ────────────────────────────────────────────────
        if_score: Optional[float] = None
        if self.iforest is not None:
            df = float(self.iforest.decision_function(xs)[0])
            if_score = max(0.0, -df)              # detection score (floored)
            if_activity = round(0.5 - df, 4)       # display: ~0.4 baseline, >0.9 on attack

        # ── PCA Autoencoder z-score ────────────────────────────────────────
        pca_z: Optional[float] = None
        if self.pca is not None and self.pca_thr is not None:
            recon = self.pca.inverse_transform(self.pca.transform(xs))
            err   = float(((xs - recon) ** 2).mean())
            pca_z = (err - self.pca_thr["baseline_recon_mean"]) / max(
                self.pca_thr["baseline_recon_std"], 1e-9
            )
            pca_activity = round(err / max(self.pca_thr["baseline_recon_mean"], 1e-9), 4)

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
                tf_activity = round(err_tf / max(self.tf_thr["baseline_recon_mean"], 1e-9), 4)
            except Exception as exc:
                LOG.debug("TF scoring error: %s", exc)

        # ── Anomaly decision ───────────────────────────────────────────────
        # The hand-written rule is kept as a FALLBACK; the learned decision-fusion
        # meta-scorer below is the primary decision maker when its model is present.
        if_fired  = if_score is not None and if_score > self.if_threshold
        pca_fired = (pca_z is not None and self.pca_thr is not None
                     and pca_z >= self.pca_thr.get("z_alert_threshold", 3.0))
        tf_fired  = (tf_z is not None and self.tf_thr is not None
                     and tf_z >= self.tf_thr.get("z_alert_threshold", 3.0))
        if REQUIRE_AE_CONSENSUS:
            rule_anomaly = if_fired or (pca_fired and tf_fired)
        else:
            rule_anomaly = if_fired or pca_fired or tf_fired

        # ── Decision-fusion meta-scorer (the final decision maker) ─────────
        # A learned logistic "stacker" fuses the three detector scores into ONE
        # calibrated attack probability -> risk score (0-100) + severity. Inputs are
        # the raw model scores (log1p on the AE z-scores, matching model/train_meta.py).
        # If the meta-model is absent it transparently falls back to the rule above.
        risk_score = None
        attack_prob = None
        severity = None
        anomaly = rule_anomaly
        if (self.fusion is not None and if_score is not None
                and pca_z is not None and tf_z is not None):
            try:
                feats = np.array([[if_score, np.log1p(max(0.0, pca_z)), np.log1p(max(0.0, tf_z))]])
                p = float(self.fusion["clf"].predict_proba(feats)[0, 1])
                attack_prob = round(p, 4)
                risk_score = round(p * 100.0, 1)
                anomaly = p >= self.fusion["threshold"]
                severity = ("critical" if p >= 0.97 else "high" if p >= 0.80
                            else "medium" if anomaly else "low")
            except Exception as exc:  # the meta-scorer must never break detection
                LOG.debug("meta-scorer failed, using rule: %s", exc)

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
            "if_activity":   if_activity,
            "pca_activity":  pca_activity,
            "tf_activity":   tf_activity,
            "risk_score":    risk_score,
            "attack_prob":   attack_prob,
            "severity":      severity,
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
    # Fast live-display state: a rolling buffer of recent rows + a display timer.
    _recent: deque = deque()
    _last_display = time.monotonic()

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
                _recent.append(row)
            except (ValueError, KeyError) as exc:
                LOG.warning("could not parse raw row: %s", exc)

        now = time.time()

        # ── Fast live-display path (sliding window, display-only) ───────────
        if scorer.ready and (time.monotonic() - _last_display) >= DISPLAY_PERIOD_S:
            _last_display = time.monotonic()
            cutoff = now - WINDOW_SECONDS
            while _recent and _recent[0].ts < cutoff:
                _recent.popleft()
            try:
                if _recent:
                    b = WindowBucket(src_ip=_recent[-1].src_ip, window_start=cutoff)
                    b.rows = list(_recent)
                    s = scorer.score(b.feature_vector())
                    import pathlib
                    pathlib.Path(LIVE_ACTIVITY_FILE).write_text(json.dumps({
                        "ts": now,
                        "if_activity":  s.get("if_activity"),
                        "pca_activity": s.get("pca_activity"),
                        "tf_activity":  s.get("tf_activity"),
                        "iforest_score": s.get("iforest_score"),
                        "pca_z": s.get("pca_z"),
                        "tf_z": s.get("tf_z"),
                        "risk_score": s.get("risk_score"),
                        "attack_prob": s.get("attack_prob"),
                        "severity": s.get("severity"),
                        "anomaly": bool(s.get("anomaly", False)),
                        "n_msgs": len(_recent),
                    }))
            except Exception as exc:  # display path must never disrupt detection
                LOG.debug("live-display score failed: %s", exc)

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
                            "risk_score":    event.get("risk_score"),
                            "attack_prob":   event.get("attack_prob"),
                            "severity":      event.get("severity"),
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
                        # Attach the protocol fingerprint so the IR layer can name
                        # the technique + explain why it fired. Best-effort: a
                        # fingerprint failure must never block the alert.
                        try:
                            event["fingerprint"] = _fingerprint(bucket.rows)
                        except Exception as exc:  # noqa: BLE001
                            LOG.debug("fingerprint failed: %s", exc)
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
