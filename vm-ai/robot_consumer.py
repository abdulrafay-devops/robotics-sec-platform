"""
Robot-behavior anomaly scorer (robot plane).  The robot-side twin of
feature_consumer.py.

Reads the rolling joint-telemetry file written by the OT passive tap
(``/var/lab/state/robot/joint_stream.jsonl``), builds the most-recent window via
the shared ``model.robot_features`` module, and scores it with TWO detectors:

  1. LSTM autoencoder  — reconstruction z-score vs the calibrated p99 threshold
  2. physical envelope — deterministic URDF/limit checks (calibrated from normal)

Outputs:
  * /var/lab/state/latest_robot_scores.json   — live gauge source (every poll)
  * RPUSH lab.anomaly.events {plane:"robot", ...} on a debounced anomaly, so the
    existing alert_bridge → ai-alerts.json → IR/exporter/dashboard path is reused.

Demo injection: while ``/var/lab/state/robot_attack_trigger.json`` is active, a
synthetic *tampered* window (one of the behavioral attacks) is scored by the REAL
LSTM — mirroring the Modbus demo injector (real model, synthetic input). Honest
"DEMO" framing; respects LAB_DEMO_MODE=0.

All feature math is delegated to ``model.robot_features`` (anti-drift).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

from model.robot_features import (
    CHANNEL_NAMES,
    MOTION_ACTIVE_THRESH,
    N_CHANNELS,
    N_JOINTS,
    ROBOT_FEATURE_VERSION,
    WINDOW_LEN,
    derive_channels,
    envelope_violations,
    recon_error,
    standardize,
    top_channels,
)

LOG = logging.getLogger("robot_consumer")
logging.basicConfig(
    level=os.environ.get("LAB_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

MODELS_DIR = os.environ.get("LAB_MODELS_DIR", "/opt/lab/models")
STREAM_FILE = os.environ.get("LAB_ROBOT_STREAM_FILE", "/var/lab/state/robot/joint_stream.jsonl")
SCORES_FILE = os.environ.get("LAB_ROBOT_SCORES_FILE", "/var/lab/state/latest_robot_scores.json")
TRIGGER_FILE = os.environ.get("LAB_ROBOT_TRIGGER_FILE", "/var/lab/state/robot_attack_trigger.json")
POLL_S = float(os.environ.get("LAB_ROBOT_POLL_S", "1.0"))
STALE_S = float(os.environ.get("LAB_ROBOT_STALE_S", "8.0"))

REDIS_HOST = os.environ.get("LAB_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("LAB_REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ.get("LAB_REDIS_PASSWORD", "")
ANOMALY_LIST = os.environ.get("LAB_REDIS_ANOMALY_LIST", "lab.anomaly.events")

ANOMALY_CONSECUTIVE_REQUIRED = int(os.environ.get("LAB_ROBOT_ANOMALY_CONSECUTIVE", "2"))
ALERT_COOLDOWN_S = float(os.environ.get("LAB_ROBOT_ALERT_COOLDOWN_S", "45.0"))
_DEMO_MODE = os.environ.get("LAB_DEMO_MODE", "1") != "0"
# Robot anomalies are an OT-zone event; use the production-PLC IP as the source so
# the IR engine (which requires a numeric SRC_IP) opens an incident normally.
ROBOT_SRC_IP = os.environ.get("LAB_ROBOT_SRC_IP", "192.168.10.10")

_should_exit = False


def _sigterm(*_a) -> None:
    global _should_exit  # noqa: PLW0603
    _should_exit = True


class RobotScorer:
    """Loads the LSTM AE + calibrated thresholds and scores a raw (T, C) window.

    Kept free of I/O so it can be unit-tested offline against a trained model."""

    def __init__(self, models_dir: str) -> None:
        self.model = None
        self.thr: Optional[dict] = None
        self.mean = None
        self.std = None
        self.envelope: Optional[dict] = None
        self.z_alert = 3.0
        self._load(models_dir)

    def _load(self, models_dir: str) -> None:
        thr_path = os.path.join(models_dir, "robot_threshold.json")
        h5_path = os.path.join(models_dir, "robot_lstm.h5")
        if os.path.exists(thr_path):
            with open(thr_path, "r", encoding="utf-8") as fh:
                self.thr = json.load(fh)
            self.mean = np.asarray(self.thr["channel_mean"], dtype=np.float64)
            self.std = np.asarray(self.thr["channel_std"], dtype=np.float64)
            self.envelope = self.thr.get("envelope")
            self.z_alert = float(self.thr.get("z_alert_threshold", 3.0))
        if os.path.exists(h5_path):
            try:
                import tensorflow as tf
                os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
                self.model = tf.keras.models.load_model(h5_path, compile=False)
                LOG.info("loaded robot LSTM autoencoder from %s", h5_path)
            except Exception as exc:  # noqa: BLE001
                LOG.error("failed to load robot_lstm.h5: %s", exc)

    @property
    def ready(self) -> bool:
        return self.model is not None and self.thr is not None

    def score(self, window_raw: np.ndarray) -> dict:
        """window_raw: (WINDOW_LEN, N_CHANNELS) in physical units."""
        # Idle gate: a resting arm (all joints nearly static — between cycles or a
        # legitimate halt/E-stop) is NOT an anomaly. The model is trained on active
        # motion, so only score when the arm is actually operating. A frozen-JOINT
        # attack still has other joints moving, so it stays "active" and is scored.
        pos = np.asarray(window_raw, dtype=np.float64)[:, :N_JOINTS]
        if float(np.max(np.std(pos, axis=0))) < MOTION_ACTIVE_THRESH:
            return {
                "robot_z": 0.0, "recon_error": 0.0, "envelope_hits": [],
                "top_channels": [], "anomaly": False, "idle": True,
                "model_version": ROBOT_FEATURE_VERSION,
            }
        env_hits = envelope_violations(window_raw, self.envelope) if self.envelope else []
        ws = standardize(window_raw, self.mean, self.std).astype(np.float32)
        recon = self.model(ws[None, ...], training=False).numpy()[0]
        err = recon_error(ws, recon)
        baseline_mean = float(self.thr["baseline_recon_mean"])
        baseline_std = float(self.thr["baseline_recon_std"])
        z = (err - baseline_mean) / max(baseline_std, 1e-9)
        anomaly = bool(z >= self.z_alert or len(env_hits) > 0)
        return {
            # Non-negative gauge: a z below 0 = reconstructs better than baseline =
            # perfectly normal motion, so floor to 0 (the anomaly test above uses raw z).
            "robot_z": float(max(0.0, z)),
            "recon_error": float(err),
            "envelope_hits": env_hits,
            "top_channels": top_channels(ws, recon, 3),
            "anomaly": anomaly,
            "model_version": ROBOT_FEATURE_VERSION,
        }


# ─── window construction from the rolling stream file ────────────────────────

def _read_positions(path: str) -> tuple[Optional[np.ndarray], float]:
    """Return (positions (N,6), file_mtime) or (None, 0) if unusable."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None, 0.0
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    pos = d.get("position") or []
                    if len(pos) >= 6:
                        rows.append([float(x) for x in pos[:6]])
                except (ValueError, TypeError):
                    continue
    except OSError:
        return None, 0.0
    if not rows:
        return None, st.st_mtime
    return np.asarray(rows, dtype=np.float64), st.st_mtime


def _latest_window(positions: np.ndarray) -> Optional[np.ndarray]:
    """Most-recent (WINDOW_LEN, N_CHANNELS) window; velocity derived over the
    whole buffer so the leading velocity is real (matches training windows)."""
    if positions is None or positions.shape[0] < WINDOW_LEN:
        return None
    ch = derive_channels(positions)
    return ch[-WINDOW_LEN:]


def _write_scores(rec: dict) -> None:
    try:
        p = Path(SCORES_FILE)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rec))
    except Exception:  # noqa: BLE001
        pass


def _signature(res: dict) -> tuple[str, int]:
    """Human signature + severity from the score result."""
    hits = res.get("envelope_hits") or []
    if hits:
        return f"AI: robot physical-limit breach ({hits[0]})", 1
    top = res.get("top_channels") or []
    detail = top[0] if top else "joint dynamics"
    return f"AI: robot motion anomaly (LSTM, {detail})", 2


# ─── demo injection (synthetic tampered window → real LSTM) ──────────────────

def _read_trigger() -> Optional[dict]:
    if not os.path.exists(TRIGGER_FILE):
        return None
    try:
        with open(TRIGGER_FILE, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except (ValueError, OSError):
        return None
    started = float(d.get("started_at", 0.0))
    dur = float(d.get("duration_s", 8.0))
    if started <= 0 or time.time() > started + dur:
        return None
    return d


def _synthetic_attack_window(attack_type: str) -> Optional[np.ndarray]:
    """Build a tampered raw window using the same generators the model was
    evaluated against (real model, synthetic input — like the Modbus demo)."""
    try:
        import random
        from model.robot_datasets import _normal_positions, ATTACK_GENERATORS, ATTACK_TYPES
        atk = attack_type if attack_type in ATTACK_GENERATORS else ATTACK_TYPES[0]
        rng = random.Random(int(time.time()))
        base = _normal_positions(10.0, 7.0, rng)
        pos = ATTACK_GENERATORS[atk](base, rng)
        ch = derive_channels(pos)
        return ch[-WINDOW_LEN:]
    except Exception as exc:  # noqa: BLE001
        LOG.debug("synthetic attack window failed: %s", exc)
        return None


def main() -> int:
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)
    LOG.info("robot_consumer starting: stream=%s models=%s", STREAM_FILE, MODELS_DIR)

    # Wait for the model to be trained (entrypoint trains on boot).
    scorer = RobotScorer(MODELS_DIR)
    for _ in range(60):
        if scorer.ready or _should_exit:
            break
        LOG.info("robot model not ready yet; retrying...")
        time.sleep(5.0)
        scorer = RobotScorer(MODELS_DIR)
    if not scorer.ready:
        LOG.warning("robot model not present; exiting (will be restarted by supervisor)")
        return 1

    # Redis is optional — without it we still publish live scores to the file.
    r = None
    try:
        import redis
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                        password=REDIS_PASSWORD or None, decode_responses=True)
        r.ping()
        LOG.info("connected to redis %s:%d", REDIS_HOST, REDIS_PORT)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("redis unavailable (%s); scores file only", exc)
        r = None

    consecutive = 0
    last_alert_ts = 0.0

    while not _should_exit:
        now = time.time()
        trig = _read_trigger()
        result: Optional[dict] = None
        injected_type = None

        if trig is not None and _DEMO_MODE:
            injected_type = trig.get("attack_type", "joint_speed_violation")
            win = _synthetic_attack_window(injected_type)
            if win is not None:
                result = scorer.score(win)
        else:
            positions, mtime = _read_positions(STREAM_FILE)
            if positions is not None and (now - mtime) <= STALE_S:
                win = _latest_window(positions)
                if win is not None:
                    result = scorer.score(win)

        if result is not None:
            rec = {"ts": now, **{k: result[k] for k in
                   ("robot_z", "recon_error", "envelope_hits", "top_channels", "anomaly")}}
            if injected_type:
                rec["attack_type"] = injected_type
            _write_scores(rec)

            if result["anomaly"]:
                consecutive += 1
                if (consecutive >= ANOMALY_CONSECUTIVE_REQUIRED
                        and now - last_alert_ts >= ALERT_COOLDOWN_S):
                    last_alert_ts = now
                    consecutive = 0
                    sig, sev = _signature(result)
                    event = {
                        "plane": "robot",
                        "category": "robot-behavior-anomaly",
                        "signature": sig,
                        "severity": sev,
                        "src_ip": ROBOT_SRC_IP,
                        "dst_ip": ROBOT_SRC_IP,
                        "robot_z": result["robot_z"],
                        "envelope_hits": result["envelope_hits"],
                        "top_joints": result["top_channels"],
                        "attack_type": injected_type,
                        "model_version": ROBOT_FEATURE_VERSION,
                    }
                    LOG.warning("ROBOT ANOMALY z=%.2f env=%s top=%s",
                                result["robot_z"], result["envelope_hits"],
                                result["top_channels"])
                    if r is not None:
                        try:
                            r.rpush(ANOMALY_LIST, json.dumps(event))
                        except Exception as exc:  # noqa: BLE001
                            LOG.warning("redis rpush failed: %s", exc)
            else:
                consecutive = 0

        time.sleep(POLL_S)

    LOG.info("robot_consumer exiting")
    return 0


if __name__ == "__main__":
    sys.exit(main())
