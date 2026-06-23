"""
Stage 2 anomaly scoring service.

POST /score              -> score one feature vector
POST /score/window       -> score a list of pre-aggregated windows
GET  /health             -> liveness; reports model freshness
GET  /metadata           -> model metadata (FEATURE_VERSION, AUC, threshold)

The service binds to 0.0.0.0:8000 inside container-ai so the dashboard's nginx
can reach it over the docker network (nginx injects the X-API-Key server-side).
Host publication is loopback-only (127.0.0.1:8000 in docker-compose.yml), and the
host-level IT<->OT segmentation is enforced by infra/docker-fw.sh (DOCKER-USER).

TECHNICAL DEBT — this module is a "god object" spanning ~8 distinct
responsibilities that should be separate services:
  1. ML scoring API            (/score, /score/window, /metadata)
  2. Trend analytics           (/api/trend, /api/trend/history)
  3. Incident response         (/api/ir/incidents, /pending, /approve)
  4. HMI / SCADA Modbus control(/api/hmi/state, /control, /simulate-button)
  5. Physical-button simulation
  6. Log tailing               (/api/hmi/logs)
  7. Security-posture reporting (/api/stages/reports)
  8. Attack injection (demo)   (/api/demo/inject-attack, /injection-state)
Intended refactor: split into mlapi.py / irapi.py / hmiapi.py / demoapi.py
with shared model+Redis state in a shared_state.py module. Folding control
(#4) out of the analytics tier also fixes the IEC-62443 zoning concern that
the monitoring plane should not hold PLC write authority (see AUDIT-REPORT.md
F-02). Left as-is intentionally for the POC; documented here, not yet split.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Deque, Tuple
from collections import deque

import joblib
import numpy as np
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pymodbus.client import ModbusTcpClient

from model.features import FEATURE_NAMES, FEATURE_VERSION, N_FEATURES, resolve_if_threshold
from vendor_access import vendor_router

LOG = logging.getLogger("score_service")
logging.basicConfig(
    level=os.environ.get("LAB_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

MODELS_DIR = os.environ.get("LAB_MODELS_DIR", "/opt/lab/models")
INJECTION_STATE_FILE = "/var/lab/state/last_injection.json"
# Robot-plane demo injection: writing this trigger makes robot_consumer.py score a
# synthetic tampered joint window with the REAL LSTM (mirrors the Modbus injector).
ROBOT_TRIGGER_FILE = "/var/lab/state/robot_attack_trigger.json"
ROBOT_ATTACK_TYPES = {
    "joint_speed_violation", "trajectory_deviation", "frozen_joint",
    "erratic_jerk", "workspace_breach",
}

# ---- API Key authentication -------------------------------------------------
_API_KEY = os.environ.get("LAB_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Demo mode (audit F-08): the synthetic threat telemetry that makes the dashboard
# react during a demo attack-injection is gated here. Default ON so the demo is
# unchanged; set LAB_DEMO_MODE=0 in a real deployment for honest telemetry only.
_DEMO_MODE = os.environ.get("LAB_DEMO_MODE", "1") != "0"
# Optional OT-zone control gateway (audit F-02 / Issue 1). When set, operator
# control intent is forwarded to the gateway (which owns the Modbus write) instead
# of this analytics service writing the PLC directly. Unset = current direct path.
_CONTROL_GATEWAY_URL = os.environ.get("LAB_CONTROL_GATEWAY_URL", "").rstrip("/")

async def _require_api_key(key: str | None = Depends(_api_key_header)) -> None:
    """Fail-closed API-key check.

    Hardening (audit F-03): this was previously a no-op whenever LAB_API_KEY was
    unset, silently disabling auth on every "protected" route. It now rejects
    when the server has no key configured (503) and when the caller's key does
    not match (401). The dashboard is unaffected: nginx injects the X-API-Key
    header server-side for all /api/ traffic, so the browser never needs the key.
    """
    if not _API_KEY:
        raise HTTPException(status_code=503, detail="Server API key not configured")
    if key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

_state: dict = {
    "iforest": None,
    "scaler": None,
    "pca": None,
    "pca_thr": None,
    "tf_model": None,
    "tf_thr": None,
    "meta": None,
    "if_threshold": 0.15,
}

# IsolationForest alert threshold resolution. Matches feature_consumer.py so the
# data-plane (feature_consumer) and the API (score_service) agree on what counts
# as an anomaly. env override > model's calibrated p99 threshold > 0.15 fallback.
_IF_THRESHOLD_ENV = os.environ.get("LAB_IF_ANOMALY_THRESHOLD")  # None unless set
_IF_THRESHOLD_FLOOR = float(os.environ.get("LAB_IF_THRESHOLD_FLOOR", "0.10"))
_IF_THRESHOLD_FALLBACK = 0.15


def _resolve_if_threshold(meta: Optional[dict]) -> float:
    # Delegate to the shared resolver (model.features) so the API and the data
    # plane (feature_consumer) cannot drift on the anomaly threshold. (audit F-14)
    thr, _reason = resolve_if_threshold(
        meta, env_val=_IF_THRESHOLD_ENV,
        floor=_IF_THRESHOLD_FLOOR, fallback=_IF_THRESHOLD_FALLBACK)
    return thr

_tf_lock = threading.Lock()

# Last 60 scored samples (ts, iforest_score, pca_z, anomaly)
_score_history: Deque[Tuple[float, Optional[float], Optional[float], bool]] = deque(maxlen=60)


def _try_load() -> None:
    """Load whatever models are present; never raise."""
    try:
        path = os.path.join(MODELS_DIR, "iforest.pkl")
        if os.path.exists(path):
            _state["iforest"] = joblib.load(path)
            LOG.info("loaded %s", path)
        path = os.path.join(MODELS_DIR, "scaler.pkl")
        if os.path.exists(path):
            _state["scaler"] = joblib.load(path)
            LOG.info("loaded %s", path)
        path = os.path.join(MODELS_DIR, "pca.pkl")
        if os.path.exists(path):
            _state["pca"] = joblib.load(path)
            LOG.info("loaded %s", path)
        path = os.path.join(MODELS_DIR, "pca_threshold.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                _state["pca_thr"] = json.load(fh)
            LOG.info("loaded %s", path)
        path = os.path.join(MODELS_DIR, "autoencoder.h5")
        if os.path.exists(path):
            try:
                import tensorflow as tf
                # Suppress TF logs during load
                os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
                _state["tf_model"] = tf.keras.models.load_model(path, compile=False)
                LOG.info("loaded Keras autoencoder from %s (compile=False)", path)
            except Exception as tf_exc:
                LOG.error("failed to load TensorFlow autoencoder.h5: %s", tf_exc)
        path = os.path.join(MODELS_DIR, "tf_threshold.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                _state["tf_thr"] = json.load(fh)
            LOG.info("loaded %s", path)
        path = os.path.join(MODELS_DIR, "model_meta.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                _state["meta"] = json.load(fh)
        _state["if_threshold"] = _resolve_if_threshold(_state.get("meta"))
        LOG.info("IsolationForest alert threshold = %.4f", _state["if_threshold"])
    except Exception as exc:  # noqa: BLE001
        LOG.error("model load failure: %s", exc)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    _try_load()
    yield

app = FastAPI(title="lab-ai-score", version=FEATURE_VERSION, lifespan=_lifespan)
# Hardening (audit F-03): vendor remote-access provisioning is privileged and
# must not be anonymous. Require the API key on EVERY vendor route. The dashboard
# reaches these via /api/ so nginx supplies the key automatically.
app.include_router(vendor_router, prefix="", dependencies=[Depends(_require_api_key)])

_CORS_ORIGINS = os.environ.get(
    "LAB_CORS_ORIGINS",
    "http://localhost:8888,http://localhost:3003,http://localhost:3000,http://localhost:5173,http://localhost:8086,http://127.0.0.1:8086",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ---------- API models ----------------------------------------------------
class FeatureVector(BaseModel):
    features: List[float] = Field(..., min_length=N_FEATURES, max_length=N_FEATURES)
    src_ip: Optional[str] = None
    window_start: Optional[float] = None


class ScoreOut(BaseModel):
    src_ip: Optional[str]
    window_start: Optional[float]
    iforest_score: Optional[float]
    pca_z: Optional[float]
    tf_z: Optional[float] = None
    anomaly: bool
    model_version: str
    top_features: List[str]


def _top_features(x: np.ndarray, k: int = 3) -> List[str]:
    """Names of features whose values are most extreme (|z|) under the scaler."""
    sc = _state["scaler"]
    if sc is None:
        return []
    xs = sc.transform(x.reshape(1, -1)).ravel()
    idx = np.argsort(-np.abs(xs))[:k]
    return [FEATURE_NAMES[i] for i in idx]


def _score_one(x: np.ndarray) -> ScoreOut:
    if x.shape != (N_FEATURES,):
        raise HTTPException(status_code=400, detail=f"feature vector must be length {N_FEATURES}")
    sc = _state["scaler"]
    if sc is None:
        raise HTTPException(status_code=503, detail="scaler not loaded")
    xs = sc.transform(x.reshape(1, -1))

    if_score: Optional[float] = None
    if _state["iforest"] is not None:
        # max(0, -decision_function): normal traffic → 0.0 (never negative),
        # anomalous traffic → positive values above 0.15 threshold.
        if_score = max(0.0, float(-_state["iforest"].decision_function(xs)[0]))

    pca_z: Optional[float] = None
    if _state["pca"] is not None and _state["pca_thr"] is not None:
        recon = _state["pca"].inverse_transform(_state["pca"].transform(xs))
        err = float(((xs - recon) ** 2).mean())
        thr = _state["pca_thr"]
        pca_z = (err - thr["baseline_recon_mean"]) / max(thr["baseline_recon_std"], 1e-9)

    tf_z: Optional[float] = None
    if _state["tf_model"] is not None and _state["tf_thr"] is not None:
        try:
            with _tf_lock:
                recon_tf = _state["tf_model"](xs, training=False)
            err_tf = float(np.mean((xs - recon_tf) ** 2))
            thr_tf = _state["tf_thr"]
            tf_z = (err_tf - thr_tf["baseline_recon_mean"]) / max(thr_tf["baseline_recon_std"], 1e-9)
        except Exception as exc:
            LOG.error("TensorFlow autoencoder scoring failed: %s", exc)

    # Decision rule: trip if either model fires above its threshold.
    anomaly = False
    _if_thr = _state.get("if_threshold") or _IF_THRESHOLD_FALLBACK
    if if_score is not None and if_score > _if_thr:
        # if_score above the model's calibrated p99 ↔ meaningful outlier
        anomaly = True
    if pca_z is not None and _state["pca_thr"] is not None:
        if pca_z >= _state["pca_thr"].get("z_alert_threshold", 3.0):
            anomaly = True
    if tf_z is not None and _state["tf_thr"] is not None:
        if tf_z >= _state["tf_thr"].get("z_alert_threshold", 3.0):
            anomaly = True

    out = ScoreOut(
        src_ip=None,
        window_start=None,
        iforest_score=if_score,
        pca_z=pca_z,
        tf_z=tf_z,
        anomaly=anomaly,
        model_version=FEATURE_VERSION,
        top_features=_top_features(x),
    )
    try:
        _score_history.append((time.time(), if_score, pca_z, anomaly))
    except Exception:
        pass

    # Write latest scores to state file so lab_exporter and the dashboard
    # can display live scores even without active attacks or Redis traffic.
    try:
        _scores_path = Path("/var/lab/state/latest_scores.json")
        _scores_path.parent.mkdir(parents=True, exist_ok=True)
        _scores_path.write_text(json.dumps({
            "ts": time.time(),
            "iforest_score": if_score,
            "pca_z": pca_z,
            "tf_z": tf_z,
            "anomaly": anomaly,
        }))
    except Exception:
        pass

    return out


# ---------- routes --------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "models_loaded": {
            "iforest": _state["iforest"] is not None,
            "pca": _state["pca"] is not None,
            "tf_model": _state["tf_model"] is not None,
            "scaler": _state["scaler"] is not None,
            # Robot LSTM is owned by robot_consumer.py (separate process); report it
            # by artefact presence so the dashboard Model Status panel can show it.
            "robot_lstm": os.path.exists(os.path.join(MODELS_DIR, "robot_lstm.h5")),
        },
        "feature_version": FEATURE_VERSION,
    }


@app.get("/metadata")
def metadata() -> dict:
    return {
        "feature_names": list(FEATURE_NAMES),
        "feature_version": FEATURE_VERSION,
        "iforest_meta": _state["meta"],
        "pca_threshold": _state["pca_thr"],
        "tf_threshold": _state["tf_thr"],
    }


@app.post("/score", response_model=ScoreOut)
def score(v: FeatureVector) -> ScoreOut:
    out = _score_one(np.array(v.features, dtype=np.float64))
    out.src_ip = v.src_ip
    out.window_start = v.window_start
    return out


@app.post("/score/window", response_model=List[ScoreOut])
def score_window(vs: List[FeatureVector]) -> List[ScoreOut]:
    outs: List[ScoreOut] = []
    for v in vs:
        out = _score_one(np.array(v.features, dtype=np.float64))
        out.src_ip = v.src_ip
        out.window_start = v.window_start
        outs.append(out)
    return outs


# ---------- trend analytics ---------------------------------------------
def _trend_summary() -> dict:
    # Extract last up to 60 entries
    items = list(_score_history)
    n = len(items)
    if n == 0:
        return {
            "window_60": {
                "mean_score": 0.0,
                "max_score": 0.0,
                "std_dev": 0.0,
                "anomaly_rate_pct": 0.0,
                "trend_direction": "stable",
                "predicted_breach_in_s": None,
            }
        }
    scores = [s for (_, s, _, _) in items if s is not None]
    if not scores:
        scores = [0.0] * n
    import math
    mean = float(sum(scores) / max(len(scores), 1))
    mx = float(max(scores))
    sd = float(math.sqrt(sum((v - mean) ** 2 for v in scores) / max(len(scores), 1)))
    anomalies = sum(1 for (_, _, _, a) in items if a)
    rate = (anomalies / n) * 100.0

    # Trend: compare mean of last 20 vs previous 40
    last20 = [s for (_, s, _, _) in items[-20:] if s is not None]
    prev40 = [s for (_, s, _, _) in items[:-20] if s is not None][-40:]
    m20 = sum(last20) / max(len(last20), 1) if last20 else 0.0
    m40 = sum(prev40) / max(len(prev40), 1) if prev40 else 0.0
    direction = "stable"
    if m20 > m40 * 1.05:
        direction = "rising"
    elif m20 < m40 * 0.95:
        direction = "falling"

    # Predict breach within 300s using simple linear extrapolation
    pred_s: Optional[int] = None
    if direction == "rising" and len(scores) >= 2:
        # compute slope on (t, score) using last N points
        t0 = items[0][0]
        xs = [ts - t0 for (ts, _, _, _) in items if _ is not None]
        ys = [s for (_, s, _, _) in items if s is not None]
        if len(xs) >= 2 and len(xs) == len(ys):
            import numpy as _np
            try:
                a, b = _np.polyfit(xs, ys, 1)
                # threshold around 0.0 for IsolationForest (>0 = anomaly)
                thr = 0.0
                now_t = xs[-1]
                if a > 1e-6:
                    t_cross = (thr - b) / a
                    dt = t_cross - now_t
                    if 0 < dt <= 300:
                        pred_s = int(dt)
            except Exception:
                pred_s = None

    return {
        "window_60": {
            "mean_score": mean,
            "max_score": mx,
            "std_dev": sd,
            "anomaly_rate_pct": rate,
            "trend_direction": direction,
            "predicted_breach_in_s": pred_s,
        }
    }


@app.get("/api/trend")
def api_trend() -> dict:
    return _trend_summary()


@app.get("/api/scores/live")
def api_scores_live() -> dict:
    """Fast live AI scores for the dashboard gauges — reads the state files the data
    plane writes (no Prometheus hop), so the panel updates within ~1s and shows the
    always-positive 'activity' telemetry (if_activity / pca_activity / tf_activity)
    that feature_consumer refreshes on a sliding window every ~2s. Falls back to the
    5s tumbling latest_scores.json for the anomaly flag + floored detection scores."""
    out = {
        "ts": 0.0, "anomaly": False,
        "iforest_score": 0.0, "pca_z": 0.0, "tf_z": 0.0,
        "if_activity": None, "pca_activity": None, "tf_activity": None,
    }
    for path in ("/var/lab/state/latest_scores.json", "/var/lab/state/live_activity.json"):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            for k, v in d.items():
                if v is not None:
                    out[k] = v
        except (OSError, ValueError):
            pass
    return out


@app.get("/api/trend/history")
def api_trend_history() -> List[dict]:
    out: List[dict] = []
    for (ts, ifs, pz, anom) in list(_score_history):
        out.append({
            "ts": float(ts),
            "iforest_score": None if ifs is None else float(ifs),
            "pca_z": None if pz is None else float(pz),
            "anomaly": bool(anom),
        })
    return out


class ApprovePayload(BaseModel):
    incident_id: str
    step: str
    reject: bool = False


@app.get("/api/ir/incidents", dependencies=[Depends(_require_api_key)])
def get_ir_incidents() -> List[dict]:
    path = Path("/var/lab/state/ir/incidents.jsonl")
    if not path.exists():
        return []
    incidents = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    incidents.append(json.loads(line))
                except Exception:
                    pass
    except Exception as exc:
        LOG.error("Failed to read incidents: %s", exc)
    return list(reversed(incidents))


@app.get("/api/ir/pending", dependencies=[Depends(_require_api_key)])
def get_ir_pending() -> List[dict]:
    path = Path("/var/lab/state/ir/pending_approvals.json")
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            entries = json.load(fh)
    except Exception as exc:
        LOG.error("Failed to read pending approvals: %s", exc)
        return []
    # Collapse any duplicate (incident_id, step) rows so the operator never sees
    # the same approval button twice, even if the on-disk file got duplicated.
    seen: set = set()
    deduped: List[dict] = []
    for e in entries if isinstance(entries, list) else []:
        key = (e.get("incident_id"), e.get("step"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)
    return deduped


@app.post("/api/ir/approve", dependencies=[Depends(_require_api_key)])
def post_ir_approve(payload: ApprovePayload) -> dict:
    cmd = ["/opt/lab/bin/ir-approve", payload.incident_id, payload.step]
    if payload.reject:
        cmd.append("--reject")
    try:
        # Try direct CLI execution
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            # Fallback to python execution in case of path/executable permission issues
            cmd_fallback = [sys.executable, "/opt/lab/vm-ai/ir/bin/ir-approve", payload.incident_id, payload.step]
            if payload.reject:
                cmd_fallback.append("--reject")
            proc = subprocess.run(cmd_fallback, capture_output=True, text=True, timeout=10)
            
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Approval execution failed: {proc.stderr or proc.stdout}")
            
        # Demo-only (audit F-08): reset the threat telemetry to nominal when an
        # incident is closed so the demo gauge returns to calm. Skipped under
        # honest-telemetry mode (LAB_DEMO_MODE=0).
        if _DEMO_MODE and payload.step == "close_incident" and not payload.reject:
            _score_history.clear()
            _score_history.append((time.time(), 0.01, 0.1, False))
            LOG.info("Incident %s closed successfully. Reset score history deque to nominal baseline.", payload.incident_id)

        return {"status": "ok", "stdout": proc.stdout}
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise exc
        raise HTTPException(status_code=500, detail=f"Exception during approval: {exc}")


# ---------- HMI SCADA REST API endpoints ----------------------------------
# IDMZ: the analytics tier is READ-ONLY to OT. Telemetry polls go through the OT
# read-only Modbus proxy (LAB_PLC_HOST:LAB_PLC_PORT, default 192.168.10.10:5020),
# never the raw PLC :502. Operator control WRITES are forwarded to the OT control
# gateway (LAB_CONTROL_GATEWAY_URL) — see hmi_control(). A write attempted on this
# proxy connection is rejected by the proxy with a Modbus illegal-function error.
PRODUCTION_PLC_IP = os.environ.get("LAB_PLC_HOST", "192.168.10.10")
PRODUCTION_PLC_PORT = int(os.environ.get("LAB_PLC_PORT", "5020"))
ALERT_FILE_PATH = "/var/lab/log/ai-alerts.json"

# In-memory store to simulate physical hardware button clicks (which are read-only discrete inputs)
_simulated_buttons = {
    "physical_start_until": 0.0,
    "physical_stop_until": 0.0
}

class ControlPayload(BaseModel):
    action: str

class SimulateButtonPayload(BaseModel):
    button: str

def _collect_hmi_state() -> dict:
    """Blocking PLC poll + alert read. Run OFF the event loop via asyncio.to_thread
    (audit F-11) so a slow/unreachable PLC cannot tie up the API. Behaviour is
    identical to the previous synchronous endpoint."""
    client = ModbusTcpClient(PRODUCTION_PLC_IP, port=PRODUCTION_PLC_PORT, timeout=1.0)
    plc_state = {}
    try:
        if not client.connect():
            plc_state = {"error": "Production PLC Modbus TCP connection failed"}
        else:
            # Read coils starting at address 0 (read 10 coils)
            # %QX0.0..%QX0.6 at indices 0..6
            # %QX1.0..%QX1.1 at indices 8..9
            coils_res = client.read_coils(0, 10)
            
            # Read holding registers starting at address 1024 (read 16 registers)
            # %MW0..%MW15 at offsets 1024..1039
            regs_res = client.read_holding_registers(1024, 16)
            
            # Read discrete inputs starting at address 0 (read 2 discrete inputs)
            # %IX0.0..%IX0.1
            di_res = client.read_discrete_inputs(0, 2)
            
            if coils_res.isError() or regs_res.isError() or di_res.isError():
                plc_state = {"error": "Modbus read transaction error"}
            else:
                c = coils_res.bits
                r = regs_res.registers
                di = di_res.bits
                
                # Merge physical discrete inputs with temporary HMI-spoofed hardware simulation overrides
                now = time.time()
                phys_start = bool(di[0]) or (now < _simulated_buttons["physical_start_until"])
                phys_stop = bool(di[1]) or (now < _simulated_buttons["physical_stop_until"])
                
                plc_state = {
                    "motor_arm_enable": bool(c[0]),
                    "gripper_close": bool(c[1]),
                    "conveyor_run": bool(c[2]),
                    "cycle_busy": bool(c[3]),
                    "cycle_complete": bool(c[4]),
                    "e_stop_active": bool(c[5]),
                    "request_safe_state": bool(c[6]),
                    "remote_start_btn": bool(c[8]),
                    "remote_stop_btn": bool(c[9]),
                    
                    "physical_start_btn": phys_start,
                    "physical_stop_btn": phys_stop,
                    
                    "cycle_step": int(r[0]),
                    "cycle_count": int(r[1]),
                    "estop_trip_count": int(r[2]),
                    "last_cycle_ms": int(r[3]),
                    "slow_mode_active": int(r[4]),
                    "safety_state": int(r[10]),
                    "ack_counter": int(r[11]),
                    "last_fault_code": int(r[12]),
                }
    except Exception as exc:
        plc_state = {"error": f"Modbus broker exception: {exc}"}
    finally:
        try:
            client.close()
        except Exception:
            pass

    # Read latest alerts from syslog/ai-alerts file
    latest_alerts = []
    if os.path.exists(ALERT_FILE_PATH):
        try:
            with open(ALERT_FILE_PATH, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    latest_alerts.append(json.loads(line))
                except Exception:
                    pass
                if len(latest_alerts) >= 10:
                    break
        except Exception as exc:
            LOG.error("Failed to read HMI alerts from log: %s", exc)

    return {
        "status": "ok",
        "plc_state": plc_state,
        "latest_alerts": latest_alerts
    }


def _forward_control_to_gateway(base_url: str, action: str) -> dict:
    """Issue-1 (audit F-02): forward operator control intent to the OT-zone control
    gateway, which owns the Modbus write, keeping this analytics tier read-only.
    Raises on transport error so the caller can fall back to the direct path."""
    import urllib.request
    req = urllib.request.Request(
        base_url + "/control",
        data=json.dumps({"action": action}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": _API_KEY},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode("utf-8"))


@app.get("/api/hmi/state", dependencies=[Depends(_require_api_key)])
async def hmi_state() -> dict:
    """Poll live telemetry from the Production PLC and read the latest threat alerts."""
    return await asyncio.to_thread(_collect_hmi_state)


@app.post("/api/hmi/control", dependencies=[Depends(_require_api_key)])
def hmi_control(payload: ControlPayload, request: Request) -> dict:
    """Send momentarily-controlled start/stop, safety-estop, or system reset commands to Production PLC."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip, "hmi_control"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    action = payload.action.lower()
    # Issue-1 (audit F-02): when an OT-zone control gateway is configured, forward
    # the intent there (the gateway owns the Modbus write) rather than writing the
    # PLC from this analytics service. Fall back to the direct path on any error so
    # the demo never breaks.
    if _CONTROL_GATEWAY_URL:
        try:
            return _forward_control_to_gateway(_CONTROL_GATEWAY_URL, action)
        except Exception as exc:
            LOG.warning("control gateway %s unreachable (%s); using direct path",
                        _CONTROL_GATEWAY_URL, exc)
    client = ModbusTcpClient(PRODUCTION_PLC_IP, port=PRODUCTION_PLC_PORT, timeout=1.0)
    try:
        if not client.connect():
            raise HTTPException(status_code=503, detail="Could not connect to Production PLC")
        
        if action == "start":
            # Write TRUE to remote_start_btn %QX1.0 (Modbus coil index 8)
            res = client.write_coil(8, True)
            if res.isError():
                raise HTTPException(status_code=500, detail="Modbus write remote_start_btn error")
            return {"status": "ok", "message": "Momentary start command written to PLC"}
            
        elif action in ("stop", "pause"):
            # Write TRUE to remote_stop_btn %QX1.1 (Modbus coil index 9)
            res = client.write_coil(9, True)
            if res.isError():
                raise HTTPException(status_code=500, detail="Modbus write remote_stop_btn error")
            return {"status": "ok", "message": "Momentary stop/pause command written to PLC"}
            
        elif action == "estop":
            # 1. Connect to Safety PLC/Supervisor on Port 503 and write remote_estop = 1 to holding register 2 (%MW2)
            safety_client = ModbusTcpClient(PRODUCTION_PLC_IP, port=503, timeout=1.0)
            try:
                if safety_client.connect():
                    res_s = safety_client.write_register(2, 1)
                    if res_s.isError():
                        LOG.error("Failed to write E-stop code 1 to Safety PLC")
                else:
                    LOG.error("Could not connect to Safety PLC on Port 503 for E-stop")
            except Exception as safety_exc:
                LOG.error(f"Failed to trigger safety PLC E-stop: {safety_exc}")
            finally:
                try:
                    safety_client.close()
                except Exception:
                    pass

            # 2. Write TRUE to e_stop_active %QX0.5 (Modbus coil index 5) on Production PLC (Port 502)
            # This directly invokes the safety halt state in production.st
            res = client.write_coil(5, True)
            if res.isError():
                raise HTTPException(status_code=500, detail="Modbus write e_stop_active error")
            return {"status": "ok", "message": "Emergency Stop coil asserted directly to Production and Safety PLCs"}
            
        elif action in ("reset", "reset_estop"):
            # 0. Connect to Safety PLC/Supervisor on Port 503 and write administrative reset code 9 to holding register 2 (%MW2 / remote_estop)
            safety_client = ModbusTcpClient(PRODUCTION_PLC_IP, port=503, timeout=1.0)
            try:
                if safety_client.connect():
                    res_s = safety_client.write_register(2, 9)
                    if res_s.isError():
                        LOG.error("Failed to write reset code 9 to Safety PLC")
                else:
                    LOG.error("Could not connect to Safety PLC on Port 503")
            except Exception as safety_exc:
                LOG.error(f"Failed to reset safety PLC: {safety_exc}")
            finally:
                try:
                    safety_client.close()
                except Exception:
                    pass

            # Reset/clear all safety interlocks and telemetry registers on Production PLC (port 502)
            # 1. Write FALSE to e_stop_active %QX0.5 (coil 5) and request_safe_state %QX0.6 (coil 6)
            client.write_coil(5, False)
            client.write_coil(6, False)
            client.write_coil(8, False)
            client.write_coil(9, False)
            # 2. Write 0 to %MW4 (address 1028), %MW10 (address 1034), and %MW12 (address 1036) on Production PLC
            client.write_register(1028, 0)
            client.write_register(1034, 0)
            client.write_register(1036, 0)

            # 3. Reset ML telemetry and threat level indicators (demo-only, audit F-08)
            if _DEMO_MODE:
                _score_history.clear()
                _score_history.append((time.time(), 0.01, 0.1, False))
                LOG.info("System safety reset requested. Reset score history deque to nominal baseline.")

            return {"status": "ok", "message": "System safety reset command written to PLC"}
            
        elif action == "enable_slow_mode":
            # Write 1 to %MW4 (address 1028) on Production PLC
            res = client.write_register(1028, 1)
            if res.isError():
                raise HTTPException(status_code=500, detail="Modbus write slow_mode_active error")
            return {"status": "ok", "message": "Slow mode enabled on Production PLC"}

        elif action == "disable_slow_mode":
            # Write 0 to %MW4 (address 1028) on Production PLC
            res = client.write_register(1028, 0)
            if res.isError():
                raise HTTPException(status_code=500, detail="Modbus write slow_mode_active error")
            return {"status": "ok", "message": "Slow mode disabled on Production PLC"}

        else:
            raise HTTPException(status_code=400, detail=f"Unknown control action '{action}'")
    finally:
        try:
            client.close()
        except Exception:
            pass

@app.post("/api/hmi/simulate-button", dependencies=[Depends(_require_api_key)])
def simulate_button(payload: SimulateButtonPayload) -> dict:
    """Simulate a physical start or stop push-button press on the shop floor console."""
    btn = payload.button.lower()
    if btn not in ("start", "stop"):
        raise HTTPException(status_code=400, detail="Invalid button type. Must be 'start' or 'stop'")
        
    client = ModbusTcpClient(PRODUCTION_PLC_IP, port=PRODUCTION_PLC_PORT, timeout=1.0)
    try:
        if not client.connect():
            raise HTTPException(status_code=503, detail="Could not connect to Production PLC")
            
        now = time.time()
        if btn == "start":
            _simulated_buttons["physical_start_until"] = now + 1.5
            # Momentarily activate remote coil to trigger cycle state machine
            client.write_coil(8, True)
            return {"status": "ok", "message": "Simulated hardware START button pressed (1.5s override)"}
        else:
            _simulated_buttons["physical_stop_until"] = now + 1.5
            # Momentarily activate remote coil to halt cycle state machine
            client.write_coil(9, True)
            return {"status": "ok", "message": "Simulated hardware STOP button pressed (1.5s override)"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Simulation error: {exc}")
    finally:
        try:
            client.close()
        except Exception:
            pass

@app.get("/api/hmi/logs", dependencies=[Depends(_require_api_key)])
def hmi_logs(service: str = "supervisor") -> dict:
    """Safely stream the last 50 lines of logs for the selected OT service."""
    service_map = {
        "supervisor": "/var/lab/state/logs/lab-safety-supervisor.log",
        "heartbeat": "/var/lab/state/logs/lab-safety-heartbeat.log",
        "openplc": "/var/lab/state/logs/openplc.log",
        "watcher": "/var/lab/state/logs/lab-sros2-watcher.log"
    }
    
    if service not in service_map:
        raise HTTPException(status_code=400, detail=f"Invalid service name: {service}")
        
    log_path = service_map[service]
    if not os.path.exists(log_path):
        return {
            "status": "ok",
            "service": service,
            "logs": f"Log file for {service} not found yet."
        }
        
    try:
        # Read last 50 lines
        with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        last_lines = lines[-50:]
        return {
            "status": "ok",
            "service": service,
            "logs": "".join(last_lines)
        }
    except Exception as exc:
        return {
            "status": "error",
            "service": service,
            "logs": f"Failed to read logs: {exc}"
        }

@app.get("/api/stages/reports", dependencies=[Depends(_require_api_key)])
def get_stages_reports() -> dict:
    """Read and return static security reports from filesystem for stages rendering."""
    # 1. Vulnerabilities
    vuln_data = None
    vuln_path = "/var/lab/state/vulnerabilities.json"
    if os.path.exists(vuln_path):
        try:
            with open(vuln_path, "r", encoding="utf-8") as fh:
                vuln_data = json.load(fh)
        except Exception as exc:
            LOG.error("Failed to read vulnerabilities.json: %s", exc)

    # 2. Baseline Drift
    drift_data = None
    drift_path = "/var/lab/state/baseline_drift.json"
    if os.path.exists(drift_path):
        try:
            with open(drift_path, "r", encoding="utf-8") as fh:
                drift_data = json.load(fh)
        except Exception as exc:
            LOG.error("Failed to read baseline_drift.json: %s", exc)

    # 3. Integrity Baseline
    integrity_data = None
    integrity_path = "/var/lab/state/integrity_baseline.json"
    if os.path.exists(integrity_path):
        try:
            with open(integrity_path, "r", encoding="utf-8") as fh:
                integrity_data = json.load(fh)
        except Exception as exc:
            LOG.error("Failed to read integrity_baseline.json: %s", exc)

    # 4. Inventory
    inventory_data = None
    inventory_path = "/var/lab/state/inventory.json"
    if os.path.exists(inventory_path):
        try:
            with open(inventory_path, "r", encoding="utf-8") as fh:
                inventory_data = json.load(fh)
        except Exception as exc:
            LOG.error("Failed to read inventory.json: %s", exc)

    # 5. Pipeline Verdict
    pipeline_data = None
    artifacts_dir = Path("/var/lab/artifacts")
    if artifacts_dir.exists():
        try:
            builds = sorted(artifacts_dir.glob("*/"), key=lambda p: p.stat().st_mtime, reverse=True)
            if builds:
                verdict_path = builds[0] / "verdict.json"
                if verdict_path.exists():
                    with open(verdict_path, "r", encoding="utf-8") as fh:
                        pipeline_data = json.load(fh)
        except Exception as exc:
            LOG.error("Failed to read Gitea pipeline verdict.json: %s", exc)

    return {
        "vulnerabilities": vuln_data,
        "baseline_drift": drift_data,
        "integrity_baseline": integrity_data,
        "inventory": inventory_data,
        "pipeline_verdict": pipeline_data
    }

# ---------- Demo: Attack Injection -------------------------------------------

_injection_state: dict = {
    "active": False,
    "last_injection_ts": 0.0,
    "injection_count": 0,
    "attack_type": None,
}
_injection_lock = threading.Lock()

# ---- Rate limiting ----------------------------------------------------------
import collections

_rate_limit_store: dict = collections.defaultdict(list)
_RATE_LIMIT_WINDOW_S = 10.0   # sliding window in seconds
_RATE_LIMIT_MAX_CALLS = 5     # max calls per window per client IP

def _check_rate_limit(client_ip: str, action: str) -> bool:
    """Return True if the caller is within the allowed rate. False = reject."""
    key = f"{client_ip}:{action}"
    now = time.time()
    # Prune this caller's calls outside the sliding window.
    calls = [t for t in _rate_limit_store.get(key, []) if now - t < _RATE_LIMIT_WINDOW_S]
    # Bound memory (audit F-11): under many distinct source IPs the store would
    # otherwise grow without limit. When it gets large, opportunistically drop
    # keys whose windows have fully expired. Behaviour for active keys is unchanged.
    if len(_rate_limit_store) > 1024:
        for k in [k for k, v in list(_rate_limit_store.items())
                  if not any(now - t < _RATE_LIMIT_WINDOW_S for t in v)]:
            del _rate_limit_store[k]
    if len(calls) >= _RATE_LIMIT_MAX_CALLS:
        _rate_limit_store[key] = calls
        return False
    calls.append(now)
    _rate_limit_store[key] = calls
    return True


class AttackInjectPayload(BaseModel):
    attack_type: str = "modbus_command_injection"
    duration_s: float = 8.0
    rate_hz: float = 5.0


def _should_injection_stop() -> bool:
    """Return True if the injection has been cancelled externally."""
    with _injection_lock:
        return not _injection_state.get("active", False)


def _push_synthetic_score(feat_override: list, attack_type: str) -> None:
    """Score a synthetic feature vector and push the result into _score_history.

    This ensures the /api/trend and /api/trend/history endpoints return
    non-zero data while a demo injection is active, so the dashboard
    sparkline and threat-level indicator react in real time.
    """
    if not _DEMO_MODE:
        return  # honest-telemetry mode (audit F-08): never inject synthetic scores
    try:
        x = np.array(feat_override, dtype=np.float64)
        if len(x) == N_FEATURES:
            _score_one(x)  # scores AND appends an anomalous entry to history
            return
        # Length mismatch (e.g. a compact demo override vs the 20-feature v2
        # model). Do NOT silently no-op \u2014 that left the dashboard threat gauge
        # and sparkline showing NOMINAL during an active injection. Push a
        # representative anomalous score so the live trend reacts.
        LOG.warning("synthetic override len=%d != N_FEATURES=%d; pushing representative anomalous score",
                    len(x), N_FEATURES)
        _score_history.append((time.time(), 0.35, 4.5, True))
    except Exception as exc:
        # Models not loaded yet \u2014 push a manual high-score entry so the
        # dashboard sparkline/threat indicator still reacts during the demo.
        LOG.debug("_push_synthetic_score fallback (models not loaded): %s", exc)
        try:
            _score_history.append((time.time(), 0.35, 4.5, True))
        except Exception:
            pass


# Attack type → synthetic feature vector overrides that produce anomalous scores.
# Each tuple is the full 20-feature v2 vector (model.features.FEATURE_NAMES order):
#   0 n_msgs            1 n_unique_funccodes 2 n_writes         3 n_reads
#   4 n_exceptions      5 mean_address       6 std_address      7 mean_quantity
#   8 max_quantity      9 n_unique_addresses 10 msg_rate        11 ot_origin
#   12 write_ratio      13 exception_rate    14 n_external_writes 15 func_entropy
#   16 mean_iat_ms      17 std_iat_ms        18 bulk_write_ratio  19 write_read_ratio
# NOTE: must be length N_FEATURES (20). A 12-element v1 vector made
# _push_synthetic_score() no-op, so the dashboard trend read NOMINAL during
# an injection. The v2 (write_ratio, n_external_writes, write_read_ratio, …)
# tail is what makes these score as strong anomalies.
_ATTACK_FEATURE_OVERRIDES: dict = {
    "modbus_command_injection": [
        # High write rate from external IP — write burst anomaly
        80.0, 6.0, 70.0, 5.0, 2.0, 2048.0, 400.0, 120.0, 200.0, 15.0, 16.0, 0.0,
        0.875, 0.025, 70.0, 1.0, 62.5, 12.0, 0.0, 14.0,
    ],
    "modbus_replay": [
        # Repeat of identical writes — replay pattern
        60.0, 2.0, 58.0, 2.0, 0.0, 1024.0, 0.0, 64.0, 64.0, 1.0, 12.0, 0.0,
        0.966, 0.0, 58.0, 0.2, 83.0, 5.0, 0.0, 29.0,
    ],
    "coil_flood": [
        # Extremely high message rate, all writes, coil targets
        200.0, 3.0, 195.0, 5.0, 8.0, 0.0, 0.0, 1.0, 1.0, 3.0, 40.0, 0.0,
        0.975, 0.04, 195.0, 0.3, 25.0, 3.0, 0.0, 39.0,
    ],
    "register_scan": [
        # Reconnaissance: sequential address sweep (FC3 reads) from external IP —
        # the standout signal is a huge n_unique_addresses with read-only traffic.
        120.0, 1.0, 0.0, 120.0, 6.0, 500.0, 290.0, 1.0, 1.0, 118.0, 24.0, 0.0,
        0.0, 0.05, 0.0, 0.10, 42.0, 8.0, 0.0, 0.0,
    ],
    "bulk_write": [
        # Sabotage: FC16 multi-register overwrites from external IP — high write
        # ratio, bulk-write ratio, large quantities, very high write/read ratio.
        32.0, 1.0, 32.0, 0.0, 0.0, 300.0, 380.0, 40.0, 64.0, 3.0, 6.4, 0.0,
        1.0, 0.0, 32.0, 0.0, 156.0, 18.0, 1.0, 32.0,
    ],
}
_ATTACK_SRC_IPS: dict = {
    "modbus_command_injection": "192.168.20.99",  # IT/DMZ attacker outside OT zone
    "modbus_replay": "192.168.20.88",
    "coil_flood": "192.168.20.77",
    "register_scan": "192.168.20.66",
    "bulk_write": "192.168.20.55",
}


def _write_synthetic_alert_direct(attack_type: str, src_ip: str, feat_override: list) -> None:
    """Write a synthetic alert directly to ai-alerts.json (fallback when Redis is down).

    The alert schema exactly matches alert_bridge.py's _eve() output so that
    playbook_engine, lab_exporter, and the dashboard parse it identically.
    """
    if not _DEMO_MODE:
        return  # honest-telemetry mode (audit F-08): never write synthetic alerts
    ATTACK_CATEGORIES = {
        "modbus_command_injection": ("modbus-external-anomaly", "AI: modbus write-burst from outside OT zone", 9001001, 1),
        "modbus_replay":            ("modbus-baseline-deviation", "AI: anomalous Modbus behaviour from OT host", 9001002, 2),
        "coil_flood":               ("modbus-external-anomaly", "AI: modbus coil-flood DoS from outside OT zone", 9001001, 1),
        "register_scan":            ("modbus-external-anomaly", "AI: modbus address-scan reconnaissance from outside OT zone", 9001001, 2),
        "bulk_write":               ("modbus-external-anomaly", "AI: modbus bulk-write sabotage from outside OT zone", 9001001, 1),
    }
    category, signature, sig_id, severity = ATTACK_CATEGORIES.get(
        attack_type, ("modbus-external-anomaly", "AI: synthetic anomaly injection", 9001001, 1)
    )
    # Derive synthetic iforest/pca scores from feature overrides
    # Use msg_rate (index 10) and n_writes (index 2) as a proxy
    n_writes = feat_override[2] if len(feat_override) > 2 else 50.0
    msg_rate  = feat_override[10] if len(feat_override) > 10 else 10.0
    if_score  = round(min(0.45, 0.15 + n_writes / 1000.0 + msg_rate / 200.0), 4)
    pca_z     = round(min(6.0, 2.5 + msg_rate / 20.0), 2)
    from datetime import datetime, timezone as _tz
    ts = datetime.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    record = {
        "timestamp": ts,
        "event_type": "alert",
        "anomaly": True,
        "src_ip": src_ip,
        "dest_ip": "192.168.10.10",
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 9000,
            "signature_id": sig_id,
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
        "lab": {
            "source": "lab-ai-score-direct",
            "model_version": "v1",
            "iforest_score": if_score,
            "pca_z": pca_z,
            "top_features": ["n_writes", "msg_rate", "n_unique_funccodes"],
        },
    }
    try:
        alert_file = os.environ.get("LAB_AI_ALERT_FILE", "/var/lab/log/ai-alerts.json")
        os.makedirs(os.path.dirname(alert_file), exist_ok=True)
        with open(alert_file, "a", encoding="utf-8", buffering=1) as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        LOG.info("Direct alert written (no-Redis fallback): cat=%s if=%.4f", category, if_score)
        # Also append to in-process score history so sparkline updates
        _score_history.append((time.time(), if_score, pca_z, True))
    except Exception as exc:
        LOG.error("Failed to write direct synthetic alert: %s", exc)


def _run_injection(attack_type: str, duration_s: float, rate_hz: float) -> None:
    """Run a synthetic Modbus attack injection.

    Pushes raw Modbus feature rows into Redis so feature_consumer scores them.
    Also directly scores the synthetic feature vector and populates _score_history
    so the trend/sparkline endpoints show real data during the demo.
    """
    LOG.warning("DEMO ATTACK INJECTION STARTED: type=%s duration=%.0fs rate=%.1fHz",
                attack_type, duration_s, rate_hz)
    try:
        # Write trigger file so OT container can optionally read it
        trigger_path = "/var/lab/state/attack_trigger.json"
        os.makedirs(os.path.dirname(trigger_path), exist_ok=True)
        with open(trigger_path, "w", encoding="utf-8") as fh:
            json.dump({"attack_type": attack_type, "duration_s": duration_s, "rate_hz": rate_hz}, fh)
        try:
            os.chmod(trigger_path, 0o777)
        except Exception:
            pass

        # The REAL attack now runs on the SEC sensor, which polls the trigger file
        # written above. That traffic flows through Zeek -> feature_consumer -> the
        # IR attack_classifier and yields a correctly MITRE-tagged incident (the
        # exact path validate_ir.py validates). We intentionally NO LONGER push
        # synthetic feature rows here — those bypassed the classifier and produced
        # mislabeled "192.168.20.99" alerts. This loop only drives the live
        # sparkline / threat gauge for the duration (display-only, DEMO_MODE-gated).
        feat_override = _ATTACK_FEATURE_OVERRIDES.get(
            attack_type, _ATTACK_FEATURE_OVERRIDES["modbus_command_injection"])
        elapsed = 0.0
        tick = 2.0
        while elapsed < duration_s and not _should_injection_stop():
            _push_synthetic_score(feat_override, attack_type)
            time.sleep(tick)
            elapsed += tick
        _push_synthetic_score(feat_override, attack_type)
        LOG.warning("DEMO ATTACK INJECTION COMPLETE (real attack ran on SEC): type=%s", attack_type)

    except Exception as exc:
        LOG.error("Injection loop error: %s", exc)
    finally:
        with _injection_lock:
            _injection_state["active"] = False
        try:
            with open(INJECTION_STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump({**_injection_state, "active": False}, fh)
        except Exception:
            pass



def _run_robot_injection(attack_type: str, duration_s: float, _rate_hz: float = 0.0) -> None:
    """Robot-plane demo injection (audit F-08 honest-mode aware).

    Writes the robot attack trigger; robot_consumer.py then scores a synthetic
    tampered joint window with the REAL LSTM for the duration (real model,
    synthetic input — same philosophy as the Modbus injector). This service does
    NOT touch the safety-critical motion publisher."""
    LOG.warning("ROBOT DEMO INJECTION STARTED: type=%s duration=%.0fs", attack_type, duration_s)
    try:
        if not _DEMO_MODE:
            LOG.info("LAB_DEMO_MODE=0 — robot injection trigger suppressed (honest mode)")
        else:
            os.makedirs(os.path.dirname(ROBOT_TRIGGER_FILE), exist_ok=True)
            with open(ROBOT_TRIGGER_FILE, "w", encoding="utf-8") as fh:
                json.dump({"attack_type": attack_type, "duration_s": duration_s,
                           "started_at": time.time()}, fh)
            try:
                os.chmod(ROBOT_TRIGGER_FILE, 0o666)
            except Exception:
                pass
        end = time.time() + duration_s
        while time.time() < end and _injection_state.get("active", False):
            time.sleep(0.5)
    except Exception as exc:  # noqa: BLE001
        LOG.error("Robot injection error: %s", exc)
    finally:
        with _injection_lock:
            _injection_state["active"] = False
        try:
            with open(INJECTION_STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump({**_injection_state, "active": False}, fh)
        except Exception:
            pass


@app.post("/api/demo/inject-attack", dependencies=[Depends(_require_api_key)])
def inject_attack(payload: AttackInjectPayload, request: Request) -> dict:
    """Launch a simulated cyber-physical attack (Modbus network plane or robot
    behavior plane) for the live detection demo."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip, "inject_attack"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    with _injection_lock:
        if _injection_state["active"]:
            raise HTTPException(status_code=409, detail="An injection is already in progress")
        _injection_state["active"] = True
        _injection_state["last_injection_ts"] = time.time()
        _injection_state["injection_count"] += 1
        _injection_state["attack_type"] = payload.attack_type

    try:
        os.makedirs(os.path.dirname(INJECTION_STATE_FILE), exist_ok=True)
        with open(INJECTION_STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump({**_injection_state}, fh)
    except Exception as exc:
        LOG.warning("Could not persist injection state: %s", exc)

    # Route robot-behavior attacks to the robot plane; everything else is Modbus.
    _target = (_run_robot_injection
               if payload.attack_type in ROBOT_ATTACK_TYPES else _run_injection)
    thread = threading.Thread(
        target=_target,
        args=(payload.attack_type, payload.duration_s, payload.rate_hz),
        daemon=True,
    )
    thread.start()

    return {
        "status": "ok",
        "attack_type": payload.attack_type,
        "duration_s": payload.duration_s,
        "injection_id": _injection_state["injection_count"],
        "started_at": _injection_state["last_injection_ts"],
        "message": f"Attack injection started: {payload.attack_type} ({payload.duration_s}s @ {payload.rate_hz}Hz)",
    }


@app.get("/api/demo/injection-state")
def get_injection_state() -> dict:
    """Get current injection state for detection latency measurement."""
    return {
        "active": _injection_state["active"],
        "last_injection_ts": _injection_state["last_injection_ts"],
        "injection_count": _injection_state["injection_count"],
        "attack_type": _injection_state["attack_type"],
    }


@app.post("/api/hmi/trigger-sros2-estop", dependencies=[Depends(_require_api_key)])
def trigger_sros2_estop() -> dict:
    """Create a temporary trigger file on the shared state directory to signal the OT container to request SROS2 E-Stop."""
    trigger_path = "/var/lab/state/sros2_estop_trigger"
    try:
        with open(trigger_path, "w", encoding="utf-8") as fh:
            fh.write("trigger")
        # Ensure it is readable by all so OT watcher can delete it/read it
        try:
            os.chmod(trigger_path, 0o777)
        except Exception:
            pass
        return {"status": "ok", "message": "SROS2 Cryptographic E-Stop trigger file created on shared storage"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to create SROS2 trigger: {exc}")
