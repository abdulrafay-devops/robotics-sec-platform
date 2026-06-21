# improvements.md — Robotics Security Platform: AI-Engine Upgrade Roadmap

> **Purpose.** This is the durable plan + context anchor so we can continue across
> sessions with zero context loss. It records (1) how the app works today, (2) the
> hard "do not break this" constraints, and (3) the full step-by-step plan for the
> agreed improvements. Update the **Progress log** at the bottom after every work
> session.
>
> **Last updated:** 2026-06-18 (investigation + plan written; no code changed yet)
> **Owner:** rafay · **Status:** PLANNING COMPLETE → ready to implement Workstream A

---

## 0. The decision (what the user asked for)

The user reviewed the AI engine / anomaly types / Gazebo sim and chose:

1. **Build the impressive option** — a *real* robot-dynamics anomaly detector (LSTM
   autoencoder) that actually consumes the robot's `/joint_states` stream. This
   closes the current credibility gap (the code *claims* an "LSTM autoencoder
   consumes joint states" but **nothing does today** — the only ML is the Modbus
   network pipeline).
2. **Add a real public ICS dataset** through the existing `load_external()` hook so
   model accuracy is defensible, not just synthetic.
3. **Increase the number of anomaly types** (free choice) — and **every** type must
   be visible/selectable in the dashboard.
4. **Do other improvements as needed.**

**Hard rules from the user:**
- Test everything; **do not break any working component**.
- Update the `interview-prep/` docs with the new material and **remove old/outdated
  practices**.
- Investigate the whole app first to avoid incompatibilities. *(Done — see §2/§3.)*
- **Focus on the AI engine. It must be impressive AND it must not drift.**

---

## 1. TL;DR — workstreams & checklist

| ID | Workstream | Risk | Rebuild needed? | Status |
|----|-----------|------|-----------------|--------|
| **A** | Robot-dynamics AI: LSTM autoencoder + physics-envelope rules on `/joint_states` | Medium | container-ai rebuild done | ✅ Backend DONE & **live-verified** (AUC 0.999, full loop). Dashboard UI = Workstream C |
| **B** | Real public ICS dataset → `load_external()` → honest AUC | Low | No | ◐ Pipeline DONE (converter + trainer real-AUC eval + skip-clean test); awaiting a real CSV drop-in (gated download) for the live number |
| **C** | More anomaly types (robot + 2 missing network) all wired into dashboard | Low–Med | dashboard rebuild done | ✅ DONE & live-verified (robot gauge/model/dropdown + `register_scan`/`bulk_write` Modbus types) |
| **D** | Anti-drift CI test, wire missing injectors, fix misleading comments, update interview-prep | Low | No | ✅ DONE (contract test, injectors, comments fixed, Part 3/4 PDFs rebuilt, robot live-smoke) |

**Key enabler discovered during investigation:** the AI and OT containers **re-copy
code from the bind-mounted `/vagrant` on every boot** (see `entrypoint_ai.sh:89-108`
and `entrypoint_ot.sh:50-62`), and models are **trained on boot if missing**
(`entrypoint_ai.sh:122-155`). **So the entire upgrade can ship with container
*restarts* — no image rebuilds.** That is the single biggest reason this can be done
without breaking the demo. (For a clean production image we *also* add the new files
to the Dockerfiles, but it is not required for dev/demo.)

---

## 2. Current architecture (the context anchor)

### 2.1 Containers, networks, shared storage

| Container | Base image | Key runtimes | Networks (IP) | Notable |
|-----------|-----------|--------------|---------------|---------|
| `container-ot` | `ros:humble-ros-base` | ROS 2 Humble (`rclpy`), OpenPLC, Gazebo Classic, `venv-traffic` (pymodbus, scapy, pyyaml, pytest) | ot `10.10`, dmz `30.10`, mgmt `40.10` | **No `redis` pip pkg.** Publishes robot joints. |
| `container-sec` | (Dockerfile.sec) | Zeek, Suricata, ntopng, `venv-shipper` (has `redis`) | ot `10.20`, dmz `30.30`, mgmt `40.20` | Passive tap → features → Redis |
| `container-ai` | `ubuntu:22.04` | `venv-ai`: **tensorflow-cpu 2.16.1**, scikit-learn 1.5.2, numpy/pandas/scipy, redis, fastapi, pymodbus. **Redis server runs here.** | mgmt `40.30`, dmz `30.35`, it `20.35` | All ML + scoring + Grafana/Prometheus |
| `container-dashboard` | nginx + React build | — | mgmt only | Reverse-proxies `/api`,`/prometheus`,`/health`,`/score` → `container-ai` |

**Shared `lab-state` volume is mounted at `/var/lab/state` in OT, SEC, and AI.**
This is the project's standard cross-container IPC channel (e.g.
`latest_scores.json`, `attack_trigger.json`, `sros2_estop_trigger`). **This is our
zero-rebuild OT→AI bridge for joint telemetry.**

TensorFlow (Keras) is already installed in `venv-ai`, so a Keras **LSTM** autoencoder
needs **no new dependency**.

### 2.2 The existing (Modbus / network) AI pipeline — works today

```
container-sec                              container-ai
  Zeek ─ modbus_features.log
      │ (tail)
  feature_pusher.py ──RPUSH──► Redis "lab.modbus.features.raw"
                                     │ BLPOP
                              feature_consumer.py  ── windows 5s, scores ──┐
                                     │                                     │
                                     │ IF + PCA-AE + TF-AE (3 models)      │
                                     ▼                                     ▼
                          RPUSH "lab.anomaly.events"          writes latest_scores.json
                                     │ BLPOP                  (live gauges, even idle)
                              alert_bridge.py
                                     │ append (eve.json schema)
                                     ▼
                       /var/lab/log/ai-alerts.json ──► playbook_engine.py (IR)
                                     │                  lab_exporter.py (Prometheus)
                                     ▼
                       dashboard AIEnginePage + SecurityPage + Grafana
```

**Files (all under `vm-ai/`):**
- `model/features.py` — **the anti-drift core.** `FEATURE_VERSION="v2"`, 20 feature
  names, `WindowBucket.feature_vector()`. Imported by **both** trainers and **both**
  scorers, so train and serve can never disagree. `resolve_if_threshold()` is the
  single source of truth for the IF alert threshold (shared by data plane + API).
- `model/datasets.py` — synthetic OT Modbus generator. Normal traffic + **5 attack
  generators**: `command_injection`, `replay`, `coil_flood`, `register_scan`,
  `bulk_write`. `load_external()` reads operator CSVs (v2 schema) from
  `/var/lab/datasets` — **this is the hook for Workstream B.**
- `model/train_iforest.py` / `train_autoencoder.py` (PCA) / `train_autoencoder_tf.py`
  (deep dense AE). Train on pure-normal, calibrate p99 threshold, report ROC-AUC/AP,
  write `*.pkl` / `*.h5` + `*_threshold.json` + `model_meta.json` to `/opt/lab/models`.
- `feature_consumer.py` — live in-process scorer (IF + PCA + TF), consensus +
  N-consecutive-window debounce + per-host cooldown. Writes `latest_scores.json`.
- `score_service.py` — FastAPI (port 8000). **God-object** (documented tech-debt at
  its top): scoring, trend, IR endpoints, HMI/PLC control, **demo attack injection**.
  `/health`, `/metadata`, `/api/trend`, `/api/demo/inject-attack`, etc.
- `alert_bridge.py` — Redis anomaly events → `ai-alerts.json` (eve.json schema).
  `_classify()` emits categories `modbus-external-anomaly` /
  `modbus-baseline-deviation`.
- `monitoring/lab_exporter.py` — **stdlib-only** Prometheus exporter on :9101. Reads
  `latest_scores.json` → `lab_stage2_latest_{iforest_score,pca_z,tf_z}`; reads
  `ai-alerts.json` → alert category/severity counts. **Adding a metric = add one
  `emit(...)` call; Prometheus auto-scrapes (job `lab_exporter`).**
- `ir/playbook_engine.py` + `ir/playbooks/*.md` — tails `ai-alerts.json`, matches the
  alert `category` against each playbook's front-matter `triggers:` list, runs graded
  steps (auto + human-approval). **New category ⇒ new playbook file.**

### 2.3 The robot / Gazebo side — publishes joints, but ML ignores them

- `vm-ot/gazebo/cyclic_motion.py` — rclpy node. Drives j1..j6 through 5 pick-and-place
  waypoints with **cosine interpolation**; publishes `JointState` (position[6],
  velocity[6], effort[6]) on topic **`/lab_arm/joint_states`** at **40 Hz** (Gazebo
  launch) or **10 Hz** (headless fallback). Already integrates safety: subscribes
  `/safety/state` (SROS2) and polls Modbus E-stop coil → freezes arm.
- `vm-ot/gazebo/launch.py` — boots gzserver + robot_state_publisher + spawn +
  cyclic_motion + `joint_state_to_gazebo.py` + workpiece animator. **All Gazebo-group
  nodes run with `ROS_SECURITY_ENABLE=false`** (important for §4.1 DDS compatibility).
- `entrypoint_ot.sh:211-222` — starts the Gazebo launch; **falls back** to telemetry-
  only `cyclic_motion.py` if Gazebo is unavailable. **Either way `/lab_arm/joint_states`
  is published by default.**
- **GAP:** grep confirms **no Python file consumes `/joint_states`** for ML. The
  comments in `cyclic_motion.py:16-21` and `robot.urdf:8-11,355-358` claim an "LSTM
  autoencoder" consumes the stream — **that model does not exist.** Workstream A makes
  the claim true (and §D fixes the comments to match reality).

### 2.4 Dashboard (React + Vite, `dashboard/src/`)

- `pages/AIEnginePage.tsx` — 3 model gauges (`IsolationForest`, `PCA Recon`, `TF Deep
  AE`), score sparkline, model-status panel, **Attack Injection panel** with
  `ATTACK_TYPES` (currently **3**: command_injection, replay, coil_flood), trend
  forecast, live anomaly log. Subtitle string lists the 3 models.
- `hooks/useMetrics.ts` — `usePrometheusMetrics()` does one `Promise.all` of
  `promQuery(...)` calls (incl. `lab_stage2_latest_tf_z`); `useModelHealth()` reads
  `/health` → `models_loaded`; `triggerInjection()` → `/api/demo/inject-attack`.
- `types/index.ts` — `PrometheusMetrics` includes `iforest_score`, `pca_z`, `tf_z`,
  etc. (add `robot_z` here in Workstream C).
- `nginx.conf` proxies `/api/`→ai:8000, `/prometheus/`→ai:9090, `/health`, `/score`.

### 2.5 Tests (`infra/tests/`)

- `stage2_dataset_smoke.py` — **offline** gate: builds synthetic dataset, trains IF,
  asserts hold-out **ROC-AUC ≥ 0.85**. (Template for the robot offline gate.)
- `stage2_live_smoke_docker.py` — drives a real replay attack from `container-sec`,
  asserts `ai-alerts.json` grew and contains the expected category. (Template for the
  robot live gate.)
- `stage_all_smoke_docker.sh` — runs the suite.

### 2.6 interview-prep (`interview-prep/`)

Four PDFs generated by `build_part1..4.py` using `_pdfkit.py` (reportlab). Helpers:
`P, H1, H2, H3, small, spacer, bullets, code, callout, tbl, rule, keep, build`.
- **Part 3** (`build_part3.py`, "The Brain") — §3 "three machine-learning models",
  the 20-feature table, the pipeline ASCII. **Primary file to extend** (3 → 4 models;
  add the robot plane).
- **Part 4** (`build_part4.py`) — demo script & Q&A. Add the robot-attack demo + new
  Q&A. Also update root `INTERVIEW-DEMO-GUIDE.md` and `SPEAKER-NOTES-Oral-Presentation.md`.
- Regenerate: `cd interview-prep && python build_part3.py` (needs `pip install reportlab`).
- The PDFs currently **do not** make the false LSTM claim (they say "three models"),
  so they are honest today; we are *adding* a real fourth model and documenting it.

---

## 3. "Do not break it" — compatibility constraints

1. **No image rebuild required.** Land everything via files under `vm-ai/` and
   `vm-ot/gazebo/` (auto-copied on boot) + a restart. Only add to Dockerfiles at the
   end as a cleanliness pass, verified separately.
2. **Never modify the safety path lightly.** `cyclic_motion.py` is safety-relevant
   (E-stop freeze). The joint telemetry tap must be a **separate, passive** node — do
   **not** add telemetry writing into `cyclic_motion.py`. (Passive tap mirrors how
   Zeek passively taps the network — also a great interview talking point.)
3. **The robot detector must degrade gracefully.** If no joint stream / stale file →
   show `WAITING` (like the Modbus gauges show `—` when idle). It must never crash a
   container or block the API.
4. **Anti-drift is mandatory (user emphasis).** Mirror the proven Modbus pattern: one
   shared, versioned feature module imported by trainer *and* scorer. See §7.
5. **Keep `LAB_DEMO_MODE` honest-mode intact.** The robot demo injection must respect
   `LAB_DEMO_MODE=0` (no synthetic telemetry) exactly like the Modbus injector does
   (`score_service.py:_DEMO_MODE`).
6. **Reuse the single alert writer.** Robot anomalies should flow through
   `alert_bridge.py` (extend `_classify`/`_eve` for the robot plane) so dedup,
   schema, IR, and exporter all keep working unchanged. Do not invent a parallel
   alert file.
7. **SROS2/DDS context** — see §4.1; the tap must run in a security context that can
   actually see `/lab_arm/joint_states`.

---

## 4. Workstream A — Robot-dynamics AI (the impressive one)

**Goal:** a real, trained, non-drifting model that scores the robot's *motion* (not
the network), consumes the live `/joint_states`, surfaces in the dashboard, and trips
an incident-response playbook — closing the cyber-physical loop
(attack → detect → E-stop).

### 4.0 Design at a glance

```
container-ot (passive tap)                         container-ai (brain)
 /lab_arm/joint_states ──► joint_telemetry_bridge.py
   (40/10 Hz)                 │ decimate→~10Hz, write rolling JSONL
                              ▼
              /var/lab/state/robot/joint_stream.jsonl  (shared lab-state volume)
                              │ tail (like feature_pusher tails Zeek)
                              ▼
                     robot_consumer.py ──► windows (T×C) via robot_features.py
                              │
                 ┌────────────┴─────────────┐
                 ▼                           ▼
        LSTM autoencoder            physics-envelope rules
        (learned, recon z)          (URDF limits: |vel|, pos range, jerk, freeze)
                 └────────────┬─────────────┘
                              ▼  anomaly?
            write latest_robot_scores.json   +   RPUSH lab.anomaly.events {plane:robot}
                              │                            │
                              ▼                            ▼
                  lab_exporter → lab_robot_lstm_z     alert_bridge → ai-alerts.json
                              │                            │ (category: robot-behavior-anomaly)
                              ▼                            ▼
                     dashboard 4th gauge        playbook_engine → pb_robot_anomaly.md
                                                            → assert safe state (E-stop)
```

**Why two detectors (LSTM + envelope rules):** mirrors the network plane's
calibrated-IF + learned-AE combo. The envelope layer is fast, explainable, and maps
directly to ISO/URDF limits ("velocity exceeded joint limit"); the LSTM catches
subtle/novel deviations from the *learned* smooth cyclic pattern. Great story, honest
engineering.

### 4.1 OT side — passive joint telemetry tap (NEW)

**New file:** `vm-ot/gazebo/joint_telemetry_bridge.py` (rclpy subscriber).
- Subscribes `/lab_arm/joint_states`; on each msg keep `(ts, name[], position[],
  velocity[], effort[])`.
- **Decimate to a fixed ~10 Hz** (so 40 Hz Gazebo and 10 Hz fallback both yield the
  same cadence — robustness + anti-drift) and append one compact JSON line to
  `/var/lab/state/robot/joint_stream.jsonl`.
- **Cap the file** (keep last ~2000 lines / rotate) so it can't grow unbounded on the
  shared volume.
- Emit nothing else; **zero feature logic on the OT side** (so there is nothing to
  drift — all feature math lives in `robot_features.py` on the AI side).

**DDS/SROS2 compatibility (critical):** add the bridge to `launch.py` as another
`ExecuteProcess` with `env={**os.environ, 'ROS_SECURITY_ENABLE': 'false'}` so it sits
in the **same security-disabled group** as `cyclic_motion` and `joint_state_to_gazebo`
(which already run with security off in the Gazebo path). Also add it to the
**headless-fallback branch** of `entrypoint_ot.sh:219-222` with matching settings so
telemetry still flows when Gazebo is absent. Run it **supervised** (it's passive — if
it dies the robot is unaffected).

**Files touched (OT):** `vm-ot/gazebo/launch.py` (+1 process),
`vm-ot/entrypoint_ot.sh` (fallback branch + optionally a supervised line). New file
auto-copied by `entrypoint_ot.sh:50-55`.

> **Alternative (documented, not chosen):** add `redis==5.0.8` to `venv-traffic` in
> `Dockerfile.ot` and push joints to a Redis list like `feature_pusher`. More
> consistent with the Modbus plane, but needs an **OT image rebuild** (heaviest
> container). Chosen approach (shared file) avoids that. Revisit only if file-tailing
> proves too laggy (it won't at 10 Hz).

### 4.2 AI side — shared feature module (NEW, anti-drift core)

**New file:** `vm-ai/model/robot_features.py` — the robot equivalent of `features.py`:
- `ROBOT_FEATURE_VERSION = "r1"`.
- Canonical config: `JOINT_NAMES = ['j1'..'j6']`, `SAMPLE_HZ = 10.0`, `WINDOW_LEN = 50`
  (≈5 s, ~ one motion phase), channel spec `CHANNELS` (start with 18: 6 pos, 6 vel,
  6 effort — or a curated subset; document the choice).
- URDF-derived limits table (copy from `robot.urdf` joint `<limit>`): per-joint
  position `lower/upper` and `velocity`. Single source of truth for the envelope rules.
- `RawJointRow` dataclass + `parse_line()` (mirrors `RawRow.from_dict`).
- `RobotWindowStore` (online windowing, like `WindowStore`) and
  `window_tensor(rows) -> np.ndarray (WINDOW_LEN, C)`.
- `envelope_violations(window) -> list[str]` (deterministic rule layer).
- Imported by **both** `train_robot_lstm.py` and `robot_consumer.py`. **This is the
  no-drift guarantee.**

### 4.3 AI side — synthetic robot dataset (NEW)

**New file:** `vm-ai/model/robot_datasets.py` (mirrors `datasets.py`):
- Reuse the exact `WAYPOINTS` + `smooth_interp` (cosine) from `cyclic_motion.py` to
  generate **normal** trajectories at `SAMPLE_HZ`, with small Gaussian sensor noise +
  per-run rate jitter → realistic windows.
- **Attack/anomaly generators** (label=1, eval only — never in training):
  1. `joint_speed_violation` — scale velocities past URDF limit on ≥1 joint.
  2. `trajectory_deviation` — shift target waypoints outside the learned envelope.
  3. `frozen_joint` — hold one joint constant (sensor freeze/spoof).
  4. `erratic_jerk` — inject high-freq acceleration noise.
  5. *(optional)* `workspace_breach` — drive j1 toward the closed fence side.
- `robot_synthetic_dataset(minutes, attack=0)` → `(X, y)` of shape `(N, WINDOW_LEN, C)`.
- `robot_attack_only(n)` for AUC eval. All seeded & reproducible.

### 4.4 AI side — LSTM autoencoder trainer (NEW)

**New file:** `vm-ai/model/train_robot_lstm.py` (mirrors `train_autoencoder_tf.py`):
- Arch: `Input(T,C) → LSTM(32) → LSTM(16)` (encoder) `→ RepeatVector(T) → LSTM(16,
  seq) → LSTM(32, seq) → TimeDistributed(Dense(C))`. Loss MSE, Adam, EarlyStopping +
  ReduceLROnPlateau (same callbacks as the dense AE).
- Per-channel standardization fit on **train-normal only** → save `robot_scaler.pkl`
  (or fold scaling into `robot_features.py` with saved stats — pick one, document).
- Train on pure-normal; calibrate threshold = **p99 of calibration recon error**;
  evaluate **ROC-AUC + AP** on `robot_attack_only`. Log detection rate at threshold.
- Artifacts → `/opt/lab/models/`: `robot_lstm.h5`, `robot_threshold.json`
  (`baseline_recon_mean/std`, `p99_threshold`, `z_alert_threshold`),
  `robot_meta.json` (`ROBOT_FEATURE_VERSION`, arch, ROC-AUC, AP, channels, window).
- **Hook into boot training** in `entrypoint_ai.sh` after step [3/3], gated on
  `[ ! -f /opt/lab/models/robot_lstm.h5 ]`. Keep `--baseline-minutes` modest so CPU
  training stays quick.

### 4.5 AI side — live robot scorer (NEW)

**New file:** `vm-ai/robot_consumer.py` (supervised, mirrors `feature_consumer.py`):
- Tail `/var/lab/state/robot/joint_stream.jsonl` (inode-rotation safe, like
  `feature_pusher`). Build windows via `robot_features.RobotWindowStore`.
- Load `robot_lstm.h5` + threshold + scaler. For each window: recon error → z-score;
  also run `envelope_violations()`.
- **Decision:** anomaly if `z ≥ z_alert_threshold` **or** any envelope violation
  (with a short debounce/cooldown like the Modbus consumer to avoid flapping).
- Always write `/var/lab/state/latest_robot_scores.json`
  `{ts, robot_z, envelope_hits, top_joints, anomaly}` (live gauge source, even when
  nominal).
- On anomaly: `RPUSH lab.anomaly.events` with
  `{plane:"robot", category:"robot-behavior-anomaly", signature, severity, robot_z,
  top_joints, attack_type?}`.
- **Demo injection path:** poll `/var/lab/state/robot_attack_trigger.json`; while
  active, synthesize a **tampered window per type** and score it with the **real LSTM**
  (mirrors `score_service._push_synthetic_score` — real model, synthetic input,
  honest "DEMO" framing). Respect `LAB_DEMO_MODE=0`.

### 4.6 AI side — make robot alerts first-class (EDITS)

- **`alert_bridge.py`** — extend `_classify()`/`_eve()`: if `ev.get("plane")=="robot"`,
  pass through `category="robot-behavior-anomaly"`, a robot signature, and severity;
  include `robot_z`/`top_joints` in the `lab` block. Keep Modbus behavior unchanged.
- **`score_service.py`** —
  - `/health` `models_loaded`: add `robot_lstm` via `os.path.exists(robot_lstm.h5)`
    (the model is owned by `robot_consumer`, so report by file presence).
  - `/api/demo/inject-attack`: route robot attack types → write
    `robot_attack_trigger.json` (don't push Modbus rows). Add them to the rate-limit
    + injection-state machinery so the dashboard "ATTACK IN PROGRESS" + latency still
    work.
  - *(optional)* `GET /api/robot/state` → last N joint samples for a live dashboard
    panel.
- **`monitoring/lab_exporter.py`** — add `emit('lab_robot_lstm_z', ...)` read from
  `latest_robot_scores.json` (stale-guard like `tf_z`); optionally
  `lab_robot_envelope_violation`. Robot alert categories are **auto-counted** already.
- **New playbook** `vm-ai/ir/playbooks/pb_robot_anomaly.md` — front-matter
  `triggers: [{source: ai_alerts, category: robot-behavior-anomaly}]`; graded steps:
  forensics (auto) → WATCH (auto) → **assert safe state / E-stop** (human approval)
  → postmortem → close. Reuse existing `/opt/lab/bin/ir-*` commands. Closes the loop.

### 4.7 Dashboard (EDITS) — see Workstream C (kept together for UI cohesion).

---

## 5. Workstream B — Real public ICS dataset

**Goal:** replace "AUC on my own synthetic attacks" (circular) with "AUC on held-out
**real** ICS traffic = X".

- **Candidate datasets** (pick one, record license + URL in code): SWaT / WADI
  (iTrust), HAI (hil-based augmented ICS), or a public Modbus-TCP capture
  (e.g. "Electra"/ICS Modbus datasets). Must be reducible to Modbus-ish per-message
  rows so the v2 20-feature schema applies.
- **New file:** `vm-ai/model/convert_public_dataset.py` — read the raw public file →
  aggregate into the **v2 feature schema** using the *same* `aggregate_rows` /
  `WindowBucket` from `features.py` (no drift) → write CSV(s) with header =
  `FEATURE_NAMES + ["label"]` into `/var/lab/datasets/` (the dir `load_external()`
  scans). Include a `--download` helper or document manual fetch.
- **Licensing/size:** raw datasets usually can't be committed. Commit the **converter
  + a tiny derived sample** (license permitting) + a fetch script. Document clearly.
- **Wire-up:** `train_iforest.py` already merges `load_external()` normals into
  training; extend the eval section (and the PCA/TF trainers) to **also report AUC on
  the real held-out attack rows**. Surface the real AUC in `model_meta.json` and quote
  it in interview-prep.
- **Test:** new `infra/tests/stage2_real_dataset_smoke.py` — if a dataset is present,
  assert schema validity + AUC ≥ a sane floor; skip cleanly if absent (CI-safe).

---

## 6. Workstream C — More anomaly types, all visible in the dashboard

**Network plane:** the 2 attack generators that exist in `datasets.py` but are **not**
selectable live — `register_scan`, `bulk_write` — get added to:
- `score_service._ATTACK_FEATURE_OVERRIDES` (+ `_ATTACK_SRC_IPS`, categories) with
  valid **20-dim v2** vectors that score as strong anomalies.
- `AIEnginePage.ATTACK_TYPES`.

**Robot plane:** the §4.3 robot attacks become selectable injections (routed to the
robot trigger path).

**Dashboard edits (`dashboard/src/`):**
- `pages/AIEnginePage.tsx`:
  - Add a **4th gauge** "Robot LSTM AE" fed by `metrics.robot_z`
    (`lab_robot_lstm_z`). Update the header subtitle to mention the robot model.
  - Extend `ATTACK_TYPES`; **group** the dropdown into *Network* vs *Robot* so all
    ~9–10 types are clearly selectable.
  - Add a `robot_lstm` row to the **Model Status** panel (from `/health`).
  - *(optional)* small "Robot Dynamics" live panel (joint velocity/effort bars) from
    `/api/robot/state`.
  - The pipeline diagram: add the robot tap as a parallel input (optional polish).
- `hooks/useMetrics.ts`: add `promQuery('lab_robot_lstm_z')` to the `Promise.all`; set
  `robot_z` in the returned metrics.
- `types/index.ts`: add `robot_z: number` to `PrometheusMetrics`.
- `AlertRow` already renders generic categories → robot alerts show with no change;
  just confirm severity/signature display.

**Result:** every anomaly type (5 network + 4–5 robot) is selectable in the injection
panel and visibly drives gauges, the anomaly log, Grafana, and IR.

---

## 7. Anti-drift design (explicit — user priority)

The Modbus plane already proves the pattern; **the robot plane copies it exactly:**

1. **One shared, versioned feature module per plane** imported by trainer *and*
   scorer: `features.py` (`FEATURE_VERSION`) for Modbus; **`robot_features.py`
   (`ROBOT_FEATURE_VERSION`)** for robot. No feature math anywhere else.
2. **Producers emit raw only.** Zeek/`feature_pusher` emit raw Modbus rows; the OT
   `joint_telemetry_bridge` emits raw joint samples. **Zero feature logic on the
   producer side**, so producers can't drift from the model.
3. **Versioned artifacts + visible version.** `robot_meta.json` records
   `ROBOT_FEATURE_VERSION`; `/health` & `/metadata` surface it. A version mismatch is
   observable, not silent.
4. **Fixed input cadence.** Decimate to `SAMPLE_HZ=10` at the tap so 40 Hz vs 10 Hz
   sources produce identical windows.
5. **A "no-drift" unit test (Workstream D):** assert the training window builder and
   the live window builder produce identical shape/values for the same raw input, and
   that `robot_features.ROBOT_FEATURE_VERSION` matches `robot_meta.json`. Mirror an
   equivalent assertion for the Modbus `FEATURE_VERSION`. This is a CI guard so future
   edits that would cause drift **fail the build**.

---

## 8. Workstream D — Other improvements

- **Anti-drift CI test** (§7.5): `infra/tests/feature_contract_test.py` (offline).
- **Wire missing network injectors** (`register_scan`, `bulk_write`) — see §6.
- **Fix misleading comments** now that the model is real:
  `vm-ot/gazebo/cyclic_motion.py:16-21` and `vm-ot/gazebo/robot.urdf:8-11,355-358` —
  point to `robot_consumer.py` / `robot_features.py` and the real `/joint_states` tap.
- **Robot smoke tests:** `stage2_robot_dataset_smoke.py` (offline AUC gate, like
  `stage2_dataset_smoke.py`) and `stageX_robot_live_smoke_docker.py` (inject robot
  attack → assert `ai-alerts.json` gains a `robot-behavior-anomaly`). Add both to
  `stage_all_smoke_docker.sh`.
- **interview-prep updates** — §10.
- **Dockerfile cleanliness pass (last):** add the new `vm-ai` files to the
  `Dockerfile.ai` COPY block and the robot training step note; confirm OT files are in
  the `gazebo/` COPY. Rebuild once **after** everything works on restart, and re-run
  the full smoke suite.

---

## 9. Test plan (run after each workstream; never skip)

**Offline (fast, no containers) — run from repo root with `venv-ai`/host Python:**
- `python infra/tests/stage2_dataset_smoke.py` — must still PASS (regression).
- `python infra/tests/stage2_robot_dataset_smoke.py` — robot AUC ≥ floor (NEW).
- `python infra/tests/feature_contract_test.py` — no-drift contract (NEW).

**Live (Docker) — after `docker compose up` (or restart of ai+ot):**
- `python infra/tests/stage2_live_smoke_docker.py` — Modbus path regression.
- `python infra/tests/stageX_robot_live_smoke_docker.py` — robot path (NEW).
- `bash infra/tests/stage_all_smoke_docker.sh` — full suite.

**Manual demo verification (the real acceptance):**
1. Restart `container-ai` + `container-ot`; watch logs for clean boot + robot training.
2. `/health` shows `robot_lstm: true`; dashboard shows the 4th gauge live (NOMINAL)
   while the robot runs its normal cycle.
3. Inject each network attack → existing gauges + log react (regression).
4. Inject each robot attack → **Robot LSTM gauge spikes**, anomaly log gets a
   `robot-behavior-anomaly`, IR opens an incident, E-stop approval appears.
5. Confirm graceful degradation: stop the joint stream → robot gauge → `WAITING`, no
   crashes, Modbus path unaffected.

**Smoke-test note for the model:** keep the offline AUC floor realistic for an LSTM on
synthetic data (start ~0.85 like the IF gate; tune once measured).

---

## 10. interview-prep doc updates (don't forget — user requirement)

- **`build_part3.py`** — change "three machine-learning models" → **four**; add a
  "Robot behavior plane" section: the passive joint tap (analogy: Zeek for the
  network = this tap for the robot), the LSTM autoencoder, the physics-envelope rule
  layer, and `ROBOT_FEATURE_VERSION` anti-drift. Add a robot pipeline ASCII (reuse §4.0).
- **`build_part4.py`** — add the **robot-attack demo** to the live script ("inject
  `joint_speed_violation` → watch the arm-behavior model fire → E-stop") and 2–3 new
  Q&A ("how does the robot model avoid drift?", "synthetic vs real data — what's your
  AUC on real ICS traffic?").
- **Remove/rewrite old practices** flagged during review: the "LSTM consumes joint
  states (aspirational)" framing → now a real, described component; any text implying
  the robot is *only* a visual prop.
- Update **root** `INTERVIEW-DEMO-GUIDE.md` and `SPEAKER-NOTES-Oral-Presentation.md`
  with the robot-attack demo beat and the "two detection planes (network + robot)"
  framing.
- Regenerate PDFs: `cd interview-prep && pip install reportlab && python build_part3.py
  && python build_part4.py`. Spot-check the PDFs render.

---

## 11. File-by-file change map (quick index)

**NEW**
- `vm-ot/gazebo/joint_telemetry_bridge.py` — passive joint tap → shared JSONL
- `vm-ai/model/robot_features.py` — shared, versioned robot feature module (anti-drift)
- `vm-ai/model/robot_datasets.py` — synthetic normal + 5 robot anomaly generators
- `vm-ai/model/train_robot_lstm.py` — LSTM autoencoder trainer
- `vm-ai/robot_consumer.py` — live robot scorer (LSTM + envelope) + demo injection
- `vm-ai/ir/playbooks/pb_robot_anomaly.md` — robot IR playbook (→ E-stop)
- `vm-ai/model/convert_public_dataset.py` — real ICS dataset → v2 CSV
- `infra/tests/stage2_robot_dataset_smoke.py`, `infra/tests/stageX_robot_live_smoke_docker.py`,
  `infra/tests/feature_contract_test.py`, `infra/tests/stage2_real_dataset_smoke.py`

**EDIT**
- `vm-ot/gazebo/launch.py` (+ telemetry bridge process, security off)
- `vm-ot/entrypoint_ot.sh` (fallback branch runs the bridge)
- `vm-ai/entrypoint_ai.sh` (train robot LSTM on boot; supervise `robot_consumer.py`)
- `vm-ai/alert_bridge.py` (robot plane in `_classify`/`_eve`)
- `vm-ai/score_service.py` (`/health` robot flag; robot injection routing; opt `/api/robot/state`)
- `vm-ai/monitoring/lab_exporter.py` (`lab_robot_lstm_z`)
- `vm-ai/model/train_iforest.py` / `train_autoencoder.py` / `train_autoencoder_tf.py` (report real-dataset AUC)
- `dashboard/src/pages/AIEnginePage.tsx`, `hooks/useMetrics.ts`, `types/index.ts`
- `infra/tests/stage_all_smoke_docker.sh` (add robot gates)
- `interview-prep/build_part3.py`, `build_part4.py`, root `INTERVIEW-DEMO-GUIDE.md`,
  `SPEAKER-NOTES-Oral-Presentation.md`
- `vm-ot/gazebo/cyclic_motion.py`, `robot.urdf` (fix misleading comments)
- *(final pass)* `vm-ai/Dockerfile.ai`, `vm-ot/Dockerfile.ot` (COPY new files)

**Shared-volume contract (new files under `/var/lab/state/`):**
- `robot/joint_stream.jsonl` (OT → AI, capped)
- `latest_robot_scores.json` (AI → exporter/dashboard)
- `robot_attack_trigger.json` (score_service → robot_consumer, demo)

---

## 12. Build / run / restart cheat-sheet

```bash
# Apply code changes without a rebuild (dev/demo): restart the two containers.
docker compose restart container-ai container-ot

# Force the robot model to retrain (after changing trainer/features):
docker exec container-ai rm -f /opt/lab/models/robot_lstm.h5 \
    /opt/lab/models/robot_threshold.json /opt/lab/models/robot_meta.json
docker compose restart container-ai   # entrypoint retrains on boot

# Watch boot + training:
docker logs -f container-ai     # look for "Training ... robot LSTM"
docker logs -f container-ot     # look for joint_telemetry_bridge start

# Live score files:
docker exec container-ai cat /var/lab/state/latest_robot_scores.json
docker exec container-ot tail -f /var/lab/state/robot/joint_stream.jsonl

# Full clean rebuild (only for the final Dockerfile pass):
docker compose build container-ai container-ot && docker compose up -d
```

---

## 13. Open decisions / risks to confirm while implementing

- **Channels (C):** 18 (pos+vel+eff) vs a curated subset. Start with 18; revisit if
  the LSTM over-memorizes. *(decide in A.2)*
- **Scaler location:** separate `robot_scaler.pkl` vs stats baked into
  `robot_features.py`. Pick one and keep it single-source. *(decide in A.2/A.4)*
- **Public dataset choice + license** for Workstream B (commit a tiny sample only).
- **DDS visibility of the tap** in the rare headless-fallback path — verify the
  security-disabled subscriber actually receives `/lab_arm/joint_states` there; if
  not, also disable security on the fallback `cyclic_motion` (it already is in the
  Gazebo launch group).
- **CPU training time** for the LSTM on boot — keep `--baseline-minutes`/epochs modest;
  if too slow, pre-train and commit `robot_lstm.h5` (note: large binary).
- **Offline AUC floor** for the robot gate — set after first measurement.

---

## 14. Progress log (append each session)

- **2026-06-18** — Full app investigation complete (containers, networks, Modbus AI
  pipeline, robot/Gazebo side, dashboard, exporter, IR engine, tests, interview-prep).
  Confirmed: no ML consumes `/joint_states` today; `lab-state` volume shared OT↔AI;
  TF-cpu present; code auto-copied on boot ⇒ no rebuild needed. Wrote this roadmap.
- **2026-06-18** — **Workstream A offline core DONE & validated** (no container
  touched). New files: `vm-ai/model/robot_features.py` (anti-drift shared module,
  `ROBOT_FEATURE_VERSION="r1"`, 12 channels = 6 pos + 6 derived vel, WINDOW_LEN=50 @
  10 Hz), `vm-ai/model/robot_datasets.py` (normal cyclic motion matching
  `cyclic_motion.py` + 5 behavioral attacks), `vm-ai/model/train_robot_lstm.py`
  (seq2seq LSTM AE 50×12→32→16→16→32→12, p99 threshold, calibrated envelope),
  `infra/tests/feature_contract_test.py`, `infra/tests/stage2_robot_dataset_smoke.py`.
  **Validated on host TF 2.21 (Keras 3, same family as container 2.16):**
  feature-contract gate PASS (incl. live-store==offline-window anti-drift proof);
  robot LSTM smoke **ROC-AUC=0.935 / AP=0.997 / 91% detection** on a small 8-min/25-ep
  run; existing Modbus gate still PASS (AUC 1.0 — no regression).
  Design decisions locked: 12 channels (pos+vel, effort dropped as redundant);
  per-channel mean/std stored in `robot_threshold.json` (no scaler pickle); velocity
  DERIVED from positions in the shared module (tap emits raw angles only); envelope
  velocity/accel thresholds CALIBRATED from normal data (URDF vel limit too low
  because the scripted trajectory itself runs fast); positions are the single raw
  input. **Next (needs Docker up):** A.1 OT telemetry tap
  (`joint_telemetry_bridge.py` → `/var/lab/state/robot/joint_stream.jsonl`), A.5
  `robot_consumer.py`, A.6 wire `alert_bridge`/`score_service`/`lab_exporter` +
  `pb_robot_anomaly.md`, then entrypoint hooks (train on boot + supervise), then
  Workstream C dashboard.
- **2026-06-18** — **Workstream A live integration DONE & verified end-to-end** on the
  running stack. New: `vm-ot/gazebo/joint_telemetry_bridge.py` (passive tap → shared
  `joint_stream.jsonl`), `vm-ai/robot_consumer.py` (LSTM + envelope live scorer with
  idle gate), `vm-ai/ir/playbooks/pb_robot_anomaly.md`. Edits: `alert_bridge.py`
  (robot plane in `_classify`/`_eve`, proto=ROS2), `score_service.py` (`/health`
  robot flag + robot injection routing), `monitoring/lab_exporter.py`
  (`lab_robot_lstm_z`), `entrypoint_ai.sh` (train robot LSTM on boot + supervise
  robot_consumer), `launch.py` + `entrypoint_ot.sh` (run the tap). Only
  **container-ai needed a rebuild** (baked entrypoint); OT picks up launch.py + tap
  via boot-copy.
  **Live verification:** boot-trained robot LSTM ROC-AUC=0.999 / full-system 99.5%;
  OT tap streaming `/lab_arm/joint_states` → AI; **normal motion nominal** (z≈−5, no
  false positives after fixing two real train/serve drifts found live — see below);
  **idle arm nominal** (idle gate, z=0); **injected `joint_speed_violation` → z=126,
  `j1_vel_over_limit` → `robot-behavior-anomaly` alert → `pb_robot_anomaly` incident
  with E-stop awaiting operator approval**; `lab_robot_lstm_z` exported; `/health`
  shows `robot_lstm:true`.
  **Two drift fixes made during live verification:** (1) the live tap decimates by
  wall clock, so finite-diff jerk is noisier than the too-clean synthetic data →
  added sampling-time jitter (`JITTER_FRAC`) to `robot_datasets` + widened envelope
  vel/accel margins (2.0/3.0) so the calibrated limits reflect real acquisition;
  (2) a resting/home arm is out-of-distribution for a motion-trained model → added an
  **idle gate** in `RobotScorer.score` (skip when max joint std < `MOTION_ACTIVE_THRESH`;
  a frozen-JOINT attack still has other joints moving so it stays scored). Both
  re-verified: offline contract PASS, smoke AUC 0.993, and live nominal.
  **Next:** Workstream C — dashboard UI (4th gauge, robot model row, robot attack
  types in the injection dropdown, `robot_z` metric wiring) + rebuild the dashboard
  image. Then Workstream B (real dataset) and D (interview-prep, fix misleading
  cyclic_motion/robot.urdf comments).
- **2026-06-18** — **Workstream C (robot half) DONE & live-verified.** Dashboard
  edits: `types/index.ts` (+`robot_z`), `hooks/useMetrics.ts` (query
  `lab_robot_lstm_z`), `pages/AIEnginePage.tsx` (4th "Robot LSTM AE" gauge with
  negative-z→0 clamp + −1 WAITING sentinel; `robot_lstm` row in Model Status;
  5 robot attack types added to the injection dropdown via grouped optgroups;
  subtitle updated). Rebuilt the dashboard image (Vite/TS compile PASS = edits
  valid), redeployed. **Verified live:** dashboard serves HTTP 200; reads
  `lab_robot_lstm_z` via its prometheus proxy (0 when idle); injecting
  `trajectory_deviation` via the dashboard API spiked the metric to ~5e5 (gauge →
  red); **Modbus injection regression intact** (11 `modbus-external-anomaly` alerts,
  the `inject_attack` routing change is non-breaking).
  Only `container-ai` + `dashboard` were rebuilt; OT untouched.
  **Remaining:** C-leftover — wire the 2 unused Modbus attack types
  (`register_scan`, `bulk_write`) into the live injector. Workstream B — real ICS
  dataset via `load_external()`. Workstream D — update interview-prep PDFs (3→4
  models, robot plane), fix the misleading "LSTM consumes joint states" comments in
  `cyclic_motion.py`/`robot.urdf` to point at the now-real `robot_consumer.py`, add
  robot live-smoke test. Stack is currently UP and working.
- **2026-06-18** — **Workstreams C-leftover, D, and B done.**
  *C-leftover:* added the 2 unused Modbus attack types to the live injector
  (`score_service._ATTACK_FEATURE_OVERRIDES` + src-IPs + categories + write-FC map,
  with an address-sweep so `register_scan` re-derives as a real recon window) and to
  the dashboard dropdown. Live-verified: `register_scan` → `modbus-external-anomaly`
  alerts from 192.168.20.66 collapsed into **1 IR incident** (campaign dedup intact);
  robot plane still fires post-restart; all 4 models loaded; dashboard HTTP 200.
  *D:* fixed the misleading "LSTM consumes joint states" comments in
  `cyclic_motion.py` + `robot.urdf` to point at the now-real `robot_consumer.py`;
  added `infra/tests/stage2_robot_live_smoke_docker.py` (PASS, alerts 2→3) wired into
  `stage_all_smoke_docker.sh`; updated interview-prep `build_part3.py` (3→4 models,
  new "robot-behavior plane" section + cheat-sheet) and `build_part4.py` (robot demo
  Step 7b, 2 new Q&As incl. anti-drift, traceability + cheat-sheet) and **rebuilt
  Part 3 & Part 4 PDFs** (reportlab 4.5.1, both OK).
  *B:* `vm-ai/model/convert_public_dataset.py` (raw per-message Modbus CSV → v2
  feature CSV via the SAME shared `features.aggregate_rows` — no drift); extended
  `train_iforest.py` to report `external_roc_auc` on real held-out attacks when a
  labelled dataset is present; `infra/tests/stage2_real_dataset_smoke.py` (skips
  cleanly with no data — verified SKIP). **B is code-complete; for the real AUC
  number, download a gated dataset (SWaT/HAI/Morris — see converter docstring),
  convert it into `/var/lab/datasets`, and retrain.**
  **All offline gates green** (contract PASS, robot smoke AUC 0.99, modbus smoke AUC
  1.0, real-dataset SKIP). Stack UP and healthy.
  **Optional remaining:** drop in a real ICS dataset for B's live AUC; stretch — a
  live "Robot Dynamics" joint panel + `/api/robot/state`; Dockerfile cleanliness pass
  (the new vm-ai files arrive via the /vagrant boot-copy, which works but isn't baked
  into `Dockerfile.ai`).
- **2026-06-19** — **Segmentation review (DMZ).** Verified live (stack had to be
  brought back up — it had Exited 137 ~15h prior, just an overnight Docker stop, not
  a crash). Confirmed-good: IT (gitea) cannot reach OT via the OT-net (10.10) or MGMT
  (40.10) interfaces; AI reaches the PLC only via MGMT (40.10:502); ot-net is
  `internal:true` (no internet); SEC↔OT and SEC→AI-Redis conduits work — ops not
  disrupted. **FINDING (real gap):** `container-ot` is directly attached to `dmz-net`
  (30.10) and OpenPLC binds 0.0.0.0, so any DMZ-attached IT-facing host (gitea,
  guacamole) can reach **OT Modbus 502 and OpenPLC web 8080 directly at 192.168.30.10**
  — bypassing the "DMZ as broker" model. The project's `stage1_connectivity_matrix`
  misses this (only probes the OT-net IP 10.10, not the DMZ IP 30.10). Relevant
  because the Gitea CI server is a supply-chain target → could write the PLC directly.
  **Proposed non-breaking fix:** in `entrypoint_ot.sh`, REJECT inbound from
  `192.168.30.0/24` to OT ports 502/503/8080 (keep RDP 3389 for the Guacamole jump
  host and OT→historian outbound). No legit service uses OT Modbus via the DMZ (AI
  uses MGMT, SEC uses OT-net). Needs an OT image rebuild (baked entrypoint). NOT yet
  applied — awaiting go-ahead.
```
