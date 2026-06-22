# AI Production-Upgrade Plan — context & progress

> **Read this first if resuming in a new session.** This is the single source of truth for the
> AI detection + remediation upgrade. Goal, decisions, current state, the 4-step plan, the
> anti-churn rules, and a running progress log.

## Goal (locked with the user 2026-06-21)
Make the AI **detection + remediation convincingly production/industrial-grade for a DEMO /
portfolio** — NOT a real factory deployment. Decisions the user confirmed:
- **Single robot arm** (no multi-device). Make it robust + richer; lower risk.
- **Medium effort (~1–2 weeks)**, do **all 4 steps** below.
- **Attack library: ~6–8 ICS attacks**, each tagged with **MITRE ATT&CK for ICS**.
- **HARD CONSTRAINT — no churn / no days lost to bug-fixing.** Every model change goes behind a
  **validation harness (safety net)** and is only swapped into the live volume **if it passes**
  (baseline calm + every attack caught + zero false alarms). Never break the live demo.
- Explain things to the user in **plain words** (they value clarity + analogies).

## Why (diagnosis)
The AI was trained on a "toy world" — one arm + one steady poller → a near **rank-1** baseline.
Symptoms we hit this week: degenerate PCA (perfect reconstruction → zero-variance threshold),
IsolationForest false-firing on normal *and* missing the real attack, score swings, train/serve
skew, and a manual retrain that introduced fake incidents. **Root causes: (a) flat/toy data,
(b) no MLOps safety net.** Steps 1–3 fix exactly these.

## Current AI state (facts for continuity)
- **Two planes:** Modbus network (IsolationForest + PCA-AE + TF-AE, 20 windowed features) and
  robot behavior (LSTM + physics envelope).
- **Model files:** `ai-models` Docker volume → `/opt/lab/models/` (autoencoder.h5, iforest.pkl,
  pca.pkl, scaler.pkl, robot_lstm.h5, *_threshold.json, model_meta.json). Git-ignored.
  Backups in parent `_model_backup_pre_retrain/` + `_model_backup_post_retrain/`.
- **Trained on the LIVE 4Hz baseline** via `vm-ai/model/capture_live_baseline.py` →
  `/var/lab/state/live_baseline_X.npy`, fed to the 3 trainers through an env-gated override in
  `datasets.py` (`LAB_LIVE_BASELINE_NPY`). Run trainers with `PYTHONPATH=/vagrant/vm-ai`.
- **Current live thresholds:** iforest gate **0.30** (model_meta.calibrated_threshold; raised
  above normal-max 0.225 to stop fake incidents); pca std floored **0.01** (degenerate on rank-1);
  tf z_alert **4.23** (healthy/sensitive). `train_iforest.py` now calibrates `max×1.25` (reproducible).
- **Baseline generator:** `vm-ot/traffic/modbus_normal.py` — steady **4Hz HMI scan** (`--rate-hz`
  is a floor), reads holding regs 0–3, read-only, runs in SEC (10.20). **Bind-mounted** → editing
  the file + restarting the process applies it, no image rebuild.
- **Pipeline:** SEC Zeek → features → Redis (conduit SEC 10.20→AI 40.30:6379) → `feature_consumer`
  (AI) → `latest_scores.json` + `lab.anomaly.events` → `alert_bridge` → `ai-alerts.json` →
  `playbook_engine` → `/var/lab/state/ir/incidents.jsonl`.
- **Anomaly logic (consumer):** `anomaly = if_fired OR (pca_fired AND tf_fired)`. On the live
  injection attack: iforest≈0.17 (<0.30, doesn't fire) but pca/tf fire → consensus → detected.
- **Existing attacks:** live scripts `vm-ot/traffic/attack_modbus_{inject,replay,flood}.py`
  (triggered by writing `/var/lab/state/attack_trigger.json`, watched by SEC's entrypoint loop).
  Synthetic generators in `datasets.py`: `_attack_command_injection`, `_attack_replay`,
  `_attack_coil_flood`, `_attack_register_scan`, `_attack_bulk_write` (used for training AUC).
- **Models persist across restarts** (entrypoint trains only if a model file is missing).
- **Git:** `-idmz` is a git repo (commits 12fca9b, bf771fc, 289d063). GitHub push PENDING (no
  gh/remote/creds; SSH key not registered). Model artifacts are git-ignored (volume-backed-up).
- **Stack:** 11 single-homed containers + `router-fw` (default-deny, 8 conduits, matrix 16/16).

## The 4-step plan

**Step 1 — Validation harness (the safety net).**  STATUS: ✅ DONE (2026-06-21)
Built `infra/tests/validate_ai.py` (host-run, drives the LIVE pipeline via docker). It (a) reads
the baseline over ~40s and asserts calm (anomaly=false, 0 false alarms); (b) triggers each attack
and asserts detected; prints a PASS/FAIL table; exit 0=PASS. **First run PASSED:** baseline calm
(0 false alarms, iforest ~0.13 < 0.30), and all 3 wired attacks detected (command injection
pca=77/tf=120k, replay pca=831/tf=208k, flood pca=224/tf=407k). Rule: run this after ANY model
change; only promote if it PASSES. (Chose a live harness over offline replay because the demo IS
the live pipeline — most faithful. Note: it currently triggers the 3 attack types SEC's watcher
knows; Step 2 extends the attack set + the harness's ATTACKS list.)

**Step 2 — Realistic scenario + 6–8 attack library (MITRE-tagged).**  STATUS: ✅ DONE (2026-06-22)
`modbus_normal.py` now does a realistic multi-block HMI scan (telemetry MW0-4 + safety MW10-12 +
occasional MW0-31 diagnostic sweep, read-only, in-range) → real window variance. Attack library =
**7 attacks**: 3 via SEC's trigger (injection T0855, replay T0831, flood T0814) + 4 in the new
`vm-ot/traffic/attack_modbus_extra.py` (recon T0846, e-stop tamper T0880, stealthy drift T0836,
bulk write T0843), all wired into `validate_ai.py`. NOTE: capture flood-guard raised (msg_rate>120)
since the dense read baseline is legit (write-attacks are excluded by the write_ratio guard).
- Richer "normal": `modbus_normal.py` polls **varied** register groups at realistic rates with
  natural variation, so the baseline is no longer rank-1 (this fixes the PCA/iforest brittleness
  at the source). NOTE: enriching the baseline **forces a retrain (Step 3)** — do NOT deploy the
  richer baseline live until Step 3 retrains on it and the harness passes.
- Attack library (~6–8), each MITRE ATT&CK for ICS tagged, as BOTH synthetic generators (for
  training/validation) and live scripts (for the demo). Proposed set: command injection
  (T0855), replay (T0831), coil/register flood / DoS (T0814), recon scan (T0846/T0888),
  malicious logic / unauthorized program (T0843/T0889), E-stop / safety-state tampering (T0858/
  T0880), stealthy setpoint drift (T0836), out-of-bounds / spoofed-value write (T0856/T0832).

**Step 3 — Trustworthy detection (retrain behind the harness).**  STATUS: ✅ DONE (2026-06-22)
Retrained all 3 Modbus models on the enriched live baseline (85 windows). `validate_ai.py` PASSED:
baseline CALM (0 false alarms, 0 negative scores), **7/7 attacks detected** (pca peaks 2.7k–743k,
even the stealthy drift + recon). Promoted; backed up in parent `_model_backup_amazing/`. iforest
gate auto-calibrated to 0.3951 (max×1.25) → dashboard threat/iforest thresholds realigned to 0.40.
NOTE: PCA is still mathematically degenerate even enriched (single-arm Modbus features are inherently
correlated → low rank → linear PCA reconstructs perfectly); the std-floor keeps it usable and it
still fires hard on attacks. The TF AE + IsolationForest are the real detectors.
Retrain on the richer baseline; validate against the WHOLE attack library via Step 1; only
promote if PASS. Add **explainability** to alerts ("fired because writes jumped 40× from a
non-OT source"). Result: calm baseline, every attack caught, sensitive models.

**Step 4 — SOC-grade response + dashboard.**  STATUS: ⬜ not started
- A **playbook per attack type** (each attack → named, validated response).
- Incident/case view: timeline + ATT&CK label + "why it fired" + analyst approve/reject + audit.
- A clean detect → investigate → respond story per attack.

## Anti-churn rules (do not violate)
1. **Never** overwrite a live model in `/opt/lab/models` unless `validate_models.py` PASSES.
2. Snapshot models (`docker cp container-ai:/opt/lab/models/. <backup>`) before any model change.
3. Verify each step before starting the next. Develop risky changes (richer baseline, retrain)
   OFF the live path; promote atomically once validated.
4. The richer baseline (Step 2) + retrain (Step 3) are coupled — never deploy one without the other.

## Hard requirement (user, 2026-06-21): scores must NEVER be negative
DONE — `feature_consumer.py` floors pca_z/tf_z to ≥0 and `robot_consumer.py` floors robot_z to ≥0
(firing still uses the raw z, so detection is unchanged). Convention now everywhere: **0 = normal
or better, higher = more anomalous** (same as IsolationForest). Verified: baseline pca/tf/robot = 0.0,
attack pca=93/tf=207k, detection intact. Baked into the AI image. Also "make models amazing &
accurate" → do Step 2+3 (richer baseline → retrain) which is what makes them genuinely accurate +
the PCA non-degenerate.

## Progress log
- **2026-06-21** — Plan locked (all 4 steps, 6–8 attacks, single-arm, demo-grade, safety-net).
  Context file created. Starting Steps 1 + 2.
- **2026-06-21** — **Step 1 DONE.** `infra/tests/validate_ai.py` built + first run PASSED
  (baseline calm, 3/3 attacks detected). This is the anti-churn gate for all later model changes.
  **NEXT = Step 2:** (i) enrich `modbus_normal.py` to poll varied register groups (kills the
  rank-1 brittleness at the source); (ii) grow the attack library to 6–8 (add recon-scan,
  malicious-logic, e-stop-tamper, setpoint-drift, out-of-bounds) as live scripts + register them
  in the harness's ATTACKS list + MITRE tags. **Then Step 3** retrains on the richer baseline and
  must PASS `validate_ai.py` before promotion. REMEMBER: richer baseline + retrain are coupled —
  develop off the live path, promote atomically only after the harness passes (never break the demo).
- **2026-06-22** — **Steps 2 + 3 DONE + non-negative scores DONE.** Enriched generator + 7-attack
  MITRE library + retrain on the 85-window enriched baseline → `validate_ai.py` **PASS: baseline
  calm, 0 negatives, 7/7 attacks detected**. Dashboard realigned (iforest gate 0.40) + rebuilt;
  validated models backed up in `_model_backup_amazing/`. **Only Step 4 remains** (SOC-grade
  response: playbook-per-attack + incident/case view + ATT&CK labels + analyst approve/reject).
  Detection plane is now demo-grade: baseline NOMINAL + non-negative + all 7 attacks caught.
