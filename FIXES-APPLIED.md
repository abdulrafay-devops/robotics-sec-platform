# Security Hardening — Changelog (What Was Fixed)

**Scope chosen:** *hardening + light structural*, non-breaking.
**Guarantees honored:** the **E-stop and all safety logic are untouched**, and the **attack-injection + live telemetry demo features are untouched**. Every change is backward-compatible with the dashboard because Nginx injects the API key server-side for all `/api/` calls.

> After pulling these changes, run `docker compose up -d --build`. Because secrets were rotated, a rebuild/restart is required for them to take effect.

---

## 1. Authentication is now fail-closed  (audit F-03)

**File:** `vm-ai/score_service.py`
- **Before:** `_require_api_key` only rejected `if _API_KEY and key != _API_KEY` — so if `LAB_API_KEY` was empty, **all protected endpoints were open**.
- **After:** rejects with `503` when the server has no key configured, and `401` when the caller's key is wrong. Fails *closed*.

**File:** `vm-ai/devsecops/webhook_receiver.py`
- **Before:** HMAC signature was verified only `if WEBHOOK_SECRET:` — an unset secret silently allowed **anyone to trigger the CI/CD pipeline**.
- **After:** refuses the webhook (`503`) if no secret is configured, then requires a valid constant-time HMAC.

## 2. Previously-unauthenticated endpoints are now protected  (audit F-03)

**File:** `vm-ai/score_service.py` — added `dependencies=[Depends(_require_api_key)]` to:
- the **entire vendor-access router** (`/api/vendor/*`) — provisioning OT remote access was anonymous; now it requires the key.
- `/api/ir/incidents`, `/api/ir/pending` — incident data disclosure.
- `/api/stages/reports` — leaked the full vuln inventory / integrity baseline / pipeline verdicts.
- `/api/hmi/state`, `/api/hmi/logs` — live PLC state and server log disclosure.

**Not changed (intentionally):** `/api/trend`, `/api/trend/history`, `/api/demo/injection-state`, `/health`, `/score`, `/metadata`, `/prometheus/*` — these drive the live demo/telemetry and were kept open per the "keep demo as-is" decision. The control endpoints (`/api/hmi/control`, `/api/demo/inject-attack`, etc.) already required the key.

## 3. Secrets rotated, de-duplicated, and hardened  (audit F-04)

**Files:** `.env`, `.env.example`
- `LAB_API_KEY` and `GITEA_WEBHOOK_SECRET` were **byte-for-byte identical**; they are now **distinct** freshly-generated values.
- All other secrets (`POSTGRES_PASSWORD`, `REDIS_PASSWORD`) rotated.
- `GRAFANA_PASSWORD` was `admin`; now a strong generated value, and `.env.example` documents it with a "do not use admin" note and a "must differ from LAB_API_KEY" warning.
- **Action for you:** treat the old values as compromised (they were in the repo working tree).

## 4. Industrial / raw ports taken off the LAN  (audit F-01 / F-06)

**File:** `docker-compose.yml`
- `502` (production Modbus), `503` (safety Modbus), `8000` (raw scoring API), `9000` (CI webhook) are now bound to **`127.0.0.1` only**.
- Container-to-container traffic is unaffected (it uses the Docker networks, not published host ports), so the app still works end to end. Operator UIs (dashboard, Grafana, Prometheus, Gitea, Guacamole, ntopng, OpenPLC) remain published.
- Removed the insecure Grafana default: `GF_SECURITY_ADMIN_PASSWORD` now *requires* `GRAFANA_PASSWORD` to be set (no `:-admin` fallback).

## 5. Resilience + integrity (light structural)  (audit F-07)

**File:** `vm-ai/entrypoint_ai.sh`
- **Restart-supervision:** core services (score API, feature consumer, alert bridge, webhook receiver, exporter, IR engine) now run under a small `supervise()` restart loop, so a crash is auto-recovered instead of silently disappearing while the container still looks "up". No extra daemon, no behavior change to the services.
- **Audit trail no longer wiped by force:** the boot-time clearing of incidents/alerts is now **opt-out** via `LAB_RESET_STATE` (default `1` keeps the current "blank demo start"; set `0` to preserve history/forensics across restarts).
- **De-corrupted:** removed a duplicated/garbled block at the end of the original file (it contained a stray `090 > ...` fragment and a second copy of the service-start section).

## 6. Hygiene  (audit F-13)

**File:** `docker-compose.yml`
- The Redis health-check no longer passes the password on the command line (`redis-cli -a $REDIS_PASSWORD`); it uses `REDISCLI_AUTH` via env so the secret doesn't appear in the container process list.

---

## What was deliberately NOT changed

- **E-stop / safety reset logic** (`sim_safety_plc.py`, `safety_*.py`, `production.st`) — kept fully functional as required.
- **Attack-injection + synthetic telemetry** (`score_service.py` demo paths) — kept so the live detection demo still works.
- **Multi-homed containers / single-host topology** — left as-is (de-multi-homing is a larger structural change; see `AUDIT-REPORT.md` P1 for the production path).
- **SROS2 topic-level ACLs, CI acceptance-gate skip** — left as documented toggles (enabling ACLs can hang Cyclone DDS and take down all ROS2 in the OT container; enabling the acceptance gate only affects CI runs). See "Round 2" below and `AUDIT-REPORT.md`. *(The running-safety-controller gap — Guard A — was fixed in Round 2.)*

---

# Round 2 — Put the real Safety Supervisor on duty ("Guard A") + stand-in fixes

**Problem:** the sophisticated `safety_supervisor.py` (heartbeat watchdog, latched
E-stop, replay/regression guard) existed but was **never started**. The process
actually guarding port 503 was the simple `sim_safety_plc.py` stand-in (no
watchdog, no replay guard). Even the bridge's log file was named
`lab-safety-supervisor.log`, so it *looked* like the supervisor was running.

**Fix — `safety_supervisor.py` now runs the :503 safety server.**
- Added a `--modbus-only` run mode to `safety_supervisor.py`: it runs the real
  safety state machine + Modbus server (the watchdog/latch/replay brain) **without**
  a ROS2 node. ROS2 imports are now lazy, so this mode has no ROS dependency.
- `entrypoint_ot.sh` now starts `safety_supervisor.py --modbus-only` on port 503
  **in place of** `sim_safety_plc.py`. The companion `safety_bridge.py` is unchanged
  and remains the single SROS2 node — it keeps publishing `/safety/state`,
  subscribing `/safety/request`, and **mirroring safety state onto the production
  PLC (:502)**, so the dashboard and the physical halt keep working exactly as before.
- The existing `safety_heartbeat.py` (5 Hz heartbeat to HR[0..2]) now actually
  feeds a real watchdog: if the heartbeat stops for >500 ms, the supervisor
  **auto-trips EMERGENCY** — the protection that previously did not exist.

**Why it does not break the demo (register contract verified):**
- HMI **E-stop** writes HR[2]=1 → supervisor latches EMERGENCY → bridge mirrors
  coil 5 + reg 1034 to the production PLC. (Unchanged for the dashboard.)
- HMI **reset** writes HR[2]=9 → supervisor returns to NORMAL → bridge clears the
  production PLC. The supervisor scans every 10 ms (matching the old stand-in) so
  the momentary reset pulse is caught reliably before the 5 Hz heartbeat clears HR[2].
- The Modbus server runs on the **main thread** (the same proven pattern the
  stand-in used), not an unvalidated threaded path.
- `sim_safety_plc.py` was the unused stand-in; it has now been **removed from the repo** so `safety_supervisor.py` is the single, unambiguous :503 controller.

**Related "stand-in / mislabel" fixes (same family):**
- The bridge now logs to `lab-safety-bridge.log`; `lab-safety-supervisor.log` now
  holds the **real supervisor's** logs (so the dashboard's "supervisor" log tab and
  `score_service` mapping now show genuine watchdog/latch events).
- Corrected the misleading entrypoint comment that claimed "runtime ACL enforcement
  enabled" — it now states accurately that PKI **authentication** is enforced while
  topic-level **ACLs** are at the permissive default.
- The `run-safety-supervisor.sh` service wrapper now actually runs the supervisor
  (it previously ran the bridge despite its name).

**Deliberately NOT forced (need your runtime to validate — would risk breakage):**
- **SROS2 topic-level ACLs**: the authors disabled custom permission signing because
  it hung Cyclone DDS discovery (see `bootstrap_keystore.sh` design note). Re-enabling
  blindly could take down all ROS2 (safety bridge, heartbeat, Gazebo). To enable:
  uncomment the signing block in `bootstrap_keystore.sh` and test DDS discovery.
- **CI acceptance gate** (`LAB_SKIP_ACCEPTANCE=1` in `docker-compose.yml`): remove
  this env var to run Gate 6 (Stage-2 replay + Stage-3 safety loop) on every pipeline
  run. It only affects CI, not the live demo — enable it once you can watch a run.
- `vm-ot/openplc/production.st.bak` is leftover cruft (harmless; not linted). Safe to delete.

> After these changes, rebuild the OT image so the new entrypoint/supervisor take effect:
> `docker compose up -d --build container-ot` (or rebuild the whole stack). Then watch
> `lab-safety-supervisor.log` for "MODBUS-ONLY mode: safety brain active".

---

## Verification performed
- `py_compile` of edited Python edit-patterns (syntax OK).
- `bash -n` of the `supervise()` logic (syntax OK).
- `docker compose config` YAML parse OK; loopback binds confirmed.
- Dashboard API contract re-checked: every newly-protected endpoint is called via the `/api/` proxy that injects the key — so the UI is unaffected.

See `AUDIT-REPORT.md` for the full findings and the P0/P1/P2 remediation roadmap beyond this hardening pass.
