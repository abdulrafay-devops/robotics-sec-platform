# IDMZ Rearchitecture — execution blueprint

> This workspace (`robotics-app-idmz`) is a **plain copy** of `robotics-app`, created to
> build a *true* Purdue Level-3.5 IDMZ without risking the working demo. The original
> `robotics-app` is committed (git `a86e464`) and untouched. **Revert = delete this folder.**
>
> Goal: eliminate the multi-homing pivot + the DMZ→OT Modbus exposure by making every
> container single-homed and forcing all cross-zone traffic through ONE router/firewall.

---

## 1. Target architecture (what we're building)

```
  IT ─┐                                            ┌─ DMZ (jump host, artifact store)
      ├──►  ROUTER / FIREWALL  (only multi-homed)  ◄┤
 MGMT ─┘     ip_forward + default-deny nftables     └─ OT (PLC+robot, control gateway)
```

Single-homing map (each container → exactly ONE network):

| Container | Zone / network | Notes |
|-----------|----------------|-------|
| `lab-gitea`, `lab-gitea-runner` | it-net `20.x` | CI; publishes signed artifacts up to DMZ |
| `lab-guacamole`, `historian`, `postgres`, `guacd` | dmz-net `30.x` | jump host + artifact/historian proxies |
| `container-ai`, `container-dashboard` | mgmt-net `40.x` | analytics; READ-ONLY to OT |
| `container-ot` | ot-net `10.x` | PLC + robot + OT-resident control gateway |
| `container-sec` | mgmt-net `40.x` + **stealth tap** on ot-net | IP on mgmt only; ot interface IP-less |
| **`router-fw`** (NEW) | all 4 nets | the ONLY multi-homed node; enforces conduits |

Allowed conduits (default-deny — everything else dropped at `router-fw`):
1. `AI → OT Modbus read-only proxy (:5020) → PLC` : the proxy (`vm-ot/modbus_read_proxy.py`,
   **built + verified**) forwards ONLY read function codes; the router denies AI→PLC:502
   direct, so AI is **network-enforced read-only** (a compromised AI cannot write the PLC).
2. `Operator → OT control gateway (:8002) → PLC write` : via gateway, auth + approval
3. `Vendor → Guacamole(DMZ) → OT` : RDP 3389 only
4. `CI → DMZ store` (publish)  ·  `OT → DMZ store` (pull + verify signature)
5. `SEC` : passive stealth tap on OT (no IP — cannot route in)
6. `SEC → AI Redis` : 6379 (alert pipeline)  ·  `AI/dashboard` intra-mgmt
7. DENY: `IT→OT`, `OT→Internet`, and any direct cross-zone that skips the router

---

## 2. How the router works in Docker (the mechanism)

- `router-fw` is attached to all 4 bridge networks and runs with `NET_ADMIN` +
  `sysctls: net.ipv4.ip_forward=1`. It forwards **inside its own netns**, so Docker's
  host-level inter-bridge isolation does not block it.
- Every other container is single-homed. To reach another zone it needs a route **via the
  router**, not via the Docker bridge gateway. We add per-zone static routes at startup
  (needs `NET_ADMIN`):
  ```sh
  # example, inside container-ai (mgmt 40.x), to reach OT:
  ip route replace 192.168.10.0/24 via <router mgmt-side IP>
  ```
  (OT, which has no internet, can instead just default-route via the router.)
- `router-fw` nftables: `FORWARD` chain `policy drop;` + explicit `accept` rules for the
  conduits in §1. This is the single auditable choke point.

### 2.1 Concrete routing scheme (Docker reality)
`router-fw` takes static IP **`.2`** on every network (`10.2 / 20.2 / 30.2 / 40.2`); the
Docker bridge gateway stays `.1`. Each container reaches other zones via the router:

| Container | Zone (single-homed) | Route override (needs `NET_ADMIN`) | How applied |
|-----------|---------------------|-------------------------------------|-------------|
| `container-ot` | ot `10.10` | `default via 10.2` (OT has no internet) | own entrypoint |
| `container-ai` | mgmt `40.30` | `route add 10.0/24 via 40.2` | own entrypoint |
| `container-sec` | mgmt `40.20` (+ stealth ot, no IP) | none (talks Redis intra-mgmt; sniffs ot passively) | own entrypoint flushes ot IP |
| `container-dashboard` | mgmt | none (talks AI intra-mgmt) | — |
| `lab-gitea` | it `20.20` | `route add 30.0/24, 40.0/24 via 20.2` | **compose entrypoint-wrap** (prebuilt image) |
| `lab-guacamole` | dmz `30.20` | `route add 10.0/24 via 30.2` (reach OT RDP) | **compose entrypoint-wrap** (prebuilt image) |
| `lab-gitea-runner`, `postgres`, `guacd`, `historian` | their zone | none (no cross-zone initiation) | — |

Only **gitea** and **guacamole** are prebuilt images that must initiate cross-zone, so only
those two need an entrypoint wrap (`sh -c "ip route add … ; exec <original-entrypoint>"`
with `cap_add: NET_ADMIN`). Everything else either is built by us (route in entrypoint) or
never initiates cross-zone (no override). `router-fw` needs `sysctls: net.ipv4.ip_forward=1`.

---

## 3. Hard-coded IPs — what actually must change

Grep found 139 `192.168.x` refs in 35 files, but they split into two buckets:

**A. LIVE connection targets — MUST re-point to single-homed IPs (the real work, ~6 files):**
| File | Current | Change to |
|------|---------|-----------|
| `vm-ai/score_service.py` | `PRODUCTION_PLC_IP=192.168.40.10` (mgmt) | `192.168.10.10` (OT), routed via router; writes go to control gateway |
| `vm-ai/monitoring/lab_exporter.py` | `PROD_HOST=192.168.40.10`, probes | `192.168.10.10` + adjust component probes to routed paths |
| `vm-sec/log_shipper/feature_pusher.py` | `REDIS_HOST=192.168.40.30` | AI's mgmt IP (unchanged if SEC stays on mgmt) |
| `vm-ot/sros2/safety_heartbeat.py` / `safety_*` | `192.168.10.11`, `.10` | stay within ot-net (intra-zone, fine) |
| `vm-ot/entrypoint_ot.sh` | alias IP `192.168.10.11`, iptables | keep intra-OT; drop the cross-zone INPUT rules (router owns that now) |
| `infra/tests/stage1_connectivity_matrix_docker.py` | probe matrix | update expected ALLOW/DENY for the new conduits **and fix the /dev/tcp probe** (also add the `30.10` DMZ-interface probe that the old test missed) |

**B. Cosmetic / synthetic — LEAVE AS-IS (not real connections):**
`vm-ai/model/datasets.py`, `robot_*`, `convert_public_dataset.py` (synthetic feature IPs);
`vm-ot/traffic/*` (attack generators target the PLC by its OT IP — fine);
`alert_bridge.py` `dest_ip` (display); dashboard `*.tsx` (display strings);
`vm-sec/vuln/*`, `cve_db.json`, baselines (inventory data); `interview-prep/*` (docs).

> Key insight: single-homing OT to `10.x` means the AI's old `40.10` PLC path disappears —
> the AI must target `10.10` and rely on the router. That's the main re-point.

---

## 4. Stage-by-stage plan (verify after each; never break more than one thing)

- **S1 — Router/firewall container.** New `infra/router/` (Alpine + nftables). Add to a new
  `docker-compose.yml` attached to all 4 nets, `ip_forward`, default-deny + conduit allows.
  *(scaffolded now; not yet wired as the gateway.)*
- **S2 — Single-home + route via router, one zone at a time.** Start with IT (lowest risk):
  remove its DMZ foot, add static route via router, confirm IT→DMZ works and IT→OT fails.
  Then DMZ, then MGMT, then OT. Re-point the §3-A IPs as each zone moves.
- **S3 — AI read-only.** Set `LAB_CONTROL_GATEWAY_URL`; router limits AI→PLC to read FCs.
- **S4 — SEC stealth tap.** Attach SEC to ot-net, `ip addr flush` that interface at boot;
  verify Zeek still sniffs and SEC cannot route into OT.
- **S5 — Brokered deploy.** DMZ artifact store; OT pulls + verifies signature.
- **S6 — Full re-verify.** Rebuild the `-idmz` stack; rerun connectivity matrix (fixed),
  the AI + robot detection demo, the safety loop; confirm `gitea→OT 30.10:502` is GONE.

## 5. Verification gates (must pass before calling a stage done)
- Cross-zone matrix: IT→OT (all interfaces) BLOCKED; AI→PLC read OK / write via gateway only;
  DMZ→OT 3389 OK; SEC→Redis OK; OT→Internet BLOCKED.
- App still works: dashboard 200, all 4 models loaded, robot + Modbus injections detected,
  safety E-stop loop intact.

## 6. Progress log
- **2026-06-19** — Workspace created (copy of `robotics-app` @ git `a86e464`). IP inventory
  done (139 refs / 35 files; ~6 files are real connection targets). Blueprint written.
- **2026-06-19** — S1 router scaffolded (`infra/router/`: Dockerfile.router, nftables.conf
  default-deny + conduits, entrypoint.sh). **L7 Modbus read-only proxy built + VERIFIED**
  (`vm-ot/modbus_read_proxy.py`): offline test confirms read FCs pass, write FCs get a
  Modbus illegal-function exception, and writes never reach the PLC. Concrete routing scheme
  locked (§2.1: router at `.2`, per-container route plan, only gitea+guacamole need
  entrypoint-wrap). Next: write the single-homed `docker-compose.yml` (S2), then per-container
  route-override entrypoints + IP re-points, then bring up `-idmz` stack and verify (S6).
- **2026-06-19** — **Routing pattern PROVEN in Docker Desktop** (2-node spike: node→router→node,
  allowed port reached, denied port blocked). S2 WIRING COMPLETE & syntax-valid: new
  single-homed `docker-compose.yml` (router-fw at `.2` all nets + every service single-homed,
  gitea/guacamole entrypoint-wrapped, sec mgmt+stealth-ot); `nftables.conf` final conduits
  (AI→OT only via proxy:5020, never 502); entrypoints — AI route to OT via router, OT default
  route via router + starts the read-only proxy, SEC flushes its OT IP (stealth);
  `score_service` PLC target re-pointed to `LAB_PLC_HOST:LAB_PLC_PORT` (proxy) + writes via
  `LAB_CONTROL_GATEWAY_URL`. Next: bring up (down original, build+up `-idmz`, fresh model
  train, debug routing) then verify (S6).
- **2026-06-19** — **BUILT, RUNNING & VERIFIED.** All 5 images built; original stack `down`;
  `-idmz` stack up. Two bugs found & fixed during bring-up (live-diagnosed, then persisted):
  (1) `entrypoint_sec.sh` crashed under `set -o pipefail` because the DMZ-interface `grep`
  found nothing now that SEC is single-homed → added `|| true` to the 3 detection lines;
  (2) allowed conduits were dropped because (a) responders lacked RETURN routes to the
  source zone and (b) `ot-net: internal:true` made Docker drop router-forwarded traffic into
  OT → removed `internal:true` (firewall enforces OT isolation via default-deny instead) and
  gave each cross-zone participant routes to all peer zones via the router (AI entrypoint +
  historian compose wrap).
  **Verification (S6) — all green:**
  • Gates: IT(gitea)→OT BLOCKED on every interface/port; AI→raw PLC:502 BLOCKED.
  • Conduits: AI→read-proxy:5020 OPEN, AI→control-gateway:8002 OPEN, IT→DMZ store OPEN.
  • App: dashboard HTTP 200; all 4 models loaded; **AI reads live PLC telemetry through the
    read-only proxy** (`/api/hmi/state` returns real coil/reg state); **operator control
    write succeeds via the gateway** (cycle started: motor_arm_enable=True) while AI cannot
    write directly (502 blocked + proxy refuses writes) = network-enforced read-only.
  • Detection: robot plane scores the live moving arm (z≈−4.9 nominal) and fires on injected
    `joint_speed_violation`; Modbus injection → 16 `modbus-external-anomaly` alerts. Both planes work.
  **Known gap (documented):** the Zeek LIVE-baseline Modbus pipeline is empty — SEC as a pure
  stealth tap can no longer GENERATE baseline OT traffic, and AI reads go via the proxy
  (proxy→PLC is localhost, off the wire). Attack-injection detection is unaffected. Proper
  fix: a dedicated HMI/poller container ON ot-net (with an IP) to produce sniffable baseline
  traffic, or extend Zeek to analyze the proxy port. Tracked as the next refinement.
- **2026-06-20** — **Live Modbus pipeline gap RESOLVED + a real Docker limitation learned.**
  First tried a *separate* `hmi-poller` container on ot-net (10.30) polling the PLC — it polled
  fine (ok=41) but Zeek saw NOTHING (`modbus_features.log`=0). **Verified empirically: a Docker
  user-defined bridge does not mirror third-party unicast to a passive port**, so an IP-less
  SPAN tap is impossible here — the monitor must be a *party* to the traffic. Pivoted to the
  proven model: **reverted the SEC stealth flush** (SEC keeps its ot-net IP `10.20`), removed the
  redundant `hmi-poller`, and let SEC's own baseline generator run. Result, verified: Zeek now
  decodes Modbus (246+ feature rows, FC3 reads 10.20→10.10:502); feature_consumer scores the
  REAL baseline (`latest_scores.json`: iforest=0.065, anomaly=false). Live network detection
  works end-to-end. **Trade-off (documented honestly):** SEC + router are now the two
  multi-homed containers; SEC's OT presence is a monitoring necessity because Docker can't do a
  hardware-style SPAN. Stronger future option: a Zeek sidecar sharing the OT netns
  (`network_mode: container:container-ot`) would see the real proxy↔PLC control traffic too,
  but needs extra plumbing to reach Redis cross-zone — left as a documented enhancement.
- **2026-06-20** — **Connectivity-matrix test rewritten for the IDMZ + a real bug it caught,
  fixed.** `infra/tests/stage1_connectivity_matrix_docker.py` now uses a robust probe
  (`nc` where present, else bash `/dev/tcp`, via `sh -c`) and the IDMZ conduit matrix (13
  probes: AI read-only to OT, IT→OT blocked, deploy/webhook/RDP/historian conduits, SEC
  monitoring). First run: **12/13, and it FAILED `Guacamole→OT:3389`** — root cause: the
  Debian-based guacamole image ships without `iproute2`, so its startup route-override
  silently failed and the RDP broker had no path to OT (the Alpine images have `ip` via
  busybox, which is why they passed). Fix: `infra/guacamole/Dockerfile` (FROM the stock
  image + `iproute2`); compose `guacamole` now builds it. Re-run: **13/13 ALL-GREEN.** The
  automated segmentation gate now matches reality.
- **2026-06-20** — **Stage 5: signed CI→OT deploy pipeline BUILT + VERIFIED (real
  supply-chain control).** Implemented the "IT never pushes, OT pulls and verifies" model so
  a new PLC program reaches the controller only if it is signed by the release key and intact.
  Components: `infra/deploy/publish.sh` (runs in container-ai, where the rsa3072 release key
  lives) GPG-signs the `.st`, exports the public key, and writes `program.st` + `.sig` +
  `release_pubkey.asc` to a new `deploy-store` volume; the **historian** serves that volume
  read-only at `/deploy` (mountpoint pre-created under the RO html bind so Docker can overlay
  it); `vm-ot/deploy_agent.py` (in container-ot) PULLS the three files over the existing
  `OT→DMZ:80` conduit, verifies the detached signature in an *ephemeral* keyring trusting only
  the published pubkey, and only on success compiles + stages the program into OpenPLC.
  **Verified both ways:** (1) good artifact → `signature VALID` → compiled → `DEPLOY ACCEPTED`;
  (2) `publish.sh --tamper` (attacker edits the `.st` after signing) → `BAD signature` →
  `DEPLOY REJECTED — controller untouched`. Connectivity matrix extended with an
  `OT→DMZ store:80 ALLOW` probe and re-run: **14/14 ALL-GREEN.** No change to the network
  architecture — this is purely additive (new volume + two scripts), so the verified
  segmentation is unchanged.
- **2026-06-20** — **SEC pivot CLOSED: monitor is now single-homed on OT (true IDMZ
  shape).** Chosen as the low-complexity, requirement-meeting option over a full Zeek
  sidecar. SEC dropped its `mgmt-net` (40.20) NIC and now has ONE interface on `ot-net`
  (10.20) — an OT-resident IDS, exactly where it belongs. Its only mgmt dependency
  (shipping ML features to AI Redis) moves onto a single SEC-IP-scoped firewall conduit:
  nft rule `ip saddr 192.168.10.20 ip daddr 192.168.40.30 tcp dport 6379 accept`, plus a
  route `192.168.40.0/24 via 192.168.10.2` added in `entrypoint_sec.sh`. Both the nft file
  and the entrypoint are baked into images (COPY, not bind-mount) — so this needed
  `docker compose up -d --build router-fw container-sec` to take effect (recreate alone
  silently kept the old ruleset/route; verified and corrected). **Result, all verified:**
  SEC has only `eth0=10.20`; SEC→Redis OPEN via the conduit (feature_pusher: "connected to
  redis", "pushed 100 rows"); SEC→mgmt dashboard 40.40:80 and SEC→AI API 40.30:8000 now
  BOTH BLOCKED — **a compromised SEC can no longer pivot into the management zone.** The
  router is now the ONLY multi-homed container. Live ML pipeline still flows with correct
  attribution (`feature_consumer` scoring windows, `src=192.168.10.20`). Connectivity
  matrix extended with two pivot-closed DENY probes + re-run: **16/16 ALL-GREEN.**
  Honest residual (documented): SEC, as an OT-resident IDS, can still reach the PLC — same
  as any in-zone monitor; closing even that is what the heavier sidecar option would buy.
- **2026-06-20** — **NOTE (pre-existing, NOT from the IDMZ work): baseline reads as a
  persistent low-confidence anomaly.** `feature_consumer` calibrated its IsolationForest
  threshold to 0.1427 while the steady single-arm baseline scores ~0.0979 (below it), so
  every baseline window is flagged ANOMALY. Confirmed pre-existing: the consumer log shows
  `if=0.0979 ANOMALY` at 06:43–06:44, BEFORE the SEC rebuild at 06:47 — the segmentation
  refactor changed only the feature *shipping path*, not the features (attribution still
  `src=10.20`). Likely environmental drift from the repeated Docker restarts shifting the
  baseline rate vs. the trained model / calibration. Tracked as a separate AI-engine
  recalibration follow-up (out of scope for the IDMZ rearchitecture).
- **2026-06-20** — **AI false-positive RESOLVED: train/serve calibration skew, not drift.**
  The dashboard was showing CRITICAL + firing IR on the *normal* baseline. Root-caused with
  a new replay diagnostic (`infra/tests/diag_baseline_drift.py`) that runs live rows through
  the exact consumer feature code and diffs each feature against the scaler's training mean:
  only three features drifted — `n_reads`/`n_msgs`/`msg_rate` (scaled_z ~+5.4) — i.e. the live
  Zeek pipeline emits ~3.5x the message volume the models were trained on. Mechanism: the
  models are calibrated on the **synthetic** dataset (`model/datasets.py`), whose 1-row-per-
  message shape doesn't match Zeek's multi-row-per-transaction + bursty inter-arrival output.
  The **IsolationForest was fine** (baseline 0.098 < 0.143 thresh; attack 0.22 — correct both
  ways); only the two **autoencoders** were mis-calibrated — their `baseline_recon_mean/std`
  came from synthetic data, so live-normal reconstruction error sat 15x (PCA) / 177x (TF) above
  the synthetic baseline, exploding `tf_z` to ~160 and tripping the AE consensus. Fix (low-risk,
  models untouched): `vm-ai/model/recalibrate_live_thresholds.py` replays ~120s of clean live
  baseline windows, measures each AE's real recon-error distribution, and rewrites
  pca/tf_threshold.json (`baseline_recon_mean/std`, p99, `z_alert`) so normal sits at z~0.6 and
  attacks (recon err 1000x+ higher) still fire. **Verified:** baseline stable `anomaly=false`
  (pca_z/tf_z ~0.6 across reads), injection attack `anomaly=true` (iforest 0.22, pca_z 87489,
  tf_z 4158), returns to false after. Thresholds persist in the `ai-models` volume.
  **Ops note:** this live recalibration must be re-run after any model retrain or `down -v`
  (a retrain rewrites the synthetic-calibrated thresholds). Same skew exists in the original
  `robotics-app`; the tool transfers. (A NOT-from-the-IDMZ-work item; surfaced during this work.)
- **2026-06-20** — **Dashboard "everything flickers every 5s" RESOLVED — slow Prometheus
  exporter, not the AI.** All `lab_*` panels (AI scores, IEC-62443 compliance, safety,
  incidents) blinked out and back on the 5s poll. Root cause: `vm-ai/monitoring/lab_exporter.py`
  `/metrics` took **16.8s** — over Prometheus's 5s `scrape_timeout` — so the `lab_exporter`
  target flapped down/up and every metric it serves went stale then fresh (the dashboard's
  `usePrometheusMetrics` overwrites all panels each poll and renders a missing metric as `-1`,
  so they flicker together). Two compounding costs, both fixed: (1) it parsed the **entire 40MB
  Suricata `eve.json` every scrape** — now tail-reads the last 2MB (bounded regardless of file
  size); (2) it probed 10 components **serially**, several of which are unreachable from the AI
  in the IDMZ by design (ntopng at SEC's *old* mgmt IP 40.20, PLC :502/:503 direct, guacamole,
  gitea) so each blocked connect waited out its timeout — now probed in **parallel** (+ tighter
  0.25s/0.4s timeouts). Result: `/metrics` **16.8s → 1.5–2.9s**, target `health=up dur=1.55s`,
  metrics present+stable across polls (no flicker). Baked into the AI image (rebuilt); recalibrated
  AE thresholds persisted across the rebuild (ai-models volume). **Follow-ups (cosmetic, not the
  flicker):** Suricata `eve.json` grows unbounded (needs log rotation in SEC; exporter is fine
  via tail-read); `COMPONENT_PROBES` still lists IDMZ-unreachable targets so those tiles read
  false-DOWN — the probe set should be re-scoped for single-homed zones; and the dashboard could
  keep-last-value on a Prometheus miss (like `useTrend`) instead of blanking to `-1`.
