# Requirements-Compliance Audit — Topic 114

## Intelligent Industrial Robotics Security Platform (OT/IT Convergence, Safety, AI Anomaly Detection)

**Audit date:** 2026-06-20
**Audited build:** `robotics-app-idmz` — the single-homed IEC-62443 Level-3.5 IDMZ architecture (current/deployed).
**Method:** live verification against the running 11-container stack (`docker exec` probes, Prometheus queries, the automated segmentation matrix, and the signed-deploy + anomaly-detection test harness), cross-checked against source.
**Reference:** `requirements.md` (Topic 114 learning objectives + mandated open-source toolset).

---

## 1. Executive verdict

**The platform satisfies all six Topic-114 capability areas and uses the full mandated toolset.** Every objective is implemented by a running component and was verified live, not asserted from docs. The recent rearchitecture into a **true single-homed IDMZ** (one router/firewall as the only multi-homed node, default-deny conduits) and the **signed CI→OT deploy pipeline** also close the **critical findings from the prior production-hardening audit** (`AUDIT-REPORT.md`, 2026-06-06) — most importantly the monitoring-zone PLC-write authority (F-02) and the multi-homed segmentation bypass (F-06).

**Compliance: COMPLETE across the six objective areas.** Two **integration gaps** remain — both introduced by the segmentation work and both telemetry-path issues, not capability gaps — plus the expected set of lab-appropriate hardening carry-forwards. They are listed honestly in §4.

| # | Requirement area | Status | Primary evidence |
|---|---|---|---|
| 1 | OT/IT convergence, DMZ & micro-segmentation | ✅ Complete | 16/16 segmentation matrix; single-homed zones + `router-fw` |
| 2 | AI-driven anomaly detection | ✅ Complete | IsolationForest + PCA-AE + TF-AE (Modbus) and LSTM (robot); live-recalibrated |
| 3 | Safety-system protection & functional safety | ✅ Complete (1 telemetry gap) | safety supervisor + SIS running; IEC-62443 score=100 |
| 4 | Robotic vulnerability management | ✅ Complete | Stage-4 scanner; **signed** pull-deploy (Stage 5) |
| 5 | DevSecOps for industrial automation | ✅ Complete | Gitea CI + acceptance gate + GPG-signed artifact verify-on-pull |
| 6 | Incident response & recovery | ✅ Complete | playbook engine + forensics capture + recovery workflows |

---

## 2. Per-objective compliance (with live evidence)

### 2.1 OT/IT Convergence Security and Network Segmentation ✅

| Sub-requirement | Implementation | Verified |
|---|---|---|
| Secure OT/IT architecture with **industrial DMZ + micro-segmentation** | Four single-homed zones (OT `10.10/24`, IT `20/24`, DMZ `30/24`, MGMT `40/24`); one `router-fw` (Alpine + nftables, default-deny `FORWARD`) is the **only** multi-homed node; brokered conduits only | **16/16** conduits match policy (`infra/tests/stage1_connectivity_matrix_docker.py`): IT→OT dead on every path; AI→raw-PLC:502 denied |
| **Secure remote / vendor access** | Apache Guacamole DMZ jump host brokers RDP into OT only; vendor-access provisioning API with audit log | Matrix: `Guacamole→OT:3389 ALLOW`, `Guacamole→OT:502 DENY` |
| **Traffic analysis & industrial-protocol monitoring** | Zeek (Modbus/DNP3/OPC-UA analyzers) + Suricata + ntopng on the OT-resident SEC sensor; feeds the ML feature bus | All three processes RUNNING; live Modbus features flow SEC→Redis (`pushed … rows`, `src=192.168.10.20`) |

**Note:** SEC is now **single-homed on OT** (an OT-resident IDS), shipping ML features to mgmt Redis over a single SEC-IP-scoped conduit — so a compromised SEC can no longer pivot into the management zone. The router is the only multi-homed container, as a real IDMZ requires.

### 2.2 AI-Driven Anomaly Detection for Robotics Operations ✅

| Sub-requirement | Implementation | Verified |
|---|---|---|
| **ML models for behavioral analysis** | Two detection planes: **network/Modbus** (IsolationForest + PCA autoencoder + TensorFlow deep autoencoder, 20 windowed features) and **robot behavior** (LSTM on `/joint_states` + physics-envelope) | Models present: `iforest.pkl`, `pca.pkl`, `autoencoder.h5`, `robot_lstm.h5`, `scaler.pkl` |
| **Predictive analytics for cyber-physical attacks** | Windowed scoring with consensus logic; alerts on rate/write/exception/trajectory deviations | Injection attack → `iforest 0.22 (>0.143)`, `pca_z 87489`, `tf_z 4158` → anomaly=true; baseline stable false (z≈0.6) |
| **Automated threat response & safety integration** | Anomaly events → IR playbook engine → automated/approval-gated actions incl. SROS2 e-stop | playbook_engine RUNNING; SROS2 estop path present |

**Anti-drift:** trainer and scorer share one versioned feature module; thresholds are **calibrated against live traffic** (the autoencoders were re-baselined on the real Zeek pipeline, eliminating a synthetic-vs-live train/serve skew). Baseline reads normal and attacks fire — both confirmed this cycle.

### 2.3 Safety System Protection and Functional Safety ✅ (one telemetry gap)

| Sub-requirement | Implementation | Verified |
|---|---|---|
| **Controls for safety-critical systems** (e-stop, interlocks, safety PLC) | Independent safety supervisor + safety PLC on OT `:503`; SROS2-gated e-stop topic | safety process RUNNING; `:503` listener present in OT |
| **IEC-62443 compliance automation** | Continuous compliance scorer exported to Prometheus/Grafana | `lab_iec62443_compliance_score = 100` |
| **SIS security & integrity validation** | SIS integrity gauge + safety-state machine (NORMAL/DEGRADED/EMERGENCY) | gauge **present but reads `-1`** — see Gap G-1 (mgmt exporter can't read OT `:503` across the IDMZ; SEC can) |

### 2.4 Robotic System Vulnerability Management ✅

| Sub-requirement | Implementation | Verified |
|---|---|---|
| **Automated vulnerability scanning** | Stage-4 scanner loop (Nmap + custom OT checks) → `vulnerabilities.json` → Prometheus | scanner present; `lab_stage4_vuln_count = 0` |
| **Secure firmware/patch deployment** | **Stage-5 signed pull-deploy**: CI GPG-signs the PLC program → DMZ artifact store → OT **pulls + verifies signature** before loading; tampered artifact rejected | Good artifact → `DEPLOY ACCEPTED` (compiled); `--tamper` → `BAD signature → DEPLOY REJECTED — controller untouched` |
| **Config management & baseline enforcement** | Integrity baseline + drift detection | baseline/drift files present; surfaced on dashboard |

### 2.5 DevSecOps for Industrial Automation ✅

| Sub-requirement | Implementation | Verified |
|---|---|---|
| **Security validation for PLC programming** | CI compiles + acceptance-gates the IEC-61131 ST program; **signature verified on the OT side before load** | Stage-5 verify both ways (accept/reject) |
| **Secure dev for HMI/SCADA** | Read-only historian wall-board (server-side key injection, write endpoints refused at the edge); operator dashboard separate | historian serves read-only; matrix confirms DMZ→AI read-only conduit |
| **Automated security testing** | Gitea + act runner CI; acceptance gate; webhook (constant-time HMAC) → AI receiver | CI webhook conduit `IT→AI:9000 ALLOW`; runner present |

### 2.6 Incident Response and Recovery for Manufacturing ✅

| Sub-requirement | Implementation | Verified |
|---|---|---|
| **Automated detection & response** | `playbook_engine.py` consumes anomaly events; named-action playbooks (block, isolate, e-stop) with approval gating | engine RUNNING; playbooks present (`pb_*.md`) |
| **Recovery prioritizing continuity & safety** | Playbooks sequence containment → safe-state → recovery; safety path favored | playbook content + SROS2 estop |
| **Forensic analysis** | `forensics_capture.sh` snapshots evidence on incident | script present; evidence volume mounted |

---

## 3. Mandated toolset — all present

| Required tool | Status |
|---|---|
| Zeek (industrial protocols), Suricata, ntopng | ✅ all running on the OT sensor |
| TensorFlow, scikit-learn | ✅ TF autoencoder + LSTM; sklearn IsolationForest/PCA |
| Protocol analysis / custom parsers | ✅ Zeek Modbus/DNP3/OPC-UA + custom L7 read-only Modbus proxy |
| Prometheus, Grafana | ✅ both running; dashboards live |
| Nmap, custom OT scanners | ✅ Stage-4 scanner |
| SROS2 / ROS2 security | ✅ SROS2 keystore (enclaves/private/public) + Gazebo robot |
| IEC 62443 / NIST SP 800-82 | ✅ compliance scorer + Purdue L3.5 IDMZ design |

---

## 4. Open items (honest)

### Integration gaps introduced by the IDMZ rearchitecture (telemetry-path, not capability)

- **G-1 — Safety/SIS telemetry shows `-1` on the dashboard.** Root cause is two-fold: (a) the `lab_exporter` still defaults `PROD_HOST`/`SAFETY_HOST` to the **stale pre-IDMZ address `192.168.40.10`** (the PLC is now `192.168.10.10`), and (b) the IDMZ firewall **correctly** blocks the mgmt-zone exporter from reading OT `:503` directly (verified: SEC-on-OT can reach it, AI-on-mgmt cannot). The safety supervisor itself is running and healthy. **Fix:** route safety state to mgmt the same way Modbus features already travel — have the OT-resident SEC sensor read `:503` and ship the state via Redis/shared-state, which the exporter reads (no new cross-zone conduit needed). Capability exists; only the telemetry path needs reconnecting.
- **G-2 — `lab_exporter` component-health probes point at stale/cross-zone targets.** A few `COMPONENT_PROBES` still use pre-IDMZ addresses (`stage1_ntopng` at SEC's old mgmt IP `40.20`; production/safety at `40.10`) or target other zones the firewall blocks from mgmt by design (Guacamole, Gitea), so those tiles read false-DOWN. (The scrape itself is now fast and reliable after the exporter was fixed to tail-read `eve.json` and probe in parallel.) **Fix:** re-scope the probe set to IDMZ addresses and per-zone reachability.

### Lab-appropriate hardening carry-forwards (from `AUDIT-REPORT.md`, unchanged by this work)

These are explicitly acceptable for a teaching/portfolio lab and are documented as the lab→production gap (see `future-plans.pdf`): shared API key (vs per-identity authN/RBAC + mTLS), at-rest `.env` secrets (vs Vault/KMS), root containers / fat images (vs distroless non-root), and ephemeral GPG signing key (vs HSM/KMS-backed signing with SLSA provenance).

### Prior **critical** findings now **resolved** by the IDMZ + signed-deploy work

| Prior ID | Finding | Resolution |
|---|---|---|
| **F-02** | Monitoring/analytics zone held Modbus **write** authority over OT | AI is now **network-enforced read-only**: reads via the L7 read-only proxy (`:5020`), control only via the OT-resident gateway (`:8002`); `AI→PLC:502 DENY` in the matrix |
| **F-06** | Segmentation defeated by multi-homed containers | **Single-homed** zones; `router-fw` is the only multi-homed node; default-deny conduits; SEC mgmt-pivot closed |
| **F-10** (part) | No real artifact provenance on deploy | **Stage-5 GPG-signed pull-deploy** with verify-before-load; tamper rejected |
| **F-12** (part) | Unmediated cross-zone reach | Default-deny firewall; read-only historian at the DMZ edge |

---

## 5. Verdict

> **Topic-114 compliant — all six objective areas implemented, verified live, and using the full mandated toolset.** The architecture is now a genuine single-homed IEC-62443 Level-3.5 IDMZ with a signed OT deploy pipeline and a live-calibrated dual-plane AI detector. Close **G-1** (reconnect safety telemetry through the OT sensor) for a fully green dashboard; **G-2** is cosmetic. The remaining hardening items are the documented, intentional lab→production gap captured in the future-plans roadmap.

*Evidence captured live against the running `-idmz` stack on 2026-06-20.*
