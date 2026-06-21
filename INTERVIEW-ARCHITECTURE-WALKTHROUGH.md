# Robotics Security Platform — Architecture Walkthrough (Interview Guide)

A companion for presenting the five Eraser diagrams. Each section gives you: **what the diagram shows**, a **60-second narration** (say this out loud), **talking points** (the "why"), and **likely questions** with crisp answers.

**Canonical, up-to-date diagrams (IDMZ):** see `ARCHITECTURE-DIAGRAMS.md` — six Mermaid diagrams matching the current single-homed IDMZ + signed-deploy architecture. The Eraser links below predate the rearchitecture and are kept only for the visual layout; narrate from the Mermaid pack / this guide.

**Eraser file (legacy layout):** https://app.eraser.io/workspace/mA78koRjnR2Ix4F2p2pm

| # | Diagram | Direct link |
|---|---|---|
| 1 | System Architecture | https://app.eraser.io/workspace/mA78koRjnR2Ix4F2p2pm?diagram=1aK_qY7QSfZ8q0p9UPi4 |
| 2 | Network Zones & Segmentation | https://app.eraser.io/workspace/mA78koRjnR2Ix4F2p2pm?diagram=WPmMOUm3ZUhZpphFcjqx |
| 3 | Detection → Response Flow | https://app.eraser.io/workspace/mA78koRjnR2Ix4F2p2pm?diagram=cKCZX28Ym-jBMw9bMhEG |
| 4 | Security Architecture (defense-in-depth) | https://app.eraser.io/workspace/mA78koRjnR2Ix4F2p2pm?diagram=i-ZbD3jTADZGhJOTfa03 |
| 5 | Safety & Control Loop | https://app.eraser.io/workspace/mA78koRjnR2Ix4F2p2pm?diagram=Du00uO-2Qr-VWoZlmU2Z |

---

## 0. The 30-second pitch (memorize this)

> "It's an intelligent security platform that protects an industrial robot on a smart-manufacturing line. It implements **OT/IT convergence security** as a true single-homed **IEC-62443 Level-3.5 IDMZ** — every service on one zone, a default-deny firewall mediating all cross-zone traffic — with the analytics plane **network-enforced read-only** to the controller. It **monitors** the robot's Modbus and ROS2 traffic with Zeek/Suricata and runs **two AI detection planes** — three models on the network traffic and an LSTM on the robot's own motion — to catch cyber-physical attacks in real time. New PLC code only reaches the controller as a **GPG-signed artifact the OT side verifies on pull**. On an attack it triggers an **authenticated emergency stop** and runs **automated incident-response playbooks**, with a **DevSecOps pipeline** validating all PLC and robot code. Entirely open-source, aligned to **IEC 62443** and **NIST SP 800-82**."

**One-liner if they want it shorter:** "A single-homed IEC-62443 IDMZ that detects cyber-physical attacks on a robotic cell with two AI planes, deploys PLC code through a signed supply chain, and responds with an automated, safety-aware incident-response engine."

---

## How to present (order + timing)

Go in diagram order — each one answers the question the previous one raises:

1. **System Architecture** → "what are the pieces and how do they talk?" (~90s)
2. **Network Segmentation** → "how are they isolated?" (~60s)
3. **Detection → Response Flow** → "what actually happens during an attack?" (~90s)
4. **Security Architecture** → "what stops the attacker at each layer?" (~60s)
5. **Safety & Control Loop** → "how do you guarantee the robot fails safe?" (~60s)

Total ≈ 6 minutes. Then invite questions.

---

## Diagram 1 — System Architecture

**What it shows:** every service grouped by its security zone (OT, SEC, AI, IT, DMZ, MGMT), and the two main data paths.

**60-second narration:**
> "There are six zones. The **OT zone** is the plant floor — the OpenPLC controller on Modbus, the safety system, and the Gazebo robot driven over ROS2. The **SEC zone** passively sniffs a mirror of OT traffic with Zeek and Suricata. The **AI zone** is the brain: a Redis bus, three ML models, the scoring API, the incident-response engine, and Prometheus/Grafana. **IT** holds Gitea and the CI/CD runner. The **DMZ** is the only place OT and IT are allowed to meet — through a Guacamole jump host and a read-only Level 3 SCADA monitoring console. The operator only ever touches the **MGMT** dashboard. Two flows: a **monitoring flow** goes up — OT → SEC → AI → dashboard; and a **control flow** comes back down — operator → dashboard → scoring API, which **reads** telemetry through an OT read-only proxy and sends any control through an authenticated OT-resident gateway. The analytics zone never speaks raw Modbus to the PLC."

**Talking points (the "why"):**
- **Separation of duties by zone** maps cleanly to directories: `vm-ot`, `vm-sec`, `vm-ai`. Easy to reason about blast radius.
- **SEC is passive** — it only receives a SPAN mirror and never injects into OT. That's why an IDS belongs there, not in OT.
- **The Redis bus decouples** producers (network sensors) from consumers (ML), so a traffic burst can't stall scoring.
- **Tech stack:** Python (FastAPI, pymodbus, scikit-learn, TensorFlow-CPU), ROS 2 Humble + SROS2/Cyclone DDS, OpenPLC (IEC 61131-3 Structured Text), React/TypeScript, Redis, Prometheus/Grafana, Zeek/Suricata/ntopng, Apache Guacamole, Gitea — all open source.

**Likely questions:**
- *Why three ML models?* They're complementary: **Isolation Forest** catches rare feature combinations cheaply; the **PCA autoencoder** catches reconstruction anomalies; the **TensorFlow autoencoder** catches subtler non-linear patterns. Any one crossing its calibrated threshold raises an alert → better recall, no single blind spot.
- *Why anomaly detection over signatures?* OT attacks often "live off the land" using legitimate protocol commands. A model of *normal* flags malicious-but-novel behaviour (e.g. a normally-read register suddenly written from outside the OT zone).
- *Where does the AI run — cloud or edge?* At the **edge**, on-prem, beside the plant, so detection and the safety loop survive a WAN outage.

---

## Diagram 2 — Network Zones & Segmentation

**What it shows:** four single-homed zone networks and the single router/firewall that mediates every cross-zone flow against a default-deny conduit list.

**60-second narration:**
> "This is a true single-homed IEC-62443 Level-3.5 IDMZ. Each Docker network models a VLAN: OT is `192.168.10`, IT is `.20`, DMZ is `.30`, MGMT is `.40`. Every container attaches to **exactly one** zone — the segmentation is structural, not advisory. The **only** multi-homed node is a dedicated router/firewall container running nftables with a **default-deny** forward policy; it sits at `.2` on all four nets. Nothing crosses a zone except through one of **eight explicitly allowed conduits** — so IT can't reach OT by any path, and the analytics zone can't reach the raw PLC at all. The two genuinely necessary management→OT flows are split: a **read-only** conduit to a Modbus proxy, and an **authenticated control** conduit to an OT-resident gateway."

**Talking points:**
- **One router is the only multi-homed node** — exactly what a firewall is supposed to be. Every other container is single-homed, so a single foothold can't bridge zones.
- **Default-deny + 8 conduits:** `AI→proxy:5020` (read), `AI→gateway:8002` (control), `Guacamole→OT:3389` (RDP), `IT→DMZ:80` (publish) / `OT→DMZ:80` (pull) for signed deploy, `IT→AI:9000` (CI webhook), `DMZ→AI:8000` (read-only wall-board), `SEC→AI:6379` (feature shipping, scoped to SEC's IP).
- **The analytics zone is network-enforced read-only to OT:** `AI→PLC:502` matches no conduit and is dropped — it physically cannot issue a raw write.
- **Verified, not asserted:** an automated matrix probes all 8 conduits + key denials (16 probes, all green).

**Likely questions:**
- *How is OT isolated?* Single-homed zones + a default-deny router; `IT→OT` matches no conduit on any path; even legitimate management reads go through a read-only proxy. That's IEC-62443 zones-and-conduits enforced at L3.
- *Where's the monitor, then?* The SEC sensor is **single-homed inside OT** (an OT-resident IDS) because a Docker bridge won't mirror third-party unicast to a passive port — the monitor must be a party to the traffic, like a hardware SPAN tap. It ships features to mgmt Redis over one SEC-IP-scoped conduit, so a compromised sensor still can't roam the management zone.
- *What's the residual weakness?* It's a single host compressing what would be per-zone hardware in a plant, and the safety controller is a software simulator — both documented in the production roadmap.

---

## Diagram 3 — Detection → Response Flow

**What it shows:** the end-to-end incident lifecycle you demo live — attack → detect → respond → recover.

**60-second narration:**
> "An attack — or a real Modbus anomaly — is parsed by Zeek and Suricata; `feature_pusher` ships the features into Redis. `feature_consumer` builds a **5-second window** and scores it with all three models. If the score crosses the threshold, `alert_bridge` writes an alert and a Prometheus metric. The **playbook engine** matches a playbook and runs the **automatic** containment steps with no approval — capture forensics, isolate the offending IP with a firewall rule. The step that changes the **physical** process — asserting a safe state or E-stop — **waits for a human**. The operator approves; the safety system latches EMERGENCY. Recovery is a **deliberate operator reset**, never automatic. Then the loop continues."

**Talking points:**
- **Automated where safe, human-gated where physical.** This mirrors NIST SP 800-61 (detect → contain → eradicate → recover) and the functional-safety principle that *clearing* a safe state is always a deliberate human action.
- **False-positive control:** models train on **pure normal traffic only**, thresholds calibrated to ~99th percentile, detection is **window-based** (5s) not per-packet, plus a 2-consecutive-window debounce and per-host cooldown. A single attack that trips several detectors is de-duplicated into **one campaign**.
- **Auditability:** every incident is a record in `incidents.jsonl`; forensic bundles are hashed and made immutable.

**Likely questions:**
- *How fast is detection?* Sub-5-second in the demo — windowed scoring plus the alert bridge.
- *How do you stop the IR engine being abused?* Containment steps that don't touch the physical process run automatically; anything physical needs operator approval. Inputs used in commands are sanitised (IP regex + shell-quoting), and duplicate detections fold into one campaign.

---

## Diagram 4 — Security Architecture (defense-in-depth)

**What it shows:** the six control layers an attacker must cross to reach the robot, ordered by how early they stop the attack.

**60-second narration:**
> "Defense-in-depth, ordered by how early each control stops an attacker. **L1** is network segmentation — keep them out of OT entirely. **L2** is brokered access — no direct OT logins, only the DMZ jump host. **L3** is application identity — every API and CI call is authenticated, fail-closed. **L4** is OT-native auth plus the safety system — SROS2 certificate auth on ROS2, and the independent SIS with a latched E-stop. **L5** is detection and response. **L6** is DevSecOps and vulnerability management wrapping the whole thing. Crucially, telemetry flows the *other* way: L5 detection feeds L4 to trip an E-stop, and L6 secures the code that becomes L3."

**Talking points:**
- This is **IEC 62443 zones-and-conduits + NIST SP 800-82** in practice.
- **Layers are complementary, not substitutes:** if L1 is bypassed by an insider on the LAN, L3/L4 still require credentials.
- **Concrete L3 controls:** API key is **fail-closed** (rejects if no key configured), nginx injects the key **server-side** so the browser never holds it, and the CI webhook requires a constant-time **HMAC**.

**Likely questions:**
- *What protects the safety system specifically?* A separate SIS with a heartbeat watchdog and a **latched** E-stop; ROS2 safety topics over SROS2 (X.509 cert auth); and the rule that clearing a safe state is always a deliberate human action.
- *Authentication vs authorization on ROS2?* Be precise: DDS-Security enforces **authentication** — every participant must present a CA-signed certificate. **Topic-level ACLs** are at the permissive default in the lab (re-enabling them hung Cyclone DDS discovery); enforcing them is on the roadmap. Stating this honestly scores points.

---

## Diagram 5 — Safety & Control Loop

**What it shows:** the heartbeat/watchdog/E-stop sequence — the heart of the OT story.

**60-second narration:**
> "The production side sends a **5 Hz heartbeat** over Modbus to the safety supervisor. The supervisor runs a **watchdog** — if the heartbeat stops for two seconds, it trips EMERGENCY — plus a **replay/regression guard** on the counter. When the operator hits E-stop on the dashboard, it goes through the scoring API and writes the E-stop register; the supervisor **latches** EMERGENCY and the only way out is a deliberate reset code. A separate **safety bridge** polls the supervisor's state and mirrors it onto the production PLC and publishes it over SROS2, so the robot **freezes at its last waypoint**. Safety always wins, and it fails safe."

**Talking points:**
- **Latched, not momentary** — once EMERGENCY, it stays until an explicit reset. Loss of heartbeat = fail-safe trip.
- **Independent supervisor** (`safety_supervisor.py`) runs the real watchdog/latch/replay logic, separate from the production controller.
- **SROS2 carries the safety topics** (`/safety/state`, `/safety/request`) with certificate authentication.

**Likely questions:**
- *What happens if the network drops?* Heartbeat stops → watchdog trips EMERGENCY within ~2s → robot freezes. The loop is local, so a WAN outage never affects it.
- *Could an attacker un-latch the E-stop?* Not from the analytics zone or IT — the firewall gives them no path to the controller, and any legitimate control goes through the authenticated OT gateway, never a raw write. The honest remaining gap is that the safety controller is still a software simulator co-located in OT; **in production the reset must be a local, physical action on an independent SIS with no network path** — that's the top item on the production roadmap.

---

## Cross-cutting talking points

- **Standards:** IEC 62443 / ISA-62443 (zones & conduits, SIS security), NIST SP 800-82 (OT security), NIST SP 800-61 (incident response).
- **Protocols on the wire:** Modbus/TCP (502 prod, 503 safety), ROS2/DDS over SROS2 (X.509), HTTP/REST + HTTPS, RDP (vendor jump host). Zeek also carries DNP3 and OPC-UA parsers for extensibility.
- **Vulnerability management:** passive asset discovery from Zeek + OT-safe Nmap + Modbus device-ID fingerprinting → correlated against an **offline** CVE/ICS-CERT feed (no outbound internet from OT).
- **DevSecOps:** a six-gate pipeline (PLC lint, HMI lint, SROS2 lint, vuln gate, baseline gate, acceptance test) triggered by an HMAC-signed Gitea webhook, producing a **signed artifact bundle**.
- **Vendor / remote access:** time-boxed, audited Guacamole sessions (read-only or maintenance), provisioned through an authenticated API.

---

## What was hardened, and what's left (this is the maturity signal)

Interviewers reward candidates who can separate *done* from *to-do* on their own design.

**Already hardened (talk about these as design decisions you made):**
1. **Single-homed zones + a default-deny router.** Every container sits on one zone; the only multi-homed node is the firewall. A single foothold can no longer bridge zones — and a compromised SEC sensor can't pivot into the management zone (it's OT-only, shipping features over one scoped conduit).
2. **Analytics is network-enforced read-only to OT.** The scoring service has no Modbus client to the PLC — reads go through a read-only proxy, and any control goes through an authenticated OT-resident gateway over a separate conduit. `AI→PLC:502` is dropped by the firewall.
3. **Signed supply-chain deploy.** New PLC code reaches the controller only as a GPG-signed artifact the OT side pulls and verifies; a tampered artifact is rejected and the controller is left untouched.
4. **AI calibrated to live traffic.** The detector's thresholds are calibrated against the real Zeek pipeline, not synthetic data, so the baseline reads normal and attacks fire — no train/serve drift.

**Still on the production roadmap (raise these yourself):**
5. **Independent hardware safety (SIS) + local-only E-stop reset** — the running safety controller is still a software simulator; a real cell needs an independent IEC-61511 SIS with no network un-latch path.
6. **Enforce SROS2 topic ACLs** (not just certificate authentication), once the Cyclone DDS discovery issue is resolved.
7. **Secrets + provenance:** vault/KMS secrets, HSM-backed signing with SLSA provenance, per-identity authN/RBAC + mTLS (today it's a shared API key).
8. **Reconnect safety telemetry across the IDMZ:** the firewall (correctly) blocks the mgmt exporter from reading the OT safety registers, so the safety panel currently reads -1 — route it through the OT sensor like the Modbus features (tracked, with the fix designed).

> Framing line: *"The rearchitecture closed the big trust-boundary gaps — single-homed zones, read-only analytics, signed deploy. The remaining gap to production is safety independence and enterprise identity/secrets, not the concepts."* (Full detail in `future-plans.pdf`.)

---

## Rapid-fire Q&A

- **Why Modbus and ROS2 together?** Modbus is the PLC/SCADA control plane; ROS2 is the robot's middleware. Real cells mix classic ICS protocols with modern robotics middleware, so I monitor and secure both.
- **Why anomaly detection windows of 5 seconds?** Long enough to compute stable statistics (rate, write ratio, entropy, inter-arrival times), short enough for sub-5s detection.
- **How do you avoid false positives?** Train on clean normal traffic, calibrate thresholds to the 99th percentile, require 2 consecutive anomalous windows, and apply per-host cooldowns.
- **What's the single most important control?** The `internal` OT network + the latched, watchdog-backed safety system. Segmentation keeps attackers out; the SIS guarantees the robot fails safe regardless.
- **What standards frameworks did you map to?** IEC 62443 for zones/conduits and SIS security; NIST SP 800-82 for OT; NIST SP 800-61 for the IR lifecycle.

---

## Key numbers cheat-sheet

| Thing | Value |
|---|---|
| Zones / subnets | OT `192.168.10` · IT `.20` · DMZ `.30` · MGMT `.40` (router-fw `.2` on all) |
| Segmentation | Single-homed zones + nftables **default-deny** router; **8 conduits**; matrix 16/16 |
| Containers | 11 (router-fw is the only multi-homed node) |
| Modbus ports | 502 production PLC · 503 safety SIS · 5020 read-only proxy · 8002 control gateway |
| ML models | **Network plane:** Isolation Forest · PCA autoencoder · TensorFlow autoencoder · **Robot plane:** LSTM + physics envelope |
| AI calibration | Thresholds calibrated to **live** traffic (no train/serve drift) |
| Feature window | 5-second tumbling, keyed by source IP, 20 features |
| Safety heartbeat | 5 Hz · 2-second watchdog · latched EMERGENCY |
| Detection bus | Redis: `…features.raw` → consumer → `…anomaly.events` → bridge |
| Signed deploy | CI GPG-signs → DMZ store → OT **pulls + verifies** (tamper rejected) |
| CI/CD gates | 6 (PLC / HMI / SROS2 lint, vuln, baseline, acceptance) |
| Standards | IEC 62443 · NIST SP 800-82 · NIST SP 800-61 |
