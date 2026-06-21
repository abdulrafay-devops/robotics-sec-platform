# Interview & Demo Guide — Robotics Security Platform

This is your practical companion for **running**, **demoing**, and **explaining** the platform in an interview. It assumes the security hardening in this repo is applied. Pair it with `PROJECT-EXPLAINED.pdf` (the deep explanation) and `ARCHITECTURE-DIAGRAMS.md` (the visuals).

---

## Part A — 30-second elevator pitch

> "It's an intelligent security platform that protects an industrial robot on a smart-manufacturing line. It implements OT/IT convergence security with Purdue-model network segmentation and an industrial DMZ, passively monitors the robot's Modbus and ROS2 traffic with Zeek/Suricata, and runs three machine-learning models to detect cyber-physical attacks in real time. When it detects an attack it can trigger an authenticated emergency stop and run automated incident-response playbooks, while a DevSecOps pipeline validates all the PLC and robot code. It's built entirely from open-source tools and aligned to IEC 62443 and NIST SP 800-82."

---

## Part B — How to run it

### Prerequisites
- Docker + Docker Compose, on Linux (or Docker Desktop). ~8 GB RAM free (the AI container trains models on first boot).
- `git`, and `sudo` on the host (for the firewall step).

### Steps
```bash
# 1. Secrets are already in .env (rotated). If starting fresh:
cp .env.example .env            # then fill in values (openssl commands are in the file)

# 2. Build and start the whole stack
docker compose up -d --build

# 3. (No host firewall step.) The router-fw container enforces default-deny zone
#    isolation from inside the stack. Verify it any time:
python infra/tests/stage1_connectivity_matrix_docker.py   # expect 16/16 all-green

# 4. Watch the AI container come up (first boot trains 4 models: 3 network + robot LSTM, ~1-3 min)
docker logs -f container-ai      # wait for "All AI and monitoring services are operational"
docker compose ps                # container-ai should be (healthy)
```

> **Tip:** `GITEA_RUNNER_TOKEN` in `.env` is only needed for the live CI/CD runner demo. The core security demo (detection → response → E-stop) works without it.

### Access points (open in a browser)

| What | URL | Login |
|---|---|---|
| **Operations Dashboard** (start here) | `http://localhost:8888` (or `https://localhost:8443`) | none (key injected by nginx) |
| Grafana threat dashboards | `http://localhost:3003` | `admin` / value of `GRAFANA_PASSWORD` in `.env` |
| Prometheus | `http://localhost:9090` | none |
| ntopng (network flows) | `http://localhost:3001` | none |
| Gitea (CI/CD repo) | `http://localhost:3000` | set on first run |
| Guacamole (vendor jump host) | `http://localhost:8081` | guacadmin / guacadmin |
| OpenPLC web UI | `http://localhost:8080` | openplc / openplc |

> After hardening, Modbus (502/503) and the raw API/webhook (8000/9000) are bound to `127.0.0.1` only — reachable from the host, never the LAN. The browser UIs above still work.

---

## Part C — The live demo script (the money shot)

Run this on the dashboard (`http://localhost:8888`). It tells the full story in ~5 minutes.

**1. Show the calm baseline.**
Open the **Overview** page. Point out the zone health, model status (IsolationForest / PCA / TF all loaded), and a flat/low threat score.
> *Say:* "Everything's green. The three ML models are trained on normal traffic and the robot is cycling normally."

**2. Show the physical process.**
Open the **PLC Control** page. Show live coils/registers (cycle running, conveyor, gripper) read straight from the production PLC over Modbus.
> *Say:* "This is live telemetry polled from the OpenPLC controller — the actual state of the cell."

**3. Launch an attack.**
On the **AI Engine** (or Overview) page, trigger the built-in **attack injection** (e.g. `modbus_command_injection`). This simulates a write-burst from an IP outside the OT zone.
> *Say:* "I'm injecting a Modbus command-injection — a flood of register writes from outside the OT zone, the classic cyber-physical attack pattern."

**4. Watch detection happen.**
The threat sparkline spikes within a few seconds; the **Security** page shows a new anomaly alert with the offending source IP and the top contributing features.
> *Say:* "The feature pipeline windowed the traffic, all three models scored it anomalous, and the alert bridge raised it — sub-5-second detection."

**5. Watch automated response.**
Open the **Incidents** page. An incident is open; automatic steps already ran (forensics capture, isolate the offender with a firewall rule). A **pending approval** is waiting for the safety step.
> *Say:* "The playbook engine opened an incident and ran the no-approval containment steps automatically. The step that changes the physical process — asserting a safe state — waits for me."

**6. Approve the safe-state / E-stop.**
Approve the pending step. On **PLC Control** you'll see `e_stop_active` set and `safety_state = EMERGENCY` (latched).
> *Say:* "I approve the safe-state. The E-stop is asserted on the production PLC and the safety system latches EMERGENCY — safety always wins."

**7. Recover deliberately.**
Once you've "investigated", issue **Reset / reset_estop** on PLC Control. The cell returns to NORMAL and resumes.
> *Say:* "Recovery is a deliberate operator action, never automatic — that's correct functional-safety behaviour. Continuity restored."

**8. (Optional) Show the breadth.**
- **Stages** page: vulnerability inventory, CVE correlation, baseline drift, integrity, pipeline verdict.
- **Vendor** page: create a time-boxed vendor remote-access session (now requires the API key) and show the Guacamole link + audit log.
- **Grafana**: the same telemetry in operational dashboards.

---

## Part D — Likely interview questions (with crisp answers)

**Q: Why three ML models instead of one?**
They are complementary. Isolation Forest catches rare feature combinations cheaply; the PCA autoencoder catches reconstruction anomalies; the TensorFlow autoencoder catches subtler non-linear patterns. Any one crossing its calibrated threshold raises an alert, which improves recall without one model's blind spot dominating.

**Q: Why anomaly detection rather than signatures?**
OT attacks are often novel and "live off the land" using legitimate protocol commands. Signatures only catch known attacks; an unsupervised model of *normal* behaviour flags malicious-but-novel activity, e.g. a normally-read register suddenly being written from outside the OT zone.

**Q: How do you avoid false positives?**
Models train on **pure normal traffic only** (no attack contamination), thresholds are calibrated to the ~99th percentile of baseline error, and detection is window-based (5 s) rather than per-packet.

**Q: How is the OT zone isolated?**
Every service is single-homed on one zone, and a default-deny nftables router (`router-fw`) is the only node that crosses zones — through just eight explicit conduits. IT↔OT matches no conduit on any path; the analytics zone is network-enforced read-only to the PLC (it reaches a read-only Modbus proxy, never raw `:502`); and OT only meets IT through the DMZ (Guacamole jump host + read-only historian at `:8086`). A 16-probe matrix verifies it. This is the IEC-62443 zones-and-conduits model enforced at L3.

**Q: What protects the safety system specifically?**
A separate Safety Instrumented System with a heartbeat watchdog and a **latched** E-stop; ROS2 safety topics carried over SROS2 (X.509 certificate auth); and the rule that clearing a safe state is always a deliberate human action.

**Q: How does the incident response avoid being abused?**
Containment steps that don't touch the physical process run automatically; anything that changes physical state requires operator approval on the dashboard. Inputs used in commands are sanitised, and a single attack that trips several detectors is de-duplicated into one campaign.

**Q: Where does AI/ML run — cloud or edge?**
At the edge, on-prem, alongside the plant — so detection and the safety loop keep working even with no internet. The optional cloud tier only receives derived telemetry one-way and sends back signed models/threat-intel; it can never command the plant.

**Q: How is the robot/PLC code itself secured?**
A six-gate DevSecOps pipeline (PLC lint, HMI lint, SROS2 lint, vuln gate, baseline gate, acceptance test). All gates are defined in **one engine** (`vm-ai/devsecops/run_pipeline.sh`) with two triggers: Gitea Actions runs the three static lints on every push (red/green per gate), and an HMAC-signed webhook runs gates 1–5 in-lab, producing a signed artifact bundle. The attack-replay acceptance gate (6) runs on demand against the Gazebo digital twin — never against a producing line (availability first).

**Q: What standards does it follow?**
IEC 62443 / ISA-62443 (zones & conduits, SIS security) and NIST SP 800-82 (OT security).

**Q: What would you improve for production?** (shows maturity)
Run the safety controller as a truly independent SIS, enforce SROS2 topic-level ACLs (not just authentication), de-multi-home the containers onto separate hosts/VLANs with a data diode to the analytics tier, move secrets to a vault, and make all telemetry append-only/tamper-evident. (See `AUDIT-REPORT.md` for the full roadmap.)

---

## Part E — Requirements cheat-sheet (say these mappings out loud)

- **OT/IT convergence + DMZ + microsegmentation** → single-homed zones + default-deny nftables router (8 conduits, matrix 16/16), analytics read-only to OT, Guacamole DMZ.
- **Secure remote/vendor access** → `vendor_access.py` + Guacamole jump host, time-boxed audited sessions.
- **Traffic & protocol monitoring** → Zeek + Suricata + ntopng with Modbus/DNP3/OPC-UA parsers.
- **ML anomaly detection + predictive analytics** → IsolationForest + PCA + TF autoencoder; trend & breach prediction.
- **Automated response + safety integration** → playbook engine + authenticated E-stop.
- **Safety controls / SIS** → safety PLC + bridge + heartbeat, latched E-stop, SROS2.
- **IEC 62443 automation + integrity** → baseline & integrity checks, governance.
- **Vuln management** → Nmap inventory, CVE correlation, firmware workflow.
- **DevSecOps** → 6-gate pipeline + signed artifacts.
- **Incident response & recovery + forensics** → playbooks, approvals, forensics capture, continuity-first recovery.

---

## Part F — Troubleshooting

| Symptom | Fix |
|---|---|
| `container-ai` not healthy | First boot trains models — wait 1–3 min; `docker logs container-ai`. |
| Dashboard loads but no data | Confirm `container-ai` is healthy; the dashboard depends on it. |
| `GRAFANA_PASSWORD must be set` on `up` | Add `GRAFANA_PASSWORD=...` to `.env` (hardening removed the insecure default). |
| Want to keep incident history across restarts | Set `LAB_RESET_STATE=0` in `container-ai`'s environment. |
| Can't reach Modbus/API from another machine | Intentional — they're bound to `127.0.0.1`. Use the dashboard, or SSH-tunnel. |
| Vendor/incident endpoints return 401 directly | Intentional — they now require the API key; the dashboard supplies it via nginx. |
