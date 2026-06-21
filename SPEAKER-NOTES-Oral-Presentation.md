# Speaker Notes — Oral Presentation

**Presenter:** Abdul Rafay
**Topic:** Implementing an Intelligent Industrial Robotics Security Platform with OT/IT Convergence, Safety System Protection, and AI-Driven Anomaly Detection for Smart Manufacturing
**Format:** 15–20 minute oral presentation (Gamma deck — Part 1: slides 1–10, Part 2: slides 11–13)

> **How to use this file:** Each slide has a *60-second narration* (say this out loud, in your own words), *key points* (the "why" — for depth), and a *transition* line to the next slide. The 30-second pitch and the rapid-fire Q&A at the end are for the examiner interview. Aim for roughly 60–90 seconds per slide.

---

## 30-Second Opening Pitch (memorize — say before Slide 1 or on Slide 1)

> "I built an intelligent security platform that protects an industrial robot on a smart-manufacturing line. It implements **OT/IT convergence security** with **Purdue-model segmentation** and an **industrial DMZ**, **passively monitors** the robot's Modbus and ROS2 traffic with Zeek and Suricata, and runs **three machine-learning models** to detect cyber-physical attacks in real time. When it detects an attack it can trigger an **authenticated emergency stop** and run **automated incident-response playbooks**, while a **DevSecOps pipeline** validates all the PLC and robot code. It's built entirely from open-source tools and aligned to **IEC 62443** and **NIST SP 800-82**."

---

## Slide 1 — Title

**Say:** "Good morning. My name is Abdul Rafay, and today I'll present my intelligent industrial robotics security platform — a system that secures a robotic manufacturing cell across the OT/IT boundary, detects attacks with AI, and guarantees the robot fails safe."

**Key points:**
- Frame the scope in one line: OT security + AI + functional safety, all on one edge-deployed platform.
- Set expectations: "I'll cover the problem, my solution, the architecture, then each capability area, and finish with standards compliance."

**Transition:** "Let me start with why this problem matters."

---

## Slide 2 — Agenda

**Say:** "Here's the path I'll take you through — from the threat landscape and my proposed solution, through the architecture, into the six core capability areas, and ending with how the platform maps to international standards."

**Key points:**
- Keep this to ~20 seconds. Don't read every line — point and move.
- Signal the structure: "framing first, then the technical body, then compliance."

**Transition:** "First, the problem."

---

## Slide 3 — Problem Statement

**Say:** "Industry 4.0 connected the plant floor to the corporate network. That created huge efficiency gains — but it pushed the attack surface into the physical world. Unlike an IT breach, an OT attack is *cyber-physical*: it can injure a worker, stop a line, or wreck a machine. We've seen this for real — Stuxnet destroyed centrifuges, and TRITON specifically targeted a *safety* system. The hard part is that industrial protocols like Modbus have no authentication, so commands can be spoofed or replayed, and classic signature-based security misses attacks that use perfectly legitimate commands in a malicious way."

**Key points:**
- Emphasize **cyber-physical** consequences — this is what separates OT from IT security.
- TRITON is the strongest example because it attacked a Safety Instrumented System — directly relevant to my safety slide later.
- The core tension: **security must not break real-time operation or worker safety.**

**Transition:** "So how do you secure that without breaking it? That's my solution."

---

## Slide 4 — Proposed Solution

**Say:** "My answer is a defense-in-depth platform built around three pillars: OT security, AI, and functional safety. I segment the network on the Purdue model with an industrial DMZ; I monitor the robot's traffic *passively* so I never interfere with control; I score that traffic with three machine-learning models for sub-five-second detection; I protect the robot with an independent, authenticated safety system; and I automate incident response — but only the safe steps; anything physical waits for a human. A DevSecOps pipeline validates all the code, and the whole thing is open-source and edge-deployed."

**Key points:**
- "Passive monitoring" is a deliberate design choice — the security tools never inject into OT.
- "Automated where safe, human-gated where physical" is your recurring theme — say it here and on the IR slide.

**Transition:** "Let me show you how the pieces fit together."

---

## Slide 5 — Platform Architecture & Basic Flow

**Say:** "There are six zones. The **OT zone** is the plant floor — the OpenPLC controller on Modbus, the safety system, and the robot driven over ROS2. The **SEC zone** passively sniffs a mirror of OT traffic with Zeek and Suricata. The **AI zone** is the brain — a Redis bus, the three ML models, the scoring API, the incident-response engine, and Prometheus/Grafana. **IT** holds Gitea and CI/CD. The **DMZ** is the *only* place OT and IT are allowed to meet — through a jump host and a read-only SCADA monitor. The operator only ever touches the **management** dashboard. Two flows: a **monitoring flow** goes up — OT to SEC to AI to the dashboard — and a **control flow** comes back down — operator to dashboard to the scoring API, which reads telemetry through an OT read-only proxy and sends any control through an authenticated OT gateway. The analytics zone never speaks raw Modbus to the PLC."

**Key points:**
- Separation of duties by zone maps cleanly to the codebase directories: `vm-ot`, `vm-sec`, `vm-ai`.
- The **Redis bus decouples** the network sensors from the ML, so a traffic burst can't stall scoring.
- The AI runs at the **edge**, on-prem, so detection and the safety loop survive a WAN outage.

**Transition:** "Let's go zone by zone, starting with how I isolate them."

---

## Slide 6 — OT/IT Convergence & Network Segmentation

**Say:** "This is a true single-homed IEC-62443 Level-3.5 IDMZ. Each network models a VLAN — OT, IT, DMZ, and management on separate subnets — and every service sits on *exactly one* of them. The only node allowed to cross zones is a dedicated router/firewall running nftables with a *default-deny* policy: it permits just eight explicit conduits and drops everything else. So IT cannot reach OT by any path, and the analytics zone is network-enforced *read-only* to the controller — it reads through a read-only Modbus proxy and sends any control through an authenticated OT gateway, never a raw write. An automated matrix proves all of this — sixteen checks, all green. Zeek parses the industrial protocols for monitoring on top."

**Key points:**
- This is the **IEC 62443 zones-and-conduits** model enforced at L3 by a real default-deny firewall — not advisory rules.
- **The one multi-homed node is the firewall itself** (as it should be); every other service is single-homed, so a single foothold cannot bridge zones, and a compromised monitor can't pivot into management.
- **Be honest about what's left** (scores maturity points): it's one host compressing what would be per-zone hardware, and the safety controller is still a software simulator — both on the production roadmap.
- Vendor access is **time-boxed, audited, and authenticated** through Guacamole.

**Transition:** "Segmentation keeps attackers out — but if one gets in, I need to detect them. That's the AI."

---

## Slide 7 — AI-Driven Anomaly Detection

**Say:** "I use anomaly detection rather than signatures, because OT attacks 'live off the land' with legitimate commands — so I model what *normal* looks like and flag deviations. Zeek's features go into Redis, and a consumer builds a five-second window of twenty features — things like packet rate, write ratio, and entropy — and scores it with three complementary models: an Isolation Forest for rare combinations, a PCA autoencoder for reconstruction errors, and a TensorFlow autoencoder for subtler non-linear patterns. If any one crosses its threshold, I raise an alert. I train only on clean traffic, calibrate to the ninety-ninth percentile, and require two consecutive anomalous windows to suppress false positives. Detection is sub-five-second."

**Key points:**
- **Why three models?** Complementary strengths, no single blind spot — better recall.
- **False-positive control** is the question examiners love: clean training data + 99th-percentile thresholds + 2-window debounce + per-host cooldown + de-duplication into one "campaign."

**Transition:** "Detection is only useful if the robot can be made safe — so let's talk about the safety system."

---

## Slide 8 — Safety System Protection & Functional Safety

**Say:** "This is the heart of the OT story. A separate safety supervisor — independent from the production controller — runs a watchdog on a five-hertz heartbeat. If that heartbeat stops for two seconds, it trips EMERGENCY and the robot freezes at its last waypoint. That's fail-safe by design. The E-stop is *latched* — once it trips, the only way out is a deliberate human reset; it never auto-clears. There's also a replay guard so an attacker can't spoof an 'all-clear.' The safety state is published over SROS2 with X.509 certificate authentication. The principle is simple: **safety always wins.**"

**Key points:**
- **Latched, not momentary** + **loss of heartbeat = trip** are the two phrases to land.
- The supervisor is **independent** — this is the functional-safety design principle (separation from the control function).
- Honest production note: in the lab the reset is reachable over Modbus for demo convenience; in production it must be a *local, physical* action with no network path.

**Transition:** "Beyond runtime protection, I also manage the vulnerabilities in the robots themselves."

---

## Slide 9 — Robotic System Vulnerability Management

**Say:** "OT equipment is fragile, so I do vulnerability management *safely*. Asset discovery is mostly passive — I fingerprint devices from the traffic Zeek already sees — supplemented by OT-safe Nmap and Modbus device-ID queries. I then correlate that inventory against an *offline* CVE and ICS-CERT feed, because the OT zone has no outbound internet. On top of that I enforce a security baseline and detect configuration drift, and I have a firmware integrity workflow."

**Key points:**
- "Passive-first, OT-safe" — active scanning can crash legacy PLCs, so this is a deliberate choice.
- The **offline CVE feed** respects the air gap — no outbound connection from OT.

**Transition:** "And to stop vulnerabilities entering in the first place, I secure the code pipeline."

---

## Slide 10 — DevSecOps for Industrial Automation

**Say:** "All the industrial code — the PLC logic, the robot config, the HMI — goes through a six-gate CI/CD pipeline, triggered by an HMAC-signed webhook so only legitimate pushes run it. The gates are: PLC lint, HMI lint, SROS2 lint, a vulnerability scan, a security-baseline check, and a safety acceptance test. If they pass, the pipeline produces a *signed artifact bundle*. This is 'shift-left' security — I catch insecure control logic before it ever reaches the plant floor."

**Key points:**
- The **safety acceptance gate** is the standout — security testing extended to *functional safety*.
- HMAC webhook is **fail-closed** — rejects if the signature is missing or wrong.

**Transition (end of Part 1):** "That covers detection and prevention. In the final part, I'll show what happens during an actual incident, then standards compliance."

---

## Slide 11 — Incident Response & Recovery *(Part 2)*

**Say:** "When an alert fires, the bridge writes it and a Prometheus metric, and the playbook engine matches a response playbook. The containment steps that *don't* touch the physical process — capturing forensics, isolating the attacker's IP with a firewall rule — run automatically with no approval. But any step that changes the *physical* process — asserting a safe state or an E-stop — waits for a human to approve it. Recovery is always a deliberate operator reset, never automatic, because manufacturing continuity and safety come first. Every incident is logged immutably for forensics."

**Key points:**
- This maps to **NIST SP 800-61**: detect → contain → eradicate → recover.
- **Automated where safe, human-gated where physical** — the design principle that prevents the IR engine itself from becoming a hazard.
- Inputs to containment commands are sanitised (IP regex + shell-quoting); duplicate detections fold into one campaign.

**Transition:** "All of this is anchored to recognised standards."

---

## Slide 12 — Standards Compliance (ISO/IEC 62443 · NIST)

**Say:** "The platform isn't ad-hoc — it's designed against established standards. ISO/IEC 62443 gives me the zones-and-conduits model and the safety-system security requirements. NIST SP 800-82 is the OT-security guidance — segmentation, passive monitoring, least privilege. NIST SP 800-61 shapes my incident-response lifecycle. ISO/IEC 27001 covers the information-security management side — access control, logging, asset management. And I can map every capability onto the five NIST Cybersecurity Framework functions: Identify, Protect, Detect, Respond, and Recover."

**Key points:**
- IEC 62443 is published as the **ISO/IEC 62443** family — that's the "ISO" link the topic asks for.
- The **NIST CSF mapping** (Identify→vuln mgmt, Protect→segmentation, Detect→ML/IDS, Respond→playbooks, Recover→reset) is a clean way to summarize the whole platform.

**Transition:** "Let me wrap up."

---

## Slide 13 — Conclusion & Key Takeaways

**Say:** "To summarize: this is an end-to-end OT security platform that detects cyber-physical attacks with AI and fails safe by design. OT/IT convergence is handled with Purdue segmentation and a brokered DMZ; the AI finds novel attacks in under five seconds; and the independent, latched safety system guarantees the robot fails safe no matter what happens at the cyber layer. It's open-source, edge-deployed, and standards-aligned. If I had to name the single most important control, it's the combination of the air-gapped OT network and the watchdog-backed safety system — segmentation keeps attackers out, and the safety system guarantees the robot fails safe regardless. Thank you — I'm happy to take questions."

**Key points:**
- End on the **"single most important control"** line — it's memorable and shows judgment.
- Invite questions confidently.

---

## Rapid-Fire Q&A (interview prep)

**Why three ML models?** Complementary: Isolation Forest catches rare feature combinations cheaply; the PCA autoencoder catches reconstruction anomalies; the TensorFlow autoencoder catches subtler non-linear patterns. Any one crossing its threshold raises an alert — better recall, no single blind spot.

**Why anomaly detection over signatures?** OT attacks often use legitimate protocol commands. A model of *normal* flags malicious-but-novel behaviour — e.g. a normally-read register suddenly being written from outside the OT zone.

**How is OT isolated?** Single-homed zones + a default-deny nftables router as the only multi-homed node; eight explicit conduits, so IT↔OT matches none and is dropped; the analytics zone is read-only to the PLC (via a read-only proxy); OT only meets IT through the DMZ. Verified by a 16-probe matrix. That's the IEC 62443 zones-and-conduits model enforced at L3.

**What's the biggest weakness / what would you harden?** Multi-homed containers on a single host — a compromise could bridge zones. I'd de-multi-home onto separate hosts/VLANs with a one-way gateway (data diode), make the analytics tier read-only to OT, and make the safety reset local-and-physical only.

**How fast is detection?** Sub-five-second — windowed scoring plus the alert bridge.

**How do you avoid false positives?** Train on clean normal traffic, calibrate thresholds to the 99th percentile, require two consecutive anomalous windows, and apply per-host cooldowns. Multiple detectors tripping on one attack are de-duplicated into a single campaign.

**What happens if the network drops?** The heartbeat stops → the watchdog trips EMERGENCY within ~2 seconds → the robot freezes. The safety loop is local, so a WAN outage never affects it.

**Could an attacker un-latch the E-stop?** In the lab the reset is reachable over Modbus (a deliberate demo convenience). In production the reset must be a local, physical, deliberate action with no network path — that's the first thing I'd change for a real cell.

**Authentication vs authorization on ROS2?** DDS-Security enforces **authentication** — every participant must present a CA-signed X.509 certificate. Topic-level ACLs (authorization) are at the permissive default in the lab; enforcing them is on the roadmap.

**Why Modbus and ROS2 together?** Modbus is the PLC/SCADA control plane; ROS2 is the robot's middleware. Real cells mix classic ICS protocols with modern robotics middleware, so I monitor and secure both.

**Where does the AI run — cloud or edge?** At the edge, on-prem, beside the plant — so detection and the safety loop survive a WAN outage. Cloud is an optional, non-safety augmentation (fleet SOC, model training) that only ever receives one-way telemetry and sends back signed, pull-only artifacts.

**What standards did you map to?** IEC 62443 (ISO/IEC 62443) for zones/conduits and SIS security; NIST SP 800-82 for OT; NIST SP 800-61 for the IR lifecycle; ISO/IEC 27001 for ISMS practices; and the NIST CSF functions across the whole platform.

---

## Key Numbers Cheat-Sheet

| Thing | Value |
|---|---|
| Zones / subnets | OT `192.168.10` · IT `.20` · DMZ `.30` · MGMT `.40` |
| Containers | 10 |
| Modbus ports | 502 production PLC · 503 safety SIS |
| ML models | Isolation Forest · PCA autoencoder · TensorFlow autoencoder |
| Feature window | 5-second tumbling, keyed by source IP, 20 features |
| Safety loop | 5 Hz heartbeat · 2-second watchdog · latched EMERGENCY |
| Detection bus | Redis: features → consumer → anomaly events → alert bridge |
| CI/CD gates | 6 (PLC / HMI / SROS2 lint, vuln, baseline, acceptance) |
| Detection latency | Sub-5-second |
| Standards | ISO/IEC 62443 · NIST SP 800-82 · NIST SP 800-61 · ISO/IEC 27001 |
