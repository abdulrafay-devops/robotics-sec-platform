# Robotics Security Platform — Architecture Diagram Pack

This document contains six diagram families, all in **Mermaid** (renders on GitHub, VS Code with the Mermaid extension, or [mermaid.live](https://mermaid.live)). Every diagram is followed by an explanation of **component placement & justification**, **data movement**, **trust boundaries**, and **dependencies** — the four things an interviewer will probe.

> **Architecture in one line.** A true single-homed **IEC-62443 Level-3.5 IDMZ**: every service sits on exactly one zone network, and a single **router/firewall** (`router-fw`, Alpine + nftables, **default-deny**) is the only multi-homed node. Nothing crosses a zone except through an explicitly allowed **conduit**. The analytics zone is **network-enforced read-only** to OT, and new PLC code reaches the controller only as a **GPG-signed artifact the OT side pulls and verifies**.

> **How to read these diagrams**
> - **Zones** follow the Purdue / IEC-62443 model: OT (plant floor) is the most trusted-but-most-fragile and must be the most isolated; IT is general-purpose; the DMZ brokers the two; MGMT is the operator/analytics plane.
> - A **trust boundary** is any line where data crosses zones. In this build *every* crossing is a numbered firewall conduit — there are no implicit paths.
> - Subnets: **OT** `192.168.10.0/24`, **IT** `192.168.20.0/24`, **DMZ** `192.168.30.0/24`, **MGMT** `192.168.40.0/24`. The router is `.2` on all four.

---

## 1. System Architecture Diagram

High-level view of every service, the single-homed zones, and the router that mediates all cross-zone traffic.

```mermaid
flowchart TB
    OP(["👤 Operator / Engineer"])

    FW{{"router-fw — the ONLY multi-homed node<br/>Alpine + nftables · default-deny FORWARD<br/>.2 on OT/IT/DMZ/MGMT · numbered conduits only"}}

    subgraph MGMT["MGMT Zone — 192.168.40.0/24 (operator + analytics)"]
        DASH["Dashboard .40<br/>React + Nginx (TLS)"]
        REDIS[("Redis .30<br/>feature + event queues")]
        FC["feature_consumer<br/>windowing + ML scoring"]
        SCORE["score_service (FastAPI) .30:8000<br/>IsolationForest + PCA-AE + TF-AE<br/>+ robot LSTM"]
        IR["playbook_engine<br/>auto + approved IR"]
        OBS["Prometheus + Grafana<br/>+ lab_exporter"]
    end

    subgraph OT["OT Zone — 192.168.10.0/24 (plant floor)"]
        ROBOT["Robotic Cell .10<br/>Gazebo + ROS2 cyclic_motion"]
        PLC["Production PLC .10<br/>OpenPLC :502 (loopback)"]
        PROXY["L7 read-only Modbus proxy :5020<br/>forwards reads, rejects writes"]
        GW["OT control gateway :8002<br/>owns the only PLC write path"]
        SAFE["Safety SIS :503<br/>supervisor + bridge + heartbeat"]
        SROS2["SROS2 / Cyclone DDS<br/>X.509 PKI auth"]
        SECSENS["SEC sensor .20 (single-homed on OT)<br/>Zeek + Suricata + ntopng + feature_pusher<br/>+ Stage-4 vuln scanner"]
    end

    subgraph IT["IT Zone — 192.168.20.0/24"]
        GITEA["Gitea + Act Runner .20<br/>CI/CD + artifact signing"]
    end

    subgraph DMZ["DMZ — 192.168.30.0/24 (broker)"]
        GUAC["Apache Guacamole .20<br/>vendor RDP jump host"]
        HIST["Historian / artifact store .40<br/>read-only wall-board + /deploy"]
    end

    OP --> DASH
    OP -. "brokered vendor RDP" .-> GUAC

    %% all cross-zone arrows pass the router (conduits)
    DASH --> SCORE
    SCORE -->|"C1 reads via proxy :5020"| PROXY --> PLC
    SCORE -->|"C2 control via gateway :8002"| GW --> PLC
    PLC <--> SAFE
    PLC --> ROBOT
    SROS2 --> SAFE
    GUAC -->|"C3 RDP :3389"| ROBOT
    GITEA -->|"C4 publish signed artifact :80"| HIST
    HIST -->|"C5 OT pulls + verifies :80"| PLC
    GITEA -->|"C6 CI webhook :9000"| SCORE
    HIST -->|"C7 read-only API :8000"| SCORE
    SECSENS -->|"C8 features :6379"| REDIS
    REDIS --> FC --> SCORE --> IR --> OBS
    OBS --> DASH

    classDef ot fill:#ffe3e3,stroke:#c0392b,stroke-width:2px,color:#000;
    classDef ai fill:#e3eeff,stroke:#2c3e9e,color:#000;
    classDef dmz fill:#fff4d6,stroke:#d39e00,color:#000;
    classDef it fill:#f0e6ff,stroke:#7d3cc0,color:#000;
    classDef fw fill:#fdebd0,stroke:#e67e22,stroke-width:3px,color:#000;
    class OT,ROBOT,PLC,PROXY,GW,SAFE,SROS2,SECSENS ot;
    class MGMT,DASH,REDIS,FC,SCORE,IR,OBS ai;
    class DMZ,GUAC,HIST dmz;
    class IT,GITEA it;
    class FW fw;
```

**Component placement & justification.** The robotic cell, production PLC, and safety SIS sit in **OT** because they are real-time and safety-critical. The **SEC sensor is single-homed *inside* OT** — an OT-resident IDS — because a Docker bridge does not mirror third-party unicast to a passive port, so the monitor must be a party to the traffic (the software equivalent of a hardware SPAN tap). The **analytics + operator plane lives in MGMT**: it does the ML, response, observability, and dashboard, but holds **no write path to the PLC**. **IT** holds developer tooling and the CI signer. The **DMZ** is the only meeting point of OT and IT, and hosts the brokered Guacamole jump host and the read-only historian/artifact store. The **operator** only ever touches the MGMT dashboard or the DMZ jump host — never OT directly.

**Data movement.** (1) **Monitoring:** OT traffic → SEC sensor → features over conduit **C8** → Redis → `feature_consumer` → scoring → alerts → IR + dashboards. (2) **Control:** operator → dashboard → `score_service`, which **reads** telemetry through the OT read-only proxy (**C1**) and issues control only through the OT control gateway (**C2**) — it never speaks raw Modbus. (3) **Deploy:** CI signs in IT → publishes to the DMZ store (**C4**) → OT **pulls and verifies** (**C5**).

**Trust boundaries.** Every arrow that leaves a `subgraph` traverses `router-fw` and matches a numbered conduit (C1–C8); everything else is dropped by default. The most sensitive boundary, MGMT→OT, is split into a **read-only** conduit (C1, proxy) and an **authenticated control** conduit (C2, gateway) — there is no path from analytics to raw `PLC:502`.

**Dependencies.** `score_service`/`feature_consumer` depend on Redis + trained models; the dashboard is health-gated on `score_service`; the SEC sensor depends on OT producing traffic; the deploy agent depends on the historian serving the signed artifact.

---

## 2. Network Diagram

The four single-homed bridge networks, the central router/firewall, and the conduit allow-list.

```mermaid
flowchart TB
    subgraph OTN["ot-net 192.168.10.0/24"]
        OT1["container-ot .10<br/>PLC 502 · safety 503 · proxy 5020 · gateway 8002 · RDP 3389"]
        SEC1["container-sec .20<br/>Zeek/Suricata/ntopng (single-homed)"]
    end
    subgraph ITN["it-net 192.168.20.0/24"]
        GIT["gitea .20 · runner .25"]
    end
    subgraph DMZN["dmz-net 192.168.30.0/24"]
        GUAC["guacamole .20 / guacd .22 / pg .21"]
        HIST["historian + /deploy store .40"]
    end
    subgraph MGMTN["mgmt-net 192.168.40.0/24"]
        AIM["container-ai .30 (Redis/API/Prom/Grafana/exporter)"]
        DASHM["dashboard .40"]
    end

    FW{{"router-fw .2 on all four nets<br/>nftables: policy DROP + 8 conduits"}}

    OTN <--> FW
    ITN <--> FW
    DMZN <--> FW
    MGMTN <--> FW

    classDef oz fill:#ffe3e3,stroke:#c0392b,color:#000;
    classDef fw fill:#fdebd0,stroke:#e67e22,stroke-width:3px,color:#000;
    class OTN,OT1,SEC1 oz;
    class FW fw;
```

**The conduit allow-list (everything else is dropped):**

| # | Source | → Destination | Port | Purpose |
|---|---|---|---|---|
| C1 | MGMT (AI) | OT `10.10` | 5020 | Telemetry read via **read-only** proxy |
| C2 | MGMT (AI) | OT `10.10` | 8002 | Control via OT gateway (only write path) |
| C3 | DMZ (Guacamole) | OT `10.10` | 3389 | Brokered vendor RDP |
| C4 | IT (Gitea) | DMZ `30.40` | 80 | CI publishes signed artifact up |
| C5 | OT | DMZ `30.40` | 80 | OT pulls signed artifact down |
| C6 | IT (Gitea) | MGMT `40.30` | 9000 | CI webhook → AI receiver |
| C7 | DMZ (historian) | MGMT `40.30` | 8000 | Read-only wall-board API |
| C8 | SEC `10.20` | MGMT `40.30` | 6379 | ML feature shipping (SEC-IP-scoped) |

**Component placement & justification.** Each Docker network models a VLAN, and **each container attaches to exactly one** — the segmentation guarantee is structural, not advisory. The only multi-homed node is `router-fw`, which is *supposed* to span zones (that is what a firewall is). Containers reach peers in other zones only by routing through `.2`, where nftables applies the default-deny policy.

**Data movement.** Cross-zone traffic is L3-routed through `router-fw` and filtered against the 8-conduit table; intra-zone traffic stays on its own bridge. There is no host-published OT control port — `PLC:502`/`safety:503` are reachable only inside OT.

**Trust boundaries.** The router's `FORWARD` chain *is* the trust boundary for the whole system. `IT→OT` matches no conduit → dropped on every path (the classic DMZ gap, closed). `AI→PLC:502` matches no conduit → dropped (read-only enforced at L3).

**Dependencies.** Bring-up order is handled by the router entrypoint (enables `ip_forward`, loads nftables) and per-zone return routes added by each service; the automated matrix (`infra/tests/stage1_connectivity_matrix_docker.py`) asserts all 8 conduits + key denials (16 probes, all green).

---

## 3. Data Flow Diagram (DFD)

Classic DFD — **external entities** (stadium), **processes** (rounded), **data stores** (cylinders), labelled flows, dashed **trust boundaries**.

```mermaid
flowchart LR
    ATK(["External:<br/>Attacker / Vendor"])
    OPR(["External:<br/>Operator"])

    subgraph TB_OT["═ OT (router-mediated) ═"]
        P1("P1 PLC / Robot")
        PRX("P1b read-only proxy :5020")
        GWP("P1c control gateway :8002")
        DS1[("Safety registers")]
    end
    subgraph TB_SEC["═ SEC (OT-resident, passive analysis) ═"]
        P2("P2 Zeek/Suricata")
        P3("P3 feature_pusher")
    end
    subgraph TB_AI["═ MGMT / Analytics (read-only to OT) ═"]
        DS2[("Redis: features")]
        P4("P4 feature_consumer + ML")
        DS3[("Redis: events")]
        P6("P6 playbook_engine")
        P7("P7 score_service API")
        DS5[("Prometheus TSDB")]
    end
    subgraph TB_MGMT["═ Operator ═"]
        P8("P8 Dashboard / Grafana")
    end

    ATK -. "malicious Modbus" .-> P1
    OPR -->|"control intent + key"| P8
    P1 -->|"observed on OT"| P2 --> P3 -->|"C8 features"| DS2
    DS2 --> P4 -->|"events"| DS3 --> P6
    P4 -->|"live scores"| P7
    P6 -->|"isolate / assert-safe (via C2)"| GWP --> P1
    P4 --> DS5
    P8 -->|"/api/ (key)"| P7
    P7 -->|"C1 read"| PRX --> P1
    P7 -->|"C2 control"| GWP
    PRX --> DS1
    DS5 --> P8
    P8 -->|"approve IR step"| P6

    classDef store fill:#f5f0e1,stroke:#b8860b,color:#000;
    class DS1,DS2,DS3,DS5 store;
```

**Component placement & justification.** Processes are grouped by the zone that runs them, so each DFD boundary equals a real firewall boundary. The decisive change from a naïve design: **the analytics process P7 has no Modbus client to the PLC** — reads go through the proxy (P1b) and any control goes through the gateway (P1c), both OT-resident. Redis decouples producers from consumers so a traffic burst can't stall scoring.

**Data movement.** Detection flows left-to-right (OT traffic → features → ML score → event → incident). Control is the return path but is **mediated**: operator → API → (read proxy | control gateway) → PLC. Observability tees into Prometheus and back to the dashboard.

**Trust boundaries.** Four crossings carry controls: (1) Attacker→PLC is the threat we detect; (2) OT→SEC analysis stays inside OT (no return path to actuate); (3) MGMT→AI API requires the key (fail-closed); (4) **AI→OT is split** into read-only (proxy) and authenticated-control (gateway) conduits — no raw write path exists.

**Dependencies.** P4/P7 depend on Redis + models; P6 on the alert store + playbooks; P7's control path depends on the OT gateway being reachable over C2.

---

## 4. Process Flow / Workflow Diagram (Incident lifecycle)

The end-to-end **attack → detect → respond → recover** workflow you demo live.

```mermaid
flowchart TD
    A["Attack begins<br/>(injected demo OR real Modbus anomaly)"] --> B["SEC sensor: Zeek/Suricata parse<br/>feature_pusher → Redis (C8)"]
    B --> C["feature_consumer builds 5s window<br/>IsolationForest + PCA-AE + TF-AE<br/>(thresholds live-calibrated)"]
    C --> D{"Anomaly?<br/>(IF alone, or AE consensus)"}
    D -- No --> C
    D -- Yes --> E["alert + Prometheus metric"]
    E --> F["playbook_engine matches by category"]
    F --> G["Auto steps:<br/>forensics_capture, isolate offender"]
    G --> H{"Needs human approval?"}
    H -- Yes --> I["Queue pending_approval<br/>(dashboard shows action)"]
    I --> J{"Operator decision"}
    J -- Approve --> K["ir-approve runs step<br/>e.g. assert safe-state / E-stop via gateway"]
    J -- Reject --> L["Step marked rejected"]
    H -- "No / done" --> M["Safety SIS enforces state<br/>EMERGENCY latched if tripped"]
    K --> M
    M --> N["Operator investigates on dashboard"]
    N --> O{"Threat cleared?"}
    O -- No --> N
    O -- Yes --> P["Deliberate operator RESET<br/>(E-stop never auto-cleared)"]
    P --> Q["Return to NORMAL<br/>manufacturing continuity restored"]
    Q --> C

    classDef danger fill:#ffd6d6,stroke:#c0392b,color:#000;
    classDef ok fill:#d6f5d6,stroke:#27ae60,color:#000;
    class A,M danger;
    class P,Q ok;
```

**Component placement & justification.** The flow alternates **automated** stages (detection, auto-containment) with **human-gated** stages (approval, reset) — mirroring NIST SP 800-61 (detect → contain → eradicate → recover) and the functional-safety rule that *clearing* a safety state is always a deliberate human action.

**Data movement.** Each box hands the next a small artifact: a feature window → an anomaly event → an alert → a pending-approval → an incident record. The loop back to scoring (`Q → C`) shows continuous operation.

**Trust boundaries.** The human-in-the-loop gates `H/J` (approval) and `P` (reset) are the privileged points; any physical-state change requires operator authority, and IR's control actions ride the same OT gateway conduit (C2) as operator control — never a raw write.

**Dependencies.** Approval depends on dashboard + `ir-approve`; recovery depends on the safety SIS accepting the reset; the whole loop depends on the SEC sensor + AI scoring being alive.

---

## 5. Security Architecture Diagram

Defense-in-depth: the controls layered between an attacker and the robot.

```mermaid
flowchart TB
    THREAT(["🌐 remote attacker · malicious vendor · supply-chain · insider"])

    subgraph L1["Layer 1 — Segmentation (the spine)"]
        N1["Single-homed zones + router-fw default-deny<br/>8 conduits only · IT↔OT impossible<br/>AI→raw PLC:502 denied"]
    end
    subgraph L2["Layer 2 — Brokered access"]
        N2["DMZ Guacamole jump host (RDP only into OT)<br/>read-only historian wall-board"]
    end
    subgraph L3["Layer 3 — Application identity"]
        N3["API key (fail-closed) · server-side key injection<br/>webhook HMAC (constant-time)"]
    end
    subgraph L4["Layer 4 — OT protocol & safety"]
        N4["Read-only Modbus proxy + control gateway<br/>SROS2/DDS X.509 · Safety SIS (latched E-stop)"]
    end
    subgraph L5["Layer 5 — Detection & response"]
        N5["Zeek/Suricata IDS · dual-plane ML (Modbus + robot)<br/>playbook IR · forensics capture"]
    end
    subgraph L6["Layer 6 — DevSecOps & vuln mgmt"]
        N6["CI lint/acceptance gates · CVE correlation<br/>GPG-signed deploy, verify-on-pull (Stage 5)"]
    end
    ROBOT(["🤖 robotic cell + safety SIS"])

    THREAT --> L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> ROBOT
    L5 -. "trips" .-> L4
    L6 -. "secures CI" .-> L3

    classDef layer fill:#eef3ff,stroke:#2c3e9e,color:#000;
    class L1,L2,L3,L4,L5,L6 layer;
```

**Component placement & justification.** Controls are ordered by how early they stop an attacker: **segmentation first** (a default-deny router, not advisory rules), then brokered access, then app identity, then OT-native protocol controls + the safety SIS (the last line before the robot), with detection/response and DevSecOps wrapping the whole thing — IEC 62443 zones-and-conduits + NIST SP 800-82 in practice.

**Data movement.** An attacker must traverse every layer inward; defenders get telemetry the other way (L5 detection can trip L4 safety; L6 secures the code that becomes L4's PLC logic via the signed pull-deploy).

**Trust boundaries.** Each layer boundary is a control point. The rearchitecture made L1 a *true* default-deny firewall, made L4 a read-only-proxy + control-gateway split (no analytics write path), and made L6 a real signed-artifact supply chain (tamper-rejected on pull).

**Dependencies.** Layers are complementary: if L1 is bypassed (insider on a zone), L3/L4 still require credentials and the safety SIS still latches; if L3 is bypassed, L5 still detects anomalous behavior.

---

## 6. Cloud / Hybrid / On-Prem Architecture

**Current** deployment is fully **on-prem / edge** (one Docker host = one plant). The diagram also shows the **target hybrid** extension and *why* each piece stays where it is.

```mermaid
flowchart TB
    subgraph PLANT["🏭 ON-PREM / EDGE — authoritative for safety"]
        direction TB
        EDGE["Edge host (Docker Compose) + router-fw"]
        OTZ["OT: PLC + robot + safety SIS + read-only proxy/gateway"]
        SECZ["SEC: Zeek/Suricata/ntopng (on OT)"]
        AIZ["MGMT: real-time scoring + IR + Redis + dashboards"]
        DMZZ["DMZ: Guacamole + historian/artifact store"]
        EDGE --- OTZ --- SECZ --- AIZ --- DMZZ
    end
    subgraph CLOUD["☁️ CLOUD (optional target) — non-safety only"]
        direction TB
        CSOC["Central SOC / SIEM (multi-plant)"]
        CTRAIN["ML training + model registry"]
        CDASH["Fleet dashboards"]
        CINTEL["Threat-intel / CVE feeds"]
    end
    OPR(["Operator / SOC analyst"])

    OTZ -->|"safety loop stays local (ms, survives WAN loss)"| OTZ
    AIZ -->|"one-way: alerts, metrics, evidence"| CSOC
    SECZ -->|"sanitized telemetry"| CDASH
    CTRAIN -->|"signed model artifacts (pull)"| AIZ
    CINTEL -->|"CVE / IOC updates (pull)"| AIZ
    OPR --> CDASH
    OPR -->|"on-site / VPN to DMZ"| DMZZ

    classDef onprem fill:#ffe3e3,stroke:#c0392b,color:#000;
    classDef cloud fill:#e3f0ff,stroke:#2c6fb3,color:#000;
    class PLANT,EDGE,OTZ,SECZ,AIZ,DMZZ onprem;
    class CLOUD,CSOC,CTRAIN,CDASH,CINTEL cloud;
```

**Component placement & justification.** Anything **safety- or latency-critical stays on-prem**: PLC, robot, safety SIS, real-time scoring, and IR must keep working even if the WAN is down. The **cloud only ever receives non-safety derived data** (alerts, metrics, evidence) and only **sends back pull-based, signed artifacts** (models, CVE feeds) — the exact same signed-pull pattern the on-prem Stage-5 deploy already uses.

**Data movement.** Edge→cloud is **one-way and sanitized**; cloud→edge is **pull-only and signed**. No cloud service can command the plant.

**Trust boundaries.** Only the AI/DMZ egress may talk to the cloud, outbound only. Operators reach cloud dashboards directly but reach OT only via the on-site DMZ jump host or VPN.

**Dependencies.** The edge is self-sufficient; the cloud tier augments fleet-scale SOC/training/dashboards and its loss never stops production or safety.

---

### Diagram-to-requirement traceability

| requirements.md objective | Diagram(s) that evidence it |
|---|---|
| OT/IT convergence, DMZ, microsegmentation | 1, 2, 6 |
| Secure remote / vendor access | 1, 2, 5 |
| Network traffic & protocol monitoring | 1, 3 |
| ML anomaly detection + predictive analytics | 3, 4 |
| Automated response + safety integration | 4, 5 |
| Safety-critical protection (E-stop, SIS, interlocks) | 1, 4, 5 |
| IEC 62443 / NIST 800-82 alignment | 1, 5, 6 |
| Vulnerability management | 5, 6 |
| DevSecOps for ICS (signed deploy) | 4, 5, 6 |
| Incident response & recovery | 3, 4 |
```
