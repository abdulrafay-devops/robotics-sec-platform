# Robotics IDMZ Security Platform

A containerized Industrial DMZ (IDMZ) reference environment built around a
robotic plant floor Ã¢â‚¬â€ combining a segmented Purdue-model network, an ML-based
anomaly detection and incident-response pipeline, and a DevSecOps gate that
blocks unsafe PLC/HMI/SROS2 code before it ever reaches the plant.

The goal is to model, end to end, how an industrial control network is
actually secured in practice: zone segmentation and brokered vendor access,
passive network monitoring feeding a detection pipeline, MITRE ATT&CK for ICS
classification and playbook-driven response, and CI/CD gates on control-system
code Ã¢â‚¬â€ rather than any single piece of that story in isolation.

## Architecture

Every service container is single-homed to exactly one network zone.
`router-fw` is the only multi-homed node in the stack and is the sole
enforcement point for cross-zone traffic, via default-deny nftables rules Ã¢â‚¬â€
there is no direct IT-to-OT or OT-to-IT path.

```mermaid
graph LR
    subgraph IT["IT Zone"]
        GITEA["Gitea + Actions Runner"]
    end

    subgraph MGMT["Management Zone"]
        AI["AI Engine<br/>detection Ã‚Â· IR Ã‚Â· DevSecOps gates"]
        DASH["Operator Dashboard"]
    end

    subgraph DMZ["Industrial DMZ"]
        GUAC["Guacamole<br/>brokered RDP access"]
        HIST["Historian<br/>read-only proxy"]
        PG[("Postgres")]
    end

    subgraph OT["OT Zone Ã¢â‚¬â€ plant floor"]
        PLC["OpenPLC + Gazebo<br/>robot cell"]
        SEC["Security Sensor<br/>Zeek / Suricata"]
    end

    FW{{"router-fw<br/>default-deny nftables"}}

    GITEA --- FW
    AI --- FW
    DASH --- FW
    GUAC --- FW
    HIST --- FW
    PLC --- FW
    SEC --- FW
    GUAC -. brokered RDP .-> PLC
    SEC -. passive monitoring .-> PLC
```

| Zone | Network | Services |
|---|---|---|
| OT (plant floor) | `ot-net` | `container-ot` Ã¢â‚¬â€ OpenPLC, Gazebo simulation, SROS2 safety supervisor |
| Security | `ot-net` (monitor) | `container-sec` Ã¢â‚¬â€ Zeek, Suricata, passive traffic monitoring, attack injection harness |
| Management | `mgmt-net` | `container-ai` Ã¢â‚¬â€ detection, incident response, DevSecOps engine; `dashboard` Ã¢â‚¬â€ operator UI |
| Industrial DMZ | `dmz-net` | `guacamole`/`guacd` Ã¢â‚¬â€ brokered, session-recorded vendor access; `historian` Ã¢â‚¬â€ read-only data view; `postgres` |
| IT | `it-net` | `gitea` + `runner` Ã¢â‚¬â€ source control and CI |

## Detection & incident response

- **Two detection planes**: an IsolationForest + PCA ensemble over Modbus
  traffic features, and an LSTM autoencoder over robot joint dynamics, fused
  by a meta-scorer.
- **7-technique MITRE ATT&CK for ICS classifier** Ã¢â‚¬â€ every anomaly is
  fingerprinted from observed protocol fields (write function codes, register
  addresses) and tagged with a real technique: `T0855` Unauthorized Command
  Message, `T0831` Manipulation of Control, `T0814` Denial of Service,
  `T0846` Remote System Discovery, `T0880` Loss of Safety, `T0836` Modify
  Parameter, `T0843` Program Download.
- **Playbook-driven response** Ã¢â‚¬â€ classified incidents open a case with a
  per-technique playbook, evidence bundle, automatic evidence capture, and
  human-approved network isolation/escalation workflow (`vm-ai/ir/`).

## DevSecOps pipeline

`vm-ai/devsecops/run_pipeline.sh` is the single gate engine used by both CI
(`.gitea/workflows/ci.yml`) and the in-lab push webhook, so a check can never
pass in one path and fail in the other:

| Gate | Checks |
|---|---|
| 1 Ã¢â‚¬â€ PLC | Structured Text lint: unsigned programs, missing E-stop guards, hard-coded credentials, safety-output writes outside a `SAFETY_` block, unbounded loops |
| 2 Ã¢â‚¬â€ HMI | HMI/SCADA screen lint |
| 3 Ã¢â‚¬â€ SROS2 | Permission/policy lint |
| 4 Ã¢â‚¬â€ Vulnerability | Dependency + service CVE scan, CVSS Ã¢â€°Â¥ 7 blocking with audited exceptions |
| 5 Ã¢â‚¬â€ Baseline | Drift check against the recorded network/behavioral baseline |
| 6 Ã¢â‚¬â€ Acceptance | Live replay + safety-loop timing gate (Ã¢â€°Â¤ 200 ms E-stop response) |

See [demos/cicd-gate](demos/cicd-gate) for a worked example: a vulnerable
manual-jog PLC routine that the gate rejects, and the hardened version it
accepts.

### Governed active scanning

The normal vulnerability inventory remains passive. Separately, `container-sec`
checks the governed active-scan policy every five minutes and runs nmap only once
per approved maintenance-window occurrence. The policy allowlists targets,
excludes fragile OT/SIS ports such as raw Modbus `502` and safety `503`, and
enforces TCP-connect-only, rate-limited scanning. Evidence is retained in
`/var/lab/state/active_scan_report.json` and
`/var/lab/state/active_scan_schedule.json`.

## Validation suite

`infra/tests/` is a set of confirmation gates, one per architecture stage Ã¢â‚¬â€
cross-zone connectivity (IDMZ conduits match default-deny expectations),
detection accuracy (steady baseline stays calm, all injected attacks are
caught), SROS2 safety-loop timing and unauthenticated-peer rejection, and IR
classification/playbook correctness. `validate_ai.py` and `validate_ir.py` in
particular are run before any model or pipeline change is accepted, so
regressions are caught before they reach the demo.

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Recharts |
| AI / detection | Python, scikit-learn, TensorFlow (LSTM autoencoder), FastAPI, Redis |
| OT | OpenPLC, Gazebo, ROS 2 / SROS2 (DDS-Security) |
| Security monitoring | Zeek, Suricata, ntopng |
| DMZ / access broker | Apache Guacamole, PostgreSQL |
| CI/CD | Gitea, Gitea Actions |
| Observability | Prometheus, Grafana |
| Networking | nftables, single-homed Docker zone networks |

## Repository layout

```
vm-ot/       PLC programs (Structured Text), robot control, SROS2 safety supervisor
vm-sec/      Network monitoring, attack injection, vulnerability scanning
vm-ai/       Detection models, MITRE classifier, IR playbooks, DevSecOps pipeline
infra/       Router firewall, Guacamole/DMZ provisioning, per-stage validation gates
dashboard/   Operator-facing web UI
hmi/         HMI/SCADA screen definitions
demos/       CI/CD gate demo Ã¢â‚¬â€ vulnerable vs. hardened PLC program
```

## Running the lab

Requires Docker and Docker Compose.

```bash
cp .env.example .env
# fill in every value in .env Ã¢â‚¬â€ see the comments in that file for how to
# generate each one (including OT_RDP_PASSWORD, OPENPLC_WEB_PASSWORD, and the
# Guacamole role passwords)
docker compose up -d --build
```

| Service | URL |
|---|---|
| Operator dashboard | `http://localhost:8888` |
| AI engine API | `http://127.0.0.1:8000` |
| OpenPLC web UI | `http://localhost:8080` |
| Guacamole (vendor access broker) | `http://localhost:8081` |
| Historian (read-only) | `http://localhost:8086` |
| Grafana | `http://localhost:3003` |
| Prometheus | `http://localhost:9090` |
| Gitea | `http://localhost:3000` |


## Fresh Ubuntu setup (zero to running)

These commands are for an Ubuntu 22.04+ lab machine. The first image download can
take longer than five minutes on a slow connection; after that, the normal startup
path is `docker compose up -d --build`.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker

git clone https://github.com/<your-account>/robotics-app-idmz.git
cd robotics-app-idmz
cp .env.example .env
nano .env

docker compose config --quiet
docker compose up -d --build
docker compose ps
```

Replace `<your-account>` with the GitHub account that owns this repository.
Generate a different strong value for every blank secret in `.env`; never commit
that file. When the main services show `Up` or `healthy`, open
`http://localhost:8888` in a browser. Run `bash test_policy.sh` to verify the
default-deny firewall policy after the stack starts.

## Fresh install checklist

Use this checklist on a new machine before an examiner demo.

1. Install Docker Engine or Docker Desktop with Docker Compose v2.
2. Clone the repository.
3. Copy `.env.example` to `.env`.
4. Fill every value in `.env` with a generated secret. Do not reuse one secret
   for two controls.
5. Validate the compose file:

```bash
docker compose config --quiet
```

6. Build and start the lab:

```bash
docker compose up -d --build
```

7. Confirm the main containers are running:

```bash
docker compose ps
```

8. Open the dashboard at `http://localhost:8888`.

The repository does not require committing `node_modules/` or local build
artifacts. The dashboard dependencies are installed from `package-lock.json`
during local setup or Docker image build.

## Verification commands

Run these before a submission or live demo:

```bash
# Firewall policy evidence: default-deny, allowed conduits, DENIED: logging, persisted deny evidence
bash test_policy.sh
docker exec router-fw tail -n 5 /var/log/idmz/firewall-deny.jsonl

# Full six-stage validation
bash infra/tests/stage_all_smoke_docker.sh
```

The full smoke test intentionally exercises safety and incident-response paths.
If the dashboard shows `EMERGENCY` after the test, reset the safety state from
the PLC Control page before normal operation.

## Demo proof

Proof-of-life screenshots are stored in `screenshots/`.

Recommended demo order:

1. Open the dashboard and show the 4-zone architecture status.
2. Run `bash test_policy.sh` to prove firewall default-deny behavior and populate the Stage 1 firewall evidence panel.
3. Show Stage 4 CVEs in the dashboard and explain asset-register scope.
4. Run the Stage 6 IR gate to prove network isolation waits for approval.
5. Run the full smoke test if the examiner wants end-to-end proof.

## GitHub hygiene

Before pushing or sharing the repository:

- Do not commit `.env`.
- Do not commit `node_modules/`.
- Do not commit generated dashboard build output from `dashboard/dist/`.
- Keep `.env.example` committed so a fresh installer knows what to provide.
- Review `git status --short` and confirm only intended source, configuration, tests,
  and screenshots are included.

## Security notes

- OT RDP, OpenPLC, ntopng, and Guacamole passwords are supplied only through
  `.env`. The containers refuse to start when a required value is missing or weak.
- Guacamole applies those values to both new and existing database volumes before
  its web application starts, including replacement of the upstream admin default.
- `.env` is never committed; copy `.env.example` and generate a distinct value
  for every secret before running the stack.
