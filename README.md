# Robotics IDMZ Security Lab

A containerized OT/IT lab that demonstrates a true Industrial DMZ (Purdue
model) architecture around a robotics/PLC plant floor, with live attack
detection, incident response, and a DevSecOps pipeline gating PLC/HMI/SROS2
code before it reaches the plant.

## Architecture

Single-homed zone design: every service container sits on exactly one network
zone, and `router-fw` is the only multi-homed node, enforcing all cross-zone
traffic with default-deny nftables rules.

| Zone   | Network      | Services |
|--------|--------------|----------|
| OT     | `ot-net`     | `container-ot` (PLC/robot plant floor, OpenPLC, Gazebo) |
| Security | `mgmt-net` (+ OT tap) | `container-sec` (Zeek/Suricata monitoring, attack injection) |
| AI     | —            | `container-ai` (anomaly detection, MITRE ATT&CK classification, IR playbooks) |
| DMZ    | `dmz-net`    | `guacamole`/`guacd` (vendor RDP access broker), `historian` (read-only data view), `postgres` |
| Management | `mgmt-net` | `gitea` + `runner` (DevSecOps CI), `dashboard` (operator UI) |

See [docker-compose.yml](docker-compose.yml) for the full service/network
definitions and [infra/](infra/) for the router firewall, Guacamole
provisioning, and the per-stage validation test suite.

## Running the lab

```bash
cp .env.example .env
# fill in the values in .env (see comments in the file for how to generate each one)
docker compose up -d
```

The dashboard is served on the port configured in `docker-compose.yml`
(`dashboard` service). OpenPLC web UI and Modbus are exposed on loopback only
for host-side debugging.

## Repo layout

- `vm-ot/` — PLC programs (Structured Text), robot control, SROS2 safety supervisor
- `vm-sec/` — network monitoring, attack injection scripts, vulnerability scanning
- `vm-ai/` — anomaly detection models, MITRE classifier, incident-response playbooks, DevSecOps pipeline gates
- `infra/` — router firewall, Guacamole/DMZ provisioning, per-stage validation gates (`infra/tests/`)
- `dashboard/` — operator-facing web UI (React/Vite)
- `hmi/` — HMI/SCADA screen definitions
- `demos/` — CI/CD gate demo artifacts (vulnerable vs. hardened PLC program)

## Security notes

- `infra/dmz/initdb/03-lab-connections.sql` provisions demo-only lab
  credentials for the Guacamole vendor-access broker — change these before
  using this outside an isolated lab environment.
- `.env` is never committed; copy `.env.example` and generate your own values.
