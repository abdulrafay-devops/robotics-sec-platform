---
id: pb_modbus_replay
title: Modbus replay attack on production PLC
severity: high
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    category: modbus-baseline-deviation
  - source: ai_alerts
    category: modbus-external-anomaly
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH src=${SRC_IP}"
    requires_human_approval: false
  - name: graded_isolate
    cmd: /opt/lab/bin/ir-isolate ${SRC_IP}
    requires_human_approval: true
  - name: graded_slow
    cmd: /opt/lab/bin/ir-slow ${INCIDENT_ID}
    requires_human_approval: true
  - name: graded_stop
    cmd: /opt/lab/bin/ir-stop ${INCIDENT_ID}
    requires_human_approval: true
  - name: post_mortem_template
    cmd: /opt/lab/bin/ir-postmortem-stub ${INCIDENT_ID} ${CATEGORY}
    requires_human_approval: false
  - name: close_incident
    cmd: python3 /opt/lab/vm-ai/ir/playbook_engine.py close-incident ${INCIDENT_ID} --postmortem-path /var/lab/state/ir/postmortems/${INCIDENT_ID}.md
    requires_human_approval: true
---

# Playbook — Modbus replay attack

## Detection

Triggered by Stage 2's anomaly detection (`feature_consumer` →
`alert_bridge`) writing a `modbus-write-anomaly` or
`modbus-baseline-deviation` event to `/var/lab/log/ai-alerts.json`.

## Analysis

Operator should review:

- The exact Modbus function code and target register from the alert
  payload — replays usually target FC=6 (write single register) or
  FC=16 (write multiple registers) on holding registers driving motion.
- Source IP — if it is *inside* the OT subnet, the attack has already
  bypassed perimeter controls; treat as Containment-class incident.

## Containment (graded — see ARCHITECTURE-DIAGRAMS.md)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Increase logging fidelity. | auto |
| Isolate | iptables DROP from `${SRC_IP}` on the docker bridge after analyst approval. | human |
| Slow | Drop robot to ISO-10218 safety speed (250 mm/s). | human |
| Stop | Safety supervisor asserts safe state. | human |

## Eradication

1. Confirm Stage 4 firmware hash matches Stage 3 baseline; if not,
   roll back via `firmware_workflow.py --restore <run_id>`.
2. Validate SROS2 keystore integrity (`bootstrap_keystore.sh --verify`).

## Recovery

Run the Stage 5 acceptance harness in a sandbox before reconnecting
the affected cell to production. Operator must press the simulated
"resume" button (Grafana panel) after visual confirmation.

## Lessons learned

The post-mortem template at `/var/lab/state/ir/postmortems/${INCIDENT_ID}.md`
must be merged into the Gitea repo before this incident can be marked
closed; the engine refuses to clear the pending entry until it sees the
merge commit.
