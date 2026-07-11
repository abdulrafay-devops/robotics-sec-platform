---
id: pb_coil_flood
title: Modbus coil flood / denial of service
attack_type: coil_flood
mitre_id: T0814
mitre_technique: Denial of Service
tactic: Inhibit Response Function
severity: high
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    attack_type: coil_flood
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH technique=T0814 src=${SRC_IP}"
    requires_human_approval: false
  - name: graded_isolate
    cmd: /opt/lab/bin/ir-isolate ${SRC_IP}
    requires_human_approval: true
  - name: graded_slow
    cmd: /opt/lab/bin/ir-slow ${INCIDENT_ID}
    requires_human_approval: true
  - name: post_mortem_template
    cmd: /opt/lab/bin/ir-postmortem-stub ${INCIDENT_ID} ${CATEGORY}
    requires_human_approval: false
  - name: close_incident
    cmd: python3 /opt/lab/vm-ai/ir/playbook_engine.py close-incident ${INCIDENT_ID} --postmortem-path /var/lab/state/ir/postmortems/${INCIDENT_ID}.md
    requires_human_approval: true
---

# Playbook — Modbus coil flood / DoS (MITRE ATT&CK for ICS **T0814**)

## Detection

An extremely high rate of FC5 coil writes to a single point (here the
`e_stop_active` coil) is **starving the PLC scan cycle** — a classic OT
denial-of-service. The message-rate feature spikes far above the steady 4 Hz HMI
poll and the classifier sees coil-only writes at tens of requests per second.

## Analysis

- DoS on a safety coil can either jam the process or chatter the safety state —
  both are operationally dangerous. Prioritise restoring deterministic scan time.
- Confirm the flood is inbound from `${SRC_IP}` and not a misbehaving local task.

## Containment (graded)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Capture rate + target coil for the post-mortem. | auto |
| Isolate | `iptables` DROP from `${SRC_IP}` to stop the flood at the edge after analyst approval. | human |
| Slow | Drop the arm to ISO-10218 safety speed while scan time recovers. | human |

## Eradication

1. Confirm the PLC scan time returned to nominal after isolation.
2. Rate-limit Modbus writes at the OT gateway so a single source cannot saturate.

## Recovery

Resume only after the scan-cycle metric is stable for a full supervised cycle.

## Lessons learned

Record the sustained write rate; tune the DoS rate alarm if it was late.
