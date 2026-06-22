---
id: pb_command_injection
title: Modbus command injection on production PLC
attack_type: modbus_command_injection
mitre_id: T0855
mitre_technique: Unauthorized Command Message
tactic: Impair Process Control
severity: critical
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    attack_type: modbus_command_injection
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH technique=T0855 src=${SRC_IP}"
    requires_human_approval: false
  - name: graded_isolate
    cmd: /opt/lab/bin/ir-isolate ${SRC_IP}
    requires_human_approval: false
  - name: graded_slow
    cmd: /opt/lab/bin/ir-slow ${INCIDENT_ID}
    requires_human_approval: true
  - name: assert_safe_state
    cmd: /opt/lab/bin/ir-stop ${INCIDENT_ID}
    requires_human_approval: true
  - name: post_mortem_template
    cmd: /opt/lab/bin/ir-postmortem-stub ${INCIDENT_ID} ${CATEGORY}
    requires_human_approval: false
  - name: close_incident
    cmd: python3 /opt/lab/vm-ai/ir/playbook_engine.py close-incident ${INCIDENT_ID} --postmortem-path /var/lab/state/ir/postmortems/${INCIDENT_ID}.md
    requires_human_approval: true
---

# Playbook — Modbus command injection (MITRE ATT&CK for ICS **T0855**)

## Detection

A non-HMI source is **writing control points the baseline only ever reads** —
toggling control coils (`motor_arm_enable`, `conveyor_run`) and forcing the
`cycle_step` register (MW0) out of its legal 0–6 range. The AI plane flags the
window (IsolationForest + AE consensus); the IR classifier confirms the technique
from the observed function codes (FC5/FC6) and target addresses.

## Analysis

- **Source** — any host other than the sanctioned HMI writing to OT is, by
  definition, unauthorized. Confirm `${SRC_IP}` against the HMI allow-list.
- **Target** — writes to `cycle_step` / control coils can force motion. Treat as
  a cyber-physical incident, not a nuisance alarm.

## Containment (graded)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Raise logging fidelity, capture full Modbus stream. | auto |
| Isolate | `iptables` DROP from `${SRC_IP}`. | auto |
| Slow | Drop the arm to ISO-10218 safety speed (250 mm/s). | human |
| Stop | Safety supervisor asserts safe state (latched). | human |

## Eradication

1. Confirm the Stage 4 control-program hash still matches the Stage 3 baseline.
2. Validate the SROS2 keystore (`bootstrap_keystore.sh --verify`) — an injected
   command often rides a compromised or spoofed publisher.

## Recovery

Re-home the arm, run one supervised normal cycle with the model watching, then
the operator presses **resume** after visual confirmation.

## Lessons learned

Record how the writer reached the PLC (which conduit) and tighten the OT write
path. The post-mortem must be committed before the incident can close.
