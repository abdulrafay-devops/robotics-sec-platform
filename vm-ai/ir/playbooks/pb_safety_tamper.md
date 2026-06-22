---
id: pb_safety_tamper
title: Safety / E-stop state tampering
attack_type: safety_tamper
mitre_id: T0880
mitre_technique: Loss of Safety
tactic: Impact
severity: critical
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    attack_type: safety_tamper
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH technique=T0880 src=${SRC_IP}"
    requires_human_approval: false
  - name: graded_isolate
    cmd: /opt/lab/bin/ir-isolate ${SRC_IP}
    requires_human_approval: false
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

# Playbook — Safety / E-stop tampering (MITRE ATT&CK for ICS **T0880**)

## Detection

Something is **writing the safety path** — toggling the e-stop coil and the
`safety_state` register (MW2). In normal operation these are **operator-read-only**;
any write here is the worst case because it can suppress or spoof the protective
function that keeps the cell safe.

## Analysis

- This is a **life-safety** event, not just a cyber event. The first priority is
  the physical safe state of the cell, then attribution.
- Determine whether the safety value is being cleared (suppressing protection) or
  forced to trip (nuisance/extortion). Either way, do not trust the reported
  safety state until verified out-of-band.

## Containment (graded)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Capture every write to the safety path. | auto |
| Isolate | `iptables` DROP from `${SRC_IP}` immediately. | auto |
| Stop | Safety supervisor asserts the latched safe state — the arm freezes. | human |

## Eradication

1. Verify the hardwired safety relay independently of the PLC-reported state.
2. Confirm the control program and safety logic match the Stage 3 baseline hash.

## Recovery

Do **not** resume until a manual safety audit confirms the protective function is
intact and the safe state is genuine. Operator presses reset after sign-off.

## Lessons learned

Treat as a reportable safety incident. Record how the writer reached the safety
registers and segment that path further.
