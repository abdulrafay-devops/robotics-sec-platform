---
id: pb_setpoint_drift
title: Stealthy setpoint drift (low-and-slow parameter change)
attack_type: setpoint_drift
mitre_id: T0836
mitre_technique: Modify Parameter
tactic: Impair Process Control
severity: high
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    attack_type: setpoint_drift
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH technique=T0836 src=${SRC_IP}"
    requires_human_approval: false
  - name: graded_isolate
    cmd: /opt/lab/bin/ir-isolate ${SRC_IP}
    requires_human_approval: false
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

# Playbook — Stealthy setpoint drift (MITRE ATT&CK for ICS **T0836**)

## Detection

A source is making **slow, small writes to a single setpoint register** (MW4),
staying just above the read-only baseline to avoid rate alarms — the "low and
slow" parameter-tampering pattern. The behavioural model still catches it because
the baseline **never writes**, so `write_ratio` lifting off zero is itself the
tell.

## Analysis

- The danger of drift is cumulative: each step is innocuous, the trajectory is
  not. Reconstruct the value timeline, not just the latest write.
- Confirm whether the setpoint affects product quality, motion, or safety to set
  the grade.

## Containment (graded)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Capture the full value timeline of MW4. | auto |
| Isolate | `iptables` DROP from `${SRC_IP}`. | auto |
| Slow | Drop the arm to safety speed if the setpoint drives motion. | human |

## Eradication

1. Restore the setpoint to its commissioned value from the golden config.
2. Add bounds/rate checks on this setpoint at the OT gateway.

## Recovery

Verify the setpoint and product output are nominal across a supervised cycle.

## Lessons learned

Record the drift rate and total displacement so the parameter-change alarm can be
tuned to catch it sooner.
