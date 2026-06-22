---
id: pb_replay
title: Modbus replay attack (recorded command sequence)
attack_type: modbus_replay
mitre_id: T0831
mitre_technique: Manipulation of Control
tactic: Impair Process Control
severity: high
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    attack_type: modbus_replay
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH technique=T0831 src=${SRC_IP}"
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

# Playbook — Modbus replay attack (MITRE ATT&CK for ICS **T0831**)

## Detection

A **previously-valid command sequence is being re-sent** to scratch registers
(MW10–MW13) at an off-baseline cadence. Each individual write looks legitimate —
that is the point of a replay — but the *sequence and rate* do not match live
operation, so the AE/IsolationForest fire and the classifier sees pure FC6 writes
to the scratch block with no coil activity.

## Analysis

- Replays evade signature IDS because the payloads are real. Lean on the AI
  behavioural deviation and the timing fingerprint, not on payload blocklists.
- Confirm whether the sequence drives motion or only scratch state; this sets the
  containment grade.

## Containment (graded)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Capture the replayed sequence + timing for the post-mortem. | auto |
| Isolate | `iptables` DROP from `${SRC_IP}`. | auto |
| Slow | Drop the arm to ISO-10218 safety speed. | human |

## Eradication

1. Rotate session credentials/keys so the captured sequence cannot be re-used.
2. Add a nonce/sequence freshness check at the OT write gateway where feasible.

## Recovery

Verify register state matches the supervisor's expected values before resuming.

## Lessons learned

Document the replay window and cadence so the timing model can be tightened.
