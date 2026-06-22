---
id: pb_bulk_write
title: Unauthorized bulk register write (block memory overwrite)
attack_type: bulk_write
mitre_id: T0843
mitre_technique: Program Download
tactic: Lateral Movement
severity: critical
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    attack_type: bulk_write
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH technique=T0843 src=${SRC_IP}"
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

# Playbook — Unauthorized bulk register write (MITRE ATT&CK for ICS **T0843**)

## Detection

A source is pushing **blocks of crafted values at once** via FC16 multi-register
writes — the baseline only ever writes single values, never blocks. A bulk write
is how an attacker overwrites a swath of PLC memory or stages tampered controller
tasking, so it is treated as a controller-integrity event.

## Analysis

- Capture the **exact register range and values** written; this is the evidence
  that the controller's memory/logic was altered.
- Correlate with Stage 4 integrity hashing — a bulk write that precedes a hash
  mismatch indicates a program/logic change, not just a data change.

## Containment (graded)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Capture the written block (range + values). | auto |
| Isolate | `iptables` DROP from `${SRC_IP}` immediately. | auto |
| Stop | Safety supervisor asserts safe state before any logic runs on tampered memory. | human |

## Eradication

1. Compare the control program/PLC image against the Stage 3 golden hash; if it
   differs, roll back via `firmware_workflow.py --restore <run_id>`.
2. Validate the SROS2 keystore — bulk writes often follow a foothold.

## Recovery

Recompile/restore from golden config, run the Stage 5 acceptance harness in a
sandbox, then reconnect the cell. Operator presses resume after sign-off.

## Lessons learned

Record the overwritten range and whether it changed logic or data; restrict FC16
write scope at the OT gateway.
