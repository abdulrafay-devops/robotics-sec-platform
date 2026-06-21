---
id: pb_integrity_mismatch
title: PLC program integrity hash mismatch
severity: critical
nist_phases: [Detection, Analysis, Containment, Recovery, Lessons-Learned]
triggers:
  - source: baseline_drift
    category: program_hash_baseline_present
  - source: ai_alerts
    category: integrity-mismatch
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID}
    requires_human_approval: false
  - name: rollback_program
    cmd: /opt/lab/bin/ir-rollback ${INCIDENT_ID}
    requires_human_approval: true
  - name: post_mortem_template
    cmd: /opt/lab/bin/ir-postmortem-stub ${INCIDENT_ID} integrity-mismatch
    requires_human_approval: false
---

# Playbook — PLC program integrity hash mismatch

## Detection

Stage 4's `firmware_workflow.py` records the SHA-256 of the deployed
program in `/var/lab/state/integrity_baseline.json`. Stage 6's
exporter scrapes the running program every 60 s and compares to
baseline. A drift event fires if the hash changes outside a workflow
run.

## Containment / Recovery

Roll back to the most recent signed Stage 5 artifact. The rollback
ALSO refreshes the Stage 3 integrity baseline so the watchdog stops
alarming after the deliberate restore.

## Why human approval

Rolling back a production PLC takes the cell out of cycle for ~10 s.
That is non-negligible — operator must confirm.
