---
id: pb_recon_scan
title: OT reconnaissance / register enumeration
attack_type: recon_scan
mitre_id: T0846
mitre_technique: Remote System Discovery
tactic: Discovery
severity: medium
nist_phases: [Detection, Analysis, Containment, Lessons-Learned]
triggers:
  - source: ai_alerts
    attack_type: recon_scan
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH technique=T0846 src=${SRC_IP}"
    requires_human_approval: false
  - name: graded_isolate
    cmd: /opt/lab/bin/ir-isolate ${SRC_IP}
    requires_human_approval: true
  - name: post_mortem_template
    cmd: /opt/lab/bin/ir-postmortem-stub ${INCIDENT_ID} ${CATEGORY}
    requires_human_approval: false
  - name: close_incident
    cmd: python3 /opt/lab/vm-ai/ir/playbook_engine.py close-incident ${INCIDENT_ID} --postmortem-path /var/lab/state/ir/postmortems/${INCIDENT_ID}.md
    requires_human_approval: true
---

# Playbook — OT reconnaissance scan (MITRE ATT&CK for ICS **T0846**)

## Detection

A source is **reading far more of the register/coil map than any HMI ever does** —
a sequential FC3 sweep across the holding registers plus FC1 coil probes. There
are **no writes**, so nothing is being changed yet; this is the enumeration phase
that typically precedes a targeted attack.

## Analysis

- Recon is read-only and low-harm in itself, but it is an **early-warning**: the
  same source often returns to write. Triage promptly and watch `${SRC_IP}`.
- Distinguish a real scan from a new/poorly-behaved monitoring tool before
  isolating, to avoid taking down a legitimate integration.

## Containment (graded)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Tag `${SRC_IP}`, raise logging, alert the analyst. | auto |
| Isolate | `iptables` DROP from `${SRC_IP}` (held for human approval — read-only, low harm). | human |

## Lessons learned

Capture which registers were enumerated; if sensitive, restrict read scope at the
OT gateway so future scans reveal less.
