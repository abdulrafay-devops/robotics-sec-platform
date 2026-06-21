---
id: pb_sros2_unauthorized
title: Unauthorized publisher on a SROS2 safety topic
severity: critical
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery]
triggers:
  - source: ai_alerts
    category: sros2-unauthorized-publisher
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: revoke_offending_enclave
    cmd: /opt/lab/bin/ir-revoke-enclave ${INCIDENT_ID}
    requires_human_approval: true
  - name: assert_safe_state
    cmd: /opt/lab/bin/ir-stop ${INCIDENT_ID}
    requires_human_approval: true
  - name: post_mortem_template
    cmd: /opt/lab/bin/ir-postmortem-stub ${INCIDENT_ID} sros2-unauthorized
    requires_human_approval: false
---

# Playbook — Unauthorized publisher on safety topic

## Detection

Stage 3's `safety_supervisor` emits a `sros2-unauthorized-publisher`
event when it observes a participant publishing to `/safety/request`
*without* having completed the DDS-Security handshake — i.e. the
`stage3_sros2_authn.py` rejection path firing in production.

## Containment

Revocation is handled by writing a CRL (Certificate Revocation List)
entry into `/opt/lab/sros2_keystore/public/crl.pem` and broadcasting a
`participant_stateless_message` to all peers. Because revocation
breaks live participants, this is a HUMAN-APPROVAL step.

## Recovery

Re-issue a fresh enclave for the legitimate node, push it via Stage 4
firmware workflow, and re-run `stage3_safety_loop.py` to confirm.
