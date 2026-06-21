---
id: pb_robot_anomaly
title: Anomalous robot joint dynamics (behavior plane)
severity: high
nist_phases: [Detection, Analysis, Containment, Eradication, Recovery, Lessons-Learned]
triggers:
  - source: ai_alerts
    category: robot-behavior-anomaly
steps:
  - name: capture_evidence
    cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID} ${SRC_IP}
    requires_human_approval: false
  - name: graded_watch
    cmd: logger -t lab-ir "incident=${INCIDENT_ID} grade=WATCH plane=robot src=${SRC_IP}"
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

# Playbook — Anomalous robot joint dynamics

## Detection

Triggered by the **robot-behavior plane** (`robot_consumer.py` → `alert_bridge`)
writing a `robot-behavior-anomaly` event to `/var/lab/log/ai-alerts.json`. That
detector watches the live `/lab_arm/joint_states` stream with two layers:

- an **LSTM autoencoder** that learns the normal cyclic pick-and-place dynamics
  and flags reconstruction error above its calibrated p99 threshold; and
- a deterministic **physical-envelope** layer (joint position/velocity/jerk limits
  and a frozen-joint check) that catches over-speed, out-of-range, jerk and
  sensor-freeze conditions the learned model alone may miss.

The alert payload (`lab.robot_z`, `lab.envelope_hits`, `lab.top_features`) names
the offending joint(s) and which layer fired.

## Analysis

Operator should review:

- **`envelope_hits`** — a `*_vel_over_limit`, `*_pos_out_of_range` or `*_frozen`
  tag is an unambiguous physical fault: the arm is moving faster, further, or
  more erratically than it ever does in normal operation, or a joint that should
  be moving has gone static (sensor spoof / actuator fault).
- **`robot_z`** with no envelope hit — a subtler trajectory deviation the learned
  model caught (e.g. the arm reaching toward a location it never visits).
- Correlate with the network plane: a robot-behavior anomaly arriving alongside a
  `modbus-*` anomaly indicates the motion change was driven by a controller
  write — treat as a containment-class cyber-physical incident.

## Containment (graded — see ARCHITECTURE-DIAGRAMS.md)

| Grade | Action | Approval |
|-------|--------|----------|
| Watch | Increase logging fidelity on the robot plane. | auto |
| Slow | Drop robot to ISO-10218 safety speed (250 mm/s). | human |
| Stop | Safety supervisor asserts safe state (latched E-stop); the arm freezes. | human |

## Eradication

1. Confirm the Stage 4 firmware/PLC hash still matches the Stage 3 baseline; a
   tampered control program is the most likely root cause of forced motion.
2. Validate the SROS2 keystore integrity (`bootstrap_keystore.sh --verify`) — an
   unauthorized DDS publisher could be injecting joint commands.

## Recovery

Re-home the arm and run one supervised normal cycle with the robot-behavior model
watching before returning the cell to production. The operator presses the
simulated "reset" button (dashboard) after visual confirmation that motion is
nominal and `robot_z` has returned below threshold.

## Lessons learned

The post-mortem template at `/var/lab/state/ir/postmortems/${INCIDENT_ID}.md`
must be merged before the incident can be closed. Capture whether the trigger was
a network-driven control write or a sensor/actuator fault, so the matching
detector threshold or envelope can be tuned.
