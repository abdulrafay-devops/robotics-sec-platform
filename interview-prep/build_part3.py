# -*- coding: utf-8 -*-
"""Part 3 — The Brain (Detection, AI, Response, DevSecOps)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _pdfkit import (P, H1, H2, H3, small, spacer, bullets, code, callout, tbl,
                     rule, keep, build, CONTENT_W, PageBreak)

st = []

# ============================================================ COVER
st += [
    P('Robotics Security Platform', 'title'),
    P('Interview Preparation &mdash; Part 3 of 4: The Brain (Detection, AI, Response &amp; DevSecOps)', 'subtitle'),
    rule(),
    P('Part 2 was the plant floor. This part is everything that watches it and reacts: how raw network traffic becomes numerical features, how four machine-learning models across two detection planes (network traffic and robot motion) decide what is an attack, how the incident-response engine contains a threat without endangering anyone, how vulnerabilities are tracked offline, and how the robot/PLC code itself is gate-checked by a CI/CD pipeline. This is the longest part &mdash; it is the "intelligent" half of "intelligent security platform".', 'body'),
    callout('The spine of this whole part is one pipeline: <b>traffic &rarr; features &rarr; score &rarr; alert &rarr; incident &rarr; response</b>. Keep that chain in your head and every component below slots into it.', 'why'),
]

# ============================================================ SEC ZONE
st += [PageBreak(), H1('1.  The Security zone: passively watching the wire')]
st += [
    P('The SEC zone\'s job is to <b>observe</b> OT traffic and turn it into something the AI can use &mdash; without ever touching the plant. It only sees a <b>mirror</b> (a copy) of the traffic, so it physically cannot interfere.', 'body'),
    H2('1.1  Zeek, Suricata, ntopng &mdash; three lenses on the same traffic'),
    tbl([
        ['Tool', 'What it is', 'Its role here'],
        ['Zeek', 'A network analyser that understands protocols deeply', 'Parses Modbus (and DNP3/OPC-UA), and emits per-message feature rows for the ML pipeline.'],
        ['Suricata', 'A signature-based IDS', 'Catches known-bad patterns with rules (e.g. a write to the motor-enable coil from a non-HMI source).'],
        ['ntopng', 'A network-flow visualiser', 'Operator-facing view of who is talking to whom on the network.'],
    ], [0.16 * CONTENT_W, 0.34 * CONTENT_W, 0.50 * CONTENT_W]),
    callout('This is "defence in depth" inside detection itself: Suricata catches the <i>known</i>, the ML models catch the <i>unknown/novel</i>, and ntopng gives a human the big picture. No single blind spot.', 'why'),
    H2('1.2  The clever Zeek rule worth quoting'),
    P('Zeek\'s local policy declares a custom alert called <b>Modbus_Write_From_Outside_OT</b>. In plain words: <b>"If you see a Modbus <i>write</i> command (function code 5, 6, 15, 16, 22, 23) and the sender is not inside the OT subnet, raise a notice."</b> That is the single most suspicious thing in this environment &mdash; a write to the controller from somewhere it should never come from.', 'body'),
    H2('1.3  Shipping the features to the brain'),
    P('A small program, <b>feature_pusher.py</b>, tails Zeek\'s feature log and pushes each row as JSON onto a Redis list named <b>lab.modbus.features.raw</b>. It is written to survive the messy realities: Zeek rotates its log every hour (it re-opens on inode change) and Redis might blip (it backs off and re-seeks so no row is lost).', 'body'),
]

# ============================================================ FEATURES
st += [PageBreak(), H1('2.  From traffic to features (the 20-number fingerprint)')]
st += [
    P('Machine-learning models do not read network packets; they read numbers. So the pipeline summarises traffic into a <b>20-number vector</b> describing one source IP\'s behaviour over a <b>5-second window</b>. The exact same code computes these for training and for live scoring, so the model and the live scorer always agree.', 'body'),
    H2('2.1  The 20 features (grouped so they are memorable)'),
    tbl([
        ['Group', 'Features', 'Intuition'],
        ['Volume', 'n_msgs, msg_rate, n_unique_funccodes, n_unique_addresses', 'How much and how varied is the traffic?'],
        ['Read vs write', 'n_reads, n_writes, write_ratio, write_read_ratio, bulk_write_ratio', 'Normal HMIs mostly read; attacks write &mdash; especially bulk writes.'],
        ['Where from', 'ot_origin, n_external_writes', '<b>The key signal:</b> writes coming from outside the OT zone.'],
        ['Errors', 'n_exceptions, exception_rate', 'Attackers poke at things and cause error storms.'],
        ['Targets', 'mean_address, std_address, mean_quantity, max_quantity', 'Which registers, and how big the operations are.'],
        ['Timing', 'mean_iat_ms, std_iat_ms', 'Bursts have low, uniform inter-arrival times.'],
        ['Shape', 'func_entropy', 'Attack traffic mixes function codes unusually (high entropy).'],
    ], [0.13 * CONTENT_W, 0.50 * CONTENT_W, 0.37 * CONTENT_W]),
    callout('If they ask "what is your single best feature?": <b>n_external_writes</b> &mdash; the count of write commands from a non-OT IP. That is the textbook command-injection / exfiltration signal, and it directly mirrors the Zeek rule from section 1.', 'say'),
    H2('2.2  The Redis bus (why a queue sits in the middle)'),
    code(
"""vm-sec                         vm-ai
feature_pusher --RPUSH--> [ lab.modbus.features.raw ] --BLPOP--> feature_consumer
                                                                     | scores window
                              [ lab.anomaly.events ] <--RPUSH-------+
                                       |
                                       +--BLPOP--> alert_bridge --> ai-alerts.json"""),
    P('Redis decouples the fast producer (network sensors) from the slower consumer (ML scoring). A sudden traffic burst piles up harmlessly in the queue instead of stalling or crashing the scorer.', 'body'),
]

# ============================================================ ML MODELS
st += [PageBreak(), H1('3.  The machine-learning models (two detection planes)')]
st += [
    P('Detection runs on <b>two independent planes</b>. The <b>network plane</b> scores each 5-second Modbus window with <b>three</b> complementary anomaly detectors (below). The <b>robot-behavior plane</b> (section 3.3) watches the robot\'s own motion with a <b>fourth</b> model. Four models, two planes, no single blind spot &mdash; if <i>any</i> detector flags its input above its calibrated threshold, it counts as anomalous.', 'body'),
    H2('3.0  Network plane &mdash; three detectors on the 20-feature Modbus vector'),
    tbl([
        ['Model', 'How it thinks', 'What it is best at'],
        ['Isolation Forest', 'Randomly "cuts" the data; anomalies get isolated in very few cuts.', 'Cheaply catching rare <i>combinations</i> of features.'],
        ['PCA autoencoder', 'Compresses then reconstructs the vector; big reconstruction error = odd.', 'Catching windows that do not fit the normal "shape" of data.'],
        ['TensorFlow autoencoder', 'A neural network that learns to reconstruct normal traffic.', 'Catching subtler, non-linear patterns the others miss.'],
    ], [0.24 * CONTENT_W, 0.42 * CONTENT_W, 0.34 * CONTENT_W]),
    H2('3.1  How they are trained (this is where the rigour shows)'),
    bullets([
        '<b>Trained on pure normal traffic only</b> &mdash; zero attack data in training. The model learns "normal" so cleanly that anything unusual stands out. (This is what makes it an <i>anomaly</i> detector, not a classifier.)',
        '<b>Threshold calibrated to the 99th percentile</b> of normal scores &mdash; aiming for at most ~1% false alarms. Crucially the autoencoder thresholds are calibrated against the <b>live</b> Zeek pipeline, not just synthetic data, so the model&apos;s notion of "normal" matches what it sees in production (no train/serve drift).',
        '<b>Quality measured with AUC</b> on held-out attack data, so the detection performance is actually quantified, not assumed.',
        'For Isolation Forest specifically: 300 trees for stable scoring, and scores are made always-non-negative so "bigger = more anomalous" is consistent.',
    ]),
    callout('"Why anomaly detection instead of signatures?" &rarr; "OT attacks often <i>live off the land</i> using legitimate protocol commands, so there is no signature to match. A model of <i>normal</i> flags malicious-but-novel behaviour &mdash; like a register that is normally only read suddenly being written from outside the OT zone."', 'say'),
    H2('3.2  Keeping false positives down (4 controls)'),
    P('A security tool that cries wolf gets switched off. So beyond the calibrated threshold, the consumer adds three more brakes:', 'body'),
    bullets([
        '<b>Two-window debounce</b> &mdash; an alert needs <i>two consecutive</i> anomalous 5-second windows. A real attack persists; a one-off blip is ignored.',
        '<b>Per-source cooldown</b> &mdash; after alerting on a source IP, it waits ~45&nbsp;seconds before alerting on it again, so one attack is not 50 alerts.',
        '<b>Calibrated (not hard-coded) thresholds</b> &mdash; each model uses its own learned 99th-percentile threshold, with an env override available for noisy links.',
        'A single attack that trips several detectors is folded into <b>one incident</b> (campaign de-duplication), not many.',
    ]),
    H2('3.3  Robot-behavior plane &mdash; the LSTM autoencoder + physical envelope'),
    P('The three models above watch the <i>network</i>. But an attacker who already controls the PLC can move the robot through <i>legitimate-looking</i> commands &mdash; so a fourth model watches the <b>robot\'s motion itself</b>. A passive tap (<b>joint_telemetry_bridge.py</b>) mirrors the live <b>/lab_arm/joint_states</b> stream to the AI &mdash; exactly as Zeek mirrors the network &mdash; and <b>robot_consumer.py</b> scores it with two layers:', 'body'),
    tbl([
        ['Layer', 'How it thinks', 'What it catches'],
        ['LSTM autoencoder', 'A recurrent neural net learns the normal pick-and-place motion over a 5&nbsp;s window of joint angles and velocities, and flags windows it reconstructs badly.', 'Subtle trajectory tampering &mdash; the arm reaching somewhere it never normally goes.'],
        ['Physical envelope', 'Deterministic limits calibrated from normal motion: joint speed, position range, jerk, and a frozen-joint check.', 'Hard faults &mdash; over-speed, out-of-range, jitter, or a sensor-frozen joint.'],
    ], [0.22 * CONTENT_W, 0.48 * CONTENT_W, 0.30 * CONTENT_W]),
    callout('Why two layers? The learned model catches the <i>subtle and novel</i>; the envelope catches the <i>physically gross</i> and is fully explainable ("j1 exceeded its speed limit"). A frozen joint is the neat case: it is <i>too simple</i> for the autoencoder to flag, so the deterministic frozen-joint rule catches it instead.', 'why'),
    bullets([
        '<b>Anti-drift by design</b> &mdash; one shared, versioned module (robot_features.py, ROBOT_FEATURE_VERSION) computes the features for <i>both</i> training and live scoring, and the tap emits only raw joint angles (velocities are derived in that one place). A contract test asserts the live windows are byte-for-byte what training saw.',
        '<b>Trained on pure-normal motion</b>, 99th-percentile threshold, <b>ROC-AUC ~0.99</b> on held-out behavioral attacks &mdash; the same rigour as the network models.',
        '<b>Closes the loop</b> &mdash; a robot anomaly raises a robot-behavior-anomaly alert that drives the same incident-response engine, whose containment ladder ends in a latched <b>E-stop</b>.',
    ]),
    callout('Key numbers: <b>network plane</b> = 5-second window, 20 features, 3 models; <b>robot plane</b> = 5-second window of 12 joint channels, LSTM autoencoder + physical envelope. All use <b>99th-percentile</b> thresholds, a <b>2-window</b> debounce and a <b>~45&nbsp;s</b> cooldown. Sub-5-second detection in the demo.', 'note', label='DETECTION CHEAT-SHEET'),
]

# ============================================================ SCORING SERVICE
st += [PageBreak(), H1('4.  The scoring service (the API in the middle)')]
st += [
    P('<b>score_service.py</b> is a FastAPI web service on port 8000. It is the hub the dashboard talks to. Its endpoints group into a few jobs:', 'body'),
    tbl([
        ['Job', 'Endpoints', 'What it does'],
        ['ML scoring', '/score, /score/window, /metadata, /health', 'Score feature vectors on demand; report model info and liveness.'],
        ['Trend analytics', '/api/trend, /api/trend/history', 'The threat sparkline the dashboard draws.'],
        ['Incident response', '/api/ir/incidents, /pending, /approve', 'List incidents, list steps awaiting approval, and approve/reject them.'],
        ['HMI / control', '/api/hmi/state, /control, /simulate-button, /logs', 'Read live PLC state; send start/stop/E-stop/reset; tail service logs.'],
        ['Security posture', '/api/stages/reports', 'Aggregate the vuln inventory, integrity baseline, and pipeline verdicts.'],
        ['Demo', '/api/demo/inject-attack, /injection-state', 'Trigger the simulated attack used in the live demo.'],
        ['Vendor access', '/api/vendor/*', 'Provision time-boxed vendor remote-access sessions (section 7).'],
    ], [0.16 * CONTENT_W, 0.40 * CONTENT_W, 0.44 * CONTENT_W]),
    H2('4.1  Two security facts to state precisely'),
    bullets([
        '<b>The API key is fail-closed.</b> If no key is configured, the server refuses (503) rather than running open; a wrong key gets 401. (It used to "fail open" &mdash; run unprotected if the key was empty &mdash; and that was fixed.)',
        '<b>The browser never holds the key.</b> The dashboard\'s nginx proxy injects the secret <b>X-API-Key</b> header server-side for every /api/ call, so the secret is never shipped to the browser.',
    ]),
    callout('Be honest about the architecture smell: score_service is a <b>"god object"</b> &mdash; one ~1,100-line service doing eight jobs (scoring, trends, IR, HMI control, logs, reports, demo, vendor). The code even documents the intended split into mlapi/irapi/hmiapi/demoapi. <b>Most importantly, a pure "monitoring" service should not hold PLC <i>write</i> authority</b> &mdash; in production that control path belongs in an authenticated OT-zone gateway, keeping analytics read-only. Raising this yourself shows you understand IEC 62443 zoning.', 'warn'),
]

# ============================================================ INCIDENT RESPONSE
st += [PageBreak(), H1('5.  Incident response (the playbook engine)')]
st += [
    P('When an alert is raised, the <b>playbook_engine.py</b> takes over. It matches the alert to a <b>playbook</b> (a YAML-like recipe) by category, then runs that playbook\'s steps in order. The flagship playbook is <b>pb_modbus_replay</b> for a Modbus attack.', 'body'),
    H2('5.1  Graded containment &mdash; the "do no harm" ladder'),
    P('This is the heart of OT incident response, and the project gets it right. The response is <b>graded</b>: gentle automatic steps first, and anything that touches the physical process <b>waits for a human</b>.', 'body'),
    tbl([
        ['Grade', 'Action', 'Approval', 'Why'],
        ['Watch', 'Increase logging detail; capture forensic evidence.', 'Automatic', 'Harmless; you always want the evidence.'],
        ['Isolate', 'Firewall-drop the attacker\'s IP (iptables DROP).', 'Automatic', 'Stops the attack at the network without touching the robot.'],
        ['Slow', 'Drop the robot to reduced safe speed (~25%).', '<b>Human</b>', 'Changes physical motion &mdash; needs a person.'],
        ['Stop', 'Assert the safe state / E-stop.', '<b>Human</b>', 'Halts production &mdash; only a human should decide that.'],
    ], [0.13 * CONTENT_W, 0.42 * CONTENT_W, 0.16 * CONTENT_W, 0.29 * CONTENT_W]),
    callout('This is the #1 OT-security principle: <b>availability is king</b>. You do NOT let an AI halt a live factory on a hunch &mdash; a false alarm that stops a line costs a fortune. So the automatic action ceiling is "isolate the attacker\'s IP"; the robot keeps running. Slowing or stopping the robot is queued and waits for an operator to click Approve. The project\'s playbook literally encodes this with requires_human_approval: true on the stop step.', 'why'),
    H2('5.2  How a human approval works'),
    P('When the engine hits a step needing approval, it does not run it &mdash; it writes the step into a <b>pending_approvals</b> queue and pauses that branch. The dashboard shows the pending action. An operator approves via the API (or the <b>ir-approve</b> tool), which then runs the queued command, records the result in <b>incidents.jsonl</b>, and auto-closes the incident when nothing is left pending.', 'body'),
    H2('5.3  Built-in safety against being abused'),
    bullets([
        'Values substituted into commands (like the attacker IP) are <b>shell-quoted</b>, and the source IP is checked against a strict numeric pattern &mdash; so a forged alert cannot inject shell commands.',
        'The lifecycle follows <b>NIST SP 800-61</b>: detect &rarr; analyse &rarr; contain &rarr; eradicate &rarr; recover &rarr; lessons-learned. Recovery is a deliberate operator reset, never automatic.',
        'Other playbooks exist too: one for an unauthorized SROS2 participant, one for an integrity mismatch.',
    ]),
    callout('"Containment that does not touch the physical process runs automatically; anything physical needs operator approval. Inputs used in commands are sanitised, and one attack that trips several detectors is de-duplicated into a single incident." That one sentence answers "how do you stop the IR engine being abused?"', 'say'),
]

# ============================================================ VULN MGMT
st += [PageBreak(), H1('6.  Vulnerability management (knowing what you have, and what is wrong with it)')]
st += [
    P('You cannot protect what you do not know you have. The SEC zone runs five tools that together answer: what devices exist, what known vulnerabilities they have, has anything changed, and how do we safely push a fix.', 'body'),
    tbl([
        ['Tool', 'In plain words', 'Output'],
        ['inventory.py', 'Finds every device: passively from Zeek logs, then a gentle rate-limited Nmap, then a Modbus "who are you?" query (function code 43) to fingerprint the PLC vendor/firmware.', 'inventory.json'],
        ['cve_correlate.py', 'Matches each device against an <b>offline</b> hand-curated CVE database (no internet from OT) to list known vulnerabilities.', 'vulnerabilities.json'],
        ['integrity_baseline.py', 'Takes a fingerprint (SHA-256 hashes) of the PLC programs, the SROS2 files, a Modbus snapshot, and which safety services are running.', 'integrity_baseline.json'],
        ['baseline_check.py', 'Compares the live system to the approved baseline and reports drift.', 'baseline_drift.json'],
        ['firmware_workflow.py', 'Drives a safe PLC-program update: stage &rarr; validate &rarr; schedule &rarr; backup &rarr; apply &rarr; verify &rarr; rollback, only inside a maintenance window.', 'a per-run audit trail'],
    ], [0.20 * CONTENT_W, 0.58 * CONTENT_W, 0.22 * CONTENT_W]),
    callout('Two details interviewers love: (1) the CVE feed is <b>offline</b> &mdash; a regulated OT site cannot make outbound internet calls, so it consumes a signed advisory snapshot, exactly as this does. (2) The Nmap scan is deliberately <b>rate-limited and port-restricted</b>, because a normal aggressive scan can crash fragile old PLC network stacks. "OT-safe scanning" is a real skill.', 'ex'),
    callout('Why fingerprint with Modbus function code 43 (Read Device Identification)? Because it is the <i>same</i> query a legitimate engineering tool uses &mdash; so you get a trustworthy vendor/product/firmware string with zero risk, rather than guessing from open ports.', 'note'),
]

# ============================================================ DEVSECOPS
st += [PageBreak(), H1('7.  DevSecOps: gate-checking the robot\'s own code')]
st += [
    P('Robot and PLC code <i>is</i> code, and unsafe code on a robot is a physical hazard. So every change runs through a <b>six-gate pipeline</b> before it is trusted. Treat dangerous code like luggage at an airport: it goes through scanners before it is allowed in.', 'body'),
    H2('7.1  The six gates'),
    tbl([
        ['#', 'Gate', 'What it blocks'],
        ['1', 'PLC lint (plc_lint.py)', 'Unsigned programs, motion with no E-stop guard, hard-coded passwords, writes to safety outputs from normal code, unbounded loops.'],
        ['2', 'HMI lint (hmi_lint.py)', 'Insecure settings in the operator-screen configuration.'],
        ['3', 'SROS2 lint (sros2_lint.py)', 'Robot-permission policy mistakes.'],
        ['4', 'Vulnerability gate (vuln_gate.py)', 'Any known CVE with score &ge; 7.0 that has no approved, time-boxed exception.'],
        ['5', 'Baseline gate (baseline_gate.py)', 'Any critical configuration drift &mdash; or a scan that is stale (&gt; 24&nbsp;h old).'],
        ['6', 'Acceptance gate (acceptance_gate.py)', 'A change that breaks detection or the safety loop &mdash; tested by replaying an attack against the <b>digital twin</b>.'],
    ], [16, 0.34 * (CONTENT_W - 16), 0.66 * (CONTENT_W - 16)]),
    H2('7.2  One engine, three triggers (the clean design)'),
    P('All gate logic lives in <b>one script, run_pipeline.sh</b>. Three different things can trigger it, so a check can never pass in one place and fail in another:', 'body'),
    code(
"""  (1) LOCAL      developer runs it before pushing      LAB_GATES=plc,hmi,sros2
  (2) GITEA CI   every push/PR -> Actions runs the      red/green per gate in
                 static gates (1-3) via the same engine the Gitea Actions tab
  (3) WEBHOOK    a push fires an HMAC-signed webhook  -> full in-lab pipeline,
                 (fail-closed) into the lab               signed artifact + verdict"""),
    callout('"One engine, two triggers" is the industry-standard <b>"thin CI, fat scripts"</b> pattern. Gates 4&ndash;6 need live lab data (fresh scans, a running digital twin), so they run in-lab, not on a bare CI runner. And you never replay attacks against a producing line &mdash; only the Gazebo twin. That is the availability-first mindset again.', 'why'),
    H2('7.3  What "signed artifacts" means'),
    P('When a build passes, the pipeline packs the approved code into a tarball and seals it: a <b>SHA-256 hash</b> (a fingerprint &mdash; change one byte and it changes) and a <b>GPG signature</b> (a cryptographic stamp only the build system can make). Before code is flashed to a robot, you re-check the seal &mdash; proving it is the <i>exact</i> code that passed every gate and nobody swapped it afterwards.', 'body'),
    callout('Analogy: the artifact is a sealed bottle of medicine. The hash is the tamper-evident seal (broken = someone opened it). The signature is the pharmacy\'s official stamp (proves it is genuine, not counterfeit). Together they defeat supply-chain tampering.', 'ex'),
    callout('Honest caveat to volunteer: in the shipped config the heavy acceptance gate (6) is skipped for speed (LAB_SKIP_ACCEPTANCE) and the signing key is generated at runtime with no external trust anchor. For production I would enforce every gate on deploy and sign with an HSM/KMS-backed key with verified provenance.', 'warn'),
]

# ============================================================ MONITORING + VENDOR + DASH
st += [PageBreak(), H1('8.  Monitoring, vendor access, and the dashboard')]
st += [
    H2('8.1  Prometheus + Grafana + a custom exporter'),
    P('<b>Prometheus</b> scrapes numerical metrics on a schedule; <b>Grafana</b> draws them as dashboards. A small zero-dependency <b>lab_exporter.py</b> publishes the lab-specific numbers that off-the-shelf exporters do not have:', 'body'),
    bullets([
        'anomaly alert counts, the live <b>safety state</b> (0 NORMAL / 1 DEGRADED / 2 EMERGENCY), vulnerability counts by severity,',
        'the last pipeline verdict (pass/fail) and its age, plus open incidents and pending approvals.',
    ]),
    H2('8.2  Vendor / remote access (the DMZ jump host)'),
    P('Outside vendors sometimes need to service the robot, but must never get a direct line into OT. <b>vendor_access.py</b> provisions a <b>time-boxed, audited</b> session (1&ndash;8 hours, "read-only" or "maintenance") that lands in <b>Apache Guacamole</b> &mdash; a browser-based jump host in the DMZ. Every session needs a name, email, and justification, is logged to an audit trail, and the provisioning endpoint now requires the API key.', 'body'),
    callout('"Vendors never touch OT directly. They get a brokered, time-limited, audited session through a DMZ jump host &mdash; read-only by default. It is the monitored visitor meeting room, not a key to the building."', 'say'),
    H2('8.3  The operator dashboard (7 pages)'),
    P('The React dashboard (served by nginx with TLS) is the single screen an operator uses. Its seven pages map onto everything above:', 'body'),
    tbl([
        ['Page', 'Shows'],
        ['Overview', 'Zone health, model status, the live threat score &mdash; the calm baseline.'],
        ['AI Engine', 'Model details and the attack-injection control used in the demo.'],
        ['PLC Control', 'Live coils/registers, and start/stop/E-stop/reset buttons.'],
        ['Security', 'Anomaly alerts with source IP and the top contributing features.'],
        ['Stages', 'Vulnerability inventory, CVE correlation, baseline drift, integrity, pipeline verdict.'],
        ['Vendor', 'Create and audit time-boxed vendor sessions.'],
        ['Incidents', 'Open incidents, the steps that ran automatically, and any pending approvals.'],
    ], [0.18 * CONTENT_W, 0.82 * CONTENT_W]),
    spacer(4),
    rule(),
    P('<b>End of Part 3.</b> You can now narrate the entire brain: traffic &rarr; 20 features &rarr; four ML models across two planes (network + robot motion) &rarr; alert &rarr; graded incident response, plus vulnerability management, the six-gate CI/CD pipeline, monitoring, vendor access, and the dashboard. <b>Part 4</b> turns all of this into performance: how to run it, the exact live demo, the questions you will be asked, and the honest trade-offs that win senior-level credibility.', 'body'),
]

build(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Part3-Detection-AI-Response-DevSecOps.pdf'),
      'Part 3: The Brain (Detection, AI, Response &amp; DevSecOps)', st)
print('Part 3 OK')
