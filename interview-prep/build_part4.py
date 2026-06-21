# -*- coding: utf-8 -*-
"""Part 4 — Demo Runbook, Q&A, Trade-offs & Cheat-Sheets."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _pdfkit import (P, H1, H2, H3, small, spacer, bullets, code, callout, tbl,
                     rule, keep, build, CONTENT_W, PageBreak)

st = []

# ============================================================ COVER
st += [
    P('Robotics Security Platform', 'title'),
    P('Interview Preparation &mdash; Part 4 of 4: Demo Runbook, Q&amp;A &amp; Cheat-Sheets', 'subtitle'),
    rule(),
    P('Parts 1&ndash;3 gave you the knowledge. This part turns it into a performance: how to start the system, the exact live demo to run (and what to say at each step), the CI/CD gate demo, the questions you will almost certainly be asked, the honest trade-offs that earn senior-level credibility, and one-page cheat-sheets to skim minutes before you walk in.', 'body'),
    callout('Golden rule of demoing: <b>rehearse the whole thing the morning of the interview.</b> Never show anything live that you have not run that day. And always have the offline backup (the local lint command in section 3) ready in case the runner misbehaves.', 'why'),
]

# ============================================================ RUN IT
st += [PageBreak(), H1('1.  How to run the platform')]
st += [
    code(
"""# 1. Secrets live in .env (already set). If starting fresh:
cp .env.example .env            # then fill in values

# 2. Build and start the whole stack
docker compose up -d --build

# 3. (No host firewall step.) The router-fw container IS the firewall: it comes up
#    with the stack, enables ip_forward, and loads the default-deny nftables conduits.
#    Verify segmentation any time:
python infra/tests/stage1_connectivity_matrix_docker.py   # expect 16/16 all-green

# 4. Watch the AI container come up (first boot trains the 4 models: 3 network + robot LSTM, ~3-6 min)
docker logs -f container-ai     # wait for "operational"; status should be (healthy)"""),
    H2('1.2  Where to click (access points)'),
    tbl([
        ['What', 'URL', 'Login'],
        ['Operations Dashboard (start here)', 'http://localhost:8888 (or https://localhost:8443)', 'none (key injected by nginx)'],
        ['Grafana threat dashboards', 'http://localhost:3003', 'admin / GRAFANA_PASSWORD from .env'],
        ['Prometheus', 'http://localhost:9090', 'none'],
        ['ntopng (network flows)', 'http://localhost:3001', 'none'],
        ['Gitea (CI/CD repo)', 'http://localhost:3000', 'set on first run'],
        ['Guacamole (vendor jump host)', 'http://localhost:8081', 'guacadmin / guacadmin'],
        ['OpenPLC web UI', 'http://localhost:8080', 'openplc / openplc'],
    ], [0.34 * CONTENT_W, 0.42 * CONTENT_W, 0.24 * CONTENT_W]),
    callout('After hardening, Modbus (502/503) and the raw API/webhook (8000/9000) are bound to <b>127.0.0.1</b> only &mdash; reachable from the host for the demo, never from the wider network. The browser UIs above still work normally.', 'note'),
]

# ============================================================ LIVE DEMO
st += [PageBreak(), H1('2.  The live demo (the money shot, ~5 minutes)')]
st += [
    P('This tells the full story: calm &rarr; attack &rarr; detect &rarr; respond &rarr; human-approved stop &rarr; deliberate recovery. Run it from the dashboard at localhost:8888.', 'body'),
    H3('Step 1 &mdash; Show the calm baseline (Overview page)'),
    P('Point out green zone health, all four models loaded (three network + the robot LSTM), a low flat threat score.', 'body'),
    callout('"Everything is green. Four ML models are loaded &mdash; three watch the network traffic, a fourth watches the robot\'s motion &mdash; and the robot is cycling normally."', 'say'),
    H3('Step 2 &mdash; Show the real physical process (PLC Control page)'),
    P('Show live coils/registers (cycle running, conveyor, gripper) read straight from the PLC over Modbus.', 'body'),
    callout('"This is live telemetry polled from the OpenPLC controller &mdash; the actual state of the cell."', 'say'),
    H3('Step 3 &mdash; Launch the attack (AI Engine / Overview)'),
    P('Trigger the built-in attack injection (a Modbus command-injection / write-burst from an IP outside the OT zone).', 'body'),
    callout('"I am injecting a Modbus command-injection &mdash; a flood of register writes from outside the OT zone, the classic cyber-physical attack pattern."', 'say'),
    H3('Step 4 &mdash; Watch detection (Security page)'),
    P('The threat sparkline spikes within a few seconds; a new anomaly alert appears with the offending source IP and the top contributing features.', 'body'),
    callout('"The feature pipeline windowed the traffic, all three models scored it anomalous, and the alert bridge raised it &mdash; sub-5-second detection."', 'say'),
    H3('Step 5 &mdash; Watch automated response (Incidents page)'),
    P('An incident is open; automatic steps already ran (forensics capture, isolate the attacker IP with a firewall rule). A pending approval waits for the safety step.', 'body'),
    callout('"The playbook engine opened an incident and ran the no-approval containment automatically. The step that changes the physical process &mdash; asserting a safe state &mdash; waits for me."', 'say'),
    H3('Step 6 &mdash; Approve the safe-state / E-stop'),
    P('Approve the pending step. On PLC Control you will see e_stop_active set and safety_state = EMERGENCY (latched).', 'body'),
    callout('"I approve the safe-state. The E-stop is asserted on the production PLC and the safety system latches EMERGENCY &mdash; safety always wins."', 'say'),
    H3('Step 7 &mdash; Recover deliberately'),
    P('After "investigating", issue Reset on PLC Control. The cell returns to NORMAL and resumes.', 'body'),
    callout('"Recovery is a deliberate operator action, never automatic &mdash; correct functional-safety behaviour. Continuity restored."', 'say'),
    H3('Step 7b &mdash; Show the second detection plane (a robot-behavior attack)'),
    P('On the AI Engine page, point at the fourth gauge (<b>Robot LSTM AE</b>), then inject a robot-plane attack from the grouped dropdown (e.g. <b>Joint Speed Violation</b> or <b>Frozen Joint</b>).', 'body'),
    callout('"The first attack was on the network. But an attacker who already controls the PLC can move the robot with legitimate-looking commands &mdash; so a fourth model watches the robot\'s <i>motion</i>. It is a passive tap on the live joint stream, exactly like Zeek on the network."', 'say'),
    P('The Robot LSTM gauge jumps from NOMINAL to ANOMALOUS, a robot-behavior-anomaly alert appears, and it opens its own incident whose containment ladder also ends in a latched E-stop.', 'body'),
    callout('"The LSTM autoencoder learned the normal pick-and-place motion, so a tampered trajectory does not reconstruct; the physical-envelope layer names the joint that broke its speed limit. Two layers, one explainable verdict &mdash; and the same response loop down to E-stop."', 'say'),
    H3('Step 8 (optional) &mdash; Show the breadth'),
    bullets([
        '<b>Stages</b> page: vulnerability inventory, CVE correlation, baseline drift, integrity, pipeline verdict.',
        '<b>Vendor</b> page: create a time-boxed vendor session and show the Guacamole link plus the audit log.',
        '<b>Grafana</b>: the same telemetry in operational dashboards.',
    ]),
]

# ============================================================ CI/CD DEMO
st += [PageBreak(), H1('3.  The CI/CD gate demo (catch a vulnerability live)')]
st += [
    P('This proves the DevSecOps story: push unsafe PLC code and the build goes <b>red</b>; push the safe version and it goes <b>green</b>.', 'body'),
    code(
"""# RED: introduce the vulnerable program and push -> build fails on Gate 1
cp demos/cicd-gate/demo_jog.VULNERABLE.st vm-ot/openplc/demo_jog.st
git add vm-ot/openplc/demo_jog.st
git commit -m "Add manual jog routine"
git push gitea main          # Gitea Actions tab: red X on "Gate 1 - PLC lint"

# GREEN: ship the hardened version -> build passes
cp demos/cicd-gate/demo_jog.CLEAN.st vm-ot/openplc/demo_jog.st
git add vm-ot/openplc/demo_jog.st
git commit -m "Harden jog routine: E-stop guard, no creds, bounded loop, signed"
git push gitea main          # green check"""),
    H3('The offline backup (always works, no runner needed)'),
    code(
"""python3 vm-ai/devsecops/plc_lint.py demos/cicd-gate/demo_jog.VULNERABLE.st  # exit 1, 7 findings
python3 vm-ai/devsecops/plc_lint.py demos/cicd-gate/demo_jog.CLEAN.st       # exit 0, clean"""),
    callout('"PLC logic is code, and unsafe code on a robot is a hazard. Every push runs a deterministic gate that blocks unsigned programs, motion paths with no emergency-stop guard, hard-coded credentials, writes to safety outputs from non-safety code, and unbounded loops. Here is a commit it rejected, and the same feature written safely that it accepts &mdash; and the Actions step and the in-lab webhook both run the same engine, so a check can never pass in CI yet fail in the plant."', 'say'),
    callout('The vulnerable file fails with <b>7 findings</b>: unsigned program, motion block with no E-stop guard, hard-coded \'admin\', two safety-output writes outside a SAFETY_ block, an unbounded FOR loop, and a commented-out safety check. Knowing the exact count and reasons makes the demo look effortless.', 'note'),
]

# ============================================================ QA
st += [PageBreak(), H1('4.  Likely interview questions (with crisp answers)')]

def qa(q, a):
    return keep([H3(q), P(a, 'body')])

st += [
    qa('Why three ML models on the network plane instead of one?',
       'They are complementary. Isolation Forest cheaply catches rare feature <i>combinations</i>; the PCA autoencoder catches windows that do not fit the normal data shape; the TensorFlow autoencoder catches subtler non-linear patterns. If any one crosses its calibrated threshold, we alert &mdash; better recall, no single blind spot.'),
    qa('Does anything watch the robot itself, not just the network?',
       'Yes &mdash; a second detection plane. A passive tap mirrors the live /lab_arm/joint_states stream (just as Zeek mirrors the network) and a fourth model scores the robot\'s <i>motion</i>: an LSTM autoencoder that learned the normal pick-and-place trajectory, plus a deterministic physical-envelope layer (joint speed, range, jerk, frozen-joint). It catches an attacker who already controls the PLC and moves the robot with legitimate-looking commands, and it raises the same kind of incident &mdash; ending in a latched E-stop. ROC-AUC is ~0.99 on held-out behavioral attacks.'),
    qa('How do you stop the models drifting from what runs live?',
       'One shared, versioned feature module computes the features for <i>both</i> training and live scoring, so the two cannot diverge; the sensors emit only raw values (the joint tap emits raw angles &mdash; velocities are derived in that one place). A contract test asserts the live windows are byte-for-byte identical to the training windows, and the feature version is recorded in the model metadata and surfaced by the API.'),
    qa('Why anomaly detection rather than signatures?',
       'OT attacks often "live off the land" using legitimate protocol commands, so there is no signature to match. A model of <i>normal</i> flags malicious-but-novel behaviour &mdash; for example a register that is normally only read suddenly being written from outside the OT zone.'),
    qa('How do you avoid false positives?',
       'Train on pure normal traffic only; calibrate thresholds to the 99th percentile; score 5-second windows, not single packets; require two consecutive anomalous windows; and apply a per-source cooldown. Multiple detectors tripping on one attack fold into a single incident.'),
    qa('How is the OT zone isolated?',
       'Every service is single-homed on one zone, and a default-deny nftables router is the only node that crosses zones &mdash; through eight explicit conduits. IT-to-OT matches no conduit on any path; the analytics zone is network-enforced read-only (it reaches a read-only Modbus proxy, never raw PLC:502); and OT only meets IT through the DMZ. An automated matrix verifies all eight conduits plus key denials (16 checks, all green). That is the IEC-62443 zones-and-conduits model enforced at L3.'),
    qa('What is the single most important control?',
       'The internal OT network plus the latched, watchdog-backed safety system. Segmentation keeps attackers out; the safety system guarantees the robot fails safe regardless of what the attacker or even the AI does.'),
    qa('How fast is detection?',
       'Sub-5-second in the demo &mdash; windowed scoring plus the alert bridge.'),
    qa('Where does the AI run &mdash; cloud or edge?',
       'At the edge, on-prem, beside the plant, so detection and the safety loop keep working even with no internet. An optional cloud tier only ever receives one-way derived telemetry and sends back signed models/threat-intel; it can never command the plant.'),
    qa('How do you stop the incident-response engine being abused?',
       'Containment that does not touch the physical process runs automatically; anything physical needs operator approval. Command inputs are shell-quoted and IP-validated, and duplicate detections fold into one campaign.'),
    qa('Authentication vs authorization on ROS2?',
       'DDS-Security enforces authentication &mdash; every participant must present a CA-signed certificate. Topic-level ACLs are at the permissive default because enforcing the signed permissions hung Cyclone DDS discovery; enforcing them is documented future work.'),
    qa('What protects the safety system specifically?',
       'An independent supervisor with a heartbeat watchdog and a latched E-stop; the safety topics travel over SROS2 with certificate auth; and clearing the safe state is always a deliberate human action.'),
    qa('Why custom Python linters instead of SonarQube / C-STAT / sanitizers?',
       'Those tools scan general application code (mostly C/C++/Java) and cannot read PLC Structured Text, HMI JSON, or SROS2 XML &mdash; and they do not know OT safety rules like "motion needs an E-stop guard." They are complementary: in production I would add SonarQube for the dashboard/Python and a certified PLC tool, plugged in as extra gates in the same one-engine pipeline.'),
    qa('What would you improve for production? (the maturity question)',
       'The rearchitecture already closed the big ones &mdash; single-homed zones with a default-deny router, network-enforced read-only analytics, and a GPG-signed pull-deploy. What is left (section 5): an independent hardware SIS with local-only reset, per-identity auth + RBAC + mTLS and a secrets vault, HSM-backed signing with SLSA provenance, append-only tamper-evident telemetry, and reconnecting the safety telemetry across the IDMZ.'),
]

# ============================================================ TRADE-OFFS
st += [PageBreak(), H1('5.  Honest trade-offs (raise these yourself &mdash; it wins points)')]
st += [
    P('Interviewers reward candidates who know the limits of their own design. Frame it as: <b>"This is a faithful teaching/POC build of the full OT-security story; the gap to production is about safety independence, trust boundaries, and honest telemetry &mdash; not about the concepts."</b>', 'body'),
    tbl([
        ['Area', 'Today (this build)', 'What I would do for production'],
        ['Safety controller', '<b>Gap:</b> software supervisor co-located in OT (network-unreachable from outside OT, but not independent).', 'A physically independent Safety Instrumented System (IEC 61511) with a hard-wired, local-only reset and no network un-latch path.'],
        ['Zoning', '<b>Done:</b> single-homed zones + default-deny router (8 conduits); one router is the only multi-homed node.', 'One host/VLAN per zone (the single host compresses that), optionally a one-way gateway / data diode into analytics.'],
        ['Analytics tier', '<b>Done:</b> network-enforced read-only to OT &mdash; reads via a read-only proxy, control via an authenticated OT gateway; no raw PLC write path.', 'Add mTLS + per-identity authZ on the control gateway; signed control intents.'],
        ['AuthN/Z', 'Single shared API key.', 'Per-identity authentication, RBAC, mTLS between services, signed approvals.'],
        ['SROS2', 'Authentication enforced; topic ACLs at permissive default.', 'Enforce per-topic ACLs once the Cyclone DDS discovery issue is resolved.'],
        ['CI/CD', 'Acceptance gate skipped in shipped config; runtime signing key.', 'Enforce all gates on deploy; sign with an HSM/KMS-backed key; verify provenance (SLSA).'],
        ['Telemetry', 'Some synthetic/self-resetting demo telemetry; state cleared on boot.', 'Append-only, tamper-evident telemetry shipped off-box; preserve audit/forensics.'],
        ['Secrets', 'At-rest .env mounted into containers.', 'A vault/KMS or orchestrator secrets, scoped per service, rotated.'],
    ], [0.16 * CONTENT_W, 0.40 * CONTENT_W, 0.44 * CONTENT_W]),
    callout('Even stronger: the project ran its own security audit, and the rearchitecture then <b>closed the critical findings</b> &mdash; the monitoring zone no longer has PLC-write authority (now read-only via proxy/gateway), the multi-homed segmentation bypass is gone (single-homed + default-deny router), and deploys are GPG-signed and verified on pull. Being able to say "I audited my own system, fixed the criticals, and here is the honest remaining roadmap" is one of the strongest things you can demonstrate.', 'why'),
]

# ============================================================ MICROSEGMENTATION
st += [PageBreak(), H1('6.  Deep-dive: segmentation vs microsegmentation (the honest answer)')]
st += [
    P('This is a favourite interview probe, because the requirement brief &mdash; and some of our own diagrams &mdash; use the word "microsegmentation". The precise, honest answer turns a potential "gotcha" into a credibility win. Read this whole section out loud once; it is written to be spoken.', 'body'),
    H2('6.1  The one-paragraph answer to recite'),
    callout('"Today the platform implements an IEC-62443 Level-3.5 IDMZ with <b>default-deny zone segmentation</b>: every service is single-homed on one zone, and a single nftables router &mdash; the only multi-homed node &mdash; permits just eight explicit source&rarr;destination:port conduits between zones. That is already a real default-deny <i>cross-zone</i> firewall, not just coarse rules. <b>True microsegmentation</b> goes one level finer &mdash; default-deny between <i>individual workloads</i>, including <i>east-west within</i> a zone, so each service reaches only the specific peers and ports it needs. To get there I would decompose each broad zone bridge into small per-flow networks (two services that should not talk share no network), and for production move to label-based, default-deny network policies on a CNI like Cilium or Calico with identity-based mTLS between services."', 'say'),
    H2('6.2  What we have today vs what microsegmentation adds'),
    P('<b>What we have (single-homed zones + default-deny cross-zone router):</b>', 'body'),
    bullets([
        'Four zone networks (OT .10, IT .20, DMZ .30, MGMT .40); <b>every container is single-homed</b> on exactly one, and the router-fw is the only multi-homed node.',
        'The router runs nftables with a <b>default-deny forward policy</b> and exactly <b>eight allowed conduits</b> &mdash; this is real default-deny <i>between</i> zones, verified by a 16-probe matrix.',
        '<b>Within a single zone, containers can still reach each other freely</b> &mdash; a Docker bridge allows east-west traffic by default. That intra-zone freedom is the remaining macro&rarr;micro gap.',
        'The analytics zone is already <b>read-only to OT</b> at the network layer (proxy for reads, gateway for control), so the most dangerous cross-zone flow is mediated, not open.',
    ]),
    P('<b>What microsegmentation adds:</b> a <b>default-deny</b> posture where every individual flow (source &rarr; destination &rarr; port &rarr; protocol) must be explicitly allowed &mdash; including <i>east-west</i> traffic <i>within</i> a zone, not just between zones.', 'body'),
    callout('Zone segmentation is a building with a few locked floors &mdash; once you are on a floor you can walk into any room. Microsegmentation gives <b>every room its own lock</b>, and your keycard opens only the rooms your job needs. Default is locked; access is granted one door at a time.', 'ex'),
    code(
"""TODAY  (zone segmentation)               GOAL  (microsegmentation)
+-----------------------------+          +------------------------------+
|  OT ZONE                    |          |  OT ZONE                     |
|  PLC <--> safety            |          |  PLC --heartbeat--> safety   |
|   ^   \\   /   ^  everyone   |          |  PLC --:502------->  HMI     |
|   |    \\ /    |  in the     |          |  sec <--mirror----  (in only)|
|  sec    robot   zone can    |          |  every other flow:  DENIED   |
|  (reach all peers & ports)  |          |  (default-deny east-west)    |
+-----------------------------+          +------------------------------+"""),
    H2('6.3  What you would change to implement it'),
    H3('Tier 1 &mdash; POC-safe (keeps the demo working, pure Docker Compose)'),
    P('Replace the few big zone networks with <b>many tiny purpose-built networks</b> &mdash; one per allowed conversation &mdash; and attach each container only to the networks it truly needs. Two containers that share no network <b>cannot reach each other</b>, so default-deny emerges by construction (and it also fixes the multi-homing weakness).', 'body'),
    tbl([
        ['Tiny network', 'Members', 'Why it exists'],
        ['net-span', 'OT &rarr; sec', 'the read-only traffic mirror'],
        ['net-hb', 'production &rarr; safety :503', 'the safety heartbeat only'],
        ['net-modbus', 'HMI/score &rarr; PLC :502', 'operator control only'],
        ['net-redis', 'sec pusher + ai consumer', 'the detection bus only'],
        ['net-scrape', 'Prometheus &rarr; each target', 'monitoring only'],
        ['net-ci', 'gitea + runner + webhook', 'CI/CD only'],
        ['net-ops', 'dashboard &rarr; score API', 'the operator UI only'],
    ], [0.20 * CONTENT_W, 0.42 * CONTENT_W, 0.38 * CONTENT_W]),
    bullets([
        'Mark every network that does not need the internet <b>internal: true</b>.',
        'Where a network must hold three or more members, disable free chatter with the bridge option <b>com.docker.network.bridge.enable_icc: "false"</b>.',
        'Cross-zone flows are <b>already</b> default-deny on the router-fw (nftables, 8 conduits); the new step is to extend that default-deny posture <b>inside</b> each zone via the per-flow networks above.',
        'Single-homing is already done at the zone level (only router-fw is multi-homed); the per-flow networks take it one level finer (per workload).',
    ]),
    callout('Gotcha to mention before they ask: several components <b>hard-code zone IPs</b> (for example the Redis host 192.168.40.30, the safety host 192.168.10.11, and the production PLC IP in score_service.py). If you re-cut the networks, switch these to Docker <b>service-name DNS</b> (e.g. container-ai) or re-pin them &mdash; miss this and the demo breaks silently.', 'warn'),
    H3('Tier 2 &mdash; the production answer (policy- and identity-based)'),
    bullets([
        'Move to Kubernetes with a policy-capable CNI (<b>Cilium</b> or <b>Calico</b>): write <b>default-deny NetworkPolicy</b> plus explicit allow-rules per workload <i>label</i>, not per IP. Cilium can even enforce <b>L7 / Modbus-aware</b> policy (e.g. allow reads, deny writes).',
        '<b>Identity over IP:</b> give each service a certificate (mTLS / service mesh) so policy follows the workload identity, not a fragile address.',
        'Add a <b>one-way gateway / data diode</b> from OT and SEC into the analytics tier, so the monitoring plane physically cannot send control back.',
    ]),
    H2('6.4  If they push: "but your brief / diagram says microsegmentation"'),
    P('Answer honestly and precisely: <b>"The zone networks are the foundation for microsegmentation, and the brief lists it as a goal. What is enforced today is zone-level; true per-workload microsegmentation is the next step, and I can describe exactly how I would implement it."</b> Then give 6.3. Owning the distinction is far stronger than over-claiming &mdash; interviewers test whether you know the difference.', 'body'),
]

# ============================================================ STANDARDS + TRACE
st += [PageBreak(), H1('7.  Standards, requirements mapping &amp; presentation order')]
st += [
    H2('7.1  Standards you are aligned to'),
    tbl([
        ['Standard', 'What it covers', 'Where it shows up here'],
        ['IEC 62443 / ISA-62443', 'Industrial control-system security; zones and conduits; SIS security', 'The whole zone architecture, the DMZ broker, the safety system.'],
        ['NIST SP 800-82', 'Guide to OT security', 'Segmentation, passive monitoring, OT-safe scanning.'],
        ['NIST SP 800-61', 'Incident-response lifecycle', 'The playbook phases: detect, analyse, contain, eradicate, recover, lessons-learned.'],
    ], [0.22 * CONTENT_W, 0.34 * CONTENT_W, 0.44 * CONTENT_W]),
    H2('7.2  Requirements-to-feature traceability (Topic 114)'),
    tbl([
        ['Requirement', 'Delivered by'],
        ['OT/IT convergence, DMZ, microsegmentation', 'Single-homed zones + default-deny nftables router (8 conduits, matrix 16/16), analytics read-only to OT, Guacamole DMZ jump host.'],
        ['Secure remote / vendor access', 'vendor_access.py + Guacamole, time-boxed audited sessions.'],
        ['Traffic &amp; protocol monitoring', 'Zeek + Suricata + ntopng with Modbus/DNP3/OPC-UA parsers.'],
        ['ML anomaly detection + predictive analytics', 'Network plane: Isolation Forest + PCA + TF autoencoder over 5s Modbus windows. Robot plane: LSTM autoencoder + physical envelope over joint-motion windows.'],
        ['Automated response + safety integration', 'Playbook engine + authenticated E-stop, graded containment.'],
        ['Safety controls / SIS', 'Safety supervisor + bridge + heartbeat, latched E-stop, SROS2.'],
        ['IEC 62443 automation + integrity', 'Baseline + integrity checks, governance, the CI gates.'],
        ['Vulnerability management', 'Nmap inventory, Modbus device-ID, offline CVE correlation, firmware workflow.'],
        ['DevSecOps for ICS', 'Six-gate pipeline + GPG-signed pull-deploy (Stage 5): OT verifies the signature before loading; tampered code rejected.'],
        ['Incident response &amp; recovery + forensics', 'Playbooks, approvals, forensics capture, continuity-first recovery.'],
    ], [0.42 * CONTENT_W, 0.58 * CONTENT_W]),
    H2('7.3  Suggested presentation order (~6 minutes)'),
    bullets([
        '<b>1. System architecture</b> (~90s) &mdash; the pieces and how they talk.',
        '<b>2. Network segmentation</b> (~60s) &mdash; how they are isolated.',
        '<b>3. Detection &rarr; response flow</b> (~90s) &mdash; what happens during an attack (run the live demo here).',
        '<b>4. Security architecture</b> (~60s) &mdash; the defence-in-depth layers.',
        '<b>5. Safety &amp; control loop</b> (~60s) &mdash; how the robot fails safe.',
        'Then invite questions and lean on sections 4 and 5 above.',
    ]),
]

# ============================================================ CHEAT SHEET + GLOSSARY
st += [PageBreak(), H1('8.  One-page cheat-sheets')]
st += [
    H2('8.1  Key numbers'),
    tbl([
        ['Thing', 'Value'],
        ['Zones / subnets', 'OT 192.168.10 &middot; IT .20 &middot; DMZ .30 &middot; MGMT .40'],
        ['Containers', '10 (3 custom-built, 7 stock images)'],
        ['Modbus ports', '502 production PLC &middot; 503 safety supervisor'],
        ['ML models', 'Network: Isolation Forest &middot; PCA AE &middot; TensorFlow AE. Robot: LSTM AE + physical envelope'],
        ['Feature window', '5-second tumbling, keyed by source IP, 20 features'],
        ['False-positive brakes', '99th-percentile threshold &middot; 2-window debounce &middot; ~45s cooldown'],
        ['Safety loop', '5 Hz heartbeat &middot; ~2-second watchdog &middot; latched EMERGENCY'],
        ['Detection bus', 'Redis: features.raw &rarr; consumer &rarr; anomaly.events &rarr; bridge'],
        ['CI/CD gates', '6 (PLC / HMI / SROS2 lint, vuln, baseline, acceptance)'],
        ['Standards', 'IEC 62443 &middot; NIST SP 800-82 &middot; NIST SP 800-61'],
    ], [0.34 * CONTENT_W, 0.66 * CONTENT_W]),
    H2('8.2  Mini-glossary (one line each)'),
    tbl([
        ['Term', 'Plain meaning'],
        ['PLC', 'Rugged industrial computer that directly controls machines.'],
        ['Structured Text', 'The IEC 61131-3 language the PLC program is written in.'],
        ['Modbus', 'Simple, unauthenticated protocol to read/write PLC registers and coils.'],
        ['ROS2 / DDS', 'Modern robot software framework and its messaging transport.'],
        ['SROS2', 'The certificate-based security layer for ROS2 messaging.'],
        ['HMI / SCADA', 'The operator screen / the wider plant-supervision system.'],
        ['SIS / E-stop', 'Independent safety guardian / the emergency-stop function (latched).'],
        ['Purdue model', 'The standard way to split a factory network into trust zones.'],
        ['DMZ', 'Buffer network where OT and IT meet only through brokered services.'],
        ['IDS', 'Intrusion-detection system; here, passive (listens to a mirror only).'],
        ['Anomaly detection', 'Learn normal, flag the different &mdash; catches novel attacks.'],
        ['Signed artifact', 'A build sealed with a hash + signature to prove it is genuine and untampered.'],
        ['Digital twin', 'A safe simulated copy (Gazebo) you can attack instead of the real line.'],
    ], [0.20 * CONTENT_W, 0.80 * CONTENT_W]),
    spacer(6),
    rule(),
    P('<b>End of Part 4 &mdash; and the guide.</b> You now have the knowledge (Parts 1&ndash;3) and the performance (Part 4): the pitch, the demo, the answers, and the honest trade-offs. Read Part 1 for the mental model, skim these cheat-sheets right before you walk in, and let the live demo tell the story. Good luck &mdash; you have got this.', 'body'),
]

build(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Part4-Demo-QA-and-Cheat-Sheets.pdf'),
      'Part 4: Demo, Q&amp;A &amp; Cheat-Sheets', st)
print('Part 4 OK')
