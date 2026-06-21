"""
Builds future-plans.pdf — the production-readiness & product roadmap for the
Robotics Security Platform. Reuses the shared _pdfkit so it matches the look of
the interview-prep guide.

Run:  python build_future_plans.py      (writes ../future-plans.pdf)
"""
from __future__ import annotations
import os
from _pdfkit import (P, H1, H2, H3, small, spacer, bullets, code, callout,
                     tbl, rule, keep, build)

OUT = os.path.join(os.path.dirname(__file__), '..', 'future-plans.pdf')


def story():
    s = []

    # ---- cover ----
    s += [P('Future Plans', 'title'),
          P('Production-Readiness &amp; Product Roadmap for the Industrial Robotics Security Platform', 'subtitle'),
          small('Companion to the Topic-114 platform. The system today is a complete, verified teaching/reference '
                'build: a single-homed IEC-62443 Level-3.5 IDMZ, a dual-plane AI detector (Modbus + robot behavior), '
                'a GPG-signed OT deploy pipeline, and playbook-driven incident response. This document is the honest '
                'path from that to a hardened, fleet-scale product.'),
          spacer(4), rule()]

    s += [callout(['The platform is intentionally a lab today (shared API key, at-rest secrets, software safety '
                   'simulator, single host). That is appropriate for its purpose. Everything below is the gap to '
                   'production and the features that would make it a compelling commercial OT-security product — '
                   'grouped so each item is independently buildable.'], kind='note', label='HOW TO READ THIS')]

    # ============================================================== A
    s += [H1('A. Production-Hardening Roadmap'),
          P('These close the lab&rarr;production gap. They do not add features; they make the existing capabilities '
            'safe to connect to something that can move.')]

    s += [H2('A1. Identity, access &amp; trust'),
          bullets([
              '<b>Per-identity authN + RBAC</b> to replace the single shared API key; distinct operator / SOC-analyst / '
              'auditor / vendor roles with least privilege on every state-changing route.',
              '<b>mTLS between services</b> (SPIFFE/SPIRE or a service mesh) so a stolen key alone cannot impersonate a component.',
              '<b>Signed, dual-control approvals</b> for IR actions and any control intent — cryptographic, not just a UI click.',
              '<b>SSO / OIDC</b> integration for enterprise identity; full audit of who did what, when.',
          ])]

    s += [H2('A2. Secrets &amp; supply chain'),
          bullets([
              '<b>Vault / KMS / SOPS</b> for all secrets with per-service scoping and rotation; stop shipping <font face="Courier">.env</font> into containers.',
              '<b>HSM/KMS-backed signing</b> for the Stage-5 deploy key (today it is an ephemeral in-container GPG key), with '
              '<b>SLSA provenance</b> and verified build attestation, not just a detached signature.',
              '<b>Pinned dependencies + SBOM</b> (CycloneDX) and real CI scanners (Trivy, pip-audit, Grype) as blocking gates, '
              'replacing the static vulnerabilities.json.',
          ])]

    s += [H2('A3. Functional safety independence'),
          bullets([
              '<b>Hardware/logically-independent SIS</b> (IEC 61511): a real safety PLC or safety relay, not a software '
              'simulator co-located with the controller.',
              '<b>Local-only E-stop reset</b> — no network un-latch path of any kind; watchdog + latch + replay-guard in the '
              '<i>running</i> controller (the design already specifies these).',
              '<b>Hard-wired de-energize</b> path independent of the network and the analytics plane.',
          ]),
          callout('A monitoring platform must never be on the safety-critical path. The roadmap keeps detection/response '
                  'advisory to an independent SIS that can always fail the cell to a safe state on its own.', kind='why')]

    s += [H2('A4. Resilience &amp; trustworthy telemetry'),
          bullets([
              '<b>Process supervision</b> (s6 / systemd / Kubernetes) with real liveness + readiness probes per service '
              '(not just a Redis ping), and durable, audited incident state that survives restarts.',
              '<b>Central, append-only, tamper-evident log/metric store</b> shipped off-box (signed); the dashboard reads views, '
              'never the source of truth.',
              '<b>Reconnect safety telemetry across the IDMZ (Gap G-1):</b> have the OT-resident SEC sensor read the safety '
              'registers and ship state via Redis (the same pattern Modbus features already use), so the firewall stays '
              'closed and the safety panel goes live instead of reading -1.',
              '<b>Re-scope monitoring probes (Gap G-2):</b> point lab_exporter at IDMZ addresses and per-zone reachability so '
              'component tiles reflect reality.',
          ])]

    s += [H2('A5. Container &amp; edge hardening'),
          bullets([
              'Non-root users, distroless multi-stage images, read-only root filesystem, <font face="Courier">cap_drop: [ALL]</font> + only required caps.',
              'Per-zone hosts/VLANs in a real plant (the single-host Docker model is the lab compression of that); optional '
              'true data-diode on the OT&rarr;analytics path.',
              'HTTP&rarr;HTTPS everywhere, security headers, authenticated Prometheus/Grafana, tightened CORS.',
          ])]

    s += [PageBreak_()]

    # ============================================================== B
    s += [H1('B. AI Engine Upgrades'),
          P('The detector is genuinely good (dual-plane, anti-drift feature module, live-calibrated thresholds). These '
            'upgrades make it more accurate, self-maintaining, and explainable.')]

    s += [H2('B1. Train on real data, end the train/serve skew permanently'),
          bullets([
              'Capture a <b>clean live baseline</b> (real Zeek Modbus features + real Gazebo /joint_states) and train "normal" '
              'on it; keep synthetic data only for <b>labeled attacks / AUC evaluation</b> (you cannot safely harvest real attacks).',
              'This retires the recalibration band-aid: the model learns the real pipeline shape (multi-row, bursty) out of the box.',
          ]),
          callout('We already hit and fixed this: synthetic-only calibration made the autoencoders flag normal traffic. '
                  'Training "normal" on real capture is the permanent fix and matches the project&apos;s "real dataset" direction.', kind='warn')]

    s += [H2('B2. Self-maintaining models'),
          bullets([
              '<b>Drift monitoring + guarded auto-recalibration</b>: detect distribution shift, recalibrate within bounds, alert when out of bounds.',
              '<b>Model registry + versioning</b> with shadow / A-B scoring and signed model artifacts pulled the same way PLC code is.',
              '<b>Online / incremental learning</b> for slow legitimate process changes, with human sign-off before promotion.',
          ])]

    s += [H2('B3. Broader &amp; deeper detection'),
          bullets([
              '<b>More protocol planes:</b> DNP3 and OPC-UA detectors (Zeek already parses them) alongside Modbus.',
              '<b>Process-physics / multivariate models:</b> cross-signal correlation (current vs torque vs position) to catch '
              'stealthy cyber-physical attacks that look normal per-signal.',
              '<b>Sequence/transformer temporal models</b> for multi-step attack patterns; few-shot adaptation for new robot types.',
              '<b>Adversarial robustness</b> against evasion; expand the attack simulator and map every attack to <b>MITRE ATT&amp;CK for ICS</b>.',
          ])]

    s += [H2('B4. Explainability'),
          bullets([
              'Surface <b>feature attributions (SHAP)</b> per alert in the UI (today we expose top-features — make it first-class with packet drill-down).',
              '<b>Natural-language alert summaries</b> ("FC6 write burst from a non-OT source at 7x baseline rate") for operators.',
              '<b>Federated / fleet learning</b> across plants (privacy-preserving) for rare-attack generalization.',
          ])]

    s += [PageBreak_()]

    # ============================================================== C
    s += [H1('C. Dashboard Improvements'),
          P('The operator UI is the product&apos;s face. These raise it from a solid lab dashboard to a SOC-grade console.')]

    s += [H2('C1. Real-time &amp; robustness'),
          bullets([
              '<b>WebSocket / SSE push</b> instead of 5s polling — instant updates, less load.',
              '<b>Keep-last-value on a metric miss</b> (the trend panel already does this) so a momentary gap never blanks a tile.',
              '<b>Live IDMZ topology map</b> showing zones, the 8 conduits, and pass/fail of the segmentation matrix in real time.',
          ])]

    s += [H2('C2. Investigation &amp; response'),
          bullets([
              '<b>Incident timeline / case management</b> with a kill-chain view and MITRE ATT&amp;CK for ICS overlay.',
              '<b>Drill-down:</b> anomaly &rarr; feature contributions &rarr; raw Zeek records / pcap.',
              '<b>SOAR-grade IR:</b> richer playbooks, case notes, and integrations (email / Slack / PagerDuty / SIEM / syslog / Splunk).',
          ])]

    s += [H2('C3. Roles, compliance &amp; reporting'),
          bullets([
              '<b>Role-based views</b> (operator vs SOC analyst vs auditor) + responsive/mobile + dark mode.',
              '<b>Compliance dashboard:</b> live IEC-62443 / NIST 800-82 control mapping with one-click evidence export (PDF).',
              '<b>Ops analytics:</b> MTTD/MTTR, SLA tracking, anomaly heatmaps, historical trend explorer.',
          ])]

    # ============================================================== D
    s += [H1('D. New Features (make it more impressive)'),
          bullets([
              '<b>Digital twin &amp; what-if simulation</b> — replay attacks against a twin to validate detections and train operators safely.',
              '<b>Fleet / multi-cell scale</b> — many robots/plants, central SOC (the hybrid-cloud target), per-site policy.',
              '<b>Multi-protocol OT</b> — EtherNet/IP, PROFINET, S7comm, BACnet beyond Modbus/ROS2.',
              '<b>Zero-trust OT</b> — per-message authenticated control through the gateway; continuous device authentication/posture.',
              '<b>Threat-intel integration</b> — CVE / ICS-CERT advisory feeds auto-correlated with the asset inventory.',
              '<b>Continuous purple-team (BAS for OT)</b> — scheduled, safe attack simulation that proves detections still work.',
              '<b>OT deception</b> — honeypot PLC/robot decoys in a sacrificial segment to catch lateral movement early.',
              '<b>Compliance automation expansion</b> — NERC CIP / NIST 800-82 / ISA-62443 evidence generation and gap reports.',
          ])]

    # ============================================================== roadmap
    s += [PageBreak_(), H1('E. Prioritized Roadmap'),
          P('A pragmatic sequencing by impact vs effort. "Now" items are the credibility-critical hardening; "Next" '
            'makes it self-maintaining and SOC-usable; "Later" is the differentiated product surface.')]

    s += [tbl([
        ['Horizon', 'Theme', 'Headline items', 'Why now'],
        ['<b>Now</b>', 'Safety + trust', 'Independent SIS &amp; local-only reset; reconnect safety telemetry (G-1); fail-closed per-identity auth; secrets in a vault', 'Disqualifying for any live cell until done'],
        ['<b>Now</b>', 'Supply chain', 'HSM-backed signing + SLSA provenance; SBOM + real scanners as CI gates', 'Makes the signed-deploy story production-true'],
        ['<b>Next</b>', 'AI', 'Train normal on real capture; drift monitor + model registry; DNP3/OPC-UA planes', 'Ends train/serve skew; broadens coverage'],
        ['<b>Next</b>', 'Dashboard', 'WebSocket push; incident/case mgmt + ATT&amp;CK-ICS; live IDMZ map; SIEM/Slack integrations', 'Turns the UI into a SOC console'],
        ['<b>Next</b>', 'Resilience', 'Process supervision; durable audited state; central tamper-evident log store', 'Survives restarts; trustworthy evidence'],
        ['<b>Later</b>', 'Scale', 'Fleet / multi-cell + hybrid-cloud SOC; multi-protocol OT', 'Multi-plant product'],
        ['<b>Later</b>', 'Differentiators', 'Digital twin; zero-trust OT; OT deception; continuous purple-team', 'Stand-out capabilities'],
    ], col_widths=[55, 80, 250, 125])]

    s += [spacer(8), rule(),
          small('Generated as the forward-looking companion to REQUIREMENTS-COMPLIANCE-AUDIT.md and '
                'ARCHITECTURE-DIAGRAMS.md. Each item is scoped to be independently buildable on the current IDMZ base.')]
    return s


# PageBreak helper (kept local so _pdfkit stays minimal)
def PageBreak_():
    from reportlab.platypus import PageBreak
    return PageBreak()


if __name__ == '__main__':
    out = build(OUT, 'Future Plans', story())
    print('wrote', os.path.abspath(out))
