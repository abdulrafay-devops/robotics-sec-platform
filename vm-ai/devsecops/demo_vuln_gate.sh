#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Stage 4/5 demo — vulnerability gate: block, then risk-accept.
#
# Shows the live "found -> blocked -> documented risk acceptance -> allowed"
# loop using the REAL gate engine (run_pipeline.sh, LAB_GATES=vuln), so the
# dashboard's Stage 5 verdict (FAIL/PASS) updates exactly as it would in CI.
#
#   demo_vuln_gate.sh fail    # remove exceptions -> gate FAILs   (dashboard red)
#   demo_vuln_gate.sh fix     # add documented exceptions -> PASS (dashboard green)
#   demo_vuln_gate.sh reset   # remove the demo exceptions (back to baseline)
#   demo_vuln_gate.sh         # run the whole fail -> fix story end to end
#
# The two findings come straight from the live scan (vulnerabilities.json):
#   CVE-2021-31229  9.1  OpenPLC Runtime v3 web RCE
#   CVE-2024-23653  7.2  pymodbus 2.5.3 framing DoS
# ---------------------------------------------------------------------------
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EXC="${HERE}/exceptions.yml"
RUN="${HERE}/run_pipeline.sh"

remove_block() {
    # Delete the marked demo block (idempotent; leaves the baseline alone).
    sed -i '/demo-risk-acceptance (managed/,/<<< demo-risk-acceptance/d' "${EXC}" 2>/dev/null || true
}

add_block() {
    grep -q 'demo-risk-acceptance' "${EXC}" && return 0
    cat >> "${EXC}" <<'YAML'
  # >>> demo-risk-acceptance (managed by demo_vuln_gate.sh) >>>
  - cve_id: "CVE-2021-31229"
    until: "2026-09-30"
    approver: "lab-admin@platform.local"
    justification: |
      OpenPLC v3 has no clean fixed release. Compensating controls in place:
      the web admin :8080 is unreachable from the IT zone (IDMZ router
      default-deny, verified) and reachable only from OT/mgmt; Zeek + Suricata
      + the AI engine monitor the PLC. Risk-accepted until 2026-09-30; tracked
      for OpenPLC upgrade + web-auth enablement at the next maintenance window.
  - cve_id: "CVE-2024-23653"
    until: "2026-09-30"
    approver: "lab-admin@platform.local"
    justification: |
      pymodbus 2.5.3 is used only as a CLIENT in OpenPLC's web monitor; the
      network-facing Modbus server on :502 is OpenPLC's C runtime, not
      pymodbus, so the server-side DoS is not reachable. A blind upgrade to
      3.x breaks the 2.x client API. Deferred to the web-monitor refactor.
  # <<< demo-risk-acceptance <<<
YAML
}

run_gate() { LAB_GATES=vuln bash "${RUN}"; }

phase_fail() {
    echo
    echo "=================== BEFORE remediation ==================="
    remove_block
    run_gate || true
    echo "----------------------------------------------------------"
    echo "Deploy BLOCKED. Open the dashboard -> Stages -> Stage 5 (DevSecOps):"
    echo "the pipeline verdict should now read FAIL (red)."
}

phase_fix() {
    echo
    echo "=========== AFTER remediation (documented risk acceptance) ==========="
    add_block
    run_gate || true
    echo "----------------------------------------------------------"
    echo "Deploy ALLOWED. Open the dashboard -> Stages -> Stage 5 (DevSecOps):"
    echo "the pipeline verdict should now read PASS (green). Findings are"
    echo "suppressed as XFAIL with a named approver + expiry, not deleted."
}

case "${1:-all}" in
    fail)  phase_fail ;;
    fix)   phase_fix ;;
    reset) remove_block; echo "exceptions.yml reset to baseline (demo block removed)." ;;
    all)
        phase_fail
        echo
        echo ">>> Applying documented risk acceptance (compensating controls + expiry)..."
        phase_fix ;;
    *) echo "usage: $0 [fail|fix|reset]"; exit 2 ;;
esac
