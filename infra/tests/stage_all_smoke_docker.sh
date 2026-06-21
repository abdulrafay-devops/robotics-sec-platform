#!/usr/bin/env bash
# Integrated End-to-End Docker Validation for all 6 stages.
#
# Usage:
#   bash infra/tests/stage_all_smoke_docker.sh
#
set -euo pipefail

echo "=================================================="
echo " 🛡️  ROBOTICS platform END-TO-END DOCKER VALIDATION 🛡️"
echo "=================================================="

RESULTS=()

run_stage() {
    local name="$1"
    local cmd="$2"
    echo
    echo "--------------------------------------------------"
    echo " 🚀 Running: ${name}"
    echo "--------------------------------------------------"
    if eval "$cmd"; then
        echo " ✅ PASS: ${name}"
        RESULTS+=("${name}=PASS")
    else
        echo " ❌ FAIL: ${name}"
        RESULTS+=("${name}=FAIL")
    fi
}

# Run all 6 Stage Gates
run_stage "Stage 1: Purdue Network Segmentation Matrix" "python3 infra/tests/stage1_connectivity_matrix_docker.py"
run_stage "Stage 2: AI Anomaly Detection & Live Replay" "python3 infra/tests/stage2_live_smoke_docker.py"
run_stage "Stage 2b: Robot-behavior LSTM Detection" "python3 infra/tests/stage2_robot_live_smoke_docker.py"
run_stage "Stage 3: SROS2 Cryptographic SIS Protection" "python3 infra/tests/run_stage3_gates_docker.py"
run_stage "Stage 4: Passive Vuln Audits & Drift Scans" "docker exec container-sec bash /vagrant/infra/tests/stage4_vuln_gate.sh"
run_stage "Stage 5: DevSecOps GitOps Signing Pipeline" "docker exec container-ai bash /vagrant/infra/tests/stage5_pipeline_gate.sh"
run_stage "Stage 6: Incident Containment & Response" "docker exec container-ai bash /vagrant/infra/tests/stage6_ir_gate.sh"

echo
echo "=================================================="
echo " 📊 FINAL VALIDATION MATRIX"
echo "=================================================="
FAILURES=0
for r in "${RESULTS[@]}"; do
    echo "  ${r}"
    if [[ "${r}" == *=FAIL ]]; then
        FAILURES=$((FAILURES + 1))
    fi
done

echo "=================================================="
if [[ ${FAILURES} -eq 0 ]]; then
    echo " 🎉  ALL 6 SECURITY STAGE GATES PASSED (ALL-GREEN)!"
    exit 0
else
    echo " ⚠️  ${FAILURES} GATE(S) FAILED. Check container states."
    exit 1
fi
