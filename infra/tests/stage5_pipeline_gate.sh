#!/usr/bin/env bash
# Stage 5 confirmation gate.
#
# Runs the full DevSecOps pipeline against the workspace's source tree
# in unit-style mode (Gate 6 acceptance is skipped because the gate is
# itself the acceptance run; we don't want a recursion).
#
# PASS condition: pipeline runner exits 0 AND verdict.json says PASS.
set -u
LOG=/tmp/stage5_gate.log
: > "${LOG}"

PY=/opt/lab/venv-ai/bin/python
RUN=/opt/lab/vm-ai/devsecops/run_pipeline.sh

say()  { echo "$@" | tee -a "${LOG}"; }
fail() { say "STAGE 5 PIPELINE GATE: FAIL — $*"; exit 1; }

[[ -x ${PY}  ]] || fail "vm-ai venv missing at ${PY}"
[[ -x ${RUN} ]] || fail "pipeline runner missing at ${RUN}"

# Sync live scripts from the host volume to ensure latest code is run
if [[ -d /vagrant/vm-ai/devsecops ]]; then
    say "Syncing live pipeline scripts from /vagrant/vm-ai/devsecops to /opt/lab/vm-ai/devsecops"
    cp -f /vagrant/vm-ai/devsecops/*.py /vagrant/vm-ai/devsecops/*.sh /opt/lab/vm-ai/devsecops/
    chmod +x /opt/lab/vm-ai/devsecops/*.sh /opt/lab/vm-ai/devsecops/*.py
fi

say "=== Stage 5 pipeline (unit mode: Gate 6 skipped) ==="
LAB_SKIP_ACCEPTANCE=1 LAB_PIPELINE_PY="${PY}" LAB_SOURCE_DIR=/vagrant \
    bash "${RUN}" 2>&1 | tee -a "${LOG}"
RC=${PIPESTATUS[0]}
[[ ${RC} -eq 0 ]] || fail "pipeline exited rc=${RC}"

# Find the latest build verdict.
LATEST=$(ls -1dt /var/lab/artifacts/*/ 2>/dev/null | head -1)
[[ -n "${LATEST}" ]] || fail "no artifact directory produced under /var/lab/artifacts"
[[ -f "${LATEST}/verdict.json" ]] || fail "verdict.json missing in ${LATEST}"

VERDICT=$(${PY} -c "import json,sys; print(json.load(open('${LATEST}/verdict.json'))['verdict'])")
[[ "${VERDICT}" == "PASS" ]] || fail "verdict=${VERDICT} (expected PASS)"

say "STAGE 5 PIPELINE GATE: PASS (artifact=${LATEST})"
exit 0
