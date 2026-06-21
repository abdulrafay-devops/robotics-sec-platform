#!/usr/bin/env bash
# Stage 5 — DevSecOps pipeline runner (CI/CD orchestrator).
#
# Sequentially executes the six Stage-5 gates against the lab's source
# tree, captures per-gate logs, and on full pass writes a signed
# artifact bundle to /var/lab/artifacts/<build_id>/.
#
# Gates:
#   1. plc_lint       — vm-ot/openplc/*.st
#   2. hmi_lint       — hmi/*.json (if present)
#   3. sros2_lint     — vm-ot/sros2/permissions/*.xml + governance.xml
#   4. vuln_gate      — /var/lab/state/vulnerabilities.json
#   5. baseline_gate  — /var/lab/state/baseline_drift.json
#   6. acceptance     — Stage 2 replay + Stage 3 safety loop
#
# Exits 0 only when ALL selected gates pass. This is the SINGLE gate
# engine: the Gitea Actions workflow (.gitea/workflows/ci.yml), the
# webhook receiver, and infra/tests/stage5_pipeline_gate.sh all invoke
# this same script so the gate logic can never drift between them.
#
# Optional environment:
#   LAB_GATES=plc,hmi,...  — comma list of gates to run, from:
#                            plc,hmi,sros2,vuln,baseline,acceptance
#                            (default: all). CI runners use the static
#                            subset plc,hmi,sros2; gates 4-6 need live
#                            lab state and run in-lab only.
#   LAB_SKIP_ACCEPTANCE=1  — skip Gate 6 (use only for the unit-style
#                            CI run; production deploys must run it)
#   LAB_SIGNING_KEY=path   — GPG key for artifact signing (defaults to
#                            the lab's release key)
#   LAB_LOG_DIR=path       — log dir (default /var/lab/log/pipeline)
#   LAB_ARTIFACTS_DIR=path — artifact dir (default /var/lab/artifacts)
set -u
LOG_DIR=${LAB_LOG_DIR:-/var/lab/log/pipeline}
ARTIFACTS_DIR=${LAB_ARTIFACTS_DIR:-/var/lab/artifacts}
SOURCE=${LAB_SOURCE_DIR:-/vagrant}
BUILD_ID=$(date -u +%Y%m%dT%H%M%SZ)-$(echo $$)
BUILD_DIR=${ARTIFACTS_DIR}/${BUILD_ID}
PY=${LAB_PIPELINE_PY:-/opt/lab/venv-ai/bin/python}

install -d -m 0755 "${LOG_DIR}" "${BUILD_DIR}"
LOG=${LOG_DIR}/${BUILD_ID}.log
: > "${LOG}"

say()   { echo "$@" | tee -a "${LOG}"; }
fail()  { say "PIPELINE FAIL: $*"; record_verdict FAIL; exit 1; }
GATES=${LAB_GATES:-all}
want()  { [[ "${GATES}" == "all" || ",${GATES}," == *",$1,"* ]]; }
record_verdict() {
    cat > "${BUILD_DIR}/verdict.json" <<JSON
{
  "build_id": "${BUILD_ID}",
  "verdict": "$1",
  "timestamp": "$(date -u +%FT%TZ)",
  "source": "${SOURCE}",
  "log": "${LOG}"
}
JSON
}

say "=== Stage 5 pipeline build ${BUILD_ID} ==="
say "source=${SOURCE}; log=${LOG}; build_dir=${BUILD_DIR}; gates=${GATES}"

# Resolve the workspace; in lab provisioning this is /vagrant.
[[ -d "${SOURCE}" ]] || fail "source directory missing: ${SOURCE}"
[[ -x "${PY}" ]]      || fail "python missing: ${PY}"
HERE=$(dirname "$(readlink -f "$0")")

# --- Gate 1 ---
if ! want plc; then
    say "--- Gate 1: SKIPPED (not in LAB_GATES) ---"
else
    say "--- Gate 1: PLC lint ---"
    ST_FILES=( "${SOURCE}/vm-ot/openplc"/*.st )
    if [[ ${#ST_FILES[@]} -eq 0 || ! -f "${ST_FILES[0]}" ]]; then
        say "no .st files found; skipping (treated as PASS)"
    else
        ${PY} "${HERE}/plc_lint.py" "${ST_FILES[@]}" 2>&1 | tee -a "${LOG}"
        rc=${PIPESTATUS[0]}
        [[ ${rc} -eq 0 ]] || fail "Gate 1 PLC lint failed (rc=${rc})"
    fi
fi

# --- Gate 2 ---
if ! want hmi; then
    say "--- Gate 2: SKIPPED (not in LAB_GATES) ---"
else
    say "--- Gate 2: HMI lint ---"
    HMI_FILES=( "${SOURCE}"/hmi/*.json )
    if [[ ${#HMI_FILES[@]} -eq 0 || ! -f "${HMI_FILES[0]}" ]]; then
        say "no HMI JSON exports found; skipping (treated as PASS)"
    else
        for f in "${HMI_FILES[@]}"; do
            ${PY} "${HERE}/hmi_lint.py" "$f" 2>&1 | tee -a "${LOG}"
            rc=${PIPESTATUS[0]}
            [[ ${rc} -eq 0 ]] || fail "Gate 2 HMI lint failed on $f (rc=${rc})"
        done
    fi
fi

# --- Gate 3 ---
if ! want sros2; then
    say "--- Gate 3: SKIPPED (not in LAB_GATES) ---"
else
    say "--- Gate 3: SROS2 lint ---"
    GOV=/opt/lab/sros2_keystore/enclaves/governance.xml
    PERMS=( "${SOURCE}/vm-ot/sros2/permissions"/*.xml )
    if [[ ! -f "${PERMS[0]}" ]]; then
        say "no permissions XMLs found; skipping (treated as PASS)"
    else
        GOV_ARG=()
        [[ -f "${GOV}" ]] && GOV_ARG=( --governance "${GOV}" )
        ${PY} "${HERE}/sros2_lint.py" "${GOV_ARG[@]}" "${PERMS[@]}" 2>&1 | tee -a "${LOG}"
        rc=${PIPESTATUS[0]}
        [[ ${rc} -eq 0 ]] || fail "Gate 3 SROS2 lint failed (rc=${rc})"
    fi
fi

# --- Gate 4 ---
if ! want vuln; then
    say "--- Gate 4: SKIPPED (not in LAB_GATES) ---"
else
    say "--- Gate 4: vulnerability gate ---"
    ${PY} "${HERE}/vuln_gate.py" 2>&1 | tee -a "${LOG}"
    rc=${PIPESTATUS[0]}
    [[ ${rc} -eq 0 ]] || fail "Gate 4 vulnerability gate failed (rc=${rc})"
fi

# --- Gate 5 ---
if ! want baseline; then
    say "--- Gate 5: SKIPPED (not in LAB_GATES) ---"
else
    say "--- Gate 5: configuration baseline gate ---"
    ${PY} "${HERE}/baseline_gate.py" 2>&1 | tee -a "${LOG}"
    rc=${PIPESTATUS[0]}
    [[ ${rc} -eq 0 ]] || fail "Gate 5 baseline gate failed (rc=${rc})"
fi

# --- Gate 6 (skippable for fast unit runs) ---
if ! want acceptance; then
    say "--- Gate 6: SKIPPED (not in LAB_GATES) ---"
elif [[ -z "${LAB_SKIP_ACCEPTANCE:-}" ]]; then
    say "--- Gate 6: simulated acceptance ---"
    ${PY} "${HERE}/acceptance_gate.py" 2>&1 | tee -a "${LOG}"
    rc=${PIPESTATUS[0]}
    [[ ${rc} -eq 0 ]] || fail "Gate 6 acceptance failed (rc=${rc})"
else
    say "--- Gate 6: SKIPPED (LAB_SKIP_ACCEPTANCE=1) ---"
fi

# --- Artifact bundle + signature ---
say "--- bundling signed artifact ---"
( cd "${SOURCE}" && \
    tar --exclude='.git' --exclude='.vagrant' --exclude='diagrams' \
        -czf "${BUILD_DIR}/source.tgz" \
        vm-ot vm-ai vm-sec infra docs *.md 2>/dev/null )
( cd "${BUILD_DIR}" && sha256sum source.tgz > source.tgz.sha256 )
cp -f "${LOG}" "${BUILD_DIR}/pipeline.log"

# GPG sign the bundle if a key is available; otherwise produce an
# unsigned-but-hashed manifest so the build is still reproducible.
if command -v gpg >/dev/null 2>&1 && \
   gpg --list-secret-keys "${LAB_SIGNING_KEY:-lab-release@lab.local}" \
        >/dev/null 2>&1; then
    gpg --batch --yes --armor --detach-sign \
        --local-user "${LAB_SIGNING_KEY:-lab-release@lab.local}" \
        --output "${BUILD_DIR}/source.tgz.asc" \
        "${BUILD_DIR}/source.tgz"
    say "  signed by ${LAB_SIGNING_KEY:-lab-release@lab.local}"
else
    say "  WARN: no GPG signing key; artifact is hash-only"
fi

record_verdict PASS
say "=== PIPELINE PASS build_id=${BUILD_ID} ==="
echo "${BUILD_DIR}"
exit 0
