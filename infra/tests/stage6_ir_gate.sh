#!/usr/bin/env bash
# Stage 6 confirmation gate.
#
# Verifies the IR playbook engine end-to-end:
#   1. inject a synthetic Stage 2 alert into ai-alerts.json
#   2. run playbook_engine.py --once
#   3. assert evidence and incident records are created
#   4. assert network isolation is queued for human approval, not executed
#   5. approve the isolate step and then assert the iptables DROP rule appears
set -euo pipefail

LOG=/tmp/stage6_gate.log
: > "${LOG}"

PY=/opt/lab/venv-ai/bin/python
ENGINE=/opt/lab/vm-ai/ir/playbook_engine.py
ALERTS=/var/lab/log/ai-alerts.json
INCIDENTS=/var/lab/state/ir/incidents.jsonl
PENDING=/var/lab/state/ir/pending_approvals.json
SYNTHETIC_SRC=192.168.10.99

say()  { echo "$@" | tee -a "${LOG}"; }
fail() { say "STAGE 6 IR GATE: FAIL - $*"; exit 1; }

[[ -x ${PY}     ]] || fail "vm-ai venv missing at ${PY}"
[[ -f ${ENGINE} ]] || fail "playbook_engine.py missing at ${ENGINE}"

if [[ -d /vagrant/vm-ai/ir ]]; then
    say "Syncing live IR engine/playbooks from /vagrant/vm-ai/ir"
    cp -f /vagrant/vm-ai/ir/playbook_engine.py /opt/lab/vm-ai/ir/playbook_engine.py
    cp -f /vagrant/vm-ai/ir/playbooks/*.md /opt/lab/vm-ai/ir/playbooks/
    cp -f /vagrant/vm-ai/ir/bin/* /opt/lab/bin/
    chmod +x /opt/lab/bin/ir-*
fi

install -d -m 0755 /var/lab/log /var/lab/state/ir /var/lab/evidence
command -v iptables >/dev/null 2>&1 || fail "iptables missing in container-ai; approved isolation cannot be enforced"

# Clean previous synthetic state so the gate is idempotent.
rm -f "${INCIDENTS}" "${PENDING}"
rm -rf /var/lab/evidence/*
iptables -D INPUT -s "${SYNTHETIC_SRC}" -j DROP 2>/dev/null || true

BEFORE_INC=0
SYNTHETIC_TS=$(date -u +%FT%TZ)
say "=== injecting synthetic Stage 2 alert ==="
: > "${ALERTS}"
echo "{\"category\":\"modbus-external-anomaly\",\"src_ip\":\"${SYNTHETIC_SRC}\",\"ts\":\"${SYNTHETIC_TS}\",\"detail\":\"stage6 gate synthetic\"}" >> "${ALERTS}"

say "=== running playbook engine (--once) ==="
${PY} ${ENGINE} --once 2>&1 | tee -a "${LOG}" || fail "playbook_engine.py exited non-zero"

AFTER_INC=$([[ -f ${INCIDENTS} ]] && wc -l < "${INCIDENTS}" || echo 0)
if [[ ${AFTER_INC} -le ${BEFORE_INC} ]]; then
    fail "no new incident appended to ${INCIDENTS}"
fi
INC_LINE=$(tail -1 "${INCIDENTS}")
say "  incident=${INC_LINE}"

INCIDENT_ID=$(${PY} -c "import json,sys; print(json.loads(sys.stdin.read())['incident_id'])" <<< "${INC_LINE}")
[[ -n "${INCIDENT_ID}" ]] || fail "could not extract incident_id"
say "  incident_id=${INCIDENT_ID}"

EV=/var/lab/evidence/${INCIDENT_ID}
[[ -d ${EV} ]] || fail "evidence directory missing: ${EV}"
[[ -f ${EV}/manifest.json ]] || fail "manifest.json missing in ${EV}"
say "  evidence: $(ls -1 "${EV}" | wc -l) files in ${EV}"

[[ -f ${PENDING} ]] || fail "pending_approvals.json missing at ${PENDING}"
N_PENDING=$(${PY} -c "import json; print(len(json.load(open('${PENDING}'))))")
[[ ${N_PENDING} -ge 1 ]] || fail "no pending-approval entries queued"
say "  pending_approvals=${N_PENDING}"

HAS_ISOLATE=$(${PY} -c "import json; data=json.load(open('${PENDING}')); print('yes' if any(e.get('step') == 'graded_isolate' and 'ir-isolate' in e.get('cmd','') for e in data) else 'no')")
[[ ${HAS_ISOLATE} == "yes" ]] || fail "graded_isolate was not queued for human approval"
say "  approval queue: graded_isolate queued for human approval"

if iptables -C INPUT -s "${SYNTHETIC_SRC}" -j DROP 2>/dev/null; then
    fail "isolate rule executed before human approval"
else
    say "  iptables: no isolate rule before approval (correct)"
fi

say "=== approving queued network isolate step ==="
/opt/lab/bin/ir-approve "${INCIDENT_ID}" graded_isolate 2>&1 | tee -a "${LOG}" || fail "ir-approve failed for graded_isolate"

if iptables -C INPUT -s "${SYNTHETIC_SRC}" -j DROP 2>/dev/null; then
    say "  iptables: ${SYNTHETIC_SRC} dropped only after approval"
else
    fail "approved isolate step did not install iptables DROP rule"
fi

N_PENDING_AFTER=$(${PY} -c "import json,os; p='${PENDING}'; print(len(json.load(open(p))) if os.path.exists(p) else 0)")
[[ ${N_PENDING_AFTER} -lt ${N_PENDING} ]] || fail "pending approval count did not decrease after approval"
say "  pending_approvals_after_approve=${N_PENDING_AFTER}"

# Clean up live IR state and synthetic firewall rule.
iptables -D INPUT -s "${SYNTHETIC_SRC}" -j DROP 2>/dev/null || true
rm -f "${INCIDENTS}" "${PENDING}"
rm -rf "${EV}"
: > "${ALERTS}"
say "  cleanup: removed synthetic incident, approvals, evidence, firewall rule; cleared alert log"

say "STAGE 6 IR GATE: PASS (human-approved isolate incident=${INCIDENT_ID})"
exit 0
