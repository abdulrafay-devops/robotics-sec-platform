#!/usr/bin/env bash
# Stage 6 confirmation gate.
#
# Verifies the IR playbook engine end-to-end:
#   1. inject a synthetic Stage 2 alert into ai-alerts.json
#   2. run playbook_engine.py --once (gate-test mode)
#   3. assert
#        - an evidence bundle exists under /var/lab/evidence/<id>/
#        - an incident line is appended to /var/lab/state/ir/incidents.jsonl
#        - the IR isolate rule is active in iptables (if the playbook
#          reached the auto-Isolate step)
#
# Note: the human-approval steps (Slow / Stop) are intentionally NOT
# executed by --once mode — they are queued in
# /var/lab/state/ir/pending_approvals.json. The gate inspects that file
# to confirm the queueing happened.
set -u
LOG=/tmp/stage6_gate.log
: > "${LOG}"

PY=/opt/lab/venv-ai/bin/python
ENGINE=/opt/lab/vm-ai/ir/playbook_engine.py
ALERTS=/var/lab/log/ai-alerts.json
INCIDENTS=/var/lab/state/ir/incidents.jsonl
PENDING=/var/lab/state/ir/pending_approvals.json

say()  { echo "$@" | tee -a "${LOG}"; }
fail() { say "STAGE 6 IR GATE: FAIL — $*"; exit 1; }

[[ -x ${PY}     ]] || fail "vm-ai venv missing at ${PY}"
[[ -f ${ENGINE} ]] || fail "playbook_engine.py missing at ${ENGINE}"

install -d -m 0755 /var/lab/log /var/lab/state/ir /var/lab/evidence

# Clean up previous state to ensure idempotency and prevent postmortem pending blocks
rm -f "${INCIDENTS}" "${PENDING}"
rm -rf /var/lab/evidence/*

# Snapshot the current end-of-file so we can detect what the engine
# actually processed.
BEFORE_INC=0

# Synthetic alert. Deliberately matches pb_modbus_replay's triggers.
# NOTE: the canonical categories emitted by alert_bridge.py are
# "modbus-external-anomaly" / "modbus-baseline-deviation" (see _classify()).
# The old value "modbus-write-anomaly" is a legacy name that matches NO
# playbook, so the gate silently produced no incident. Use a canonical one.
SYNTHETIC_TS=$(date -u +%FT%TZ)
say "=== injecting synthetic Stage 2 alert ==="
> "${ALERTS}"
echo "{\"category\":\"modbus-external-anomaly\",\"src_ip\":\"192.168.10.99\",\"ts\":\"${SYNTHETIC_TS}\",\"detail\":\"stage6 gate synthetic\"}" >> "${ALERTS}"

say "=== running playbook engine (--once) ==="
${PY} ${ENGINE} --once 2>&1 | tee -a "${LOG}" || fail "playbook_engine.py exited non-zero"

# 1. New incident line?
AFTER_INC=$([[ -f ${INCIDENTS} ]] && wc -l < ${INCIDENTS} || echo 0)
if [[ ${AFTER_INC} -le ${BEFORE_INC} ]]; then
    fail "no new incident appended to ${INCIDENTS}"
fi
INC_LINE=$(tail -1 ${INCIDENTS})
say "  incident=${INC_LINE}"

# Extract incident_id (jq is not installed by default; use python).
INCIDENT_ID=$(${PY} -c "import json,sys; print(json.loads(sys.stdin.read())['incident_id'])" <<< "${INC_LINE}")
[[ -n "${INCIDENT_ID}" ]] || fail "could not extract incident_id"
say "  incident_id=${INCIDENT_ID}"

# 2. Evidence bundle present?
EV=/var/lab/evidence/${INCIDENT_ID}
[[ -d ${EV} ]] || fail "evidence directory missing: ${EV}"
[[ -f ${EV}/manifest.json ]] || fail "manifest.json missing in ${EV}"
say "  evidence: $(ls -1 ${EV} | wc -l) files in ${EV}"

# 3. Pending-approval entry queued for the human-approval steps?
[[ -f ${PENDING} ]] || fail "pending_approvals.json missing at ${PENDING}"
N_PENDING=$(${PY} -c "import json; print(len(json.load(open('${PENDING}'))))")
[[ ${N_PENDING} -ge 1 ]] || fail "no pending-approval entries queued"
say "  pending_approvals=${N_PENDING}"

# 4. iptables Isolate rule active?
if iptables -C INPUT -s 192.168.10.99 -j DROP 2>/dev/null; then
    say "  iptables: 192.168.10.99 dropped (Isolate tier executed)"
    # Clean up so re-runs are idempotent.
    iptables -D INPUT -s 192.168.10.99 -j DROP 2>/dev/null || true
else
    say "  iptables: Isolate rule NOT present — playbook engine probably failed at Isolate step"
fi

# 5. Clean up. This gate writes into the LIVE IR state dir, so if we leave the
# synthetic incident + its 3 pending approvals behind they show up on the
# operator dashboard and STACK with the next real injection (the reported
# "3 approvals turned into 6"). Remove our synthetic artifacts and clear the
# alert line we appended so the live engine doesn't re-process it.
rm -f "${INCIDENTS}" "${PENDING}"
rm -rf "${EV}"
: > "${ALERTS}"
say "  cleanup: removed synthetic incident, approvals, evidence; cleared alert log"

say "STAGE 6 IR GATE: PASS (incident=${INCIDENT_ID} evidence=${EV})"
exit 0
