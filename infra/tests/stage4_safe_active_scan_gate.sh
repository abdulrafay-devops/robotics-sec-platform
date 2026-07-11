#!/usr/bin/env bash
# Stage 4 safe active-scan confirmation gate.
#
# This is intentionally separate from stage4_vuln_gate.sh. The normal Stage 4
# smoke gate remains passive and can run any time. This gate demonstrates the
# governed active-scanning path using a simulated approved maintenance window.
set -euo pipefail
set -o pipefail

LOG=/tmp/stage4_safe_active_scan_gate.log
: > "${LOG}"
PY=/opt/lab/venv-shipper/bin/python
ROOT=/opt/lab/vm-sec/vuln
STATE=/var/lab/state
INSIDE_WINDOW=2026-07-12T01:30:00Z
OUTSIDE_WINDOW=2026-07-12T04:30:00Z

say() { echo "$@" | tee -a "${LOG}"; }
fail() { say "STAGE 4 SAFE ACTIVE SCAN GATE: FAIL - $*"; exit 1; }

[[ -x ${PY} ]] || fail "shipper venv missing at ${PY}"
[[ -d ${ROOT} ]] || fail "Stage 4 code missing at ${ROOT}"

if [[ -d /vagrant/vm-sec/vuln ]]; then
    say "Syncing live safe-scan code/config from /vagrant/vm-sec/vuln to ${ROOT}"
    cp -f /vagrant/vm-sec/vuln/*.py /vagrant/vm-sec/vuln/*.yml "${ROOT}/"
    chmod +x "${ROOT}"/*.py
fi

say "=== Safe active scan / step 1: dry-run inside maintenance window ==="
${PY} "${ROOT}/safe_active_scan.py" --dry-run --now "${INSIDE_WINDOW}" --state-dir "${STATE}" \
    2>&1 | tee -a "${LOG}" || fail "dry-run failed"
${PY} - <<'PY' 2>&1 | tee -a "${LOG}" || fail "dry-run report invalid"
import json
r=json.load(open('/var/lab/state/active_scan_report.json'))
assert r['status']=='DRY_RUN', r['status']
assert '--max-rate' in r['nmap_command'], r['nmap_command']
assert '--scan-delay' in r['nmap_command'], r['nmap_command']
print('dry-run report: schema ok')
PY

say "=== Safe active scan / step 2: execution blocked outside window ==="
if ${PY} "${ROOT}/safe_active_scan.py" --execute --now "${OUTSIDE_WINDOW}" --state-dir "${STATE}" \
    2>&1 | tee -a "${LOG}"; then
    fail "execute unexpectedly succeeded outside maintenance window"
else
    say "outside-window execution correctly blocked"
fi

say "=== Safe active scan / step 3: execute low-rate nmap inside maintenance window ==="
${PY} "${ROOT}/safe_active_scan.py" --execute --now "${INSIDE_WINDOW}" --state-dir "${STATE}" \
    2>&1 | tee -a "${LOG}" || fail "safe active scan execution failed"

${PY} - <<'PY' 2>&1 | tee -a "${LOG}" || fail "execute report invalid"
import json
r=json.load(open('/var/lab/state/active_scan_report.json'))
assert r['status']=='PASS', r['status']
cmd=r['nmap_command']
for required in ('-sT','-Pn','-n','--max-rate','--scan-delay','--max-retries','--max-parallelism'):
    assert required in cmd, f'missing {required}: {cmd}'
for forbidden in ('-A','-O','-sS','-sU','-sV','--script','--traceroute'):
    assert forbidden not in cmd, f'forbidden flag present {forbidden}: {cmd}'
ports={p for target in r['targets'] for p in target['ports']}
assert not ({102,502,503,20000,44818,4840} & ports), ports
assert r['findings'], 'expected nmap finding entries'
print(f"execute report: {len(r['findings'])} findings; safe ports={sorted(ports)}")
PY

say "=== Safe active scan / step 4: scheduler runs only once per maintenance window ==="
rm -f "${STATE}/active_scan_schedule.json"
${PY} "${ROOT}/safe_active_scan.py" --scheduled --execute --now "${INSIDE_WINDOW}" --state-dir "${STATE}" \
    2>&1 | tee -a "${LOG}" || fail "scheduled active scan execution failed"

${PY} - <<'PY' 2>&1 | tee -a "${LOG}" || fail "scheduled active scan state invalid"
import json
s=json.load(open('/var/lab/state/active_scan_schedule.json'))
r=json.load(open('/var/lab/state/active_scan_report.json'))
assert s['status'] == 'PASS', s
assert s['last_result'] == 'PASS', s
assert s['last_attempt_window'], s
assert r['status'] == 'PASS', r
print('scheduled scan: first maintenance-window execution recorded')
PY

${PY} "${ROOT}/safe_active_scan.py" --scheduled --execute --now "${INSIDE_WINDOW}" --state-dir "${STATE}" \
    2>&1 | tee -a "${LOG}" || fail "second scheduled check should skip successfully"

${PY} - <<'PY' 2>&1 | tee -a "${LOG}" || fail "duplicate scan protection invalid"
import json
s=json.load(open('/var/lab/state/active_scan_schedule.json'))
r=json.load(open('/var/lab/state/active_scan_report.json'))
assert s['status'] == 'ALREADY_RUN', s
assert s['last_result'] == 'PASS', s
assert r['status'] == 'PASS', r
print('scheduled scan: duplicate run blocked for the same maintenance window')
PY

${PY} "${ROOT}/safe_active_scan.py" --scheduled --execute --now "${OUTSIDE_WINDOW}" --state-dir "${STATE}" \
    2>&1 | tee -a "${LOG}" || fail "scheduled outside-window check should be a safe no-op"

${PY} - <<'PY' 2>&1 | tee -a "${LOG}" || fail "outside-window scheduler state invalid"
import json
s=json.load(open('/var/lab/state/active_scan_schedule.json'))
assert s['status'] == 'OUTSIDE_WINDOW', s
assert s['last_result'] == 'PASS', s
assert s['last_attempt_window'], s
print('scheduled scan: outside-window check did not launch nmap')
PY

say "STAGE 4 SAFE ACTIVE SCAN GATE: PASS"
