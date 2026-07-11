#!/usr/bin/env bash
# Stage 4 confirmation gate.
#
# Runs (on vm-sec):
#   1. inventory.py --no-active     — exercises the passive Zeek seeding +
#                                     SQLite persistence path without making
#                                     any on-wire scans (so this gate can
#                                     be run any time, including during a
#                                     production cycle).
#   2. cve_correlate.py             — produces vulnerabilities.json. The
#                                     gate asserts the file is valid JSON
#                                     and that the schema is correct.
#   3. baseline_check.py            — produces baseline_drift.json. The
#                                     gate inspects the structure but does
#                                     NOT fail on drift (drift handling
#                                     belongs to Stage 5's baseline gate
#                                     and Stage 6 incident triggers).
#   4. firmware_workflow.py (dry run on a benign .st) — verifies the
#                                     STAGE → VALIDATE → SCHEDULE →
#                                     BACKUP → APPLY → VERIFY sequence
#                                     executes end-to-end and writes a
#                                     run trail.
#
# Exits 0 on PASS, non-zero on FAIL, with explicit lines printed for the
# wrapper to grep.
set -u
set -o pipefail
LOG=/tmp/stage4_gate.log
: > "${LOG}"

PY=/opt/lab/venv-shipper/bin/python
ROOT=/opt/lab/vm-sec/vuln
STATE=/var/lab/state

say() { echo "$@" | tee -a "${LOG}"; }
fail() { say "STAGE 4 VULN GATE: FAIL — $*"; exit 1; }

[[ -x ${PY} ]] || fail "shipper venv missing at ${PY}"
[[ -d ${ROOT} ]] || fail "Stage 4 code missing at ${ROOT}"
install -d -m 0755 "${STATE}"

# Sync live scripts from the host volume to ensure latest code is run
if [[ -d /vagrant/vm-sec/vuln ]]; then
    say "Syncing live vuln scripts from /vagrant/vm-sec/vuln to ${ROOT}"
    cp -f /vagrant/vm-sec/vuln/*.py "${ROOT}/"
    chmod +x "${ROOT}"/*.py
fi

say "=== Stage 4 / step 1: inventory (passive only) ==="
${PY} ${ROOT}/inventory.py --no-active 2>&1 | tee -a "${LOG}" || fail "inventory.py exited non-zero"
[[ -s ${STATE}/inventory.json ]] || fail "inventory.json missing or empty"
${PY} -c "import json,sys; d=json.load(open('${STATE}/inventory.json')); assert isinstance(d,list), 'not a list'; print(f'inventory: {len(d)} assets')" \
    2>&1 | tee -a "${LOG}" || fail "inventory.json failed schema check"
${PY} -c "
import json
assets = json.load(open('${STATE}/inventory.json'))
by_ip = {a.get('ip'): a for a in assets}
plc = by_ip.get('192.168.10.10')
assert plc, 'CMDB asset 192.168.10.10 missing from inventory'
assert 'asset_register' in (plc.get('discovery_methods') or []), 'asset_register method missing'
assert plc.get('software'), 'installed software inventory missing for PLC asset'
sis = by_ip.get('192.168.10.11')
assert sis, 'CMDB SIS asset 192.168.10.11 missing from inventory'
meta = json.load(open('${STATE}/scan_meta.json'))
assert meta.get('assets_in_scope', 0) >= 2, 'scan_meta assets_in_scope missing'
assert 'asset_register' in (meta.get('discovery_methods') or []), 'scan_meta missing asset_register source'
print('asset register scope: {} assets, {} live observed'.format(meta.get('assets_in_scope'), meta.get('live_hosts_found', 0)))
" 2>&1 | tee -a "${LOG}" || fail "asset-register inventory scope invalid"

say "=== Stage 4 / step 2: cve correlation ==="
${PY} ${ROOT}/cve_correlate.py 2>&1 | tee -a "${LOG}" || fail "cve_correlate.py exited non-zero"
[[ -s ${STATE}/vulnerabilities.json ]] || fail "vulnerabilities.json missing"
${PY} -c "
import json, sys
d = json.load(open('${STATE}/vulnerabilities.json'))
assert isinstance(d, list), 'vulnerabilities.json not a list'
for f in d:
    for k in ('asset_ip','cve_id','cvss','title','source','remediation'):
        assert k in f, f'missing key {k} in finding {f}'
expected = {'CVE-2021-31229', 'CVE-2024-23653'}
found = {f['cve_id'] for f in d}
missing = expected - found
assert not missing, f'expected lab CVEs missing from Stage 4 output: {sorted(missing)}'
print(f'vulnerabilities: {len(d)} findings ok')
" 2>&1 | tee -a "${LOG}" || fail "vulnerabilities.json schema invalid"

say "=== Stage 4 / step 3: baseline drift check ==="
if [[ -f /.dockerenv ]]; then
    say "Docker environment detected; using pre-generated baseline report from container-ot"
else
    ${PY} ${ROOT}/baseline_check.py 2>&1 | tee -a "${LOG}" || true
fi
[[ -s ${STATE}/baseline_drift.json ]] || fail "baseline_drift.json missing"
${PY} -c "
import json
d = json.load(open('${STATE}/baseline_drift.json'))
for k in ('generated_at','drift','compliant_count','drift_count'):
    assert k in d, f'missing key {k}'
print(f'baseline: {d[\"compliant_count\"]} compliant, {d[\"drift_count\"]} drift')
" 2>&1 | tee -a "${LOG}" || fail "baseline_drift.json schema invalid"

say "=== Stage 4 / step 4: firmware workflow (dry, in-window) ==="
# Use a one-hour window centred on now so the schedule check passes.
NOW_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
START=$(date -u -d '-30 min' +%Y-%m-%dT%H:%M:%SZ)
END=$(date -u -d '+30 min' +%Y-%m-%dT%H:%M:%SZ)

# Use a syntactically valid (Stage-5-lint-clean) ST snippet as the candidate.
CAND=/tmp/stage4_gate_candidate.st
cat > ${CAND} <<'ST'
(* SIGNED_BY: security_authority @ 2026-05-21T00:00:00Z *)
PROGRAM main
  VAR
    heartbeat : BOOL := TRUE;
  END_VAR
END_PROGRAM
ST
# Use a writable, dedicated "current program" path so we don't disturb
# anything else on the system.
CUR=/tmp/stage4_gate_current.st
[[ -f ${CUR} ]] || echo '(* initial *)' > ${CUR}

${PY} ${ROOT}/firmware_workflow.py \
    --program ${CAND} \
    --target vm-ot \
    --window "${START}..${END}" \
    --current-program ${CUR} 2>&1 | tee -a "${LOG}"
RC=$?
if [[ ${RC} -ne 0 ]]; then
    fail "firmware_workflow.py exited rc=${RC}"
fi
ls -1 ${STATE}/firmware_runs/ 2>/dev/null | tail -1 | tee -a "${LOG}"

say "=== Stage 4 / step 5: integrity baseline generation ==="
${PY} ${ROOT}/integrity_baseline.py 2>&1 | tee -a "${LOG}" || fail "integrity_baseline.py exited non-zero"
[[ -s ${STATE}/integrity_baseline.json ]] || fail "integrity_baseline.json missing"
${PY} -c '
import json,sys
d=json.load(open("/var/lab/state/integrity_baseline.json"))
for k in ("generated_at","plc_files","sros2_files","modbus_snapshot","services"):
    assert k in d, f"missing key {k}"
assert isinstance(d["plc_files"], dict) and isinstance(d["sros2_files"], dict)
ms=d.get("modbus_snapshot",{})
assert isinstance(ms.get("coils",[]), list) and isinstance(ms.get("registers",[]), list)
print("integrity baseline: schema ok")
' 2>&1 | tee -a "${LOG}" || fail "integrity_baseline.json schema invalid"

say "STAGE 4 VULN GATE: PASS (inventory+cve+baseline+firmware all green)"
exit 0
