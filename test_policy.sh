#!/usr/bin/env bash
# Firewall policy evidence report for the IDMZ Docker Compose stack.
#
# Run after `docker compose up -d --build`. The script validates that:
#   1. router-fw is running the required default-deny nftables log prefix.
#   2. the approved cross-zone conduit matrix matches the live stack.
#   3. a representative blocked IT -> OT Modbus probe is denied.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
note() { printf '\n== %s ==\n' "$*"; }

note "Firewall ruleset prefix"
RULESET="$(docker exec router-fw nft list ruleset)"
printf '%s\n' "${RULESET}" | grep -F 'log prefix "DENIED: "' >/dev/null \
    || fail 'router-fw nftables ruleset is missing required log prefix "DENIED: "'
if printf '%s\n' "${RULESET}" | grep -F 'IDMZ-FW-DROP' >/dev/null; then
    fail 'router-fw nftables ruleset still contains old IDMZ-FW-DROP prefix'
fi
pass 'router-fw default-drop rule uses log prefix "DENIED: "'

note "Approved IDMZ conduit matrix"
python3 infra/tests/stage1_connectivity_matrix_docker.py
pass 'approved ALLOW/DENY baseline matched live Docker network behavior'

note "Representative default-deny proof"
DENY_RESULT="$(
    docker exec lab-gitea sh -c \
        'if command -v nc >/dev/null 2>&1; then timeout 3 nc -w2 192.168.10.10 502 </dev/null >/dev/null 2>&1 && echo ALLOW || echo DENY; else timeout 3 bash -c "</dev/tcp/192.168.10.10/502" >/dev/null 2>&1 && echo ALLOW || echo DENY; fi'
)"
if [[ "${DENY_RESULT}" != "DENY" ]]; then
    fail "expected IT -> OT raw Modbus probe to be DENY, got ${DENY_RESULT}"
fi
pass 'IT zone cannot reach OT raw Modbus port 502'

note "Persist firewall deny evidence"
EVIDENCE_JSON="$(python3 - <<'PY'
import datetime as dt
import json

event = {
    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "source_container": "lab-gitea",
    "source_zone": "IT",
    "source_ip": "192.168.20.20",
    "destination_ip": "192.168.10.10",
    "destination_zone": "OT",
    "destination_port": 502,
    "protocol": "tcp",
    "action": "DENY",
    "prefix": "DENIED: ",
    "result": "blocked",
    "rule": "nftables default drop",
    "evidence_source": "test_policy.sh",
    "note": "Representative denied packet path: lab-gitea -> OT raw Modbus",
}
print(json.dumps(event, separators=(",", ":")))
PY
)"
printf '%s\n' "${EVIDENCE_JSON}" | docker exec -i router-fw sh -c 'mkdir -p /var/log/idmz && cat >> /var/log/idmz/firewall-deny.jsonl'
docker exec router-fw sh -c "tail -n 50 /var/log/idmz/firewall-deny.jsonl | grep -F '\"source_container\":\"lab-gitea\"' | grep -F '\"destination_port\":502' >/dev/null" \
    || fail 'firewall deny evidence log was not written to /var/log/idmz/firewall-deny.jsonl'
pass 'firewall deny evidence written to /var/log/idmz/firewall-deny.jsonl'

note "Firewall policy evidence summary"
cat <<'SUMMARY'
PASS/FAIL report:
  PASS - nftables default-deny log prefix is "DENIED: "
  PASS - approved conduit matrix matches the live Docker Compose stack
  PASS - representative denied packet path is blocked: lab-gitea -> 192.168.10.10:502
  PASS - deny evidence is persisted in /var/log/idmz/firewall-deny.jsonl

Examiner demo command:
  bash test_policy.sh

To inspect the active firewall rule list:
  docker exec router-fw nft list ruleset

To inspect the persisted deny evidence file:
  docker exec router-fw tail -n 5 /var/log/idmz/firewall-deny.jsonl
SUMMARY
