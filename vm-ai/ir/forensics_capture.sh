#!/usr/bin/env bash
# Stage 6 — Forensic capture script.
#
# Called by the playbook engine on the first step of every playbook.
# Bundles all volatile + non-volatile evidence relevant to a single
# incident and writes it under /var/lab/evidence/<incident_id>/, with
# a SHA-256 manifest. The directory itself is set chattr +i (immutable)
# after writing so a follow-on attacker cannot tamper with the bundle.
#
# Usage:
#   forensics_capture.sh <incident_id> [<offending_src_ip>]
set -u
INCIDENT_ID=${1:?usage: forensics_capture.sh <incident_id> [<src_ip>]}
SRC_IP=${2:-}
OUT=/var/lab/evidence/${INCIDENT_ID}
install -d -m 0750 "${OUT}"

echo "[forensics] capture incident=${INCIDENT_ID} src=${SRC_IP:-(none)} → ${OUT}"

# 1. Current OpenPLC program (deployed)
if [[ -f /opt/lab/openplc/webserver/st_files/production.st ]]; then
    cp -f /opt/lab/openplc/webserver/st_files/production.st \
        "${OUT}/openplc_running.st" 2>/dev/null || true
elif [[ -f /vagrant/vm-ot/openplc/production.st ]]; then
    cp -f /vagrant/vm-ot/openplc/production.st \
        "${OUT}/openplc_running.st" 2>/dev/null || true
fi

# 2. Stage 3 SROS2 permissions (live state)
if [[ -d /opt/lab/sros2_keystore ]]; then
    tar -C /opt/lab -czf "${OUT}/sros2_keystore.tgz" sros2_keystore 2>/dev/null || true
fi

# 3. Zeek log window (last 5 minutes)
if [[ -d /var/lab/sec-log/zeek/current ]]; then
    tar -C /var/lab/sec-log/zeek -czf "${OUT}/zeek_current.tgz" current 2>/dev/null || true
elif [[ -d /var/lab/log/zeek/current ]]; then
    tar -C /var/lab/log/zeek -czf "${OUT}/zeek_current.tgz" current 2>/dev/null || true
fi

# 4. Suricata eve.json
if [[ -f /var/lab/sec-log/suricata/eve.json ]]; then
    tail -c 1048576 /var/lab/sec-log/suricata/eve.json > "${OUT}/suricata_tail.json" 2>/dev/null || true
elif [[ -f /var/lab/log/suricata/eve.json ]]; then
    tail -c 1048576 /var/lab/log/suricata/eve.json > "${OUT}/suricata_tail.json" 2>/dev/null || true
fi

# 5. Stage 4 inventory + vulnerabilities snapshot
for f in /var/lab/state/inventory.json \
         /var/lab/state/vulnerabilities.json \
         /var/lab/state/baseline_drift.json \
         /var/lab/state/integrity_baseline.json; do
    [[ -f "$f" ]] && cp -f "$f" "${OUT}/" 2>/dev/null || true
done

# 6. Stage 5 most-recent artifact verdict
LATEST_BUILD=$(ls -1dt /var/lab/artifacts/*/ 2>/dev/null | head -1)
if [[ -n "${LATEST_BUILD}" ]]; then
    cp -f "${LATEST_BUILD}/verdict.json" "${OUT}/last_pipeline_verdict.json" 2>/dev/null || true
fi

# 7. Brief tcpdump (10 s, 5 MB cap) from the OT span. Skipped if tcpdump
#    is missing OR if we cannot identify the span interface.
if command -v tcpdump >/dev/null 2>&1; then
    SPAN=$(ip -o -4 addr show | awk '/192\.168\.10\./ {print $2; exit}')
    if [[ -n "${SPAN}" ]]; then
        timeout 10 tcpdump -i "${SPAN}" -w "${OUT}/ot_span.pcap" \
            -W 1 -C 5 -s 256 2>/dev/null || true
    fi
fi

# 8. Audit metadata.
cat > "${OUT}/manifest.json" <<JSON
{
  "incident_id": "${INCIDENT_ID}",
  "src_ip": "${SRC_IP}",
  "captured_at": "$(date -u +%FT%TZ)",
  "captured_on_host": "$(hostname)",
  "files": $(ls -1 "${OUT}" 2>/dev/null | sed 's/.*/"&"/' | paste -sd, | sed 's/^/[/;s/$/]/' )
}
JSON

# Hash everything for chain-of-custody.
( cd "${OUT}" && sha256sum * > manifest.sha256 2>/dev/null || true )

# Make the bundle immutable so an attacker who keeps a foothold cannot
# rewrite it. Best-effort — chattr requires CAP_LINUX_IMMUTABLE and a
# filesystem that supports it. If unavailable we just chmod -w.
if command -v chattr >/dev/null 2>&1; then
    chattr +i "${OUT}"/* 2>/dev/null || chmod -R a-w "${OUT}"
else
    chmod -R a-w "${OUT}"
fi

echo "[forensics] evidence sealed in ${OUT}"
