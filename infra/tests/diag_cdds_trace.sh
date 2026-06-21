#!/usr/bin/env bash
# Stage 3 diagnostic: enable Cyclone DDS finest-verbosity tracing on the
# safety supervisor, restart it, run the gate-1 test once, and dump the
# parts of the trace that show whether the DDS-Security plugins were
# loaded and whether the participant handshake succeeded.
#
# Run on vm-ot:
#   sudo bash /vagrant/infra/tests/diag_cdds_trace.sh
set +e
TRACE=/tmp/cdds_supervisor.log

install -d -m 0755 /etc/systemd/system/lab-safety-supervisor.service.d
cat >/etc/systemd/system/lab-safety-supervisor.service.d/trace.conf <<EOF
[Service]
Environment=CYCLONEDDS_URI=file:///vagrant/vm-ot/sros2/cyclonedds_trace.xml
EOF
systemctl daemon-reload

: >"${TRACE}"
chmod 666 "${TRACE}" 2>/dev/null || true
systemctl restart lab-safety-supervisor
sleep 5

echo '=== supervisor active? ==='
systemctl is-active lab-safety-supervisor

echo '=== trace head (config + plugin load) ==='
head -80 "${TRACE}" 2>/dev/null | sed -n '1,80p'

echo '=== trace lines mentioning security/auth/access/crypto ==='
grep -E 'security|auth|access|crypto|handshake|plugin' "${TRACE}" 2>/dev/null | head -40

echo '=== run gate 1 once (10s budget) ==='
( sleep 14 ; pkill -9 -f stage3_safety_loop >/dev/null 2>&1 || true ) &
WD=$!
timeout 12 /opt/lab/bin/run-stage3-safety-loop.sh
RC=$?
kill ${WD} >/dev/null 2>&1 || true
echo "[gate1 rc=${RC}]"

echo '=== trace lines after the test (handshake outcome) ==='
tail -120 "${TRACE}" 2>/dev/null | grep -E 'handshake|auth|MATCH|REJECT|fail|error|denied' | head -40

echo '=== trace tail (last 40 lines, raw) ==='
tail -40 "${TRACE}" 2>/dev/null
