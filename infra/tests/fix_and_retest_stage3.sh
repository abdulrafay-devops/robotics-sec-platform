#!/usr/bin/env bash
# One-shot: re-bootstrap the SROS2 keystore (refreshing permissions.p7s
# from the corrected XML templates), restart the supervisor + heartbeat,
# and run both Stage 3 gates.
#
# Why this exists: the original bootstrap had two bugs that caused the
# permissions.p7s to fall back to the restrictive default produced by
# `ros2 security create_enclave`, which blocked rt/safety/request from
# the production_plc enclave.
set +e
LOG=/tmp/stage3.log
: > "${LOG}"

say() { echo "$@" | tee -a "${LOG}"; }
run() { "$@" 2>&1 | tee -a "${LOG}"; return ${PIPESTATUS[0]}; }

# Kill any leftover test processes from a previous (canceled) run so they
# don't keep sockets/discovery slots warm.
pkill -9 -f stage3_safety_loop  >/dev/null 2>&1 || true
pkill -9 -f stage3_sros2_authn  >/dev/null 2>&1 || true

# Apply (or refresh) systemd drop-ins that cap stop-time at 5s. Without
# these, a single `systemctl restart lab-safety-supervisor` takes 90s
# because rclpy.shutdown() deadlocks. Drop-ins persist after this run.
say "=== installing TimeoutStopSec=5 drop-ins ==="
for SVC in lab-safety-supervisor lab-safety-heartbeat; do
    install -d -m 0755 /etc/systemd/system/${SVC}.service.d
    cat >/etc/systemd/system/${SVC}.service.d/override.conf <<EOF
[Service]
TimeoutStopSec=5
KillMode=mixed
KillSignal=SIGTERM
EOF
done
systemctl daemon-reload

say "=== wipe + rebuild keystore (drops broken custom permissions.p7s) ==="
# Previous runs replaced the default permissions.p7s with custom ones that
# caused Cyclone DDS to hang at discovery. The keystore is regenerable
# (no external state depends on it within the lab), so a clean rebuild is
# the most reliable way to restore the known-good default permissions.
rm -rf /opt/lab/sros2_keystore
run bash /vagrant/vm-ot/sros2/bootstrap_keystore.sh

say "=== stage cyclonedds.xml + refresh service wrappers ==="
# Stage 3 wrappers in vm-ot.sh now export CYCLONEDDS_URI pointing at the
# loopback peer-discovery config; we restage them here so re-runs don't
# require a full vagrant re-provision.
install -d -m 0755 /opt/lab/vm-ot/sros2
cp -f /vagrant/vm-ot/sros2/cyclonedds.xml /opt/lab/vm-ot/sros2/cyclonedds.xml

# Remove the diagnostic trace drop-in (if present) so we use the production
# cyclonedds.xml that the wrappers point at.
rm -f /etc/systemd/system/lab-safety-supervisor.service.d/trace.conf
systemctl daemon-reload

# Re-run only the wrapper-creation portion of the provisioner: the simplest
# way is to re-execute the relevant heredocs directly here.
cat >/opt/lab/bin/run-safety-supervisor.sh <<'BASH'
#!/usr/bin/env bash
set -e
export HOME=/root
export ROS_LOG_DIR=/var/lab/log/ros
mkdir -p "${ROS_LOG_DIR}"
set +u
source /opt/ros/humble/setup.bash
set -u
export ROS_DOMAIN_ID=0
export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/safety_supervisor
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
export LAB_SAFETY_HOST=0.0.0.0
export LAB_SAFETY_PORT=503
exec /opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_supervisor.py
BASH
chmod 0755 /opt/lab/bin/run-safety-supervisor.sh

cat >/opt/lab/bin/run-safety-heartbeat.sh <<'BASH'
#!/usr/bin/env bash
set -e
export HOME=/root
export ROS_LOG_DIR=/var/lab/log/ros
mkdir -p "${ROS_LOG_DIR}"
set +u
source /opt/ros/humble/setup.bash
set -u
export ROS_DOMAIN_ID=0
export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/production_plc
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
export LAB_SAFETY_HOST=192.168.10.11
export LAB_SAFETY_PORT=503
exec /opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_heartbeat.py
BASH
chmod 0755 /opt/lab/bin/run-safety-heartbeat.sh

cat >/opt/lab/bin/run-stage3-safety-loop.sh <<'BASH'
#!/usr/bin/env bash
set -e
export HOME=/root
export ROS_LOG_DIR=/var/lab/log/ros
mkdir -p "${ROS_LOG_DIR}"
set +u
source /opt/ros/humble/setup.bash
set -u
export ROS_DOMAIN_ID=0
export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/production_plc
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
exec /opt/lab/venv-traffic/bin/python /vagrant/infra/tests/stage3_safety_loop.py
BASH
chmod 0755 /opt/lab/bin/run-stage3-safety-loop.sh

cat >/opt/lab/bin/run-stage3-sros2-authn.sh <<'BASH'
#!/usr/bin/env bash
set -e
export HOME=/root
export ROS_LOG_DIR=/var/lab/log/ros
mkdir -p "${ROS_LOG_DIR}"
set +u
source /opt/ros/humble/setup.bash
set -u
export ROS_DOMAIN_ID=0
# Intentionally no ROS_SECURITY_* — this test must run unsigned.
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
exec /opt/lab/venv-traffic/bin/python /vagrant/infra/tests/stage3_sros2_authn.py
BASH
chmod 0755 /opt/lab/bin/run-stage3-sros2-authn.sh
cp -f /vagrant/vm-ot/sros2/safety_supervisor.py /opt/lab/vm-ot/sros2/
cp -f /vagrant/vm-ot/sros2/safety_heartbeat.py  /opt/lab/vm-ot/sros2/

say "=== cert subjects (must match <subject_name> in permissions.xml) ==="
for ENC in safety_supervisor production_plc ai_subscriber cyclic_motion; do
    C=/opt/lab/sros2_keystore/enclaves/lab/${ENC}/cert.pem
    SUBJ=$(openssl x509 -in "${C}" -noout -subject 2>&1)
    PERM_SUBJ=$(grep -o 'subject_name>[^<]*<' /opt/lab/sros2_keystore/enclaves/lab/${ENC}/permissions.xml | head -1 | sed 's/subject_name>//;s/<$//')
    say "  ${ENC}: cert=${SUBJ}; perms=${PERM_SUBJ}"
done

say "=== verify each permissions.p7s decodes + contains expected topics ==="
PERM_CA=/opt/lab/sros2_keystore/public/permissions_ca.cert.pem
for ENC in safety_supervisor production_plc ai_subscriber cyclic_motion; do
    P=/opt/lab/sros2_keystore/enclaves/lab/${ENC}/permissions.p7s
    XML=$(openssl smime -verify -in "${P}" -CAfile "${PERM_CA}" 2>/dev/null)
    VRC=$?
    if [[ ${VRC} -ne 0 ]]; then
        say "  ${ENC}: p7s SIGNATURE VERIFY FAILED (rc=${VRC})"
        continue
    fi
    if echo "${XML}" | grep -q "<dds"; then
        ROOT_OK="root=<dds>"
    else
        ROOT_OK="root=NOT-DDS!"
    fi
    if echo "${XML}" | grep -q "rt/safety/request"; then
        FOUND="rt/safety/request: yes"
    else
        FOUND="rt/safety/request: no"
    fi
    say "  ${ENC}: signature OK; ${ROOT_OK}; ${FOUND}"
done

say "=== decoded XML of safety_supervisor (first 30 lines) ==="
openssl smime -verify -in /opt/lab/sros2_keystore/enclaves/lab/safety_supervisor/permissions.p7s \
    -CAfile "${PERM_CA}" 2>/dev/null | head -30 | tee -a "${LOG}"

say "=== restart services ==="
run systemctl restart lab-safety-supervisor lab-safety-heartbeat
sleep 6

say "=== supervisor health check ==="
SUP_ACTIVE=$(systemctl is-active lab-safety-supervisor 2>&1)
say "  is-active: ${SUP_ACTIVE}"
say "  --- last 20 lines of /var/lab/log/lab-safety-supervisor.log ---"
tail -20 /var/lab/log/lab-safety-supervisor.log 2>&1 | tee -a "${LOG}"
say "  --- last 20 journalctl lines ---"
journalctl -u lab-safety-supervisor -n 20 --no-pager 2>&1 | tee -a "${LOG}"
if [[ "${SUP_ACTIVE}" != "active" ]]; then
    say "STAGE 3: FAIL — supervisor is not active after restart; gates skipped"
    exit 1
fi

say "=== GATE 1: safety loop ==="
LOG_BEFORE=$(wc -c < /var/lab/log/lab-safety-supervisor.log 2>/dev/null || echo 0)
# Out-of-band watchdog: even if `timeout` fails to kill the test (which
# we've observed under SROS2 Enforce when DDS C-threads block signals),
# this background process will SIGKILL the python by name after 14s.
( sleep 20 ; pkill -9 -f stage3_safety_loop >/dev/null 2>&1 || true ) &
WD1=$!
run timeout --kill-after=3 -s TERM 16 /opt/lab/bin/run-stage3-safety-loop.sh
RC1=$?
kill ${WD1} >/dev/null 2>&1 || true
wait ${WD1} 2>/dev/null || true
say "[GATE1 exit=${RC1}]"
pkill -9 -f stage3_safety_loop >/dev/null 2>&1 || true

LOG_AFTER=$(wc -c < /var/lab/log/lab-safety-supervisor.log 2>/dev/null || echo 0)
DELTA=$(( LOG_AFTER - LOG_BEFORE ))
say "--- supervisor log delta during gate1 (${DELTA} bytes) ---"
if [[ ${DELTA} -gt 0 ]]; then
    tail -c "${DELTA}" /var/lab/log/lab-safety-supervisor.log | tee -a "${LOG}"
fi
say "------------------------------------------------------------"

say "=== restart services (clear EMERGENCY latch) ==="
run systemctl restart lab-safety-supervisor lab-safety-heartbeat
sleep 6

say "=== GATE 2: SROS2 authn rejection ==="
( sleep 14 ; pkill -9 -f stage3_sros2_authn >/dev/null 2>&1 || true ) &
WD2=$!
run timeout --kill-after=3 -s TERM 10 /opt/lab/bin/run-stage3-sros2-authn.sh
RC2=$?
kill ${WD2} >/dev/null 2>&1 || true
wait ${WD2} 2>/dev/null || true
say "[GATE2 exit=${RC2}]"
pkill -9 -f stage3_sros2_authn >/dev/null 2>&1 || true

say "=== DONE ==="
if [[ ${RC1} -eq 0 && ${RC2} -eq 0 ]]; then
    say "STAGE 3 OVERALL: PASS"
    say "===END==="
    exit 0
fi
say "STAGE 3 OVERALL: FAIL (gate1=${RC1} gate2=${RC2})"
say "===END==="
exit 1
