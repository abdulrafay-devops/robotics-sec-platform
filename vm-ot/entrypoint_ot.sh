#!/usr/bin/env bash
# Entrypoint for secure OT container (container-ot)
set -euo pipefail

# Configure safety supervisor alias IP on eth0 if not already present.
# Needs cap_add: [NET_ADMIN] in docker-compose.yml to run successfully.
if [ -d /sys/class/net/eth0 ]; then
    echo "Configuring alias IP 192.168.10.11 on eth0..."
    ip addr add 192.168.10.11/24 dev eth0 label eth0:safety || echo "Alias IP already assigned or insufficient privileges."
fi

# ── IDMZ: OT single-homed on ot-net (internal). Route all cross-zone traffic
# (e.g. OT -> DMZ artifact store) through the router/firewall. ───────────────
ip route replace default via 192.168.10.2 2>/dev/null \
    && echo "IDMZ: default route via router (192.168.10.2) installed" \
    || echo "IDMZ: could not install default route (need NET_ADMIN)"

# ── IDMZ: L7 Modbus READ-ONLY proxy in front of the PLC (port 5020). The AI reads
# telemetry through this; the router denies AI->PLC:502 direct, and writes go via
# the control gateway. Auto-restart loop; runs from the mounted workspace. ─────
( while true; do
    LAB_MBPROXY_PORT=5020 LAB_PLC_HOST=127.0.0.1 LAB_PLC_PORT=502 \
        python3 /vagrant/vm-ot/modbus_read_proxy.py >> /var/lab/log/modbus-read-proxy.log 2>&1
    echo "$(date -u +%FT%TZ) modbus_read_proxy exited; restarting in 2s" >> /var/lab/log/modbus-read-proxy.log
    sleep 2
done ) &

# Enforce network segregation: OT zone must NOT reach Guacamole web interface in DMZ
# And add iptables rules to comply with Stage 4 baseline checks
if command -v iptables >/dev/null 2>&1; then
    echo "Configuring network segregation iptables rules..."
    iptables -N LAB_LOGREJ || true
    iptables -A LAB_LOGREJ -m limit --limit 5/min -j LOG --log-prefix 'LAB-FW: ' --log-level 4 || true
    iptables -A LAB_LOGREJ -j REJECT --reject-with icmp-port-unreachable || true
    
    iptables -A INPUT -p tcp --dport 8080 -s 192.168.40.0/24 -j ACCEPT || true
    iptables -A INPUT -s 192.168.20.0/24 -j LAB_LOGREJ || true
    iptables -A INPUT -p tcp --dport 503 -s 192.168.10.10 -j ACCEPT || true
    iptables -A OUTPUT -d 192.168.30.20 -p tcp --dport 8080 -j REJECT || echo "Failed to apply iptables rule."
fi

# Ensure logging and state directories exist
mkdir -p /var/lab/log/ros /var/lab/state /var/log
mkdir -p /var/lab/state/logs
chmod 0777 /var/lab/state/logs
echo "openplc program started and logging to syslog active" > /var/log/syslog

# Rotate the local RDP and OpenPLC passwords before either service accepts a login.
# Missing or weak values stop this OT container rather than restoring a demo default.
/opt/lab/bin/configure_runtime_credentials.py

# Minimal restart-supervision (mirrors vm-ai/entrypoint_ai.sh). Keeps a critical
# safety process alive across crashes so a transient failure (e.g. a momentary
# heartbeat TCP blip, or the heartbeat process dying) cannot leave the heartbeat
# dead and thus permanently latch the safety watchdog into EMERGENCY.
supervise() {
    local name="$1"; local logf="$2"; local cmd="$3"
    (
        while true; do
            echo "$(date -u +%FT%TZ) [supervisor] starting ${name}" >> "$logf"
            bash -c "$cmd" >> "$logf" 2>&1
            rc=$?
            echo "$(date -u +%FT%TZ) [supervisor] ${name} exited (rc=${rc}); restarting in 3s" >> "$logf"
            sleep 3
        done
    ) &
}

# Keep GUI/Gazebo helper scripts live-editable from the mounted workspace.
if [ -d /vagrant/vm-ot/gazebo ]; then
    mkdir -p /opt/lab/vm-ot/gazebo
    cp -rf /vagrant/vm-ot/gazebo/* /opt/lab/vm-ot/gazebo/ 2>/dev/null || true
    chmod +x /opt/lab/vm-ot/gazebo/start_gazebo_gui.sh \
        /opt/lab/vm-ot/gazebo/joint_state_to_gazebo.py 2>/dev/null || true
fi

# Keep SROS2 helper scripts live-editable from the mounted workspace.
if [ -d /vagrant/vm-ot/sros2 ]; then
    mkdir -p /opt/lab/vm-ot/sros2
    cp -rf /vagrant/vm-ot/sros2/* /opt/lab/vm-ot/sros2/ 2>/dev/null || true
    chmod +x /opt/lab/vm-ot/sros2/*.py /opt/lab/vm-ot/sros2/*.sh 2>/dev/null || true
fi

# Start the RDP desktop endpoint used by Apache Guacamole.
if command -v xrdp >/dev/null 2>&1; then
    echo "Starting OT RDP desktop for Guacamole (port 3389, DMZ only)..."
    mkdir -p /var/run/dbus /run/xrdp
    rm -f /var/run/xrdp/*.pid /run/xrdp/*.pid 2>/dev/null || true
    dbus-daemon --system --fork || true
    /usr/sbin/xrdp-sesman || true
    /usr/sbin/xrdp || true
fi

# Generate/Bootstrap SROS2 Keystore. NOTE: this enforces PKI *authentication*
# (every DDS participant must present a CA-signed certificate). Topic-level
# *authorization* (ACLs) is currently left at the permissive default - see the
# design note in bootstrap_keystore.sh for why and how to enable it.
if [ -f /opt/lab/vm-ot/sros2/bootstrap_keystore.sh ]; then
    echo "Bootstrapping SROS2 keystore..."
    export LAB_SROS2_KEYSTORE=/opt/lab/sros2_keystore
    export LAB_SROS2_TEMPLATE_DIR=/opt/lab/vm-ot/sros2/permissions
    export ROS_SETUP=/opt/ros/humble/setup.bash
    cd /opt/lab/vm-ot/sros2 && bash bootstrap_keystore.sh
    chmod 0750 /opt/lab/sros2_keystore
fi

# Create service wrappers to comply with Stage 4 baseline checks
mkdir -p /opt/lab/bin

cat >/opt/lab/bin/run-safety-supervisor.sh <<'BASH'
#!/usr/bin/env bash
set -e
export HOME=/root
export ROS_LOG_DIR=/var/lab/log/ros
mkdir -p "${ROS_LOG_DIR}"
set +u
source /opt/ros/humble/setup.bash
set -u
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export ROS_DOMAIN_ID=0
export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/safety_supervisor
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
export LAB_SAFETY_HOST=0.0.0.0
export LAB_SAFETY_PORT=503
# Runs the real safety brain (watchdog/latch/replay) as the :503 Modbus server.
exec /opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_supervisor.py --modbus-only
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
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
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


# Start Production OpenPLC
echo "Starting Production OpenPLC (Modbus port 502, Web port 8080)..."
/opt/lab/openplc/start_openplc.sh > /var/lab/state/logs/openplc.log 2>&1 &

# After OpenPLC starts, generate and persist trusted integrity baseline
(
  sleep 10
  echo "Generating trusted integrity baseline..."
  /usr/bin/env python3 /vagrant/vm-sec/vuln/integrity_baseline.py || true
) &

# Start the Safety Supervisor as the :503 Modbus server (audit fix - "Guard A").
# This replaces the previous stand-in sim_safety_plc.py (which had NO heartbeat
# watchdog, NO latching, NO replay guard). It runs in --modbus-only mode so that
# safety_bridge.py below remains the single SROS2 node; this process provides the
# real safety brain (heartbeat watchdog, latched E-stop, replay/regression guard)
# on port 503, fed by safety_heartbeat.py's 5 Hz heartbeat.
echo "Starting Safety Supervisor (Modbus port 503: watchdog + latch + replay)..."
supervise "safety-supervisor" /var/lab/state/logs/lab-safety-supervisor.log \
    "/opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_supervisor.py --modbus-only"

# Wait for safety PLC to start
sleep 2

# Set ROS2 env vars for secured nodes
export HOME=/root
export ROS_LOG_DIR=/var/lab/log/ros
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export ROS_DOMAIN_ID=0
export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml

# Source ROS2 Humble setup
set +u
source /opt/ros/humble/setup.bash
set -u

# Start Safety Bridge (the single SROS2 node: subscribes /safety/request,
# publishes /safety/state, and MIRRORS the supervisor's safety state from :503
# onto the production PLC :502 so the cell halts and the dashboard reflects it).
# The safety decision logic itself lives in the supervisor process started above.
echo "Starting SROS2 Safety Bridge..."
export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/safety_supervisor
export LAB_SAFETY_HOST=127.0.0.1
export LAB_SAFETY_PORT=503
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
supervise "safety-bridge" /var/lab/state/logs/lab-safety-bridge.log \
    "/opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_bridge.py --plc-host 127.0.0.1 --plc-port 503"

# Start Safety Heartbeat
echo "Starting SROS2 Safety Heartbeat..."
export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/production_plc
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
supervise "safety-heartbeat" /var/lab/state/logs/lab-safety-heartbeat.log \
    "/opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_heartbeat.py"

# OT-zone control gateway (audit F-02): owns Modbus writes to the LOCAL PLC so
# the analytics tier can be read-only. It is dormant unless score_service is told
# to use it (LAB_CONTROL_GATEWAY_URL) — running it here is harmless either way.
# Sourced from the bind-mounted repo so it is always present.
supervise "control-gateway" /var/lab/state/logs/lab-control-gateway.log \
    "/opt/lab/venv-traffic/bin/python /vagrant/vm-ot/control_gateway.py --port 8002"

# Verify SROS2 keystore/enclave ACLs are loaded at runtime
echo "Verifying SROS2 security enclaves..."
if command -v ros2 >/dev/null 2>&1; then
    set +e
    ros2 security list_enclaves 2>/dev/null | tee /var/lab/state/logs/sros2-enclaves.txt || true
    set -e
fi

# Start Gazebo server, spawned robot, Gazebo joint bridge, and cyclic motion.
echo "Starting headless Gazebo lab cell and SROS2 cyclic motion publisher..."
export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/cyclic_motion
if command -v ros2 >/dev/null 2>&1 && command -v gzserver >/dev/null 2>&1; then
    export LAB_GAZEBO_DIR=/opt/lab/vm-ot/gazebo
    export LIBGL_ALWAYS_SOFTWARE=1
    export QT_X11_NO_MITSHM=1
    ros2 launch /opt/lab/vm-ot/gazebo/launch.py > /var/lab/log/gazebo-launch.log 2>&1 &
else
    echo "Gazebo packages not available; falling back to telemetry-only cyclic motion."
    export ROS_SECURITY_ENABLE=false
    python3 /opt/lab/vm-ot/gazebo/cyclic_motion.py --ros-args -p rate_hz:=10.0 -p cycle_seconds:=6.0 -r __ns:=/lab_arm > /var/lab/log/cyclic_motion.log 2>&1 &
    # Passive joint-telemetry tap for the robot-behavior plane (best-effort). With
    # security disabled it pairs with the fallback cyclic_motion above; Modbus-based
    # E-stop in cyclic_motion is unaffected by the DDS security setting.
    ROS_SECURITY_ENABLE=false python3 /opt/lab/vm-ot/gazebo/joint_telemetry_bridge.py > /var/lab/log/joint-telemetry-bridge.log 2>&1 &
fi

# Note: Modbus Traffic baseline generator has been relocated to container-sec 
# to ensure traffic passes through the Docker L2 network bridge rather than 
# looping back internally on localhost. This allows Zeek to sniff the traffic.

# Start background baseline checker loop
echo "Starting Stage 4 Configuration Baseline loop..."
run_baseline_loop() {
    # Wait for enclaves and OpenPLC to fully bootstrap first
    sleep 8
    while true; do
        echo "Running scheduled OT configuration baseline check..."
        export ROS_SECURITY_STRATEGY=Enforce
        export ROS_DOMAIN_ID=0
        export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml
        python3 /vagrant/vm-sec/vuln/baseline_check.py || true
        sleep 600
    done
}
run_baseline_loop > /var/lab/log/lab-baseline-loop.log 2>&1 &

# Start SROS2 background watcher for HMI simulated DDS estop requests
watch_sros2_triggers() {
    sleep 5
    _ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
    echo "$(_ts) [sros2-watcher] STARTED - monitoring the DDS/SROS2 cryptographic e-stop path"
    echo "$(_ts) [sros2-watcher] keystore=/opt/lab/sros2_keystore  enclave=/lab/production_plc"
    echo "$(_ts) [sros2-watcher] DDS-Security=Enforce  rmw=cyclonedds  domain=0"
    echo "$(_ts) [sros2-watcher] ARMED - awaiting authenticated e-stop requests (trigger: /var/lab/state/sros2_estop_trigger)"
    i=0
    while true; do
        if [ -f /var/lab/state/sros2_estop_trigger ]; then
            echo "$(_ts) [sros2-watcher] HMI requested SROS2 cryptographic E-Stop - verifying enclave + signature..."
            rm -f /var/lab/state/sros2_estop_trigger

            export HOME=/root
            export ROS_LOG_DIR=/var/lab/log/ros
            export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
            export ROS_DOMAIN_ID=0
            export ROS_SECURITY_KEYSTORE=/opt/lab/sros2_keystore
            export ROS_SECURITY_ENABLE=true
            export ROS_SECURITY_STRATEGY=Enforce
            export ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/production_plc
            export CYCLONEDDS_URI=file:///opt/lab/vm-ot/sros2/cyclonedds.xml

            set +u
            source /opt/ros/humble/setup.bash
            set -u
            if /opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/safety_heartbeat.py --request-estop; then
                echo "$(_ts) [sros2-watcher] OK - signed E-Stop published to the safety supervisor over SROS2 (DDS-Security Enforce)"
            else
                echo "$(_ts) [sros2-watcher] FAILED - SROS2 e-stop request rejected (signature/keystore/enclave error)"
            fi
        fi
        i=$((i + 1))
        # Liveness heartbeat every ~20s so the operator console shows the watcher is
        # actively armed even when no e-stop has been requested.
        if [ $((i % 40)) -eq 0 ]; then
            echo "$(_ts) [sros2-watcher] heartbeat - armed, DDS-Security Enforce, $((i / 2))s monitored, no unauthorized e-stop attempts"
        fi
        sleep 0.5
    done
}
watch_sros2_triggers > /var/lab/state/logs/lab-sros2-watcher.log 2>&1 &

# Start background OT services monitor to share process status with other containers
echo "Starting OT services monitor daemon..."
/opt/lab/venv-traffic/bin/python /opt/lab/vm-ot/sros2/ot_services_monitor.py > /var/lab/state/logs/ot-services-monitor.log 2>&1 &

# Keep container running by tailing openplc log
echo "All secure OT services are operational."
tail -f /var/lab/state/logs/openplc.log
