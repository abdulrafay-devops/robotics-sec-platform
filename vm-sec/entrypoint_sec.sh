#!/usr/bin/env bash
# Entrypoint for security monitoring container (container-sec)
set -euo pipefail

# Ensure logging and state directories exist
mkdir -p /var/lab/log/zeek /var/lab/log/suricata /var/lab/state/zeek-spool /var/log/suricata

# Remove any stale attack trigger file left over from a previous run.
# Without this, the watch_attack_triggers loop below would immediately re-launch
# an attack every time the container restarts, causing the dashboard to show
# "ELEVATED" threat level and spurious anomaly alerts on every boot.
rm -f /var/lab/state/attack_trigger.json
echo "Cleared stale attack_trigger.json (if any)."

# Dynamically detect interfaces by checking subnet IP assignments
# `|| true` so a missing zone (e.g. SEC is single-homed now and not on the DMZ)
# does not abort the script under `set -o pipefail` when grep finds no match.
OT_IF=$(ip -o -4 addr show | grep '192.168.10.' | awk '{print $2}' | head -n 1 || true)
DMZ_IF=$(ip -o -4 addr show | grep '192.168.30.' | awk '{print $2}' | head -n 1 || true)
MGMT_IF=$(ip -o -4 addr show | grep '192.168.40.' | awk '{print $2}' | head -n 1 || true)

# Fallbacks in case dynamic detection fails
OT_IF=${OT_IF:-"eth0"}
DMZ_IF=${DMZ_IF:-"eth0"}
MGMT_IF=${MGMT_IF:-"eth1"}

# ── IDMZ: SEC is SINGLE-HOMED on the OT segment (its only NIC is the OT one). It
# participates on OT so it can BOTH generate the baseline read traffic AND sniff
# it — a Docker user-defined bridge does NOT mirror third-party unicast to a
# passive port (verified empirically), so a true IP-less SPAN tap would see
# nothing; the monitor must be a party to the traffic (in a real plant this role
# is a hardware SPAN/TAP port). SEC no longer carries a second NIC into mgmt, so a
# compromised SEC can no longer pivot into the management zone — the router is now
# the ONLY multi-homed container, as a true IDMZ should be.
ip link set "${OT_IF}" promisc on 2>/dev/null || true

# SEC's only mgmt dependency is shipping ML features to the AI Redis (40.30). With
# no mgmt NIC, reach it through the router via the single SEC-scoped firewall
# conduit (OT 10.20 -> mgmt 40.30:6379) instead of a second interface.
ip route replace 192.168.40.0/24 via 192.168.10.2 2>/dev/null || true

echo "Detected OT interface: ${OT_IF}"
echo "Detected DMZ interface: ${DMZ_IF}"
echo "Detected MGMT interface: ${MGMT_IF}"

# Render Zeek configuration
echo "Configuring Zeek..."
sed -e "s|@@SPAN_OT_IF@@|${OT_IF}|g" \
    -e "s|@@SPAN_DMZ_IF@@|${DMZ_IF}|g" \
    /opt/zeek/etc/node.cfg.tpl > /opt/zeek/etc/node.cfg

if [ -f /vagrant/vm-sec/zeek/local.zeek ]; then
    echo "Syncing Zeek site scripts from /vagrant to /opt/zeek/share/zeek/site/"
    cp -f /vagrant/vm-sec/zeek/local.zeek /opt/zeek/share/zeek/site/local.zeek
    cp -f /vagrant/vm-sec/zeek/scripts/modbus-features.zeek /opt/zeek/share/zeek/site/modbus-features.zeek
    cp -f /vagrant/vm-sec/zeek/scripts/dnp3-features.zeek   /opt/zeek/share/zeek/site/dnp3-features.zeek || true
    cp -f /vagrant/vm-sec/zeek/scripts/opcua-features.zeek  /opt/zeek/share/zeek/site/opcua-features.zeek || true
fi

# Render Suricata configuration
echo "Configuring Suricata..."
if [ -f /etc/suricata/suricata.yaml ]; then
    sed -i -e "s|@@SPAN_OT_IF@@|${OT_IF}|g" \
           -e "s|@@SPAN_DMZ_IF@@|${DMZ_IF}|g" \
           /etc/suricata/suricata.yaml
fi

# Render ntopng configuration
echo "Configuring ntopng..."
if [ -f /opt/lab/vm-sec/ntopng/ntopng.conf ]; then
    sed -e "s|@@SPAN_OT_IF@@|${OT_IF}|g" \
        -e "s|@@SPAN_DMZ_IF@@|${DMZ_IF}|g" \
        -e "s|@@MGMT_IF@@|${MGMT_IF}|g" \
        -e "s|192.168.40.20|0.0.0.0|g" \
        /opt/lab/vm-sec/ntopng/ntopng.conf > /etc/ntopng.conf
    # container-ai runs Redis with requirepass, so ntopng must authenticate or
    # it gets NOAUTH and exits (web UI on :3001 down). ntopng's -r option format
    # is host:port:password@db — inject the password into the rendered config.
    if [ -n "${LAB_REDIS_PASSWORD:-}" ]; then
        sed -i -E "s|^-r=([^@[:space:]]+)@([0-9]+)|-r=\1:${LAB_REDIS_PASSWORD}@\2|" /etc/ntopng.conf
        echo "ntopng: injected Redis password into -r directive"
    fi
fi

# Start Zeek via zeekctl
echo "Deploying Zeek..."
rm -rf /var/lab/log/zeek/current || true
/opt/zeek/bin/zeekctl install || true
/opt/zeek/bin/zeekctl deploy || echo "Zeek deploy completed with warnings/errors"

# Ensure the log file exists inside the symlinked directory so that feature_pusher doesn't crash on startup
mkdir -p /var/lab/state/zeek-spool/manager
touch /var/lab/state/zeek-spool/manager/modbus_features.log
touch /var/lab/state/zeek-spool/manager/dnp3_features.log || true
touch /var/lab/state/zeek-spool/manager/opcua_features.log || true

# Confirm scripts are referenced by Zeek site policy
if grep -q "dnp3-features.zeek" /opt/zeek/share/zeek/site/local.zeek && \
   grep -q "opcua-features.zeek" /opt/zeek/share/zeek/site/local.zeek; then
    echo "Zeek: dnp3-features.zeek and opcua-features.zeek are configured to load."
else
    echo "Zeek WARNING: dnp3/opcua feature scripts not referenced in local.zeek"
fi

# Start Suricata
echo "Starting Suricata..."
# Set up a base signature rule if needed (e.g. empty or copy from vm-sec rules)
mkdir -p /etc/suricata/rules
if [ -d /opt/lab/vm-sec/suricata/rules ]; then
    cp -rf /opt/lab/vm-sec/suricata/rules/* /etc/suricata/rules/ || true
fi
touch /var/lab/log/suricata/eve.json
suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -i ${OT_IF} > /var/log/suricata/suricata-startup.log 2>&1 &

# Configure ntopng admin login from .env.
# The credential is written to Redis before ntopng starts. Retrying here avoids
# continuing with a stale value from a persistent Redis volume.
echo "Configuring ntopng admin credential from NTOPNG_ADMIN_PASSWORD..."
attempt=1
while [ "$attempt" -le 10 ]; do
    if /opt/lab/venv-shipper/bin/python /opt/lab/vm-sec/ntopng/seed_admin.py; then
        break
    fi
    if [ "$attempt" -eq 10 ]; then
        echo "ntopng credential configuration failed after ${attempt} attempts" >&2
        exit 1
    fi
    echo "ntopng credential configuration attempt ${attempt} failed; retrying..." >&2
    attempt=$((attempt + 1))
    sleep 2
done

# Start ntopng
echo "Starting ntopng..."
mkdir -p /var/run/ntopng /var/lib/ntopng
ntopng /etc/ntopng.conf > /var/log/ntopng.log 2>&1 &

# Wait for Zeek current directory structure to form
sleep 5

# Start log shipper feature_pusher.py
echo "Starting Modbus feature log shipper..."
export LAB_FEATURES_LOG=/var/lab/log/zeek/current/modbus_features.log
export LAB_REDIS_HOST=192.168.40.30
export LAB_REDIS_PORT=6379
export LAB_REDIS_RAW_LIST=lab.modbus.features.raw
export LAB_LOG_LEVEL=INFO

# Ensure Python shipper can execute
/opt/lab/venv-shipper/bin/python /opt/lab/log_shipper/feature_pusher.py > /var/lab/log/lab-feature-pusher.log 2>&1 &

# Setup Stage 4 Vulnerability scanner background scheduler
echo "Starting Stage 4 Vulnerability Scanner loop..."
# Running it in a background loop instead of cron to keep the container self-contained and stable
run_vuln_scans() {
    while true; do
        echo "Running scheduled Stage 4 vulnerability scans..."
        /opt/lab/venv-shipper/bin/python /opt/lab/vm-sec/vuln/inventory.py --no-active || true
        /opt/lab/venv-shipper/bin/python /opt/lab/vm-sec/vuln/cve_correlate.py || true
        # Note: baseline_check.py is run inside container-ot because SROS2 & iptables reside there
        # Run every 600 seconds (10 minutes) for testing, instead of 24h
        sleep 600
    done
}
run_vuln_scans > /var/lab/log/lab-vuln-scan.log 2>&1 &

# The active scanner is separate from passive recurring scans. It wakes up
# periodically, but safe_active_scan.py permits only one nmap run per approved
# maintenance-window occurrence and never retries a failed window automatically.
echo "Starting governed safe active-scan scheduler..."
run_safe_active_scan_scheduler() {
    local poll_seconds="${LAB_SAFE_ACTIVE_SCAN_POLL_SECONDS:-300}"
    if ! [[ "${poll_seconds}" =~ ^[0-9]+$ ]] || (( poll_seconds < 60 || poll_seconds > 3600 )); then
        echo "Invalid LAB_SAFE_ACTIVE_SCAN_POLL_SECONDS=${poll_seconds}; using 300 seconds"
        poll_seconds=300
    fi

    while true; do
        /opt/lab/venv-shipper/bin/python /opt/lab/vm-sec/vuln/safe_active_scan.py \
            --scheduled --execute --policy /opt/lab/vm-sec/vuln/active_scan_policy.yml \
            --state-dir /var/lab/state || echo "Governed active scan reported an error; no repeat scan will run this window."
        sleep "${poll_seconds}"
    done
}
run_safe_active_scan_scheduler > /var/lab/log/lab-safe-active-scan.log 2>&1 &

# Start Modbus Traffic baseline generator
echo "Starting Modbus baseline generator..."
mkdir -p /var/lab/log
/opt/lab/venv-shipper/bin/python /opt/lab/vm-ot/traffic/modbus_normal.py --host 192.168.10.10 --port 502 --rate-hz 1 > /var/lab/log/lab-traffic-modbus.log 2>&1 &

# Start background attack trigger watcher loop
echo "Starting Stage 2 Attack Trigger watcher loop..."
watch_attack_triggers() {
    mkdir -p /var/lab/state
    while true; do
        if [ -f /var/lab/state/attack_trigger.json ]; then
            echo "Attack trigger file found. Parsing attack parameters..."
            ATTACK_TYPE=$(/opt/lab/venv-shipper/bin/python -c "import json; print(json.load(open('/var/lab/state/attack_trigger.json'))['attack_type'])")
            DURATION=$(/opt/lab/venv-shipper/bin/python -c "import json; print(json.load(open('/var/lab/state/attack_trigger.json'))['duration_s'])")
            RATE=$(/opt/lab/venv-shipper/bin/python -c "import json; print(json.load(open('/var/lab/state/attack_trigger.json'))['rate_hz'])")
            
            # Immediately delete the trigger file
            rm -f /var/lab/state/attack_trigger.json
            
            echo "Launching attack locally on container-sec: type=$ATTACK_TYPE duration=$DURATION rate=$RATE"
            # All 7 Modbus techniques run as REAL attacks from the SEC sensor so
            # they flow through Zeek -> feature_consumer -> the IR classifier and
            # produce a correctly MITRE-tagged incident (same path the harness
            # validates). The 3 originals use their dedicated scripts; the 4 added
            # in the Step 2 library run via attack_modbus_extra.py's modes.
            EXTRA=/opt/lab/vm-ot/traffic/attack_modbus_extra.py
            if [ "$ATTACK_TYPE" = "modbus_command_injection" ]; then
                /opt/lab/venv-shipper/bin/python /opt/lab/vm-ot/traffic/attack_modbus_inject.py --host 192.168.10.10 --duration-s "$DURATION" --rate-hz "$RATE" > /var/lab/log/lab-attack-injection.log 2>&1 &
            elif [ "$ATTACK_TYPE" = "modbus_replay" ]; then
                /opt/lab/venv-shipper/bin/python /opt/lab/vm-ot/traffic/attack_modbus_replay.py --host 192.168.10.10 --duration-s "$DURATION" --multiplier 5 > /var/lab/log/lab-attack-replay.log 2>&1 &
            elif [ "$ATTACK_TYPE" = "coil_flood" ]; then
                /opt/lab/venv-shipper/bin/python /opt/lab/vm-ot/traffic/attack_modbus_flood.py --host 192.168.10.10 --duration-s "$DURATION" --rate-hz "$RATE" > /var/lab/log/lab-attack-flood.log 2>&1 &
            elif [ "$ATTACK_TYPE" = "register_scan" ]; then
                /opt/lab/venv-shipper/bin/python "$EXTRA" --host 192.168.10.10 --mode recon --duration-s "$DURATION" --rate-hz "$RATE" > /var/lab/log/lab-attack-recon.log 2>&1 &
            elif [ "$ATTACK_TYPE" = "safety_tamper" ]; then
                /opt/lab/venv-shipper/bin/python "$EXTRA" --host 192.168.10.10 --mode estop --duration-s "$DURATION" --rate-hz "$RATE" > /var/lab/log/lab-attack-estop.log 2>&1 &
            elif [ "$ATTACK_TYPE" = "setpoint_drift" ]; then
                /opt/lab/venv-shipper/bin/python "$EXTRA" --host 192.168.10.10 --mode drift --duration-s "$DURATION" --rate-hz "$RATE" > /var/lab/log/lab-attack-drift.log 2>&1 &
            elif [ "$ATTACK_TYPE" = "bulk_write" ]; then
                /opt/lab/venv-shipper/bin/python "$EXTRA" --host 192.168.10.10 --mode bulk --duration-s "$DURATION" --rate-hz "$RATE" > /var/lab/log/lab-attack-bulk.log 2>&1 &
            else
                echo "Unknown attack type: $ATTACK_TYPE"
            fi
        fi
        sleep 0.5
    done
}
watch_attack_triggers > /var/lab/log/lab-attack-watcher.log 2>&1 &

echo "All Security services started. Keeping container alive."
tail -f /var/lab/log/lab-feature-pusher.log
