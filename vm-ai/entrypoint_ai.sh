#!/usr/bin/env bash
# Entrypoint for deep learning and monitoring container (container-ai)
set -euo pipefail

# Ensure logging and state directories exist
mkdir -p /opt/lab/models /var/lab/log /var/lab/state/ir/postmortems /var/lab/evidence /var/lab/artifacts /var/lab/log/pipeline /var/lab/ingest /var/lab/log/ros

# ── IDMZ: single-homed on mgmt-net ───────────────────────────────────────────
# Reach the OT zone (Modbus read-only proxy :5020 + control gateway :8002) ONLY
# via the router/firewall. AI has no route to OT except through the firewall, and
# the firewall denies AI->PLC:502 direct. (cap_add NET_ADMIN set in compose.)
for _net in 192.168.10.0/24 192.168.20.0/24 192.168.30.0/24; do
    ip route replace "$_net" via 192.168.40.2 2>/dev/null || true
done
echo "IDMZ: routes to OT/IT/DMZ zones via router (192.168.40.2) installed"

# ── Minimal restart-supervision (audit F-07) ────────────────────────────────
# Each core service runs in a small restart loop so that a crash is
# auto-recovered instead of silently vanishing while the container still looks
# "up". Intentionally simple: no extra supervisor daemon, no behaviour change to
# the services themselves.
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

# ── Clean stale session state from previous runs (OPTIONAL) ──────────────────
# These files live on persistent volumes (ai-logs, lab-state). Wiping them makes
# the dashboard start blank, which is convenient for a fresh demo. Hardening
# (audit F-07): this is now OPT-OUT. Set LAB_RESET_STATE=0 in the environment to
# PRESERVE the incident/alert history and forensic trail across restarts.
if [ "${LAB_RESET_STATE:-1}" = "1" ]; then
    echo "Clearing stale session state from previous run (LAB_RESET_STATE=1)..."

    # Hardening (audit F-07): never DESTROY the audit/forensic trail. Before
    # wiping for a blank demo start, copy the incident/alert records into a
    # timestamped archive so history is preserved, only set aside. Best-effort:
    # every step is guarded so it can never fail the (set -e) entrypoint.
    _ARCHIVE="/var/lab/log/archive/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "${_ARCHIVE}" 2>/dev/null || true
    cp -f /var/lab/log/ai-alerts.json            "${_ARCHIVE}/" 2>/dev/null || true
    cp -f /var/lab/state/ir/incidents.jsonl      "${_ARCHIVE}/" 2>/dev/null || true
    cp -f /var/lab/state/ir/pending_approvals.json "${_ARCHIVE}/" 2>/dev/null || true
    rmdir "${_ARCHIVE}" 2>/dev/null || true   # remove the dir again if nothing was archived

    # Alert log — the Security page and playbook engine read this
    truncate -s 0 /var/lab/log/ai-alerts.json 2>/dev/null || true

    # Incident and approval state — the Incidents page and StagesPage read these
    rm -f /var/lab/state/ir/incidents.jsonl
    rm -f /var/lab/state/ir/pending_approvals.json
    rm -f /var/lab/state/ir/ir_engine_offset.json
    rm -f /var/lab/state/ir/drift_seen.json

    # Live score cache — Grafana and the dashboard sparkline read this
    rm -f /var/lab/state/latest_scores.json

    # Injection state — prevents the "injection active" indicator being stuck on
    rm -f /var/lab/state/last_injection.json
    rm -f /var/lab/state/attack_trigger.json

    echo "Session state cleared."
else
    echo "LAB_RESET_STATE=0 — preserving incident/alert history across restart."
fi
# ────────────────────────────────────────────────────────────────────────────

# Start Redis Server
echo "Starting Redis server..."
if [ -f /etc/redis/redis.conf ]; then
    sed -i "s|^bind .*|bind 0.0.0.0|" /etc/redis/redis.conf
    # Enable password authentication if REDIS_PASSWORD is set
    if [ -n "${REDIS_PASSWORD:-}" ]; then
        sed -i "s|^# requirepass .*|requirepass ${REDIS_PASSWORD}|" /etc/redis/redis.conf
        grep -q "^requirepass" /etc/redis/redis.conf || echo "requirepass ${REDIS_PASSWORD}" >> /etc/redis/redis.conf
    fi
    redis-server /etc/redis/redis.conf --daemonize yes
else
    if [ -n "${REDIS_PASSWORD:-}" ]; then
        redis-server --daemonize yes --requirepass "${REDIS_PASSWORD}"
    else
        redis-server --daemonize yes
    fi
fi

# Wait for Redis to boot
sleep 2

# Resolve vm-ai and IR scripts from the mounted workspace when available so updates are reflected immediately
if [ -d /vagrant/vm-ai ]; then
    cp -f /vagrant/vm-ai/*.py /opt/lab/vm-ai/ 2>/dev/null || true
    cp -rf /vagrant/vm-ai/devsecops/* /opt/lab/vm-ai/devsecops/ 2>/dev/null || true
    cp -rf /vagrant/vm-ai/model/* /opt/lab/vm-ai/model/ 2>/dev/null || true
    if [ -d /vagrant/vm-ai/ir ]; then
        cp -rf /vagrant/vm-ai/ir/* /opt/lab/vm-ai/ir/ 2>/dev/null || true
        cp -rf /opt/lab/vm-ai/ir/bin/* /opt/lab/bin/ 2>/dev/null || true
        chmod +x /opt/lab/bin/* /opt/lab/vm-ai/ir/*.py /opt/lab/vm-ai/ir/*.sh 2>/dev/null || true
    fi
fi

# Resolve monitoring config from the mounted workspace when available so
# dashboard/provisioning updates do not require a full image rebuild.
MONITORING_SRC="/opt/lab/vm-ai/monitoring"
if [ -d /vagrant/vm-ai/monitoring ]; then
    MONITORING_SRC="/vagrant/vm-ai/monitoring"
    mkdir -p /opt/lab/vm-ai/monitoring/dashboards
    cp -rf "${MONITORING_SRC}/dashboards/"* /opt/lab/vm-ai/monitoring/dashboards/ 2>/dev/null || true
    cp -f "${MONITORING_SRC}/lab_exporter.py" /opt/lab/vm-ai/monitoring/lab_exporter.py 2>/dev/null || true
fi

# Force retrain if iforest was built with attack contamination (old runs).
# Detect this by checking if the model_meta.json records attack_episodes > 0.
if [ -f /opt/lab/models/model_meta.json ]; then
    AE=$(python3 -c "import json; print(json.load(open('/opt/lab/models/model_meta.json')).get('attack_episodes_used', 1))" 2>/dev/null || echo "1")
    if [ "$AE" != "0" ]; then
        echo "Old IsolationForest was trained with attack contamination (attack_episodes=$AE). Deleting to force clean retrain..."
        rm -f /opt/lab/models/iforest.pkl /opt/lab/models/scaler.pkl \
              /opt/lab/models/pca.pkl /opt/lab/models/pca_threshold.json \
              /opt/lab/models/model_meta.json
    fi
fi

# Train models on boot if any are missing.
# All three must exist: iforest.pkl (IsolationForest), pca.pkl (PCA AE), autoencoder.h5 (TF AE)
if [ ! -f /opt/lab/models/autoencoder.h5 ] || \
   [ ! -f /opt/lab/models/iforest.pkl ]    || \
   [ ! -f /opt/lab/models/pca.pkl ]; then
    echo "Training Anomaly Detection Models..."
    # Temporarily disable set -e so a training failure does not kill the container.
    # Each step logs to a file so failures are still visible in docker logs.
    set +e
    cd /opt/lab/vm-ai

    # 1. IsolationForest + StandardScaler
    # attack-episodes=0: pure normal traffic only — prevents false positives on baseline traffic.
    # contamination=0.05 in train_iforest.py ensures the model does not over-flag normal windows.
    echo "  [1/3] Training IsolationForest..."
    /opt/lab/venv-ai/bin/python -m model.train_iforest \
        --models-dir /opt/lab/models --baseline-minutes 30 --attack-episodes 0
    echo "  [1/3] IsolationForest exit code: $?"

    # 2. PCA Autoencoder
    echo "  [2/3] Training PCA Autoencoder..."
    /opt/lab/venv-ai/bin/python -m model.train_autoencoder \
        --models-dir /opt/lab/models --baseline-minutes 30
    echo "  [2/3] PCA exit code: $?"

    # 3. TensorFlow Dense Autoencoder
    echo "  [3/3] Training TensorFlow Autoencoder..."
    /opt/lab/venv-ai/bin/python -m model.train_autoencoder_tf \
        --models-dir /opt/lab/models --baseline-minutes 30
    echo "  [3/3] TF exit code: $?"

    set -e
    echo "Model training complete."
fi

# Train the decision-fusion meta-scorer (the final decision maker) on boot if missing.
# It stacks the three Modbus detectors into one calibrated risk score + writes the
# Model-Performance report. Depends on the base models above; fast (no new training,
# just scores the labelled set + fits a logistic regression).
if [ -f /opt/lab/models/iforest.pkl ] && [ ! -f /opt/lab/models/meta_model.pkl ]; then
    echo "Training decision-fusion meta-scorer..."
    set +e
    cd /opt/lab/vm-ai
    /opt/lab/venv-ai/bin/python -m model.train_meta
    echo "  meta-scorer exit code: $?"
    set -e
fi

# Train the robot-behavior LSTM autoencoder on boot if missing (independent of the
# Modbus models above). Synthetic, seeded, reproducible; a few minutes on CPU.
if [ ! -f /opt/lab/models/robot_lstm.h5 ]; then
    echo "Training Robot-behavior LSTM Autoencoder..."
    set +e
    cd /opt/lab/vm-ai
    /opt/lab/venv-ai/bin/python -m model.train_robot_lstm \
        --models-dir /opt/lab/models --baseline-minutes 20 --epochs 60
    echo "  Robot LSTM exit code: $?"
    set -e
    echo "Robot LSTM training complete."
fi

# Generate DevSecOps GPG Release Key
if ! gpg --list-secret-keys lab-release@lab.local >/dev/null 2>&1; then
    echo "Generating GPG Release Key for DevSecOps signing..."
    cat > /tmp/lab-gpg.batch <<EOF
%no-protection
Key-Type: RSA
Key-Length: 3072
Name-Real: Lab Release
Name-Email: lab-release@lab.local
Expire-Date: 1y
%commit
EOF
    gpg --batch --gen-key /tmp/lab-gpg.batch || echo "Warning: GPG key generation failed."
    rm -f /tmp/lab-gpg.batch
fi

# Start Prometheus
echo "Starting Prometheus..."
if [ -f "${MONITORING_SRC}/prometheus.yml" ]; then
    prometheus \
        --config.file="${MONITORING_SRC}/prometheus.yml" \
        --storage.tsdb.path=/var/lib/prometheus \
        --storage.tsdb.retention.time=30d \
        --web.listen-address=:9090 > /var/lab/log/prometheus.log 2>&1 &
fi

# Start Grafana Server
echo "Starting Grafana Server..."
mkdir -p /var/lib/grafana /var/log/grafana /etc/grafana /etc/grafana/provisioning
if [ -f "${MONITORING_SRC}/grafana/grafana.ini" ]; then
    cp -f "${MONITORING_SRC}/grafana/grafana.ini" /etc/grafana/grafana.ini
fi
if [ -d "${MONITORING_SRC}/grafana/provisioning" ]; then
    cp -rf "${MONITORING_SRC}/grafana/provisioning/"* /etc/grafana/provisioning/
fi
grafana-server \
    --homepath /usr/share/grafana \
    --config /etc/grafana/grafana.ini \
    --pidfile /run/grafana-server.pid > /var/lab/log/grafana.log 2>&1 &

# ── Core services (restart-supervised) ──────────────────────────────────────
# Start FastAPI Anomaly Score Service (binds 0.0.0.0 so the dashboard's nginx
# can reach it across the docker network; host exposure is loopback-only — see
# docker-compose.yml).
echo "Starting FastAPI Anomaly Score Service (port 8000)..."
export LAB_MODELS_DIR=/opt/lab/models
export LAB_LOG_LEVEL=INFO
supervise "score-api" /var/lab/log/lab-ai-score.log \
    "/opt/lab/venv-ai/bin/uvicorn score_service:app --app-dir /opt/lab/vm-ai --host 0.0.0.0 --port 8000"

# Start Redis Feature Consumer
echo "Starting Redis Feature Consumer..."
export LAB_REDIS_HOST=127.0.0.1
export LAB_REDIS_PORT=6379
export LAB_REDIS_PASSWORD="${REDIS_PASSWORD:-}"
supervise "feature-consumer" /var/lab/log/lab-ai-feature-consumer.log \
    "/opt/lab/venv-ai/bin/python /opt/lab/vm-ai/feature_consumer.py"

# Start Robot-behavior Consumer (robot plane: LSTM autoencoder + physical envelope
# scoring of the live /lab_arm/joint_states stream tapped by container-ot).
echo "Starting Robot-behavior Consumer..."
supervise "robot-consumer" /var/lab/log/lab-ai-robot-consumer.log \
    "/opt/lab/venv-ai/bin/python /opt/lab/vm-ai/robot_consumer.py"

# Start Alert Bridge
echo "Starting Alert Bridge..."
export LAB_AI_ALERT_FILE=/var/lab/log/ai-alerts.json
export LAB_REDIS_PASSWORD="${REDIS_PASSWORD:-}"
supervise "alert-bridge" /var/lab/log/lab-ai-alert-bridge.log \
    "/opt/lab/venv-ai/bin/python /opt/lab/vm-ai/alert_bridge.py"

# Start Gitea Webhook Receiver
echo "Starting Gitea Webhook Receiver (port 9000)..."
supervise "webhook-receiver" /var/lab/log/lab-ai-webhook.log \
    "/opt/lab/venv-ai/bin/python /opt/lab/vm-ai/devsecops/webhook_receiver.py"

# Start Prometheus Exporter
echo "Starting Lab Prometheus Exporter (port 9101)..."
supervise "lab-exporter" /var/lab/log/lab-ir-exporter.log \
    "/opt/lab/venv-ai/bin/python /opt/lab/vm-ai/monitoring/lab_exporter.py --port 9101"

# Start Incident Response Playbook Engine
echo "Starting Incident Response Playbook Engine..."
supervise "ir-engine" /var/lab/log/lab-ir-engine.log \
    "python3 /opt/lab/vm-ai/ir/playbook_engine.py --interval 2.0"

# Touch log file to tail
touch /var/lab/log/lab-ai-score.log

echo "All AI and monitoring services are operational."
tail -f /var/lab/log/lab-ai-score.log
