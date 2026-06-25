#!/usr/bin/env python3
"""Stage 6 — lab-specific Prometheus exporter.

Exposes one HTTP endpoint (default :9101/metrics) with the metrics that
matter for the Grafana dashboards but are NOT covered by node_exporter:

    lab_stage2_alerts_total{category="..."}        gauge
    lab_zeek_modbus_features_total                 gauge
    lab_suricata_events_total{event_type="..."}    gauge
    lab_suricata_alerts_total{severity="..."}      gauge
    lab_stage3_safety_state                        gauge (0=NORMAL,1=DEGRADED,2=EMERGENCY)
    lab_stage4_vuln_count{severity="critical|high|medium"}
    lab_stage4_baseline_drift_count{severity="..."}
    lab_stage5_pipeline_last_verdict{verdict="PASS|FAIL"}  gauge (1 or 0)
    lab_stage5_pipeline_age_seconds                gauge
    lab_stage6_open_incidents                      gauge
    lab_stage6_pending_approvals                   gauge

The exporter intentionally has zero third-party dependencies — it uses
only the standard library — so it can run inside any of the lab's
existing venvs without extra pip installs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import socket
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG = logging.getLogger('stage6.lab_exporter')

AI_ALERTS = Path('/var/lab/log/ai-alerts.json')
VULN = Path('/var/lab/state/vulnerabilities.json')
DRIFT = Path('/var/lab/state/baseline_drift.json')
ARTIFACTS = Path('/var/lab/artifacts')
INCIDENTS = Path('/var/lab/state/ir/incidents.jsonl')
PENDING = Path('/var/lab/state/ir/pending_approvals.json')
SEC_LOG = Path('/var/lab/sec-log')
LAST_INJECTION = Path('/var/lab/state/last_injection.json')
# Written by feature_consumer.py after every 5-second window regardless of anomaly status.
# This is the primary live score source — shows scores even without active attacks.
LATEST_SCORES = Path('/var/lab/state/latest_scores.json')
# Written by robot_consumer.py every poll — robot-behavior plane LSTM z-score.
LATEST_ROBOT_SCORES = Path('/var/lab/state/latest_robot_scores.json')
ZEEK_MODBUS = SEC_LOG / 'zeek/current/modbus_features.log'
SURICATA_EVE = SEC_LOG / 'suricata/eve.json'
PROD_HOST = os.environ.get('LAB_PROD_HOST', '192.168.40.10')
PROD_PORT = int(os.environ.get('LAB_PROD_PORT', '502'))
SAFETY_HOST = os.environ.get('LAB_SAFETY_HOST', PROD_HOST)
SAFETY_PORT = int(os.environ.get('LAB_SAFETY_PORT', '503'))

# Health probes from the AI / management plane (where this exporter runs). Only
# targets this zone can LEGITIMATELY reach are probed — the OT cell is verified via
# its read-only proxy (5020) and control gateway (8002), never raw PLC:502 (that is
# deliberately firewalled). IT (gitea) and DMZ (guacamole) are unreachable from here
# by IEC-62443 segmentation BY DESIGN, so probing them would falsely report DOWN;
# their health is surfaced on their own pages instead.
COMPONENT_PROBES = {
    'ot_production_plc': ('192.168.10.10', 5020),   # OT read-only proxy
    'ot_control_gateway': ('192.168.10.10', 8002),  # OT control/safety gateway
    'ai_score_service': ('127.0.0.1', 8000),
    'ai_redis_bus': ('127.0.0.1', 6379),
    'prometheus': ('127.0.0.1', 9090),
    'grafana': ('127.0.0.1', 3000),
    'lab_exporter': ('127.0.0.1', 9101),
}


# --- collectors --------------------------------------------------------

def _stage2_alerts() -> dict[str, int]:
    counts: Counter[str] = Counter()
    if not AI_ALERTS.exists():
        return {}
    with AI_ALERTS.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = rec.get('alert') if isinstance(rec.get('alert'), dict) else {}
            cat = (
                rec.get('category') or
                rec.get('alert_type') or
                alert.get('category') or
                alert.get('signature') or
                'unknown'
            )
            counts[cat] += 1
    return dict(counts)


def _stage2_alert_severities() -> dict[str, int]:
    counts: Counter[str] = Counter()
    if not AI_ALERTS.exists():
        return {}
    severity_names = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
    with AI_ALERTS.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = rec.get('alert') if isinstance(rec.get('alert'), dict) else {}
            raw = rec.get('severity') or alert.get('severity') or 'medium'
            try:
                sev = severity_names.get(int(raw), 'medium')
            except (TypeError, ValueError):
                sev = str(raw).lower()
            counts[sev] += 1
    return dict(counts)


def _stage2_latest_scores() -> tuple[float, float]:
    """Return (iforest_score, pca_z) for Prometheus.

    Priority order:
      1. /var/lab/state/latest_scores.json — written by feature_consumer after
         every 5-second Modbus window regardless of anomaly status. This means
         scores show up immediately from live traffic without needing an attack.
      2. ai-alerts.json tail-read — fallback for when feature_consumer is not
         running or has not yet processed a window.
    Returns -1.0 only when neither source has data yet.
    """
    # Source 1: live score file from feature_consumer (updated every ~5s)
    if LATEST_SCORES.exists():
        try:
            data = json.loads(LATEST_SCORES.read_text())
            iforest = _float_or_default(data.get('iforest_score'), -1.0)
            pca_z = _float_or_default(data.get('pca_z'), -1.0)
            # Only use if the file was written in the last 5 minutes (stale guard)
            ts = float(data.get('ts', 0))
            if ts > 0 and (dt.datetime.utcnow().timestamp() - ts) < 300:
                if 'iforest_score' in data or 'pca_z' in data:
                    return iforest, pca_z
        except Exception:
            pass

    # Source 2: tail of ai-alerts.json (anomaly events only — fallback)
    if not AI_ALERTS.exists():
        return -1.0, -1.0
    TAIL_BYTES = 4096
    try:
        with AI_ALERTS.open('rb') as fh:
            fh.seek(0, 2)
            file_size = fh.tell()
            seek_to = max(0, file_size - TAIL_BYTES)
            fh.seek(seek_to)
            tail = fh.read().decode('utf-8', errors='replace')
    except OSError:
        return -1.0, -1.0
    for raw_line in reversed(tail.splitlines()):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            latest = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        lab = latest.get('lab') if isinstance(latest.get('lab'), dict) else {}
        iforest = latest.get('iforest_score', lab.get('iforest_score', -1.0))
        pca_z = latest.get('pca_z', lab.get('pca_z', -1.0))
        return _float_or_default(iforest, -1.0), _float_or_default(pca_z, -1.0)
    return -1.0, -1.0


def _count_data_lines(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith('#'):
                count += 1
    return count


def _suricata_event_counts() -> tuple[dict[str, int], dict[str, int]]:
    event_types: Counter[str] = Counter()
    alert_severities: Counter[str] = Counter()
    if not SURICATA_EVE.exists():
        return {}, {}
    severity_names = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
    # Only scan the TAIL of eve.json. Suricata appends forever and the file reaches
    # tens of MB; parsing the whole thing every scrape made /metrics take >5s and
    # blow the 5s scrape_timeout, so the target flapped and every lab_* metric
    # flickered on the dashboard. Bounding the read keeps the scrape fast regardless
    # of total file size (counts become "recent activity", which is what a live gauge wants).
    _TAIL_BYTES = 2 * 1024 * 1024
    try:
        _size = SURICATA_EVE.stat().st_size
        with SURICATA_EVE.open('rb') as _fh:
            if _size > _TAIL_BYTES:
                _fh.seek(_size - _TAIL_BYTES)
                _fh.readline()  # discard the partial first line after the seek
            _tail = _fh.read().decode('utf-8', errors='replace')
    except OSError:
        return {}, {}
    for line in _tail.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = str(rec.get('event_type') or 'unknown')
            event_types[event_type] += 1
            if event_type == 'alert':
                alert = rec.get('alert') if isinstance(rec.get('alert'), dict) else {}
                raw = alert.get('severity', 'unknown')
                try:
                    sev = severity_names.get(int(raw), 'unknown')
                except (TypeError, ValueError):
                    sev = str(raw).lower()
                alert_severities[sev] += 1
    return dict(event_types), dict(alert_severities)


def _read_safety_registers(start: int, count: int) -> list[int] | None:
    """Return [safety_state, ack_counter, last_fault_code] (MW10-12) via
    score_service's /api/hmi/state.

    The AI/management plane cannot — and by IEC-62443 segmentation MUST NOT — reach
    the raw PLC:502 directly, so the old direct-Modbus read to 192.168.40.10:503
    always failed (-1). score_service (same container) already reads the production
    PLC through the OT read-only proxy, so we reuse that single source of truth."""
    if start != 10:
        return None
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/hmi/state",
            headers={"X-API-Key": os.environ.get("LAB_API_KEY", "")},
        )
        with urllib.request.urlopen(req, timeout=0.8) as resp:
            d = json.loads(resp.read().decode("utf-8"))
        plc = d.get("plc_state") or {}
        if not isinstance(plc, dict) or "error" in plc or "safety_state" not in plc:
            return None
        return [int(plc.get("safety_state", -1)),
                int(plc.get("ack_counter", 0)),
                int(plc.get("last_fault_code", 0))]
    except Exception:
        return None


def _stage3_safety_state() -> int:
    """Read and normalize the safety supervisor state.

    The full safety supervisor uses 0=NORMAL, 1=DEGRADED, 2=EMERGENCY.
    The lightweight simulator initializes HR[10] to 1 as "healthy"; when
    HR[12] fault_code is 0, normalize that simulator healthy state to 0
    so Grafana does not show a false WARN.
    """
    regs = _read_safety_registers(10, 3)
    if regs is None:
        return -1
    state, _ack_counter, fault_code = regs
    if state == 1 and fault_code == 0:
        return 0
    return state if state in (0, 1, 2) else -1


def _stage4_vulns() -> dict[str, int]:
    if not VULN.exists():
        return {}
    try:
        v = json.loads(VULN.read_text())
    except json.JSONDecodeError:
        return {}
    counts: Counter[str] = Counter()
    for f in v:
        cvss = float(f.get('cvss', 0))
        sev = ('critical' if cvss >= 9 else
               'high' if cvss >= 7 else
               'medium' if cvss >= 4 else 'low')
        counts[sev] += 1
    return dict(counts)


def _stage4_drift() -> dict[str, int]:
    if not DRIFT.exists():
        return {}
    try:
        d = json.loads(DRIFT.read_text())
    except json.JSONDecodeError:
        return {}
    counts: Counter[str] = Counter()
    for entry in d.get('drift', []):
        counts[entry.get('severity', 'medium')] += 1
    return dict(counts)


def _stage5_last_verdict() -> tuple[str, float]:
    if not ARTIFACTS.exists():
        return 'NONE', float('inf')
    builds = sorted(ARTIFACTS.glob('*/'), key=lambda p: p.stat().st_mtime,
                    reverse=True)
    if not builds:
        return 'NONE', float('inf')
    latest = builds[0] / 'verdict.json'
    if not latest.exists():
        return 'NONE', float('inf')
    try:
        v = json.loads(latest.read_text())
    except json.JSONDecodeError:
        return 'NONE', float('inf')
    age = (dt.datetime.utcnow() -
           dt.datetime.fromisoformat(v['timestamp'].replace('Z', ''))
           ).total_seconds()
    return v.get('verdict', 'NONE'), age


def _stage6_counts() -> tuple[int, int]:
    n_inc = 0
    if INCIDENTS.exists():
        with INCIDENTS.open('r', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    inc = json.loads(line)
                    # Count only open (active) incidents
                    if not inc.get('closed', False) and not inc.get('postmortem_committed', False):
                        n_inc += 1
                except Exception:
                    # Fallback to counting it if json parsing fails
                    n_inc += 1
    n_pending = 0
    if PENDING.exists():
        try:
            n_pending = len(json.loads(PENDING.read_text()))
        except json.JSONDecodeError:
            n_pending = 0
    return n_inc, n_pending


def _stage6_incidents_by_playbook() -> dict[str, int]:
    counts: Counter[str] = Counter()
    if not INCIDENTS.exists():
        return {}
    with INCIDENTS.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            counts[rec.get('playbook') or 'unknown'] += 1
    return dict(counts)


def _tcp_up(host: str, port: int, timeout: float = 0.25) -> int:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 1
    except OSError:
        return 0


def _component_health() -> dict[str, int]:
    # Probe components in PARALLEL. In the IDMZ several targets are deliberately
    # unreachable from the AI (other zones / firewalled ports), so each connect
    # blocks for the full timeout; doing them serially summed to ~2s+ and pushed the
    # /metrics scrape over its 5s timeout (dashboard panels flickered). Running them
    # concurrently bounds the total cost to roughly a single timeout.
    from concurrent.futures import ThreadPoolExecutor
    items = list(COMPONENT_PROBES.items())
    with ThreadPoolExecutor(max_workers=max(1, len(items))) as ex:
        results = list(ex.map(lambda it: _tcp_up(it[1][0], it[1][1]), items))
    return {name: r for (name, _hp), r in zip(items, results)}


def _float_or_default(value: object, default: float) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _iec62443_compliance_score() -> float:
    """Derive an IEC 62443 compliance score (0–100) from existing state data.

    Deductions:
      -20 per critical CVE (capped at -40)
      -15 per critical baseline-drift entry (capped at -30)
      -2  per pending approval (capped at -20)
      -10 if safety state is DEGRADED (1) or EMERGENCY (2)
    """
    score = 100.0

    vuln = _stage4_vulns()
    score -= min(vuln.get('critical', 0) * 20, 40)

    drift = _stage4_drift()
    score -= min(drift.get('critical', 0) * 15, 30)

    _, n_pending = _stage6_counts()
    score -= min(n_pending * 2, 20)

    state = _stage3_safety_state()
    if state in (1, 2):
        score -= 10

    return max(0.0, round(score, 1))


def _stage3_sis_integrity() -> int:
    """Validate SIS register integrity from the actual Stage 3 register map.

    HR[10] is safety_state, HR[11] is ack_counter, and HR[12] is
    last_fault_code. Earlier dashboard logic expected a fake sentinel in
    HR[11], which made the real simulator look failed. Integrity is OK
    when the safety PLC is reachable and its state/fault registers are
    internally valid.
    """
    regs = _read_safety_registers(10, 3)
    if regs is None:
        return -1
    state, _ack_counter, fault_code = regs
    if state not in (0, 1, 2):
        return 0
    if state == 2 and fault_code == 0:
        return 0
    if fault_code not in (0, 1, 2, 3, 4):
        return 0
    return 1


def _stage1_modbus_traffic_rate() -> float:
    """Live Modbus/TCP request rate (req/s) observed by Zeek over the last 60 s.

    This is the real on-wire industrial-protocol throughput for Stage 1
    OT/IT-convergence monitoring (Objective 1) — the baseline HMI poll plus any
    attack burst — NOT an alert count. We read only the TAIL of the (large,
    continuously-growing) modbus_features.log and count *request* records whose
    timestamp falls inside the last 60 s, so the scrape stays fast.
    """
    if not ZEEK_MODBUS.exists():
        return 0.0
    cutoff = dt.datetime.utcnow() - dt.timedelta(seconds=60)
    try:
        size = ZEEK_MODBUS.stat().st_size
        with ZEEK_MODBUS.open('rb') as fh:
            # 512 KiB of tail covers several minutes even at attack rates.
            window = 512 * 1024
            if size > window:
                fh.seek(size - window)
                fh.readline()  # discard the partial first line
            data = fh.read().decode('utf-8', errors='replace')
    except OSError:
        return 0.0
    count = 0
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Count requests only so a request/response pair isn't double-counted.
        if rec.get('is_request') is False:
            continue
        ts_raw = rec.get('ts')
        if not ts_raw:
            continue
        try:
            ts = dt.datetime.fromisoformat(str(ts_raw).replace('Z', ''))
        except (ValueError, TypeError):
            continue
        if ts >= cutoff:
            count += 1
    return round(count / 60.0, 4)


def _stage4_firmware_patch_status() -> int:
    """Count vulnerability entries relating to firmware or patch management.

    Supports Objective 4 (Robotic System Vulnerability Management —
    secure firmware management and patch deployment).
    """
    if not VULN.exists():
        return 0
    try:
        v = json.loads(VULN.read_text())
    except json.JSONDecodeError:
        return 0
    count = 0
    for f in v:
        comp = str(f.get('component', '')).lower()
        vuln_type = str(f.get('type', '')).lower()
        if 'firmware' in comp or 'firmware' in vuln_type or 'patch' in vuln_type:
            count += 1
    return count


def _injection_metrics() -> tuple[int, int]:
    """Return (injection_count, is_active) from the last injection state file."""
    if not LAST_INJECTION.exists():
        return 0, 0
    try:
        data = json.loads(LAST_INJECTION.read_text())
    except (json.JSONDecodeError, OSError):
        return 0, 0
    return int(data.get('injection_count', 0)), (1 if data.get('active', False) else 0)


def _detection_latency() -> float:
    """Compute time (seconds) between last injection and first subsequent AI alert.

    Returns -1.0 when no injection has occurred or no post-injection alert exists.
    """
    if not LAST_INJECTION.exists() or not AI_ALERTS.exists():
        return -1.0
    try:
        inj = json.loads(LAST_INJECTION.read_text())
        injection_ts = float(inj.get('last_injection_ts', 0.0))
    except (json.JSONDecodeError, OSError, ValueError, TypeError):
        return -1.0
    if injection_ts <= 0:
        return -1.0

    best_latency = -1.0
    with AI_ALERTS.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts_raw = rec.get('timestamp') or rec.get('ts')
            if not ts_raw:
                continue
            try:
                alert_ts = dt.datetime.fromisoformat(
                    str(ts_raw).replace('Z', '').replace('+00:00', '')
                ).timestamp()
            except (ValueError, TypeError):
                continue
            if alert_ts > injection_ts:
                candidate = round(alert_ts - injection_ts, 3)
                if best_latency < 0 or candidate < best_latency:
                    best_latency = candidate
    return best_latency


def _ai_anomaly_alerts_recent(window_s: float = 300.0) -> dict[str, int]:
    """Count AI anomaly alarms raised in the last `window_s` seconds, by plane.

    This is honest live ALARM LOAD — how many anomalies the detectors are
    raising right now — split into network (Modbus) and robot planes. A burst
    while nothing is being injected is the operational signal that a detector is
    misbehaving ("alert storm"). It deliberately does NOT label the alarms as
    false positives: that cannot be known live without ground-truth triage.
    """
    out = {'network': 0, 'robot': 0, 'all': 0}
    if not AI_ALERTS.exists():
        return out
    cutoff = dt.datetime.utcnow() - dt.timedelta(seconds=window_s)
    with AI_ALERTS.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts_raw = rec.get('timestamp') or rec.get('ts')
            if ts_raw:
                try:
                    ts = dt.datetime.fromisoformat(str(ts_raw).replace('Z', ''))
                    if ts < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
            alert = rec.get('alert') if isinstance(rec.get('alert'), dict) else {}
            cat = str(rec.get('category') or alert.get('category') or '').lower()
            plane = 'robot' if 'robot' in cat else 'network'
            out[plane] += 1
            out['all'] += 1
    return out


def _render_metrics() -> str:
    out: list[str] = []

    def emit(name: str, help_: str, type_: str,
             samples: list[tuple[dict[str, str], float]]) -> None:
        out.append(f'# HELP {name} {help_}')
        out.append(f'# TYPE {name} {type_}')
        for labels, value in samples:
            if labels:
                ls = ','.join(f'{k}="{v}"' for k, v in labels.items())
                out.append(f'{name}{{{ls}}} {value}')
            else:
                out.append(f'{name} {value}')

    components = _component_health()
    emit('lab_component_up',
         'Core lab component TCP health by architecture stage',
         'gauge',
         [({'component': c}, n) for c, n in components.items()])

    emit('lab_security_sensor_log_up',
         'Stage 1 passive sensor log availability as seen by Prometheus exporter',
         'gauge',
         [
             ({'sensor': 'zeek', 'path': str(ZEEK_MODBUS)}, 1 if ZEEK_MODBUS.exists() else 0),
             ({'sensor': 'suricata', 'path': str(SURICATA_EVE)}, 1 if SURICATA_EVE.exists() else 0),
         ])

    emit('lab_zeek_modbus_features_total',
         'Stage 1 Zeek Modbus feature rows decoded from mirrored OT traffic',
         'gauge', [({}, _count_data_lines(ZEEK_MODBUS))])

    suri_events, suri_alerts = _suricata_event_counts()
    emit('lab_suricata_events_total',
         'Stage 1 Suricata EVE events by event_type from mirrored OT traffic',
         'gauge',
         [({'event_type': e}, n) for e, n in suri_events.items()] or
         [({'event_type': 'none'}, 0)])
    emit('lab_suricata_alerts_total',
         'Stage 1 Suricata signature alerts by severity from mirrored OT traffic',
         'gauge',
         [({'severity': s}, n) for s, n in suri_alerts.items()] or
         [({'severity': 'none'}, 0)])

    s2 = _stage2_alerts()
    emit('lab_stage2_alerts_total',
         'Stage 2 anomaly alerts emitted to ai-alerts.json by category',
         'gauge',
         [({'category': c}, n) for c, n in s2.items()] or
         [({'category': 'none'}, 0)])

    alarm_load = _ai_anomaly_alerts_recent(300.0)
    emit('lab_ai_anomaly_alerts_5m',
         'AI anomaly alarms raised in the last 5 minutes (live alarm LOAD by '
         'plane=network|robot|all). NOT a false-positive count: a burst with no '
         'injected attack indicates a misbehaving detector / alert storm.',
         'gauge',
         [({'plane': p}, alarm_load[p]) for p in ('network', 'robot', 'all')])

    s2sev = _stage2_alert_severities()
    emit('lab_stage2_alert_severity_total',
         'Stage 2 anomaly alerts by severity',
         'gauge',
         [({'severity': s}, n) for s, n in s2sev.items()] or
         [({'severity': 'none'}, 0)])

    iforest, pca_z = _stage2_latest_scores()
    emit('lab_stage2_latest_iforest_score',
         'Latest Stage 2 Isolation Forest anomaly score (live from feature_consumer or ai-alerts.json)',
         'gauge', [({}, iforest)])
    emit('lab_stage2_latest_pca_z',
         'Latest Stage 2 PCA reconstruction z-score (live from feature_consumer or ai-alerts.json)',
         'gauge', [({}, pca_z)])

    # TF AE z-score — read from latest_scores.json (written by score_service._score_one)
    tf_z_val = -1.0
    if LATEST_SCORES.exists():
        try:
            _d = json.loads(LATEST_SCORES.read_text())
            _ts = float(_d.get('ts', 0))
            if _ts > 0 and (dt.datetime.utcnow().timestamp() - _ts) < 300:
                tf_z_val = _float_or_default(_d.get('tf_z'), -1.0)
        except Exception:
            pass
    emit('lab_stage2_latest_tf_z',
         'Latest Stage 2 TensorFlow Autoencoder reconstruction z-score',
         'gauge', [({}, tf_z_val)])

    # Robot-behavior plane — LSTM autoencoder reconstruction z-score on the live
    # joint stream, written by robot_consumer.py. -1 when no recent robot data.
    robot_z_val = -1.0
    if LATEST_ROBOT_SCORES.exists():
        try:
            _rd = json.loads(LATEST_ROBOT_SCORES.read_text())
            _rts = float(_rd.get('ts', 0))
            if _rts > 0 and (dt.datetime.utcnow().timestamp() - _rts) < 30:
                robot_z_val = _float_or_default(_rd.get('robot_z'), -1.0)
        except Exception:
            pass
    emit('lab_robot_lstm_z',
         'Latest robot-behavior LSTM autoencoder reconstruction z-score '
         '(-1 = no recent joint telemetry)',
         'gauge', [({}, robot_z_val)])

    state = _stage3_safety_state()
    emit('lab_stage3_safety_state',
         'Stage 3 safety supervisor state (-1=unreachable,0=NORMAL,1=DEGRADED,2=EMERGENCY)',
         'gauge', [({}, state)])

    s4v = _stage4_vulns()
    emit('lab_stage4_vuln_count',
         'Stage 4 CVE findings against the live inventory by severity',
         'gauge',
         [({'severity': s}, s4v.get(s, 0))
          for s in ('critical', 'high', 'medium', 'low')])

    s4d = _stage4_drift()
    emit('lab_stage4_baseline_drift_count',
         'Stage 4 baseline-drift entries by severity',
         'gauge',
         [({'severity': s}, s4d.get(s, 0))
          for s in ('critical', 'high', 'medium', 'low')])

    verdict, age = _stage5_last_verdict()
    emit('lab_stage5_pipeline_last_verdict',
         'Stage 5 pipeline most-recent verdict (1=PASS, 0=FAIL/NONE)',
         'gauge',
         [({'verdict': v}, 1.0 if verdict == v else 0.0)
          for v in ('PASS', 'FAIL', 'NONE')])
    emit('lab_stage5_pipeline_age_seconds',
         'Age in seconds of the most-recent Stage 5 build verdict',
         'gauge',
         [({}, age if age != float('inf') else -1.0)])

    n_inc, n_pending = _stage6_counts()
    emit('lab_stage6_open_incidents',
         'Total Stage 6 incidents recorded',
         'gauge', [({}, n_inc)])
    emit('lab_stage6_pending_approvals',
         'Stage 6 graded-containment steps awaiting operator approval',
         'gauge', [({}, n_pending)])

    s6pb = _stage6_incidents_by_playbook()
    emit('lab_stage6_incidents_by_playbook',
         'Stage 6 incidents grouped by triggered playbook',
         'gauge',
         [({'playbook': p}, n) for p, n in s6pb.items()] or
         [({'playbook': 'none'}, 0)])

    # IEC 62443 compliance score (Objective 3 — functional safety / compliance)
    emit('lab_iec62443_compliance_score',
         'IEC 62443 compliance score derived from CVE count, drift, safety state, '
         'and pending approvals (0=non-compliant, 100=fully compliant)',
         'gauge', [({}, _iec62443_compliance_score())])

    # SIS integrity state (Objective 3 — safety instrumented system validation)
    emit('lab_stage3_sis_integrity',
         'Stage 3 SIS integrity check using Modbus HR[10:12] '
         '(-1=unreachable, 0=FAIL, 1=OK)',
         'gauge', [({}, _stage3_sis_integrity())])

    # Modbus traffic rate (Objective 1 — industrial protocol security monitoring)
    emit('lab_stage1_modbus_traffic_rate',
         'Stage 1 Modbus alert rate per second averaged over the last 60 s '
         'from ai-alerts.json (OT/IT protocol monitoring)',
         'gauge', [({}, _stage1_modbus_traffic_rate())])

    # Firmware / patch status (Objective 4 — robotic firmware management)
    emit('lab_stage4_firmware_patch_status',
         'Stage 4 count of firmware or patch-related vulnerability entries '
         'from the automated vulnerability scanner',
         'gauge', [({}, _stage4_firmware_patch_status())])

    # Attack injection counters (Demo / end-to-end detection pipeline)
    inj_count, inj_active = _injection_metrics()
    emit('lab_attack_injection_total',
         'Total number of demo attack injections fired into the OT network',
         'gauge', [({}, inj_count)])
    emit('lab_attack_injection_active',
         'Set to 1 while a demo attack injection is in progress',
         'gauge', [({}, inj_active)])

    # End-to-end detection latency (Objective 2 — AI-driven threat response speed)
    emit('lab_detection_latency_seconds',
         'Time in seconds from last attack injection to first AI alert '
         '(-1 = no injection yet or alert not yet observed)',
         'gauge', [({}, _detection_latency())])

    return '\n'.join(out) + '\n'


# --- HTTP server -------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path != '/metrics':
            self.send_response(404)
            self.end_headers()
            return
        body = _render_metrics().encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        LOG.debug(fmt, *args)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=9101)
    args = ap.parse_args(argv)

    server = HTTPServer((args.bind, args.port), _Handler)
    LOG.info('lab_exporter listening on %s:%d/metrics', args.bind, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
