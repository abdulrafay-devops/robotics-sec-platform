#!/usr/bin/env python3
"""Stage 4 - governed OT-safe active scanner.

This is the active-scanning companion to inventory.py. It exists because active
OT scanning must be deliberate, scheduled, and tightly constrained:

* targets are allowlisted;
* fragile controller/SIS ports are blocked by policy;
* nmap uses TCP connect scans only, with low rate and delay limits;
* unsafe nmap modes such as UDP, OS detection, version detection, NSE scripts,
  and aggressive scans are never accepted;
* execution is allowed only inside an approved maintenance window.

Default mode is a dry-run policy check. Use --execute only for an approved
maintenance window.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception as exc:  # pragma: no cover - configuration dependency
    yaml = None
    YAML_IMPORT_ERROR = exc
else:
    YAML_IMPORT_ERROR = None

LOG = logging.getLogger('stage4.safe_active_scan')

DEFAULT_POLICY = Path(__file__).with_name('active_scan_policy.yml')
DEFAULT_STATE_DIR = Path('/var/lab/state')
REPORT_JSON = 'active_scan_report.json'
REPORT_TXT = 'active_scan_report.txt'
SCHEDULE_JSON = 'active_scan_schedule.json'

FORBIDDEN_FLAGS = {
    '-A', '-O', '-sS', '-sU', '-sV', '-T4', '-T5',
    '--script', '--script-args', '--osscan-guess', '--traceroute',
    '--version-all', '--version-intensity', '--min-rate',
}


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse_now(value: str | None) -> dt.datetime:
    if not value:
        return _utc_now()
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _parse_hhmm(value: str) -> dt.time:
    hour_s, minute_s = value.split(':', 1)
    return dt.time(int(hour_s), int(minute_s), tzinfo=dt.timezone.utc)


def _day_key(value: dt.datetime) -> str:
    return value.strftime('%a').lower()[:3]


def _previous_day_key(value: dt.datetime) -> str:
    return (value - dt.timedelta(days=1)).strftime('%a').lower()[:3]


def _matching_window(now: dt.datetime, windows: list[dict[str, Any]]) -> dict[str, Any] | None:
    now = now.astimezone(dt.timezone.utc)
    now_time = now.timetz().replace(tzinfo=dt.timezone.utc)
    today = _day_key(now)
    yesterday = _previous_day_key(now)
    for window in windows:
        days = {str(day).lower()[:3] for day in window.get('days', [])}
        start = _parse_hhmm(str(window['start_utc']))
        end = _parse_hhmm(str(window['end_utc']))
        if start <= end:
            if today in days and start <= now_time <= end:
                return window
        else:
            if (today in days and now_time >= start) or (yesterday in days and now_time <= end):
                return window
    return None


def _load_policy(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError(f'PyYAML is required to read {path}: {YAML_IMPORT_ERROR}')
    data = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError(f'policy must be a mapping: {path}')
    return data


def _as_int(value: Any, name: str, min_value: int, max_value: int) -> int:
    if not isinstance(value, int):
        raise ValueError(f'{name} must be an integer')
    if not min_value <= value <= max_value:
        raise ValueError(f'{name} must be between {min_value} and {max_value}')
    return value


def _normalise_targets(policy: dict[str, Any]) -> list[dict[str, Any]]:
    allowed_cidrs = [ipaddress.ip_network(str(cidr)) for cidr in policy.get('allowed_cidrs', [])]
    if not allowed_cidrs:
        raise ValueError('policy.allowed_cidrs must not be empty')
    fragile_ports = {int(p) for p in policy.get('fragile_ports', [])}
    out: list[dict[str, Any]] = []
    for target in policy.get('targets', []):
        if not isinstance(target, dict):
            raise ValueError('each target must be a mapping')
        ip = ipaddress.ip_address(str(target.get('host')))
        if not any(ip in cidr for cidr in allowed_cidrs):
            raise ValueError(f'target {ip} is outside allowed_cidrs')
        ports = sorted({int(p) for p in target.get('ports', [])})
        if not ports:
            raise ValueError(f'target {ip} has no ports')
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(f'target {ip} has invalid port {port}')
            if port in fragile_ports:
                raise ValueError(f'target {ip}:{port} is blocked as fragile OT/SIS service')
        rationale = str(target.get('rationale') or '').strip()
        if not rationale:
            raise ValueError(f'target {ip} requires a rationale')
        out.append({'host': str(ip), 'ports': ports, 'rationale': rationale})
    if not out:
        raise ValueError('policy.targets must not be empty')
    return out


def _rate_limits(policy: dict[str, Any]) -> dict[str, int]:
    safe = policy.get('safe_nmap') or {}
    limits = {
        'max_rate': _as_int(safe.get('max_rate', 2), 'safe_nmap.max_rate', 1, 5),
        'scan_delay_ms': _as_int(safe.get('scan_delay_ms', 500), 'safe_nmap.scan_delay_ms', 200, 5000),
        'max_retries': _as_int(safe.get('max_retries', 1), 'safe_nmap.max_retries', 0, 2),
        'max_parallelism': _as_int(safe.get('max_parallelism', 1), 'safe_nmap.max_parallelism', 1, 4),
        'host_timeout_s': _as_int(safe.get('host_timeout_s', 45), 'safe_nmap.host_timeout_s', 15, 300),
    }
    return limits


def _build_nmap_command(targets: list[dict[str, Any]], limits: dict[str, int]) -> list[str]:
    hosts = sorted({t['host'] for t in targets})
    ports = sorted({port for t in targets for port in t['ports']})
    cmd = [
        'nmap',
        '-sT',              # TCP connect only; no raw SYN scan
        '-Pn',              # skip host discovery probes
        '-n',               # no DNS lookups
        '--max-rate', str(limits['max_rate']),
        '--scan-delay', f"{limits['scan_delay_ms']}ms",
        '--max-retries', str(limits['max_retries']),
        '--max-parallelism', str(limits['max_parallelism']),
        '--host-timeout', f"{limits['host_timeout_s']}s",
        '-p', ','.join(str(port) for port in ports),
        '-oX', '-',
        *hosts,
    ]
    bad = [arg for arg in cmd if arg in FORBIDDEN_FLAGS]
    if bad:
        raise ValueError(f'forbidden nmap flags present: {bad}')
    return cmd


def _parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    root = ET.fromstring(xml_text)
    for host in root.findall('host'):
        address_el = host.find('address')
        if address_el is None:
            continue
        host_ip = address_el.attrib.get('addr')
        for port_el in host.findall('./ports/port'):
            state_el = port_el.find('state')
            service_el = port_el.find('service')
            findings.append({
                'host': host_ip,
                'port': int(port_el.attrib['portid']),
                'protocol': port_el.attrib.get('protocol', 'tcp'),
                'state': state_el.attrib.get('state') if state_el is not None else 'unknown',
                'service': service_el.attrib.get('name') if service_el is not None else None,
            })
    return findings


def _base_report(
    status: str,
    mode: str,
    policy_path: Path,
    now: dt.datetime,
    window: dict[str, Any] | None,
    targets: list[dict[str, Any]],
    limits: dict[str, int],
    cmd: list[str],
    message: str,
) -> dict[str, Any]:
    return {
        'status': status,
        'mode': mode,
        'generated_at': _utc_now().isoformat(timespec='seconds'),
        'maintenance_checked_at': now.isoformat(timespec='seconds'),
        'maintenance_window': window,
        'policy_file': str(policy_path),
        'targets': targets,
        'rate_limits': limits,
        'nmap_command': cmd,
        'nmap_command_display': shlex.join(cmd),
        'forbidden_flags': sorted(FORBIDDEN_FLAGS),
        'safeguards': [
            'target allowlist required',
            'fragile OT/SIS ports blocked',
            'maintenance window required for execution',
            'TCP connect scan only (-sT)',
            'host discovery disabled (-Pn)',
            'DNS disabled (-n)',
            'rate-limited nmap command',
            'no UDP, OS detection, version detection, NSE scripts, or aggressive scan flags',
        ],
        'message': message,
        'findings': [],
    }


def _write_report(state_dir: Path, report: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    json_path = state_dir / REPORT_JSON
    txt_path = state_dir / REPORT_TXT
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
    lines = [
        'Stage 4 Safe Active Scan Report',
        f"Status: {report['status']}",
        f"Mode: {report['mode']}",
        f"Maintenance checked at: {report['maintenance_checked_at']}",
        f"Window: {report.get('maintenance_window')}",
        f"Command: {report['nmap_command_display']}",
        f"Message: {report['message']}",
        '',
        'Findings:',
    ]
    for finding in report.get('findings', []):
        lines.append(
            f"  {finding['host']}:{finding['port']}/{finding['protocol']} "
            f"{finding['state']} {finding.get('service') or ''}".rstrip()
        )
    if not report.get('findings'):
        lines.append('  none')
    txt_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def _window_occurrence_key(now: dt.datetime, window: dict[str, Any]) -> str:
    """Return a stable key for one scheduled maintenance-window occurrence."""
    now = now.astimezone(dt.timezone.utc)
    start = _parse_hhmm(str(window['start_utc']))
    end = _parse_hhmm(str(window['end_utc']))
    occurrence_date = now.date()

    # An overnight window belongs to the date on which it began.
    if start > end and now.timetz().replace(tzinfo=dt.timezone.utc) <= end:
        occurrence_date -= dt.timedelta(days=1)

    name = str(window.get('name') or 'unnamed-window')
    return f'{occurrence_date.isoformat()}::{name}::{start.isoformat()}-{end.isoformat()}'


def _load_schedule_state(state_dir: Path) -> dict[str, Any]:
    path = state_dir / SCHEDULE_JSON
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f'scheduler state is unreadable; refusing automatic scan: {exc}') from exc
    if not isinstance(data, dict):
        raise ValueError('scheduler state must be a JSON object; refusing automatic scan')
    return data


def _write_schedule_state(state_dir: Path, state: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / SCHEDULE_JSON
    tmp_path = path.with_suffix('.tmp')
    tmp_path.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    tmp_path.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    parser.add_argument('--state-dir', type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument('--now', help='UTC timestamp override for deterministic maintenance-window tests')
    parser.add_argument('--execute', action='store_true', help='run nmap if policy and maintenance window allow it')
    parser.add_argument('--dry-run', action='store_true', help='validate policy and write report without running nmap')
    parser.add_argument(
        '--scheduled',
        action='store_true',
        help='automatic mode: execute at most once per approved maintenance-window occurrence',
    )
    args = parser.parse_args(argv)

    if args.scheduled and not args.execute:
        parser.error('--scheduled requires --execute')

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
    mode = 'execute' if args.execute else 'dry-run'

    try:
        policy = _load_policy(args.policy)
        targets = _normalise_targets(policy)
        limits = _rate_limits(policy)
        cmd = _build_nmap_command(targets, limits)
        now = _parse_now(args.now)
        window = _matching_window(now, policy.get('maintenance_windows') or [])
    except Exception as exc:  # noqa: BLE001
        print(f'safe_active_scan: policy error: {exc}', file=sys.stderr)
        return 2

    if not policy.get('enabled', False):
        report = _base_report('DISABLED', mode, args.policy, now, window, targets, limits, cmd, 'active scanning disabled by policy')
        _write_report(args.state_dir, report)
        if args.scheduled:
            _write_schedule_state(args.state_dir, {
                'status': 'DISABLED',
                'checked_at': now.isoformat(timespec='seconds'),
                'message': 'active scanning disabled by policy',
            })
            return 0
        return 3 if args.execute else 0

    if args.scheduled:
        try:
            schedule_state = _load_schedule_state(args.state_dir)
        except ValueError as exc:
            print(f'safe_active_scan: {exc}', file=sys.stderr)
            return 2

        if window is None:
            schedule_state.update({
                'status': 'OUTSIDE_WINDOW',
                'checked_at': now.isoformat(timespec='seconds'),
                'message': 'no scan run outside an approved maintenance window',
            })
            _write_schedule_state(args.state_dir, schedule_state)
            return 0

        window_key = _window_occurrence_key(now, window)
        if schedule_state.get('last_attempt_window') == window_key:
            schedule_state.update({
                'status': 'ALREADY_RUN',
                'checked_at': now.isoformat(timespec='seconds'),
                'window_key': window_key,
                'message': 'this maintenance-window occurrence was already attempted; no repeat scan',
            })
            _write_schedule_state(args.state_dir, schedule_state)
            return 0

        # Record the attempt before spawning the already-governed execution path.
        # A restart cannot trigger a second scan in the same maintenance window.
        schedule_state.update({
            'status': 'RUNNING',
            'checked_at': now.isoformat(timespec='seconds'),
            'last_attempt_window': window_key,
            'last_attempted_at': now.isoformat(timespec='seconds'),
            'window_key': window_key,
            'message': 'running the one permitted scan for this maintenance window',
        })
        _write_schedule_state(args.state_dir, schedule_state)

        child_cmd = [
            sys.executable,
            str(Path(__file__).resolve()),
            '--execute',
            '--policy', str(args.policy),
            '--state-dir', str(args.state_dir),
        ]
        if args.now:
            child_cmd.extend(['--now', args.now])
        proc = subprocess.run(child_cmd, capture_output=True, text=True, check=False)
        if proc.stdout:
            print(proc.stdout, end='')
        if proc.stderr:
            print(proc.stderr, end='', file=sys.stderr)

        result = 'PASS' if proc.returncode == 0 else 'ERROR'
        schedule_state.update({
            'status': result,
            'completed_at': _utc_now().isoformat(timespec='seconds'),
            'last_result': result,
            'last_exit_code': proc.returncode,
            'last_report': str(args.state_dir / REPORT_JSON),
            'message': 'scheduled active scan completed' if result == 'PASS' else 'scheduled active scan failed; no automatic retry this window',
        })
        _write_schedule_state(args.state_dir, schedule_state)
        return proc.returncode

    if window is None:
        report = _base_report('BLOCKED_OUTSIDE_WINDOW', mode, args.policy, now, window, targets, limits, cmd, 'outside approved maintenance window')
        _write_report(args.state_dir, report)
        print('safe_active_scan: blocked outside approved maintenance window')
        return 3 if args.execute else 0

    if not args.execute:
        report = _base_report('DRY_RUN', mode, args.policy, now, window, targets, limits, cmd, 'policy valid; nmap not executed')
        _write_report(args.state_dir, report)
        print(f"safe_active_scan: DRY_RUN would execute: {report['nmap_command_display']}")
        return 0

    if shutil.which('nmap') is None:
        report = _base_report('ERROR', mode, args.policy, now, window, targets, limits, cmd, 'nmap binary not found')
        _write_report(args.state_dir, report)
        print('safe_active_scan: nmap binary not found', file=sys.stderr)
        return 2

    LOG.info('running governed nmap command: %s', shlex.join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=limits['host_timeout_s'] + 30, check=False)
    except subprocess.TimeoutExpired as exc:
        report = _base_report('ERROR', mode, args.policy, now, window, targets, limits, cmd, f'nmap timed out: {exc}')
        _write_report(args.state_dir, report)
        return 4

    if proc.returncode != 0:
        report = _base_report('ERROR', mode, args.policy, now, window, targets, limits, cmd, f'nmap exited rc={proc.returncode}: {proc.stderr[:400]}')
        _write_report(args.state_dir, report)
        print(report['message'], file=sys.stderr)
        return 4

    try:
        findings = _parse_nmap_xml(proc.stdout)
    except ET.ParseError as exc:
        report = _base_report('ERROR', mode, args.policy, now, window, targets, limits, cmd, f'could not parse nmap XML: {exc}')
        _write_report(args.state_dir, report)
        return 4

    report = _base_report('PASS', mode, args.policy, now, window, targets, limits, cmd, 'safe active scan completed')
    report['findings'] = findings
    _write_report(args.state_dir, report)
    open_count = sum(1 for f in findings if f.get('state') == 'open')
    print(f'safe_active_scan: PASS hosts={len({t["host"] for t in targets})} findings={len(findings)} open={open_count}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
