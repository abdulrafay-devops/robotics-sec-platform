#!/usr/bin/env python3
"""Stage 4 — configuration baseline drift checker.

Loads each YAML baseline under `/opt/lab/vm-sec/vuln/baselines/`, runs
the named *check* for every required setting, and emits a structured
drift report at `/var/lab/state/baseline_drift.json`.

Each check is a small, self-contained predicate. Adding a new check
means: (a) add a `check: <name>:<args>` line to the YAML, (b) implement
`check_<name>(args)` returning True (compliant) or a string (drift
description). That's it.

Schema of baseline_drift.json (consumed by Stage 5 baseline gate and
Stage 6 incident triggers):

    {
      "generated_at": "2026-05-19T22:30:00Z",
      "drift": [
        {
          "device_class": "openplc_runtime",
          "id": "webui_default_password_disabled",
          "severity": "critical",
          "description": "Webserver default password ...",
          "detail": "Webserver responded with HTTP 200 to default 'openplc'/'openplc' login"
        },
        ...
      ],
      "compliant_count": 9,
      "drift_count": 1
    }

Usage on vm-sec:
    sudo /opt/lab/venv-shipper/bin/python \
        /opt/lab/vm-sec/vuln/baseline_check.py
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import socket
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from typing import Callable

LOG = logging.getLogger('stage4.baseline_check')

BASELINE_DIR = Path('/opt/lab/vm-sec/vuln/baselines')
if not BASELINE_DIR.exists():
    BASELINE_DIR = Path('/vagrant/vm-sec/vuln/baselines')
STATE_DIR = Path('/var/lab/state')
OUT = STATE_DIR / 'baseline_drift.json'


# --- check primitives -------------------------------------------------

def _check_webui_credentials_not_default(_args: str) -> bool | str:
    """Verify OpenPLC uses the managed web password applied in the OT container.

    This deliberately checks the local OpenPLC configuration instead of trying a
    factory login over HTTP. It avoids distributing a credential pair to the
    monitoring tier while still detecting password drift.
    """
    configured_password = os.environ.get('OPENPLC_WEB_PASSWORD', '')
    if len(configured_password) < 16:
        return 'OPENPLC_WEB_PASSWORD is unavailable or does not meet the minimum length'

    db_path = Path('/opt/lab/openplc/webserver/openplc.db')
    if not db_path.exists():
        return f'OpenPLC database is unavailable: {db_path}'

    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                'SELECT password FROM Users WHERE username = ?', ('openplc',)
            ).fetchone()
    except sqlite3.Error as exc:
        return f'unable to read the OpenPLC user database: {exc}'

    if row is None:
        return 'OpenPLC managed web account is missing'
    if row[0] != configured_password:
        return 'OpenPLC web password does not match OPENPLC_WEB_PASSWORD'
    return True


def _check_iptables_rule(needle: str) -> bool | str:
    try:
        out = subprocess.check_output(['iptables', '-S'], text=True, timeout=5)
    except Exception as exc:
        return f'unable to read iptables: {exc}'
    needle_parts = needle.split()
    for line in out.splitlines():
        if all(part in line for part in needle_parts):
            return True
    return f'iptables rule missing: {needle}'


def _check_iptables_dport_8080_restricted_to_mgmt(_args: str) -> bool | str:
    return _check_iptables_rule('--dport 8080 -s 192.168.40.0/24 -j ACCEPT')


def _check_iptables_dport_502_drops_it_zone(_args: str) -> bool | str:
    return _check_iptables_rule('-s 192.168.20.0/24 -j LAB_LOGREJ')


def _check_iptables_dport_503_restricted(_args: str) -> bool | str:
    return _check_iptables_rule('--dport 503 -s 192.168.10.10')


def _check_openplc_log_to_syslog(_args: str) -> bool | str:
    p = Path('/var/log/syslog')
    if p.exists() and 'openplc' in p.read_text(errors='replace').lower():
        return True
    return 'no OpenPLC entries found in /var/log/syslog'


def _check_sros2_enforce_in_systemd_unit(_args: str) -> bool | str:
    paths = [
        Path('/opt/lab/bin/run-safety-supervisor.sh'),
        Path('/opt/lab/bin/run-safety-heartbeat.sh'),
    ]
    for p in paths:
        if not p.exists():
            return f'wrapper missing: {p}'
        if 'ROS_SECURITY_STRATEGY=Enforce' not in p.read_text():
            return f'{p} does not set ROS_SECURITY_STRATEGY=Enforce'
    return True


def _check_integrity_baseline_file_present(_args: str) -> bool | str:
    p = Path('/var/lab/state/integrity_baseline.json')
    if not p.exists():
        return f'baseline file missing: {p}'
    return True


def _check_env_var_eq(args: str) -> Callable[[str], bool | str]:
    return None  # placeholder, dispatcher handles parameterised checks


# --- parameterised dispatcher ----------------------------------------

def _resolve_check(check_str: str) -> Callable[[], bool | str]:
    """Return a zero-arg callable for a `check:` value from YAML.

    Forms accepted:
        bare_name                    → look up _check_bare_name
        bare_name:arg1:arg2          → look up _check_bare_name with arg
        env_var_eq:NAME:VALUE        → assert os.environ[NAME] == VALUE
        env_var_contains:NAME:SUB    → assert SUB in os.environ.get(NAME)
        file_mode:PATH:MODE:OWN:GRP  → stat check
        xml_contains:PATH:NEEDLE     → substring check on a file
    """
    parts = check_str.split(':')
    name = parts[0]

    if name == 'env_var_eq' and len(parts) == 3:
        var, want = parts[1], parts[2]
        return lambda: (
            True if os.environ.get(var) == want
            else f'env {var}={os.environ.get(var)!r}, expected {want!r}'
        )

    if name == 'env_var_contains' and len(parts) == 3:
        var, sub = parts[1], parts[2]
        return lambda: (
            True if sub in (os.environ.get(var) or '')
            else f'env {var}={os.environ.get(var)!r} does not contain {sub!r}'
        )

    if name == 'file_mode' and len(parts) == 5:
        path, mode_s, own, grp = parts[1], parts[2], parts[3], parts[4]

        def _f() -> bool | str:
            try:
                st = os.stat(path)
            except FileNotFoundError:
                return f'{path} not found'
            actual_mode = oct(stat.S_IMODE(st.st_mode))
            want_mode = oct(int(mode_s, 8))
            if actual_mode != want_mode:
                return f'{path} mode {actual_mode}, expected {want_mode}'
            try:
                import pwd
                import grp as grpmod
                if pwd.getpwuid(st.st_uid).pw_name != own:
                    return f'{path} owner {pwd.getpwuid(st.st_uid).pw_name}, expected {own}'
                if grpmod.getgrgid(st.st_gid).gr_name != grp:
                    return f'{path} group {grpmod.getgrgid(st.st_gid).gr_name}, expected {grp}'
            except ImportError:
                pass
            return True
        return _f

    if name == 'xml_contains' and len(parts) == 3:
        path, needle = parts[1], parts[2]

        def _x() -> bool | str:
            try:
                txt = Path(path).read_text(errors='replace')
            except FileNotFoundError:
                return f'{path} not found'
            # Allow `attr>value` shorthand to mean `>value</attr>` substring
            # OR `attr=value` substring — easier than full XPath.
            if '>' in needle:
                attr, val = needle.split('>', 1)
                if f'>{val}<' in txt or f'>{val}\n' in txt:
                    return True
                return f'{path} missing {attr}={val}'
            if needle in txt:
                return True
            return f'{path} missing literal "{needle}"'
        return _x

    # Fallback: look up _check_<name>
    fn = globals().get(f'_check_{name}')
    if fn is None:
        return lambda: f'unknown check: {check_str}'
    return lambda: fn(':'.join(parts[1:]))


def _yaml_load(path: Path) -> dict:
    """Tiny dependency-free YAML loader for *our* baseline files only.

    The lab provisioner installs PyYAML in /opt/lab/venv-shipper, so
    prefer that. Fall back to a minimal parser only if PyYAML is missing
    (e.g. running unit tests on the host).
    """
    try:
        import yaml  # type: ignore
        return yaml.safe_load(path.read_text())
    except ImportError:
        # Minimal parser: only handles the structure we author.
        # Not a general YAML implementation.
        out: dict = {'required_settings': [], 'disallowed_settings': []}
        section = None
        cur: dict | None = None
        for raw in path.read_text().splitlines():
            line = raw.rstrip()
            if not line or line.lstrip().startswith('#'):
                continue
            if not line.startswith(' '):
                k, _, v = line.partition(':')
                v = v.strip()
                if v == '':
                    section = k
                    if section in ('required_settings', 'disallowed_settings'):
                        out.setdefault(section, [])
                else:
                    out[k] = v
            elif line.lstrip().startswith('- '):
                cur = {}
                out.setdefault(section, []).append(cur)
                kv = line.lstrip()[2:]
                k, _, v = kv.partition(':')
                if cur is not None:
                    cur[k.strip()] = v.strip()
            else:
                if cur is None:
                    continue
                k, _, v = line.strip().partition(':')
                cur[k.strip()] = v.strip()
        return out


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    drift: list[dict] = []
    compliant = 0
    for yml in sorted(BASELINE_DIR.glob('*.yml')):
        baseline = _yaml_load(yml)
        cls = baseline.get('device_class', yml.stem)
        for setting in baseline.get('required_settings', []) or []:
            check_str = setting.get('check', '')
            if not check_str:
                continue
            verdict = _resolve_check(check_str)()
            if verdict is True:
                compliant += 1
                continue
            drift.append({
                'device_class': cls,
                'id': setting.get('id'),
                'severity': setting.get('severity', 'medium'),
                'description': setting.get('description', ''),
                'iec62443_req': setting.get('iec62443_req', ''),
                'detail': verdict if isinstance(verdict, str) else 'failed',
            })

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        'generated_at': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'drift': drift,
        'compliant_count': compliant,
        'drift_count': len(drift),
    }, indent=2, sort_keys=True))
    LOG.info('baseline check: %d compliant, %d drift entries → %s',
             compliant, len(drift), OUT)
    # Exit 1 if there is any critical drift, so this can gate a build.
    if any(d['severity'] == 'critical' for d in drift):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
