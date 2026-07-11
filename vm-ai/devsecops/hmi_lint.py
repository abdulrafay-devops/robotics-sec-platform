#!/usr/bin/env python3
"""Stage 5 - Gate 2: HMI / SCADA security validator.

Walks an HMI-screen JSON export and asserts policy rules. The export
format is intentionally agnostic - most modern HMIs (Ignition, Rapid
SCADA, FactoryStudio) can emit JSON. The lab's reference format is the
Ignition-style `screens.json` schema:

    [
      {
        "screen_id": "main",
        "requires_login": true,
        "min_role": "operator",
        "widgets": [
          {
            "type": "button",
            "id": "btn_force_motor",
            "label": "Force motor on",
            "writes_register": "%MX0.5",
            "requires_role": "engineer",
            "requires_confirm": true
          },
          ...
        ]
      },
      ...
    ]

Rules:
  H1  every screen sets requires_login=true
  H2  any widget with `force` in its label/id requires_role >= engineer
  H3  any widget that writes_register requires_confirm=true
  H4  no widget writes directly to safety-owned registers/topics
  H5  no screen has type=="debug" with any deploy_to_production:true
  H6  no screen/widget contains hard-coded credentials or secrets
  H7  every operator input widget declares explicit validation rules

Usage:
    python hmi_lint.py path/to/screens.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    rule: str
    screen: str
    widget: str
    detail: str

    def fmt(self) -> str:
        return f'[{self.rule}] {self.screen}/{self.widget}: {self.detail}'


_INPUT_TYPES = {
    'input',
    'number_input',
    'numeric_input',
    'slider',
    'spinner',
    'text_input',
    'textbox',
}
_SAFETY_REGISTERS = {'%MW2', '%MW10', '%MW11', '%MW12'}
_URI_WITH_CREDENTIALS = re.compile(
    r'[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s]+@',
    re.IGNORECASE,
)


def _key_name(key: str) -> str:
    key = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key)
    return re.sub(r'[^a-z0-9]+', '_', key.lower()).strip('_')


def _is_credential_key(key: str) -> bool:
    normalised = _key_name(key)
    compact = normalised.replace('_', '')
    tokens = {token for token in normalised.split('_') if token}
    return bool(
        {'password', 'passwd', 'pwd', 'secret', 'token', 'credential',
         'credentials', 'username', 'user'} & tokens
        or compact in {'apikey', 'authkey', 'authtoken', 'connectionstring'}
        or compact.endswith(('password', 'secret', 'token'))
    )


def _is_external_secret_ref(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    return (
        (value.startswith('${') and value.endswith('}'))
        or value.startswith(('env:', 'secret:', 'vault:', 'keyring:'))
    )


def _credential_findings(
    obj: Any,
    screen: str,
    widget: str,
    path: str = '<root>',
) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = key if path == '<root>' else f'{path}.{key}'
            if (
                _is_credential_key(key)
                and value not in (None, '', [])
                and not isinstance(value, (dict, list))
                and not _is_external_secret_ref(value)
            ):
                findings.append(Finding(
                    'H6_no_hardcoded_credentials', screen, widget,
                    f'credential-like field "{child_path}" contains a literal value',
                ))
            findings.extend(
                _credential_findings(value, screen, widget, child_path)
            )
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            findings.extend(
                _credential_findings(item, screen, widget, f'{path}[{idx}]')
            )
    elif isinstance(obj, str) and _URI_WITH_CREDENTIALS.search(obj):
        findings.append(Finding(
            'H6_no_hardcoded_credentials', screen, widget,
            f'connection string "{path}" embeds credentials',
        ))
    return findings


def _is_safety_write_target(target: str) -> bool:
    target_upper = target.strip().upper()
    return (
        target_upper.startswith('%QX0.')
        or target_upper.startswith('/SAFETY/')
        or target_upper in _SAFETY_REGISTERS
        or 'E_STOP' in target_upper
        or 'ESTOP' in target_upper
        or 'SAFETY' in target_upper
    )


def _validation_error(widget: dict[str, Any]) -> str | None:
    validation = widget.get('validation')
    if not isinstance(validation, dict):
        return 'operator input is missing a validation object'

    vtype = str(validation.get('type', '')).lower()
    if vtype in {'integer', 'int', 'number', 'numeric', 'float'}:
        min_value = validation.get('min')
        max_value = validation.get('max')
        if (
            not isinstance(min_value, (int, float))
            or not isinstance(max_value, (int, float))
        ):
            return 'numeric validation must declare numeric min and max'
        if min_value >= max_value:
            return 'validation min must be lower than max'
        return None

    if vtype == 'enum':
        values = validation.get('values', validation.get('allowed_values'))
        if not isinstance(values, list) or not values:
            return 'enum validation must declare non-empty values'
        return None

    if vtype in {'text', 'string'}:
        pattern = validation.get('pattern')
        max_length = validation.get('max_length')
        if not isinstance(pattern, str) or not pattern:
            return 'text validation must declare a regex pattern'
        if not isinstance(max_length, int) or max_length <= 0:
            return 'text validation must declare positive max_length'
        return None

    return 'validation.type must be one of integer, number, enum, or text'


def _lint(screens: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for sc in screens:
        sid = sc.get('screen_id', '<unknown>')
        if not sc.get('requires_login', False):
            findings.append(Finding('H1_requires_login', sid, '<screen>',
                                    'screen does not require login'))
        if sc.get('type') == 'debug' and sc.get('deploy_to_production'):
            findings.append(Finding('H5_no_debug_in_production', sid,
                                    '<screen>',
                                    'debug screen marked deploy_to_production'))

        screen_meta = {key: value for key, value in sc.items()
                       if key != 'widgets'}
        findings.extend(_credential_findings(screen_meta, sid, '<screen>'))

        for w in sc.get('widgets', []) or []:
            wid = w.get('id', '<unknown>')
            label = (w.get('label') or '').lower()
            wid_lc = wid.lower()
            is_force = 'force' in label or 'force' in wid_lc
            if is_force and (w.get('requires_role') or '') not in ('engineer', 'admin'):
                findings.append(Finding(
                    'H2_force_requires_engineer', sid, wid,
                    'force-style widget without requires_role>=engineer'))
            target = w.get('writes_register') or w.get('writes_topic') or ''
            if target and not w.get('requires_confirm'):
                findings.append(Finding(
                    'H3_writer_requires_confirm', sid, wid,
                    f'widget writes "{target}" without requires_confirm=true'))
            if target and _is_safety_write_target(str(target)):
                findings.append(Finding(
                    'H4_no_safety_target', sid, wid,
                    f'HMI must not write safety-owned target "{target}"'))

            findings.extend(_credential_findings(w, sid, wid))
            widget_type = str(w.get('type', '')).lower()
            if widget_type in _INPUT_TYPES or w.get('operator_input') is True:
                validation_error = _validation_error(w)
                if validation_error:
                    findings.append(Finding(
                        'H7_input_validation', sid, wid,
                        validation_error))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('path', type=Path)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args(argv)

    if not args.path.exists():
        print(f'error: file not found: {args.path}', file=sys.stderr)
        return 2
    try:
        data = json.loads(args.path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        print(f'error: invalid JSON: {exc}', file=sys.stderr)
        return 2
    if not isinstance(data, list):
        print('error: HMI export must be a JSON array of screens',
              file=sys.stderr)
        return 2

    findings = _lint(data)
    if not args.quiet:
        for f in findings:
            print(f.fmt())
    print(f'hmi_lint: {len(findings)} finding(s) across {len(data)} screen(s)')
    return 0 if not findings else 1


if __name__ == '__main__':
    sys.exit(main())
