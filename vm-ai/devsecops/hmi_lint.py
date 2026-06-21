#!/usr/bin/env python3
"""Stage 5 — Gate 2: HMI / SCADA security validator.

Walks an HMI-screen JSON export and asserts policy rules. The export
format is intentionally agnostic — most modern HMIs (Ignition, Rapid
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
  H4  no widget targets a safety register (%QX0.x or topic /safety/*)
  H5  no screen has type=="debug" with any deploy_to_production:true

Usage:
    python hmi_lint.py path/to/screens.json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    rule: str
    screen: str
    widget: str
    detail: str

    def fmt(self) -> str:
        return f'[{self.rule}] {self.screen}/{self.widget}: {self.detail}'


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
            if target.startswith('%QX0.') or target.startswith('/safety/'):
                findings.append(Finding(
                    'H4_no_safety_target', sid, wid,
                    f'HMI must not target safety register/topic "{target}"'))
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
        data = json.loads(args.path.read_text())
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
