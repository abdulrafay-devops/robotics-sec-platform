#!/usr/bin/env python3
"""Stage 5 — Gate 4: Vulnerability gate.

Reads `vulnerabilities.json` (produced by Stage 4's `cve_correlate.py`)
and fails the build if there is ANY finding with CVSS >= the configured
threshold (default 7.0) that is not present in the per-build exception
list.

The exception file (`exceptions.yml`) lives in the same directory as
this script and is itself audited:

    exceptions:
      - cve_id: "CVE-2024-23653"
        until: "2026-12-31"
        approver: "alice@plant-ot.example"
        justification: |
          pymodbus 3.7.2 is the latest release at the time of this audit;
          the upstream patch is tracked in PR-1234. Exception expires
          2026-12-31 which forces a re-review.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

DEFAULT_VULN_PATH = Path('/var/lab/state/vulnerabilities.json')
DEFAULT_EXCEPTIONS = Path(__file__).parent / 'exceptions.yml'


def _parse_exceptions(path: Path) -> list[dict]:
    """Tiny YAML loader for our exceptions schema only."""
    if not path.exists():
        return []
    out: list[dict] = []
    cur: dict | None = None
    in_just = False
    for raw in path.read_text().splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith('#'):
            continue
        if line.startswith('exceptions:'):
            continue
        if re.match(r'^\s+-\s+cve_id:', line):
            cur = {'cve_id': line.split(':', 1)[1].strip().strip('\'"')}
            out.append(cur)
            in_just = False
            continue
        if cur is None:
            continue
        m = re.match(r'^\s+(\w+):\s*(.*)$', line)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if k == 'justification' and (v == '|' or v == '>'):
                in_just = True
                cur[k] = ''
                continue
            in_just = False
            cur[k] = v.strip('\'"')
            continue
        if in_just:
            cur['justification'] = (cur.get('justification') or '') + line.strip() + ' '
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--vulnerabilities', type=Path, default=DEFAULT_VULN_PATH)
    ap.add_argument('--exceptions', type=Path, default=DEFAULT_EXCEPTIONS)
    ap.add_argument('--threshold', type=float, default=7.0,
                    help='fail on any finding with CVSS >= threshold')
    args = ap.parse_args(argv)

    if not args.vulnerabilities.exists():
        print(f'error: vulnerabilities.json missing at {args.vulnerabilities}',
              file=sys.stderr)
        return 2
    findings = json.loads(args.vulnerabilities.read_text())
    exceptions = _parse_exceptions(args.exceptions)
    today = dt.date.today()

    # Build an index of currently-valid exceptions.
    excepted: dict[str, dict] = {}
    for ex in exceptions:
        until_s = ex.get('until')
        try:
            if until_s and dt.date.fromisoformat(until_s) < today:
                continue  # expired exception cannot suppress
        except ValueError:
            continue
        excepted[ex['cve_id']] = ex

    failures: list[dict] = []
    suppressed: list[dict] = []
    for f in findings:
        cvss = float(f.get('cvss', 0))
        if cvss < args.threshold:
            continue
        cve_id = f.get('cve_id')
        if cve_id in excepted:
            suppressed.append({**f, 'exception': excepted[cve_id]})
            continue
        failures.append(f)

    print(f'vuln_gate: threshold={args.threshold}; total findings={len(findings)}; '
          f'over-threshold={sum(1 for f in findings if float(f.get("cvss",0))>=args.threshold)}; '
          f'suppressed={len(suppressed)}; FAILING={len(failures)}')
    for f in failures:
        print(f'  FAIL  {f["cve_id"]} CVSS={f["cvss"]}  {f["asset_ip"]}  '
              f'{f.get("asset_product") or ""}')
    for s in suppressed:
        print(f'  XFAIL {s["cve_id"]} CVSS={s["cvss"]}  '
              f'(exception until {s["exception"].get("until")} '
              f'by {s["exception"].get("approver")})')
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
