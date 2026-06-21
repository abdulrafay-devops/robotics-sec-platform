#!/usr/bin/env python3
"""Stage 5 — Gate 5: Configuration baseline drift gate.

Reads `baseline_drift.json` (produced by Stage 4's `baseline_check.py`)
and fails the build if there is ANY drift entry of severity `critical`,
or if the report itself is missing/stale (older than `--max-age-hours`,
default 24h).

Stale reports are a build failure too — silently passing because the
last scan happened a week ago is exactly the kind of supply-chain
foot-gun this stage exists to prevent.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


DEFAULT_DRIFT_PATH = Path('/var/lab/state/baseline_drift.json')


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--drift', type=Path, default=DEFAULT_DRIFT_PATH)
    ap.add_argument('--max-age-hours', type=float, default=24.0)
    args = ap.parse_args(argv)

    if not args.drift.exists():
        print(f'baseline_gate: FAIL — drift report missing at {args.drift}')
        return 1

    data = json.loads(args.drift.read_text())
    gen_s = data.get('generated_at', '')
    try:
        generated = dt.datetime.fromisoformat(gen_s.replace('Z', '+00:00'))
    except ValueError:
        print(f'baseline_gate: FAIL — generated_at unparsable: {gen_s!r}')
        return 1
    age_h = (dt.datetime.now(dt.timezone.utc) - generated).total_seconds() / 3600.0
    if age_h > args.max_age_hours:
        print(f'baseline_gate: FAIL — drift report is {age_h:.1f}h old '
              f'(max {args.max_age_hours}h); rerun baseline_check.py')
        return 1

    drift = data.get('drift', [])
    crit = [d for d in drift if d.get('severity') == 'critical']
    print(f'baseline_gate: drift_count={len(drift)} '
          f'critical={len(crit)} age_h={age_h:.1f}')
    for d in crit:
        print(f'  CRIT  {d["device_class"]}/{d["id"]}: {d["detail"]}')
    return 0 if not crit else 1


if __name__ == '__main__':
    sys.exit(main())
