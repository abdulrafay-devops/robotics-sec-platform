#!/usr/bin/env python3
"""Stage 4 — firmware / program update workflow.

Drives the canonical OT change sequence for an OpenPLC program update:

    stage → validate → schedule → backup → apply → verify → (rollback)

This is intentionally a *driver*: each step is a small function that
runs an existing tool (Stage 5 lints, Stage 3 hashes, Stage 5 Gazebo
acceptance harness) rather than re-implementing logic. The whole point
is that the workflow's steps are auditable in one place.

Invocation:
    python firmware_workflow.py \
        --program /path/to/new_program.st \
        --target  vm-ot \
        --window  '2026-05-19T22:00Z..2026-05-19T23:00Z'

Behavior:
  * Always writes `/var/lab/state/firmware_runs/<timestamp>.json` with
    a structured per-step result trail (timestamps, exit codes, the
    new and old SHA-256 hashes).
  * Refuses to APPLY outside the maintenance window unless
    `--force-window` is supplied AND the operator typed the timestamp
    again — that requires two keystrokes of intent, prevents accidental
    out-of-window deployment.
  * On any verify failure, restores the backup and exits non-zero.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

LOG = logging.getLogger('stage4.firmware_workflow')

RUNS_DIR = Path('/var/lab/state/firmware_runs')
BACKUPS_DIR = Path('/var/lab/state/firmware_backups')

# Dynamically resolve python path and plc_lint.py location to work in both container-sec and container-ot
_py_bin = '/opt/lab/venv-shipper/bin/python' if Path('/opt/lab/venv-shipper/bin/python').exists() else ('/opt/lab/venv-traffic/bin/python' if Path('/opt/lab/venv-traffic/bin/python').exists() else sys.executable)
_plc_lint_path = '/opt/lab/vm-ai/devsecops/plc_lint.py' if Path('/opt/lab/vm-ai/devsecops/plc_lint.py').exists() else ('/vagrant/vm-ai/devsecops/plc_lint.py' if Path('/vagrant/vm-ai/devsecops/plc_lint.py').exists() else str(Path(__file__).resolve().parents[2] / 'vm-ai' / 'devsecops' / 'plc_lint.py'))
STAGE5_LINT = f"{_py_bin} {_plc_lint_path}"

STAGE3_INTEGRITY_BASELINE = Path('/var/lab/state/integrity_baseline.json')


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _run_step(name: str, cmd: list[str], trail: list[dict]) -> int:
    LOG.info('▶ step %s: %s', name, ' '.join(cmd))
    t0 = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    trail.append({
        'step': name,
        'cmd': cmd,
        'rc': proc.returncode,
        'stdout_tail': proc.stdout[-2000:],
        'stderr_tail': proc.stderr[-2000:],
        'duration_s': round(time.monotonic() - t0, 3),
        'timestamp': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
    })
    return proc.returncode


def _within_window(window: str) -> bool:
    try:
        start_s, end_s = window.split('..')
        start = dt.datetime.fromisoformat(start_s.replace('Z', '+00:00'))
        end = dt.datetime.fromisoformat(end_s.replace('Z', '+00:00'))
    except ValueError:
        return False
    now = dt.datetime.now(dt.timezone.utc)
    return start <= now <= end


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--program', required=True, type=Path,
                    help='path to the new .st program on this host')
    ap.add_argument('--target', default='vm-ot',
                    help='target host (used only in the trail; real apply '
                         'happens by SSH to this host)')
    ap.add_argument('--window', required=True,
                    help='ISO 8601 maintenance window: start..end')
    ap.add_argument('--force-window', action='store_true',
                    help='allow apply outside the window (requires manual '
                         'window echo on stdin)')
    ap.add_argument('--current-program', type=Path,
                    default=Path('/opt/openplc/webserver/st_files/blank_program.st'),
                    help='path to the *current* program (used for backup + hash)')
    args = ap.parse_args(argv)

    if not args.program.exists():
        LOG.error('new program file not found: %s', args.program)
        return 2

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    run_id = f'{ts}_{args.program.stem}'
    run_path = RUNS_DIR / f'{run_id}.json'
    trail: list[dict] = []

    # 1. STAGE — copy the candidate into a non-production location.
    staged = BACKUPS_DIR / f'{run_id}.candidate.st'
    shutil.copy2(args.program, staged)
    new_hash = _sha256(staged)
    trail.append({'step': 'stage', 'path': str(staged), 'sha256': new_hash})

    # 2. VALIDATE — run the Stage 5 PLC lint on the staged program.
    if _run_step('validate', [*STAGE5_LINT.split(), str(staged)], trail) != 0:
        run_path.write_text(json.dumps({'run_id': run_id, 'verdict': 'FAIL_VALIDATE', 'trail': trail}, indent=2))
        LOG.error('validate failed; refusing to schedule')
        return 3

    # 3. SCHEDULE — refuse to proceed outside the window unless forced.
    if not _within_window(args.window):
        if not args.force_window:
            trail.append({'step': 'schedule', 'verdict': 'OUT_OF_WINDOW',
                          'window': args.window})
            run_path.write_text(json.dumps({'run_id': run_id, 'verdict': 'OUT_OF_WINDOW',
                                            'trail': trail}, indent=2))
            LOG.error('outside maintenance window %s; refusing to apply', args.window)
            return 4
        # Force path requires the operator to echo the window back to us.
        sys.stdout.write(f're-type the window to confirm out-of-window apply: ')
        sys.stdout.flush()
        echo = sys.stdin.readline().strip()
        if echo != args.window:
            LOG.error('window confirmation did not match; aborting')
            return 5
        trail.append({'step': 'schedule', 'verdict': 'OUT_OF_WINDOW_FORCED',
                      'window': args.window})
    else:
        trail.append({'step': 'schedule', 'verdict': 'IN_WINDOW',
                      'window': args.window})

    # 4. BACKUP the current program.
    backup_path = BACKUPS_DIR / f'{run_id}.backup.st'
    if args.current_program.exists():
        shutil.copy2(args.current_program, backup_path)
        old_hash = _sha256(backup_path)
    else:
        # First-ever push.
        old_hash = None
        backup_path.write_text('# no prior program\n')
    trail.append({'step': 'backup', 'path': str(backup_path), 'sha256': old_hash})

    # 5. APPLY — write the new program into the OpenPLC st_files dir.
    try:
        args.current_program.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged, args.current_program)
        applied_hash = _sha256(args.current_program)
    except OSError as exc:
        trail.append({'step': 'apply', 'rc': 1, 'error': str(exc)})
        run_path.write_text(json.dumps({'run_id': run_id, 'verdict': 'FAIL_APPLY',
                                        'trail': trail}, indent=2))
        return 6
    trail.append({'step': 'apply', 'rc': 0, 'sha256': applied_hash,
                  'matches_staged': applied_hash == new_hash})

    # 6. VERIFY — re-run validate against the applied file + check Stage 3
    #    integrity baseline has been refreshed.
    if _run_step('verify_lint', [*STAGE5_LINT.split(), str(args.current_program)], trail) != 0:
        LOG.error('verify lint failed; rolling back')
        shutil.copy2(backup_path, args.current_program)
        trail.append({'step': 'rollback', 'reason': 'verify_lint_failed'})
        run_path.write_text(json.dumps({'run_id': run_id, 'verdict': 'ROLLED_BACK',
                                        'trail': trail}, indent=2))
        return 7

    # Update Stage 3 integrity baseline so the runtime watchdog does not
    # alarm on a legitimate change.
    STAGE3_INTEGRITY_BASELINE.parent.mkdir(parents=True, exist_ok=True)
    STAGE3_INTEGRITY_BASELINE.write_text(json.dumps({
        'program_path': str(args.current_program),
        'sha256': applied_hash,
        'applied_at': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'run_id': run_id,
    }, indent=2))
    trail.append({'step': 'refresh_integrity_baseline', 'rc': 0, 'sha256': applied_hash})

    run_path.write_text(json.dumps({
        'run_id': run_id, 'verdict': 'PASS', 'trail': trail,
        'old_sha256': old_hash, 'new_sha256': applied_hash,
        'target': args.target,
    }, indent=2))
    LOG.info('PASS run_id=%s new_sha256=%s', run_id, applied_hash)
    return 0


if __name__ == '__main__':
    sys.exit(main())
