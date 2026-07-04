#!/usr/bin/env python3
"""Stage 5 — Gate 6: Gazebo + Stage-3 simulated acceptance test.

This is the *runtime* gate. It simulates the smallest reasonable end-to-
end check that the change about to be deployed has not broken the safety
loop:

  1. Verify the safety supervisor is healthy
        (lab-safety-supervisor.service active, /safety/state observable).
  2. Inject a recorded Modbus replay attack from vm-sec
        (the exact same attack Stage 2's live smoke uses).
  3. Assert that
       a) Stage 2's anomaly detection writes at least one alert to
          /var/lab/log/ai-alerts.json within 30 s of the replay, AND
       b) Stage 3's safety supervisor flips /safety/state to EMERGENCY
          when the test publishes an authenticated remote E-stop.

Because all three checks already have stand-alone gate scripts in
`infra/tests/`, this gate is essentially a thin orchestrator.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

LOG = logging.getLogger('stage5.acceptance_gate')

# These wrappers must be present on the target host. The gate is
# intended to run on vm-ai (which can SSH/exec into the others), but for
# the lab's single-host topology we just shell-out locally.
# Stage-2 replay smoke + Stage-3 safety loop. These run only when Gate 6 is
# enabled (i.e. LAB_SKIP_ACCEPTANCE unset). Stored as full argv so each uses the
# correct interpreter -- both now point at the Docker *_docker.py harnesses.
# (History: REPLAY was repointed from the old stage2_live_smoke.sh, and
# SAFETY_LOOP from the Vagrant-era fix_and_retest_stage3.sh, when those legacy
# scripts were removed. run_stage3_gates_docker.py runs the same two Stage-3
# gates -- safety-loop timing + unsigned-peer rejection -- against container-ot.)
REPLAY = ['python3', '/vagrant/infra/tests/stage2_live_smoke_docker.py']
SAFETY_LOOP = ['python3', '/vagrant/infra/tests/run_stage3_gates_docker.py']


def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    LOG.info('▶ %s (timeout=%ds)', ' '.join(cmd), timeout)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return 124, f'TIMEOUT after {timeout}s: {exc}'
    return proc.returncode, (proc.stdout + proc.stderr)[-4000:]


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--skip-replay', action='store_true',
                    help='skip the Stage 2 replay attack step (fast path)')
    ap.add_argument('--skip-safety', action='store_true',
                    help='skip the Stage 3 safety-loop step')
    args = ap.parse_args(argv)

    results: list[dict] = []
    if not args.skip_replay:
        rc, out = _run(REPLAY, timeout=120)
        results.append({'step': 'stage2_replay', 'rc': rc,
                        'pass': rc == 0, 'tail': out[-1500:]})
    if not args.skip_safety:
        rc, out = _run(SAFETY_LOOP, timeout=180)
        results.append({'step': 'stage3_safety_loop', 'rc': rc,
                        'pass': rc == 0, 'tail': out[-1500:]})

    failed = [r for r in results if not r['pass']]
    print(json.dumps({'acceptance_gate': 'PASS' if not failed else 'FAIL',
                      'steps': [{k: r[k] for k in ('step', 'rc', 'pass')}
                                for r in results]}, indent=2))
    if failed:
        for f in failed:
            print(f'\n--- {f["step"]} tail ---\n{f["tail"]}')
    return 0 if not failed else 1


if __name__ == '__main__':
    sys.exit(main())
