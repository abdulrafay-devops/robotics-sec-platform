#!/usr/bin/env python3
"""
Stage 1 — cross-zone connectivity matrix for the TRUE IDMZ (single-homed + router).

Probes real TCP reachability from inside each container and asserts it matches the
expected ALLOW / DENY for the IDMZ conduits enforced by `router-fw` (default-deny).
Run on the host AFTER `docker compose up -d` of the `-idmz` stack.

Probe method: a single `sh -c` that uses `nc` where present (alpine/busybox) and
falls back to bash `/dev/tcp` (ubuntu/debian) — works across all the lab images.

Usage:
    python infra/tests/stage1_connectivity_matrix_docker.py
"""
from __future__ import annotations

import argparse
import dataclasses
import logging
import shutil
import subprocess
import sys
from typing import List, Optional

LOG = logging.getLogger('stage1-idmz-matrix')


@dataclasses.dataclass(frozen=True)
class Probe:
    from_container: str
    target_ip: str
    target_port: int
    expect: str        # 'ALLOW' or 'DENY'
    label: str


# ── Expected IDMZ conduit matrix (router-fw default-deny; only these are open) ──
EXPECTED: List[Probe] = [
    # AI is network-enforced READ-ONLY to OT
    Probe('container-ai', '192.168.10.10', 5020, 'ALLOW', 'AI reads telemetry via OT read-only proxy'),
    Probe('container-ai', '192.168.10.10', 8002, 'ALLOW', 'AI control writes via OT control gateway'),
    Probe('container-ai', '192.168.10.10', 502,  'DENY',  'AI must NOT reach the raw PLC directly'),

    # IT cannot reach OT by ANY path (the original DMZ gap, now closed)
    Probe('lab-gitea', '192.168.10.10', 502,  'DENY', 'IT (Gitea) must NOT reach OT Modbus'),
    Probe('lab-gitea', '192.168.10.10', 5020, 'DENY', 'IT must NOT reach the OT proxy either'),

    # Brokered deploy + CI webhook conduits from IT
    Probe('lab-gitea', '192.168.30.40', 80,   'ALLOW', 'IT publishes to the DMZ artifact store'),
    Probe('lab-gitea', '192.168.40.30', 9000, 'ALLOW', 'IT Gitea webhook reaches the AI receiver'),

    # Stage 5 signed deploy: OT PULLS signed programs from the DMZ store (never IT->OT push)
    Probe('container-ot', '192.168.30.40', 80, 'ALLOW', 'OT pulls signed PLC programs from the DMZ store'),

    # DMZ jump host brokers RDP into OT (and nothing else). Probe from guacd — it is
    # the daemon that actually opens the RDP connection, so it (not just the webapp)
    # must have the OT route + conduit. (Probing the webapp masked a real outage.)
    Probe('lab-guacd', '192.168.10.10', 3389, 'ALLOW', 'guacd brokers RDP to OT'),
    Probe('lab-guacd', '192.168.10.10', 502,  'DENY',  'guacd must NOT reach OT Modbus'),

    # SEC is single-homed on OT: monitors the PLC, ships features to Redis via ONE
    # scoped conduit, and can no longer pivot into the rest of the mgmt zone.
    Probe('container-sec', '192.168.10.10', 502,  'ALLOW', 'SEC polls the PLC for the baseline (monitoring)'),
    Probe('container-sec', '192.168.40.30', 6379, 'ALLOW', 'SEC ships features to AI Redis (scoped conduit)'),
    Probe('container-sec', '192.168.40.30', 8000, 'DENY',  'SEC pivot closed: no AI API, only the Redis conduit'),
    Probe('container-sec', '192.168.40.40', 80,   'DENY',  'SEC pivot closed: cannot reach the mgmt dashboard'),

    # OT cannot pivot out to IT; read-only historian may reach the AI API
    Probe('container-ot', '192.168.20.20', 3000, 'DENY',  'OT must NOT reach the IT Gitea web UI'),
    Probe('lab-historian-stub', '192.168.40.30', 8000, 'ALLOW', 'Read-only historian wall-board reaches AI API'),
]

# nc where available (busybox/openbsd), else bash /dev/tcp. -w2 bounds the connect.
_PROBE = (
    "if command -v nc >/dev/null 2>&1; then "
    "timeout 3 nc -w2 {ip} {port} </dev/null >/dev/null 2>&1 && echo ALLOW || echo DENY; "
    "else timeout 3 bash -c '</dev/tcp/{ip}/{port}' >/dev/null 2>&1 && echo ALLOW || echo DENY; fi"
)


def _run_probe(p: Probe) -> str:
    cmd = ['docker', 'exec', p.from_container, 'sh', '-c',
           _PROBE.format(ip=p.target_ip, port=p.target_port)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=False)
    except subprocess.TimeoutExpired:
        return 'ERROR'
    except Exception as exc:  # noqa: BLE001
        LOG.warning('probe error %s: %s', p.from_container, exc)
        return 'ERROR'
    out = [l.strip() for l in (res.stdout or '').splitlines() if l.strip()]
    if out and out[-1] in ('ALLOW', 'DENY'):
        return out[-1]
    LOG.warning('bad probe output from %s: %r (stderr=%s)',
                p.from_container, res.stdout, (res.stderr or '')[:160])
    return 'ERROR'


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--verbose', '-v', action='count', default=0)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')

    if shutil.which('docker') is None:
        LOG.error('docker not found on PATH')
        return 2

    LOG.info('running %d IDMZ connectivity probe(s)', len(EXPECTED))
    fails = errors = 0
    for p in EXPECTED:
        result = _run_probe(p)
        ok = (result == p.expect)
        if not ok:
            errors += result == 'ERROR'
            fails += result != 'ERROR'
        LOG.info('%-4s %-20s -> %s:%-5d  expect=%-5s got=%-5s  %s',
                 'PASS' if ok else 'FAIL', p.from_container, p.target_ip,
                 p.target_port, p.expect, result, p.label)

    npass = len(EXPECTED) - fails - errors
    print('\n' + '=' * 88)
    print(f' IDMZ SEGMENTATION MATRIX | pass={npass} fail={fails} error={errors} total={len(EXPECTED)}')
    print('=' * 88)
    if fails == 0 and errors == 0:
        print('\nALL IDMZ CONDUITS MATCH THE DEFAULT-DENY POLICY. All-green!\n')
        return 0
    if errors:
        print('\nSome probes errored — ensure the -idmz stack is fully up (`docker compose ps`).')
    if fails:
        print('\nOne or more flows do NOT match expected — segmentation behaves unexpectedly.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
