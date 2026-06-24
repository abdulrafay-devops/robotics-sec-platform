#!/usr/bin/env python3
"""Stage 4 — CVE / ICS-CERT correlation.

Reads `inventory.json` (produced by `inventory.py`) and the offline CVE
database `cve_db.json`, joins by (vendor, product, firmware), and emits
`/var/lab/state/vulnerabilities.json` — the structured input Stage 5's
vulnerability gate (`vuln_gate.py`) consumes.

Why an offline CVE DB rather than a live NVD pull:
  * The single-PC lab is *intentionally* offline-capable. A live NVD
    fetch would require outbound HTTPS from VM-SEC, which the firewall
    policy rejects.
  * The bundled `cve_db.json` is a hand-curated, signed snapshot of CVEs
    and ICS-CERT advisories that actually affect the lab's stack
    (OpenPLC, pymodbus, Cyclone DDS, Linux kernel, Guacamole) — exactly
    what a regulated OT environment would consume from an offline
    advisory feed.

Schema of vulnerabilities.json (consumed by Stage 5 vuln gate):

    [
      {
        "asset_ip": "192.168.10.10",
        "asset_product": "OpenPLC Runtime 3.0",
        "cve_id": "CVE-2021-31229",
        "cvss": 9.1,
        "title": "...",
        "source": "NVD",
        "url": "...",
        "remediation": "..."
      },
      ...
    ]

Usage on vm-sec:
    sudo /opt/lab/venv-shipper/bin/python \
        /opt/lab/vm-sec/vuln/cve_correlate.py
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

LOG = logging.getLogger('stage4.cve_correlate')

STATE_DIR = Path('/var/lab/state')
INVENTORY = STATE_DIR / 'inventory.json'
CVE_DB = Path('/opt/lab/vm-sec/vuln/cve_db.json')
OUT = STATE_DIR / 'vulnerabilities.json'


def _firmware_lt(actual: str | None, threshold: str) -> bool:
    """Loose semver-ish comparison: split on dots, compare numerically.

    Anything we can't parse is treated as "below threshold" so we
    over-report rather than miss a CVE. That is the right OT bias —
    false positives cost an engineer five minutes of triage, false
    negatives can cost an outage.
    """
    if not actual:
        return True

    def parts(v: str) -> list[int]:
        out: list[int] = []
        for chunk in v.split('.'):
            num = ''
            for c in chunk:
                if c.isdigit():
                    num += c
                else:
                    break
            out.append(int(num) if num else 0)
        return out

    a = parts(actual)
    t = parts(threshold)
    # Pad to equal length.
    n = max(len(a), len(t))
    a += [0] * (n - len(a))
    t += [0] * (n - len(t))
    return a < t


def _matches(component: dict, cve: dict) -> bool:
    """Does this software component (vendor/product/firmware) match the CVE?"""
    pm = cve.get('product_match', {})
    if 'vendor_contains' in pm:
        if pm['vendor_contains'].lower() not in (component.get('vendor') or '').lower():
            return False
    if 'product_contains' in pm:
        if pm['product_contains'].lower() not in (component.get('product') or '').lower():
            return False
    if 'firmware_lt' in pm:
        if not _firmware_lt(component.get('firmware'), pm['firmware_lt']):
            return False
    return True


def _components(asset: dict) -> list[dict]:
    """Every (vendor, product, firmware) tuple this asset exposes.

    A host runs more than one piece of software, so we correlate CVEs
    against each installed component from the asset register (the
    `software` list) as well as the host-level identity. Each component is
    normalised to the vendor/product/firmware shape `_matches` expects.
    """
    comps: list[dict] = []
    # Host-level identity (from Modbus device-id probe or register).
    if asset.get('vendor') or asset.get('product') or asset.get('firmware'):
        comps.append({
            'vendor': asset.get('vendor'),
            'product': asset.get('product'),
            'firmware': asset.get('firmware'),
        })
    # Installed software inventory.
    for sw in asset.get('software') or []:
        comps.append({
            'vendor': sw.get('vendor'),
            'product': sw.get('product'),
            'firmware': sw.get('version'),
        })
    return comps


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    if not INVENTORY.exists():
        LOG.error('inventory.json not found at %s; run inventory.py first',
                  INVENTORY)
        return 1
    if not CVE_DB.exists():
        LOG.error('cve_db.json not found at %s', CVE_DB)
        return 1

    assets = json.loads(INVENTORY.read_text())
    cves = json.loads(CVE_DB.read_text())

    findings: list[dict] = []
    for asset in assets:
        seen: set[tuple[str, str]] = set()  # (asset_ip, cve_id) dedupe
        for component in _components(asset):
            for cve in cves:
                if not _matches(component, cve):
                    continue
                key = (asset['ip'], cve['id'])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    'asset_ip': asset['ip'],
                    'asset_vendor': component.get('vendor'),
                    'asset_product': component.get('product'),
                    'asset_firmware': component.get('firmware'),
                    'cve_id': cve['id'],
                    'cvss': float(cve['cvss']),
                    'title': cve['title'],
                    'source': cve['source'],
                    'url': cve['url'],
                    'remediation': cve['remediation'],
                })

    # Sort findings: highest CVSS first, then asset IP, then CVE id, so the
    # output is deterministic across runs (handy for diffing in audits).
    findings.sort(key=lambda f: (-f['cvss'], f['asset_ip'], f['cve_id']))

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(findings, indent=2, sort_keys=True))
    LOG.info('wrote %d findings to %s (highest CVSS=%.1f)',
             len(findings), OUT,
             findings[0]['cvss'] if findings else 0.0)
    return 0


if __name__ == '__main__':
    sys.exit(main())
