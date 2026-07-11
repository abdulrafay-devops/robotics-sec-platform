#!/usr/bin/env python3
"""Stage 4 - passive asset inventory.

inventory.py is deliberately passive by default. It parses Zeek observations,
merges the lab CMDB/asset-register identity, and writes inventory.json for CVE
correlation without sending probes to OT devices.

Governed active scanning lives in safe_active_scan.py. That companion workflow
uses nmap only with target allowlists, fragile-port exclusions, low rate limits,
and an approved maintenance window. Keeping active scans out of the recurring
inventory loop lets the project satisfy the examiner's safe active-scanning
requirement without normalizing unscheduled probes against fragile OT stacks.

Usage on vm-sec:
    sudo /opt/lab/venv-shipper/bin/python \
        /opt/lab/vm-sec/vuln/inventory.py [--no-active]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

LOG = logging.getLogger('stage4.inventory')

STATE_DIR = Path('/var/lab/state')
DB_PATH = STATE_DIR / 'inventory.sqlite'
JSON_PATH = STATE_DIR / 'inventory.json'
SCAN_META = STATE_DIR / 'scan_meta.json'

# SEC writes Zeek logs under /var/lab/log (the live spool is symlinked to
# .../current); some older builds used /var/log/zeek. Try the live path
# first and fall back to the legacy one so passive discovery always works.
ZEEK_CONN_CANDIDATES = (
    Path('/var/lab/log/zeek/current/conn.log'),
    Path('/var/log/zeek/current/conn.log'),
)

OT_SUBNET = '192.168.10.0/24'

# ---------------------------------------------------------------------------
# Asset register (CMDB).
#
# Modbus/TCP and most OT protocols do not self-report a software version, so
# the network scan alone can confirm *reachability* and *open ports* but not
# *what is installed*. A real OT security programme keeps that ground truth in
# an asset register / CMDB. This is that register for the lab: it reflects the
# software actually deployed on each host (see vm-ot/Dockerfile.ot), so the
# CVE correlation matches genuinely-installed versions against the advisory
# feed rather than guessing from a banner.
#
#   192.168.10.10 (container-ot): OpenPLC Runtime v3 (cloned from
#     thiagoralves/OpenPLC_v3, webserver exposed on tcp/8080) and the
#     system pymodbus 2.5.3 package.
#
# Registered assets remain in vulnerability scope even when Zeek has not seen
# live traffic since the last rebuild. `passive_zeek` means observed-live;
# `asset_register` means in-scope for CVE correlation.
# ---------------------------------------------------------------------------
KNOWN_ASSETS: dict[str, dict] = {
    '192.168.10.10': {
        'vendor': 'OpenPLC Project',
        'product': 'OpenPLC Runtime v3',
        'firmware': '3.0',
        'software': [
            {'vendor': 'OpenPLC Project', 'product': 'OpenPLC Runtime v3',
             'version': '3.0'},
            {'vendor': 'pymodbus', 'product': 'pymodbus', 'version': '2.5.3'},
        ],
    },
    # container-ot also binds 192.168.10.11 (eth0:safety / LAB_SAFETY_HOST) —
    # the logically-separate Safety Instrumented System endpoint (BPCS/SIS
    # separation per IEC 61511). Identity ONLY: it is the SAME OpenPLC runtime
    # as .10, so we deliberately omit a `software` list and use a product label
    # without "Runtime" so the OpenPLC CVE is not double-counted here.
    '192.168.10.11': {
        'vendor': 'OpenPLC Project',
        'product': 'Safety Instrumented System (SIS)',
        'firmware': '3.0',
    },
}


@dataclass
class Asset:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    firmware: str | None = None
    # Installed software components (vendor/product/version), from the
    # asset register. Drives version-aware CVE correlation.
    software: list[dict] = field(default_factory=list)
    discovery_methods: list[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)


def _ensure_db() -> sqlite3.Connection:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            ip TEXT PRIMARY KEY,
            open_ports TEXT,
            protocols TEXT,
            vendor TEXT,
            product TEXT,
            firmware TEXT,
            discovery_methods TEXT,
            last_seen REAL
        )
    """)
    conn.commit()
    return conn


def _passive_from_zeek(assets: dict[str, Asset]) -> None:
    """Walk Zeek conn.log and seed assets dict with observed peers."""
    conn_log = next((p for p in ZEEK_CONN_CANDIDATES if p.exists()), None)
    if conn_log is None:
        LOG.warning('zeek conn.log not found in %s; skipping passive seed',
                    [str(p) for p in ZEEK_CONN_CANDIDATES])
        return
    # Zeek may emit JSON or TSV depending on policy. The Stage 1 install
    # pins `LogAscii::use_json=T` so each line is one JSON object.
    #
    # CRITICAL: conn.log can include approved maintenance-window scans. A
    # closed port still produces a conn record (responder sends RST ->
    # conn_state REJ). If we counted every observed resp_p as "open" we would
    # mark every tested port open on every host. So we only treat a responder
    # port as a real service when the responder actually ANSWERED the SYN, i.e.
    # the connection reached the established state (SF/S1/S2/S3/RSTO/RSTR).
    # REJ (port closed) and S0 (no reply) are excluded.
    ANSWERED = {'SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR'}
    seen = 0
    with conn_log.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # The RESPONDER's port is the listening service (what we want to
            # treat as an "open port"); the ORIGINATOR's port is an ephemeral
            # client port and must NOT be recorded as a service. We still
            # register the originator as a live host so it shows in inventory.
            for ip_field, port_field, record_port in (
                ('id.orig_h', None, False),
                ('id.resp_h', 'id.resp_p', True),
            ):
                ip = rec.get(ip_field)
                if not ip or not ip.startswith('192.168.10.'):
                    continue
                a = assets.setdefault(ip, Asset(ip=ip))
                if record_port and rec.get('conn_state', 'SF') in ANSWERED:
                    port = rec.get(port_field)
                    if isinstance(port, int) and port not in a.open_ports:
                        a.open_ports.append(port)
                    svc = rec.get('service')
                    if svc and svc not in a.protocols:
                        a.protocols.append(svc)
                if 'passive_zeek' not in a.discovery_methods:
                    a.discovery_methods.append('passive_zeek')
                seen += 1
    LOG.info('passive Zeek seed (%s): %d records, %d unique OT hosts',
             conn_log, seen, sum(1 for a in assets.values()
                                 if 'passive_zeek' in a.discovery_methods))



def _enrich_from_register(assets: dict[str, Asset]) -> None:
    """Fill vulnerability-scope identity + software from the CMDB.

    Passive observation only proves reachability and ports. The software list
    is the authoritative installed-package inventory used by CVE correlation.
    A CMDB-only asset is not marked live: it gets no ports/protocols and a
    zero last_seen until passive telemetry observes it.
    """
    for ip, reg in KNOWN_ASSETS.items():
        a = assets.get(ip)
        if a is None:
            a = Asset(ip=ip, last_seen=0.0)
            assets[ip] = a
        a.vendor = a.vendor or reg.get('vendor')
        a.product = a.product or reg.get('product')
        a.firmware = a.firmware or reg.get('firmware')
        if reg.get('software'):
            a.software = reg['software']
        if 'asset_register' not in a.discovery_methods:
            a.discovery_methods.append('asset_register')


def _persist(assets: Iterable[Asset]) -> None:
    assets = list(assets)
    conn = _ensure_db()
    with conn:
        for a in assets:
            conn.execute(
                """
                INSERT INTO assets(ip, open_ports, protocols, vendor,
                                   product, firmware, discovery_methods,
                                   last_seen)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    open_ports=excluded.open_ports,
                    protocols=excluded.protocols,
                    vendor=COALESCE(excluded.vendor, assets.vendor),
                    product=COALESCE(excluded.product, assets.product),
                    firmware=COALESCE(excluded.firmware, assets.firmware),
                    discovery_methods=excluded.discovery_methods,
                    last_seen=excluded.last_seen
                """,
                (
                    a.ip,
                    json.dumps(sorted(set(a.open_ports))),
                    json.dumps(sorted(set(a.protocols))),
                    a.vendor, a.product, a.firmware,
                    json.dumps(sorted(set(a.discovery_methods))),
                    a.last_seen,
                ),
            )
    conn.close()

    # Also export a flat JSON for downstream consumers.
    JSON_PATH.write_text(json.dumps(
        [asdict(a) for a in assets], indent=2, sort_keys=True
    ))
    LOG.info('persisted %d assets to %s + %s', len(assets), DB_PATH, JSON_PATH)


def _write_scan_meta(assets: list[Asset], targets: list[str],
                     active: bool) -> None:
    """Record inventory provenance for the dashboard and audit evidence."""
    # Listening services only - drop ephemeral client ports (>= 32768) that
    # can leak in from passive observation, so the summary shows real ports.
    open_ports = sorted({p for a in assets for p in a.open_ports if p < 32768})
    methods = sorted({m for a in assets for m in a.discovery_methods})
    live_hosts = sum(1 for a in assets if 'passive_zeek' in a.discovery_methods)
    registered_assets = sum(1 for a in assets
                            if 'asset_register' in a.discovery_methods)
    meta = {
        'last_scan': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'last_scan_ts': time.time(),
        'subnet': OT_SUBNET,
        'targets_scanned': sorted(set(targets)),
        # Backward-compatible name used by the dashboard. It now means
        # inventory scope, not "reachable hosts from a probe".
        'hosts_found': len(assets),
        'assets_in_scope': len(assets),
        'live_hosts_found': live_hosts,
        'registered_assets': registered_assets,
        'open_ports': open_ports,
        'discovery_methods': methods,
        'scanner': (
            'governed active scan + asset register'
            if active else 'passive Zeek + asset register'
        ),
        'ports_probed': [],
    }
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        SCAN_META.write_text(json.dumps(meta, indent=2, sort_keys=True))
    except OSError as exc:
        LOG.warning('could not write scan_meta.json: %s', exc)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--no-active', action='store_true',
                    help='compatibility flag; inventory is passive by default')
    ap.add_argument('--active', action='store_true',
                    help='refused here; use safe_active_scan.py --execute')
    args = ap.parse_args(argv)

    assets: dict[str, Asset] = {}
    _passive_from_zeek(assets)

    targets: list[str] = []
    run_active = False
    if args.active:
        LOG.error('active scanning is governed by safe_active_scan.py; refusing ungated inventory scan')
        return 2
    if args.no_active:
        LOG.info('active scan disabled (--no-active); passive inventory only')
    else:
        LOG.info('active scan disabled by default; run safe_active_scan.py during an approved maintenance window')

    # Asset register enrichment runs last so a live Modbus identity wins, but
    # the installed-software inventory is always attached for CVE matching.
    _enrich_from_register(assets)

    asset_list = [assets[ip] for ip in sorted(assets)]
    _persist(asset_list)
    _write_scan_meta(asset_list, targets, active=run_active)
    return 0


if __name__ == '__main__':
    sys.exit(main())
