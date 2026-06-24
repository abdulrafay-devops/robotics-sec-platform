#!/usr/bin/env python3
"""Stage 4 — passive + active asset inventory.

Sources of truth (in priority order):
  1. **Passive**: parse Zeek `conn.log` for every (orig_h, resp_h, resp_p)
     tuple we have ever observed; this gives us live IPs and the
     protocols they speak with zero on-wire risk.
  2. **Active host discovery**: a fast `nmap -sn` ping sweep of the OT
     subnet finds which hosts are actually up, so we only port-scan
     live assets (no point hammering 254 empty addresses).
  3. **Active port scan (OT-safe Nmap)**: `nmap -sT -Pn --max-rate 5
     --scan-delay 200ms -p 502,44818,20000,102,4840` against the
     *discovered* hosts to confirm what is reachable from VM-SEC. We
     deliberately constrain rate and ports — vanilla Nmap can flood old
     PLC TCP stacks. We scan the discovered host list (not the whole
     /24) so the scan finishes in seconds and never times out.
  4. **Active (protocol-native)**: a Modbus Read Device Identification
     (function code 43 / MEI type 14) against any device that responded
     on tcp/502. This is the *correct* way to fingerprint a PLC —
     same query an engineering tool issues — and gives us a trustable
     vendor/product/firmware tuple *when the device answers*.
  5. **Asset register (CMDB)**: many OT devices (OpenPLC included) do
     NOT answer the Modbus identity query, so protocols alone cannot
     tell us the software version. A maintained asset register — the
     same ground truth a real OT security team keeps in a CMDB — fills
     vendor/product/version for known hosts and enumerates the software
     components installed on them. The CVE correlation then matches
     those real, deployed versions against the offline advisory feed.

The merged result lands in a SQLite database at
`/var/lab/state/inventory.sqlite`, exported as JSON to
`/var/lab/state/inventory.json` for downstream consumers
(`cve_correlate.py`, the Stage 5 vulnerability gate, the Stage 6
forensic_capture script). A small `/var/lab/state/scan_meta.json`
records when the scan ran, what it targeted and what it found, so the
dashboard can show that the findings come from a live scan.

Usage on vm-sec:
    sudo /opt/lab/venv-shipper/bin/python \
        /opt/lab/vm-sec/vuln/inventory.py [--no-active]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
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
OT_PORTS = (502, 44818, 20000, 102, 4840)  # Modbus, EIP, DNP3, S7, OPC UA
# OT-safe nmap flags — see file docstring. The target host(s) are appended
# at call time (we scan discovered live hosts, never the whole /24).
NMAP_ARGS = [
    '-sT', '-Pn',
    '--max-rate', '5',
    '--scan-delay', '200ms',
    '-p', ','.join(str(p) for p in OT_PORTS),
    '-oG', '-',  # greppable output to stdout
]

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
    # CRITICAL: conn.log also records our OWN active nmap probes. A closed
    # port still produces a conn record (responder sends RST -> conn_state
    # REJ). If we counted every observed resp_p as "open" we would mark every
    # scanned port open on every host. So we only treat a responder port as a
    # real service when the responder actually ANSWERED the SYN, i.e. the
    # connection reached the established state (SF/S1/S2/S3/RSTO/RSTR). REJ
    # (port closed) and S0 (no reply) are excluded.
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


def _discover_live_hosts(timeout: float = 60.0) -> list[str]:
    """Fast `nmap -sn` ping sweep of the OT subnet to find live hosts.

    No ports are touched here — this is just so the OT-safe port scan only
    targets addresses that are actually up, keeping the scan to seconds.
    """
    cmd = ['nmap', '-sn', '-n', '--max-rate', '100', '-oG', '-', OT_SUBNET]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        LOG.warning('host-discovery sweep failed (%s); falling back to '
                    'passive + known hosts only', exc)
        return []
    hosts: list[str] = []
    for line in out.splitlines():
        if line.startswith('Host:') and 'Status: Up' in line:
            ip = line.split()[1]
            if ip.startswith('192.168.10.'):
                hosts.append(ip)
    LOG.info('host discovery: %d live OT hosts %s', len(hosts), hosts)
    return hosts


def _active_nmap(assets: dict[str, Asset], targets: list[str]) -> None:
    """Run OT-safe nmap against the given target hosts; merge into assets."""
    if not targets:
        LOG.info('no nmap targets; skipping active port scan')
        return
    cmd = ['nmap', *NMAP_ARGS, *targets]
    LOG.info('running OT-safe nmap on %d host(s): %s',
             len(targets), ' '.join(cmd))
    try:
        out = subprocess.check_output(cmd, text=True, timeout=300)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        LOG.error('nmap failed: %s', exc)
        return
    for line in out.splitlines():
        # Greppable output: Host: 192.168.10.10 (vm-ot) Ports: 502/open/tcp//modbus///, ...
        if not line.startswith('Host:'):
            continue
        parts = line.split('\t')
        host_field = parts[0]
        ip = host_field.split()[1]
        a = assets.setdefault(ip, Asset(ip=ip))
        if 'active_nmap' not in a.discovery_methods:
            a.discovery_methods.append('active_nmap')
        for p in parts[1:]:
            if not p.startswith('Ports:'):
                continue
            for portspec in p[len('Ports:'):].split(','):
                # Greppable port field: portid/state/proto/owner/service/...
                # Accept ONLY ports whose state is exactly "open" (not
                # "closed", "filtered", or "open|filtered").
                fields = portspec.strip().split('/')
                if len(fields) < 2 or fields[1] != 'open':
                    continue
                try:
                    port = int(fields[0])
                except ValueError:
                    continue
                if port not in a.open_ports:
                    a.open_ports.append(port)


def _modbus_identity(ip: str, port: int = 502, timeout: float = 2.0) -> dict | None:
    """Issue Modbus FC=43 / MEI=14 (Read Device Identification, basic).

    Frame layout (MBAP + PDU):
        00 01  txid
        00 00  protocol id
        00 05  length (unit + fc + mei + read_dev_id_code + object_id)
        01     unit id
        2B     fc 43
        0E     MEI type 14
        01     basic device id
        00     object id (vendor name)
    """
    req = bytes.fromhex('00010000000501' + '2B' + '0E' + '01' + '00')
    try:
        with closing(socket.create_connection((ip, port), timeout=timeout)) as s:
            s.sendall(req)
            data = s.recv(4096)
    except (OSError, socket.timeout):
        return None
    # Parse the response loosely: walk TLV-style objects after the header.
    if len(data) < 14 or data[7] != 0x2B:
        return None
    n_objects = data[13]
    pos = 14
    objects: dict[int, str] = {}
    for _ in range(n_objects):
        if pos + 2 > len(data):
            break
        obj_id = data[pos]
        obj_len = data[pos + 1]
        if pos + 2 + obj_len > len(data):
            break
        objects[obj_id] = data[pos + 2:pos + 2 + obj_len].decode(
            'utf-8', errors='replace')
        pos += 2 + obj_len
    if not objects:
        return None
    return {
        'vendor': objects.get(0),
        'product': objects.get(1),
        'firmware': objects.get(2),
    }


def _active_protocol_probes(assets: dict[str, Asset]) -> None:
    """For every asset with tcp/502 open, query Modbus device identity."""
    for ip, a in assets.items():
        if 502 not in a.open_ports:
            continue
        ident = _modbus_identity(ip)
        if ident is None:
            continue
        a.vendor = ident.get('vendor')
        a.product = ident.get('product')
        a.firmware = ident.get('firmware')
        if 'active_modbus_id' not in a.discovery_methods:
            a.discovery_methods.append('active_modbus_id')
        LOG.info('modbus identity %s: vendor=%s product=%s fw=%s',
                 ip, a.vendor, a.product, a.firmware)


def _enrich_from_register(assets: dict[str, Asset]) -> None:
    """Fill identity + software inventory for known hosts from the CMDB.

    Only fields the active probes could NOT determine are overwritten, so a
    real Modbus identity (if the device ever answers) always wins. The
    software list is the authoritative installed-package inventory used by
    the CVE correlation.
    """
    for ip, reg in KNOWN_ASSETS.items():
        a = assets.get(ip)
        if a is None:
            # Host is in the register but was not seen live this scan — do not
            # invent reachability; skip it so the inventory reflects reality.
            continue
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
    """Record scan provenance for the dashboard (live-scan evidence)."""
    # Listening services only — drop ephemeral client ports (>= 32768) that
    # can leak in from passive observation, so the summary shows real ports.
    open_ports = sorted({p for a in assets for p in a.open_ports if p < 32768})
    methods = sorted({m for a in assets for m in a.discovery_methods})
    meta = {
        'last_scan': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'last_scan_ts': time.time(),
        'subnet': OT_SUBNET,
        'targets_scanned': sorted(set(targets)),
        'hosts_found': len(assets),
        'open_ports': open_ports,
        'discovery_methods': methods,
        'scanner': 'nmap 7.x (OT-safe -sT -Pn --max-rate 5)' if active
                   else 'passive (Zeek conn.log)',
        'ports_probed': list(OT_PORTS),
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
                    help='skip nmap and protocol probes (passive Zeek only)')
    args = ap.parse_args(argv)

    assets: dict[str, Asset] = {}
    _passive_from_zeek(assets)

    targets: list[str] = []
    if not args.no_active:
        # Targets = live hosts from a fast ping sweep, plus anything we have
        # seen passively, plus the registered assets. Scanning this explicit
        # list (not the /24) keeps the OT-safe port scan to a few seconds.
        live = _discover_live_hosts()
        targets = sorted(
            set(live)
            | {ip for ip, a in assets.items()
               if 'passive_zeek' in a.discovery_methods}
            | set(KNOWN_ASSETS.keys())
        )
        _active_nmap(assets, targets)
        _active_protocol_probes(assets)

    # Asset register enrichment runs last so a live Modbus identity wins, but
    # the installed-software inventory is always attached for CVE matching.
    _enrich_from_register(assets)

    asset_list = list(assets.values())
    _persist(asset_list)
    _write_scan_meta(asset_list, targets, active=not args.no_active)
    return 0


if __name__ == '__main__':
    sys.exit(main())
