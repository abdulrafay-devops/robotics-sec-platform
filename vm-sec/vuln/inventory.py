#!/usr/bin/env python3
"""Stage 4 — passive + active asset inventory.

Sources of truth (in priority order):
  1. **Passive**: parse Zeek `conn.log` for every (orig_h, resp_h, resp_p)
     tuple we have ever observed; this gives us live IPs and the
     protocols they speak with zero on-wire risk.
  2. **Active (OT-safe Nmap)**: `nmap -sT -Pn --max-rate 5
     --scan-delay 200ms -p 502,44818,20000,102,4840` against the OT
     subnet to confirm what is reachable from VM-SEC. We deliberately
     constrain rate and ports — vanilla Nmap can flood old PLC TCP
     stacks.
  3. **Active (protocol-native)**: a Modbus Read Device Identification
     (function code 43 / MEI type 14) against any device that responded
     on tcp/502. This is the *correct* way to fingerprint a PLC —
     same query an engineering tool issues — and gives us a trustable
     vendor/product/firmware tuple.

The merged result lands in a SQLite database at
`/var/lab/state/inventory.sqlite`, exported as JSON to
`/var/lab/state/inventory.json` for downstream consumers
(`cve_correlate.py`, the Stage 5 vulnerability gate, the Stage 6
forensic_capture script).

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
from pathlib import Path
from typing import Iterable

LOG = logging.getLogger('stage4.inventory')

STATE_DIR = Path('/var/lab/state')
DB_PATH = STATE_DIR / 'inventory.sqlite'
JSON_PATH = STATE_DIR / 'inventory.json'
ZEEK_CONN = Path('/var/log/zeek/current/conn.log')

OT_SUBNET = '192.168.10.0/24'
OT_PORTS = (502, 44818, 20000, 102, 4840)  # Modbus, EIP, DNP3, S7, OPC UA
# OT-safe nmap flags — see file docstring.
NMAP_ARGS = [
    '-sT', '-Pn',
    '--max-rate', '5',
    '--scan-delay', '200ms',
    '-p', ','.join(str(p) for p in OT_PORTS),
    '-oG', '-',  # greppable output to stdout
]


@dataclass
class Asset:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    firmware: str | None = None
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
    if not ZEEK_CONN.exists():
        LOG.warning('zeek conn.log missing at %s; skipping passive seed',
                    ZEEK_CONN)
        return
    # Zeek may emit JSON or TSV depending on policy. The Stage 1 install
    # pins `LogAscii::use_json=T` so each line is one JSON object.
    seen = 0
    with ZEEK_CONN.open('r', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            for ip_field, port_field, proto_field in (
                ('id.orig_h', 'id.orig_p', 'service'),
                ('id.resp_h', 'id.resp_p', 'service'),
            ):
                ip = rec.get(ip_field)
                if not ip or not ip.startswith('192.168.10.'):
                    continue
                a = assets.setdefault(ip, Asset(ip=ip))
                port = rec.get(port_field)
                if isinstance(port, int) and port not in a.open_ports:
                    a.open_ports.append(port)
                svc = rec.get(proto_field)
                if svc and svc not in a.protocols:
                    a.protocols.append(svc)
                if 'passive_zeek' not in a.discovery_methods:
                    a.discovery_methods.append('passive_zeek')
                seen += 1
    LOG.info('passive Zeek seed: %d records, %d unique OT hosts',
             seen, sum(1 for a in assets.values()
                       if 'passive_zeek' in a.discovery_methods))


def _active_nmap(assets: dict[str, Asset]) -> None:
    """Run OT-safe nmap against OT subnet; merge into assets."""
    cmd = ['nmap', *NMAP_ARGS, OT_SUBNET]
    LOG.info('running OT-safe nmap: %s', ' '.join(cmd))
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
                portspec = portspec.strip()
                if not portspec or '/open/' not in portspec:
                    continue
                try:
                    port = int(portspec.split('/')[0])
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


def _persist(assets: Iterable[Asset]) -> None:
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
    LOG.info('persisted %d assets to %s + %s', len(list(assets)), DB_PATH, JSON_PATH)


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
    if not args.no_active:
        _active_nmap(assets)
        _active_protocol_probes(assets)
    _persist(list(assets.values()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
