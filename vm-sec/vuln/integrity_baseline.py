#!/usr/bin/env python3
"""
Stage 4 — integrity baseline generator.

Generates /var/lab/state/integrity_baseline.json containing hashes of PLC
program files and SROS2 ACLs, a Modbus state snapshot, and runtime status
of safety-critical services.

Schema:
{
  "generated_at": ISO8601,
  "plc_files": {filename: sha256},
  "sros2_files": {filename: sha256},
  "modbus_snapshot": {"coils": [...], "registers": [...]},
  "services": {name: running_bool}
}
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, List

try:
    from pymodbus.client import ModbusTcpClient
except Exception:  # noqa: BLE001
    ModbusTcpClient = None  # type: ignore

OUT = Path("/var/lab/state/integrity_baseline.json")

PLC_DIR = Path("/opt/openplc/webserver/st_files/")
SROS2_DIR = Path("/opt/lab/vm-ot/sros2/permissions/")

PRODUCTION_PLC_IP = os.environ.get("LAB_PRODUCTION_PLC_IP", "192.168.40.10")
PRODUCTION_PLC_PORT = int(os.environ.get("LAB_PRODUCTION_PLC_PORT", "502"))


def _read_ot_services_file() -> Dict[str, bool] | None:
    path = Path("/var/lab/state/.ot_services.json")
    if not path.exists():
        return None
    try:
        # Check if the file is fresh (modified in the last 15 seconds)
        mtime = path.stat().st_mtime
        if time.time() - mtime > 15:
            return None
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_tree(root: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not root.exists():
        return out
    for p in sorted(root.glob("**/*")):
        if p.is_file():
            try:
                out[str(p.relative_to(root))] = _sha256_file(p)
            except Exception:  # noqa: BLE001
                continue
    return out


def _modbus_snapshot() -> Dict[str, List[int]]:
    coils: List[int] = []
    regs: List[int] = []
    if ModbusTcpClient is None:
        return {"coils": coils, "registers": regs}
    client = ModbusTcpClient(PRODUCTION_PLC_IP, port=PRODUCTION_PLC_PORT, timeout=1.0)
    try:
        if not client.connect():
            return {"coils": coils, "registers": regs}
        cr = client.read_coils(0, 10)
        rr = client.read_holding_registers(0, 16)
        if not (cr.isError() or rr.isError()):
            coils = [int(bool(b)) for b in (cr.bits or [])][:10]
            regs = [int(x) for x in (rr.registers or [])][:16]
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass
    return {"coils": coils, "registers": regs}


def _proc_running(name: str) -> bool:
    try:
        # Check in procfs for simplicity
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                cmd = Path(f"/proc/{pid}/cmdline").read_text(errors="replace")
            except Exception:
                continue
            if name in cmd:
                return True
    except Exception:
        return False
    return False


def main() -> int:
    ot_services = _read_ot_services_file()
    if ot_services is not None:
        services = ot_services
    else:
        services = {
            "safety_supervisor": _proc_running("safety_bridge.py"),
            "safety_heartbeat": _proc_running("safety_heartbeat.py"),
            "openplc": _proc_running("openplc") or _proc_running("OpenPLC")
        }

    data = {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "plc_files": _hash_tree(PLC_DIR),
        "sros2_files": _hash_tree(SROS2_DIR),
        "modbus_snapshot": _modbus_snapshot(),
        "services": services,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2, sort_keys=True))
    print(f"integrity baseline written → {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
