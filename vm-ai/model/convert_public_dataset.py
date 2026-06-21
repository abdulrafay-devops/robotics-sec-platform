"""
Convert a real public ICS / Modbus dataset into the v2 feature-CSV schema that
``model.datasets.load_external`` (and the trainers) consume.

WHY: the synthetic generator is reproducible but circular — training and eval on
your own attacks inflates AUC. Dropping in a real capture lets you quote an honest
"ROC-AUC on held-out real ICS traffic" number. This converter reuses the SAME
``model.features`` aggregator that training and live scoring use, so the real data
is windowed into exactly the same 20-feature vectors — no drift, no second code path.

INPUT: a CSV of per-message Modbus records (one row per Modbus request/response).
Map your dataset's columns to these canonical fields (defaults shown; override on
the CLI). Unknown/missing optional fields default sensibly.

    ts         timestamp (epoch seconds or ISO-8601)      [required]
    src_ip     source IP                                   [required]
    dst_ip     destination IP                              [optional]
    func_code  Modbus function code (int)                  [required]
    is_request true/false (response rows may be omitted)    [optional, default true]
    address    register/coil address (int)                 [optional]
    quantity   quantity (int)                              [optional]
    exception  Modbus exception flag (bool)                [optional]
    label      1=attack, 0=normal (per message)            [optional, default 0]

OUTPUT: ``<out-dir>/<name>.csv`` with header = FEATURE_NAMES + ["label"]; one row
per 5-second window. A window is labelled 1 if any message in it is labelled 1.

RECOMMENDED PUBLIC DATASETS (download manually — most require registration):
  * SWaT / WADI (iTrust, Singapore Univ. of Tech & Design) — request access.
  * HAI (HIL-based Augmented ICS, ICS Security) — github.com/icsdataset/hai
  * Morris/MSU SCADA / gas-pipeline Modbus datasets — sites.google.com/site/icsdataset
  * Any Zeek `modbus`-parsed pcap exported to CSV with the columns above.
Place the converted CSV(s) in the dir bound to ``/var/lab/datasets`` and retrain.

USAGE (run inside container-ai or anywhere with the repo on PYTHONPATH):
    python -m model.convert_public_dataset --in raw_modbus.csv \
        --out-dir /var/lab/datasets --name swat_slice
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
from typing import Dict, List

import numpy as np

from .features import FEATURE_NAMES, RawRow, aggregate_rows, window_key

LOG = logging.getLogger("convert_public_dataset")

DEFAULT_MAP = {
    "ts": "ts", "src_ip": "src_ip", "dst_ip": "dst_ip", "func_code": "func_code",
    "is_request": "is_request", "address": "address", "quantity": "quantity",
    "exception": "exception", "label": "label",
}


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "t", "yes", "y")


def convert(in_path: str, out_dir: str, name: str, colmap: Dict[str, str],
            ot_prefixes: List[str]) -> str:
    rows: List[RawRow] = []
    labels_by_msg: List[tuple] = []   # (window_key, label) to label windows afterwards

    with open(in_path, "r", newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise SystemExit(f"{in_path}: no header row")
        for rec in reader:
            try:
                src = str(rec.get(colmap["src_ip"], "") or "")
                ot_origin = any(src.startswith(p) for p in ot_prefixes)
                r = RawRow.from_dict({
                    "ts": rec.get(colmap["ts"]),
                    "src_ip": src,
                    "dst_ip": rec.get(colmap.get("dst_ip", "dst_ip"), ""),
                    "func_code": rec.get(colmap["func_code"], 0),
                    "is_request": rec.get(colmap.get("is_request", "is_request"), True),
                    "address": rec.get(colmap.get("address", "address"), 0),
                    "quantity": rec.get(colmap.get("quantity", "quantity"), 0),
                    "exception": rec.get(colmap.get("exception", "exception"), False),
                    "ot_origin": ot_origin,
                })
            except (KeyError, ValueError, TypeError) as exc:
                LOG.debug("skipping malformed row: %s", exc)
                continue
            label = 1 if _truthy(rec.get(colmap.get("label", "label"), 0)) else 0
            rows.append(r)
            labels_by_msg.append((window_key(r.ts, r.src_ip), label))

    if not rows:
        raise SystemExit(f"{in_path}: no usable Modbus rows after parsing")

    # Window label = 1 if any message in that (src_ip, window) is an attack.
    win_label: Dict[tuple, int] = {}
    for key, label in labels_by_msg:
        win_label[key] = max(win_label.get(key, 0), label)

    buckets = aggregate_rows(rows)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{name}.csv")
    n_attack = 0
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(list(FEATURE_NAMES) + ["label"])
        for b in buckets:
            vec = b.feature_vector()
            key = (b.src_ip, b.window_start)
            label = int(win_label.get(key, 0))
            n_attack += label
            w.writerow([f"{x:.6g}" for x in vec] + [label])

    LOG.info("wrote %d windows (%d attack / %d normal) -> %s",
             len(buckets), n_attack, len(buckets) - n_attack, out_path)
    return out_path


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    p.add_argument("--in", dest="in_path", required=True, help="raw per-message Modbus CSV")
    p.add_argument("--out-dir", default="/var/lab/datasets")
    p.add_argument("--name", default="external_modbus")
    p.add_argument("--ot-prefixes", default="192.168.10.,10.0.0.",
                   help="comma-separated IP prefixes treated as inside the OT zone")
    for f in DEFAULT_MAP:
        p.add_argument(f"--col-{f}", default=DEFAULT_MAP[f],
                       help=f"source column name for '{f}' (default: {DEFAULT_MAP[f]})")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    colmap = {f: getattr(args, f"col_{f}") for f in DEFAULT_MAP}
    ot_prefixes = [s for s in args.ot_prefixes.split(",") if s]
    convert(args.in_path, args.out_dir, args.name, colmap, ot_prefixes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
