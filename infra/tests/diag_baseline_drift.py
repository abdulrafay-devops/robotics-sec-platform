#!/usr/bin/env python3
"""One-shot diagnostic: replay live Modbus rows through the SAME feature code the
consumer uses, then show how far each feature is from the scaler's TRAINING mean.
Pinpoints which features drove an autoencoder false-positive. Run inside container-ai."""
import json, time, sys
import numpy as np, joblib
from model.features import FEATURE_NAMES, RawRow, WindowStore

LOG = sys.argv[1] if len(sys.argv) > 1 else "/var/lab/sec-log/zeek/current/modbus_features.log"
rows = []
with open(LOG) as f:
    for ln in f.readlines()[-600:]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(RawRow.from_dict(json.loads(ln)))
        except Exception:
            pass

store = WindowStore(grace_seconds=2.0)
for r in rows:
    store.add(r)
buckets = list(store.flush_until(time.time() + 3600))

scaler = joblib.load("/opt/lab/models/scaler.pkl")
mean, scale = scaler.mean_, scaler.scale_
print(f"rows replayed: {len(rows)}   windows: {len(buckets)}")
for b in buckets[-3:]:
    v = np.asarray(b.feature_vector(), dtype=float)
    xs = (v - mean) / scale
    print(f"\n== window src={b.src_ip} n_msgs={len(b.rows)} start={b.window_start} ==")
    print(f"   {'feature':20s} {'value':>12s} {'train_mean':>12s} {'scaled_z':>9s}")
    for i in np.argsort(-np.abs(xs)):
        flag = "  <== DRIFT" if abs(xs[i]) > 4 else ""
        print(f"   {FEATURE_NAMES[i]:20s} {v[i]:12.4f} {mean[i]:12.4f} {xs[i]:9.2f}{flag}")
