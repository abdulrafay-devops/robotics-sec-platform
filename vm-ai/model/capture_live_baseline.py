#!/usr/bin/env python3
"""
Capture REAL baseline windows from the live Zeek Modbus log and save them as the
training matrix X. Replays rows through the SAME feature module the consumer uses,
so the captured windows are byte-identical to what the model will score in
production (no train/serve skew). Only clean, recent, read-only windows are kept —
including the naturally under-filled ones, so the autoencoder learns those as
normal too. Run inside container-ai with PYTHONPATH=/vagrant/vm-ai.
"""
from __future__ import annotations
import json, os, sys, time
import numpy as np
from model.features import RawRow, WindowStore, FEATURE_NAMES

LOG = os.environ.get("CAPTURE_LOG", "/var/lab/sec-log/zeek/current/modbus_features.log")
OUT = sys.argv[1] if len(sys.argv) > 1 else "/var/lab/state/live_baseline_X.npy"
RECENT_S = float(os.environ.get("CAPTURE_RECENT_S", "1200"))   # last 20 min of 4Hz traffic
MIN_MSGS = int(os.environ.get("CAPTURE_MIN_MSGS", "5"))
_IDX = {n: i for i, n in enumerate(FEATURE_NAMES)}


def _clean(v: np.ndarray) -> bool:
    g = lambda n: v[_IDX[n]] if n in _IDX else 0.0
    if g("n_writes") > 1:           return False
    if g("n_exceptions") > 0:       return False
    if g("n_external_writes") > 0:  return False
    if g("write_ratio") > 0.05:     return False
    if g("msg_rate") > 40:          return False   # exclude flood
    return True


def main() -> int:
    rows = []
    with open(LOG, errors="replace") as fh:
        for ln in fh:                      # whole file; the recency filter trims it
            ln = ln.strip()
            if ln:
                try: rows.append(RawRow.from_dict(json.loads(ln)))
                except Exception: pass
    if not rows:
        print("no rows in log"); return 2
    tmax = max(r.ts for r in rows)
    rows = [r for r in rows if r.ts >= tmax - RECENT_S]
    store = WindowStore(grace_seconds=2.0)
    for r in rows:
        store.add(r)
    buckets = [b for b in store.flush_until(time.time() + 3600) if len(b.rows) >= MIN_MSGS]
    X, sizes = [], []
    for b in buckets:
        v = np.asarray(b.feature_vector(), dtype=float)
        if _clean(v):
            X.append(v); sizes.append(len(b.rows))
    X = np.asarray(X)
    if len(X) == 0:
        print("no clean windows captured"); return 2
    np.save(OUT, X)
    import collections
    print(f"captured {len(X)} clean baseline windows -> {OUT}  shape={X.shape}")
    print("window-size distribution (n_msgs):", dict(sorted(collections.Counter(sizes).items())))
    print("feature means (first 6):", {FEATURE_NAMES[i]: round(float(X[:, i].mean()), 2) for i in range(6)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
