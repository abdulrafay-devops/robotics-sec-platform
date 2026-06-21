#!/usr/bin/env python3
"""Show messages-per-5s-window from the live zeek modbus log, to explain why the
PCA/TF z-scores swing (uneven window fill). Run in container-ai."""
import json, math, datetime as dt, sys
from collections import Counter
LOG = sys.argv[1] if len(sys.argv) > 1 else "/var/lab/sec-log/zeek/current/modbus_features.log"

rows = []
for ln in open(LOG, errors="replace").read().splitlines()[-1500:]:
    ln = ln.strip()
    if ln:
        try: rows.append(json.loads(ln))
        except Exception: pass

def ep(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

buck = Counter()
for r in rows:
    try: buck[math.floor(ep(r["ts"]) / 5) * 5] += 1
    except Exception: pass

ks = sorted(buck)[-26:]
vals = [buck[k] for k in ks]
print("last %d consecutive 5s windows -> n_msgs each:" % len(ks))
print(vals)
print("distribution:", dict(sorted(Counter(vals).items())))
if vals:
    print("min=%d max=%d  (the AE sees msg_rate = n/5, so these map to different feature vectors)" % (min(vals), max(vals)))
