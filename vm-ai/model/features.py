"""
Canonical Modbus-feature engineering for Stage 2.  v2 — 20-dimensional vector.

Both training and inference import the same FEATURE_NAMES and aggregate_window
so the model and the live scorer always see identical vectors.  Any change here
REQUIRES retraining and bumping FEATURE_VERSION.

Window strategy: 5-second tumbling windows keyed by src_ip.

New in v2 (8 additional features):
  write_ratio        — n_writes / n_msgs          (write-heavy = suspicious)
  exception_rate     — n_exceptions / n_msgs       (exception storms = attack)
  n_external_writes  — writes from non-OT IPs      (THE key exfil/injection signal)
  func_entropy       — Shannon entropy of FC dist   (attack traffic = high entropy)
  mean_iat_ms        — mean inter-arrival time ms   (bursts = low IAT)
  std_iat_ms         — std of inter-arrival time    (uniform bursts = low std)
  bulk_write_ratio   — FC 15/16 ratio               (bulk writes = very suspicious)
  write_read_ratio   — n_writes / (n_reads + 1)     (injection attacks = very high)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

FEATURE_VERSION = "v2"
WINDOW_SECONDS = 5.0

WRITE_FCS  = frozenset({5, 6, 15, 16, 22, 23})
READ_FCS   = frozenset({1, 2, 3, 4})
BULK_WRITE_FCS = frozenset({15, 16})

FEATURE_NAMES: Tuple[str, ...] = (
    # --- original 12 ---
    "n_msgs",
    "n_unique_funccodes",
    "n_writes",
    "n_reads",
    "n_exceptions",
    "mean_address",
    "std_address",
    "mean_quantity",
    "max_quantity",
    "n_unique_addresses",
    "msg_rate",
    "ot_origin",
    # --- new 8 (v2) ---
    "write_ratio",
    "exception_rate",
    "n_external_writes",
    "func_entropy",
    "mean_iat_ms",
    "std_iat_ms",
    "bulk_write_ratio",
    "write_read_ratio",
)
N_FEATURES = len(FEATURE_NAMES)   # 20


def resolve_if_threshold(meta, env_val=None, floor: float = 0.10,
                         fallback: float = 0.15):
    """Single source of truth for the IsolationForest alert threshold.

    Resolution order: explicit env override > model's calibrated 99th-percentile
    threshold (floored) > conservative fallback. Returns ``(threshold, reason)``
    where reason is one of ``"env"``, ``"calibrated"`` or ``"fallback"``.

    Both the data plane (``feature_consumer.py``) and the API
    (``score_service.py``) call this so the two can never drift on what counts as
    an anomaly (was previously re-implemented in both — audit F-14).
    """
    if env_val is not None:
        try:
            return float(env_val), "env"
        except (TypeError, ValueError):
            pass  # fall through to calibrated/fallback on a bad override
    cal = meta.get("calibrated_threshold") if isinstance(meta, dict) else None
    if cal is not None:
        try:
            return max(float(cal), floor), "calibrated"
        except (TypeError, ValueError):
            pass
    return fallback, "fallback"


@dataclass
class RawRow:
    """One parsed Modbus message from Zeek's modbus_features.log."""

    ts: float
    src_ip: str
    dst_ip: str
    func_code: int
    is_request: bool
    address: int = 0
    quantity: int = 0
    exception: bool = False
    ot_origin: bool = False

    @classmethod
    def from_dict(cls, d: Dict) -> "RawRow":
        def _b(v) -> bool:
            return str(v).lower() in ("t", "true", "1", "yes")

        def _ts(v) -> float:
            if isinstance(v, (int, float)):
                return float(v)
            s = str(v)
            try:
                return float(s)
            except ValueError:
                pass
            from datetime import datetime
            s_clean = s.replace("Z", "+00:00") if s.endswith("Z") else s
            return datetime.fromisoformat(s_clean).timestamp()

        return cls(
            ts=_ts(d["ts"]),
            src_ip=str(d.get("src_ip") or d.get("id.orig_h") or ""),
            dst_ip=str(d.get("dst_ip") or d.get("id.resp_h") or ""),
            func_code=int(d.get("func_code", 0)),
            is_request=_b(d.get("is_request", True)),
            address=int(d.get("address", 0) or 0),
            quantity=int(d.get("quantity", 0) or 0),
            exception=_b(d.get("exception", False)),
            ot_origin=_b(d.get("ot_origin", False)),
        )


@dataclass
class WindowBucket:
    """Mutable accumulator for one 5-second window of one src_ip."""

    src_ip: str
    window_start: float
    rows: List[RawRow] = field(default_factory=list)

    def add(self, r: RawRow) -> None:
        self.rows.append(r)

    def feature_vector(self) -> np.ndarray:
        if not self.rows:
            return np.zeros(N_FEATURES, dtype=np.float64)

        n = len(self.rows)
        fcs = [r.func_code for r in self.rows]
        addrs = [r.address for r in self.rows if r.address > 0]
        qtys  = [r.quantity for r in self.rows if r.quantity > 0]

        # --- original 12 features ---
        n_writes   = sum(1 for fc in fcs if fc in WRITE_FCS)
        n_reads    = sum(1 for fc in fcs if fc in READ_FCS)
        n_exc      = sum(1 for r in self.rows if r.exception)
        mean_addr  = float(np.mean(addrs)) if addrs else 0.0
        std_addr   = float(np.std(addrs))  if len(addrs) > 1 else 0.0
        mean_qty   = float(np.mean(qtys))  if qtys else 0.0
        max_qty    = float(max(qtys))       if qtys else 0.0
        uniq_addr  = float(len(set(addrs)))
        rate       = n / max(WINDOW_SECONDS, 1e-3)
        ot         = 1.0 if any(r.ot_origin for r in self.rows) else 0.0

        # --- new 8 features (v2) ---
        write_ratio       = n_writes / n if n else 0.0
        exception_rate    = n_exc    / n if n else 0.0
        n_ext_writes      = float(sum(
            1 for r in self.rows
            if r.func_code in WRITE_FCS and not r.ot_origin
        ))

        # Shannon entropy of function-code distribution
        from collections import Counter
        fc_counts = Counter(fcs)
        total_fc  = sum(fc_counts.values())
        func_ent  = -sum(
            (c / total_fc) * math.log2(c / total_fc)
            for c in fc_counts.values() if c > 0
        ) if total_fc > 1 else 0.0

        # Inter-arrival time in milliseconds
        sorted_ts = sorted(r.ts for r in self.rows)
        if len(sorted_ts) > 1:
            iats      = [(sorted_ts[i+1] - sorted_ts[i]) * 1000.0
                         for i in range(len(sorted_ts) - 1)]
            mean_iat  = float(np.mean(iats))
            std_iat   = float(np.std(iats))
        else:
            mean_iat  = float(WINDOW_SECONDS * 1000.0)
            std_iat   = 0.0

        bulk_write_ratio  = sum(1 for fc in fcs if fc in BULK_WRITE_FCS) / n if n else 0.0
        write_read_ratio  = n_writes / max(n_reads, 1)

        return np.array([
            # original
            float(n),
            float(len(set(fcs))),
            float(n_writes),
            float(n_reads),
            float(n_exc),
            mean_addr,
            std_addr,
            mean_qty,
            max_qty,
            uniq_addr,
            rate,
            ot,
            # v2
            write_ratio,
            exception_rate,
            n_ext_writes,
            func_ent,
            mean_iat,
            std_iat,
            bulk_write_ratio,
            write_read_ratio,
        ], dtype=np.float64)

    def meta(self) -> Dict[str, str]:
        return {
            "src_ip": self.src_ip,
            "window_start": f"{self.window_start:.3f}",
            "n_msgs": str(len(self.rows)),
        }


def window_key(ts: float, src_ip: str) -> Tuple[str, float]:
    return (src_ip, math.floor(ts / WINDOW_SECONDS) * WINDOW_SECONDS)


def aggregate_rows(rows: Iterable[RawRow]) -> List[WindowBucket]:
    buckets: Dict[Tuple[str, float], WindowBucket] = {}
    for r in rows:
        key = window_key(r.ts, r.src_ip)
        b = buckets.get(key)
        if b is None:
            b = WindowBucket(src_ip=r.src_ip, window_start=key[1])
            buckets[key] = b
        b.add(r)
    return list(buckets.values())


class WindowStore:
    """Online windowing used by feature_consumer.py."""

    def __init__(self, grace_seconds: float = 2.0) -> None:
        self._buckets: Dict[Tuple[str, float], WindowBucket] = {}
        self._grace = grace_seconds

    def add(self, r: RawRow) -> None:
        key = window_key(r.ts, r.src_ip)
        b = self._buckets.get(key)
        if b is None:
            b = WindowBucket(src_ip=r.src_ip, window_start=key[1])
            self._buckets[key] = b
        b.add(r)

    def flush_until(self, now: float) -> List[WindowBucket]:
        ready = [(k, b) for k, b in self._buckets.items()
                 if b.window_start <= now - (WINDOW_SECONDS + self._grace)]
        for k, _ in ready:
            del self._buckets[k]
        return [b for _, b in ready]

    def flush_all(self) -> List[WindowBucket]:
        out = list(self._buckets.values())
        self._buckets.clear()
        return out


def parse_zeek_tsv_line(line: str, columns: List[str]) -> Optional[RawRow]:
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        return None
    parts = line.split("\t")
    if len(parts) != len(columns):
        return None
    d = dict(zip(columns, parts))
    try:
        return RawRow.from_dict(d)
    except (KeyError, ValueError):
        return None
