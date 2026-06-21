"""
Tails Zeek's /var/lab/log/zeek/current/modbus_features.log on vm-sec and
RPUSHes each row as JSON to the vm-ai Redis list `lab.modbus.features.raw`.

Robust against:
  * `current/` symlink rotating to a different file every hour (zeekctl
    rotates logs hourly). We re-open whenever inode changes.
  * Redis briefly unavailable: exponential backoff with cap, no row drop
    while we hold the file (we re-seek to `.tell()` on reconnect).
  * Empty file at start: poll 200ms until the first line arrives.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from typing import List, Optional

import redis

LOG = logging.getLogger("feature_pusher")
logging.basicConfig(
    level=os.environ.get("LAB_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

LOG_PATH = os.environ.get(
    "LAB_FEATURES_LOG", "/var/lab/log/zeek/current/modbus_features.log",
)
REDIS_HOST = os.environ.get("LAB_REDIS_HOST", "192.168.40.30")
REDIS_PORT = int(os.environ.get("LAB_REDIS_PORT", "6379"))
RAW_LIST = os.environ.get("LAB_REDIS_RAW_LIST", "lab.modbus.features.raw")

# Zeek TSV header columns. Updated when modbus-features.zeek changes.
DEFAULT_COLUMNS: List[str] = [
    "ts", "uid", "src_ip", "dst_ip", "src_port", "dst_port",
    "func_code", "is_request", "address", "quantity", "exception", "ot_origin",
]

_should_exit = False


def _sigterm(*_a) -> None:
    global _should_exit  # noqa: PLW0603
    _should_exit = True


def _parse_columns_from_header(header_lines: List[str]) -> List[str]:
    """Zeek's TSV writes a `#fields` header. Use it if available."""
    for line in header_lines:
        if line.startswith("#fields"):
            return line.rstrip("\n").split("\t")[1:]
    return list(DEFAULT_COLUMNS)


REDIS_PASSWORD = os.environ.get("LAB_REDIS_PASSWORD", "")


def _connect_redis() -> redis.Redis:
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD or None,
        decode_responses=True,
        socket_keepalive=True,
        socket_timeout=5.0,
    )


def _open(path: str):
    try:
        return open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return None


def _row_to_json(line: str, columns: List[str]) -> Optional[str]:
    """Convert one log row to a compact JSON string ready for RPUSH.

    Handles BOTH supported Zeek output formats:
      * JSON-per-line  (LogAscii::use_json = T): pass-through after validation
      * TSV            (default ASCII):           zip with column header
    """
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        return None
    # JSON line (this is what local.zeek configures).
    if line.lstrip().startswith("{"):
        try:
            json.loads(line)  # validate; cheap on small lines
        except ValueError:
            return None
        return line
    # TSV fallback.
    parts = line.split("\t")
    if len(parts) != len(columns):
        return None
    return json.dumps(dict(zip(columns, parts)), separators=(",", ":"))


def main() -> int:
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)
    LOG.info("feature_pusher: tailing %s -> redis %s:%d list=%s",
             LOG_PATH, REDIS_HOST, REDIS_PORT, RAW_LIST)

    backoff = 1.0
    r: Optional[redis.Redis] = None
    while r is None and not _should_exit:
        try:
            r = _connect_redis()
            r.ping()
            LOG.info("connected to redis")
        except redis.RedisError as exc:
            LOG.warning("redis not reachable yet (%s); retry in %.1fs", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            r = None

    fh = None
    fh_inode: Optional[int] = None
    columns = list(DEFAULT_COLUMNS)
    pushed = 0

    while not _should_exit:
        # (Re)open the file if it doesn't exist yet, or the inode rotated.
        try:
            st = os.stat(LOG_PATH)
        except FileNotFoundError:
            if fh:
                fh.close()
                fh = None
            time.sleep(0.5)
            continue
        if fh is None or fh_inode != st.st_ino:
            if fh:
                fh.close()
            fh = _open(LOG_PATH)
            fh_inode = st.st_ino
            if fh is None:
                time.sleep(0.5)
                continue
            # Read header (first ~10 lines) to pick up #fields.
            head: List[str] = []
            for _ in range(20):
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    fh.seek(pos)
                    break
                if line.startswith("#"):
                    head.append(line)
                else:
                    fh.seek(pos)
                    break
            if head:
                columns = _parse_columns_from_header(head)
                LOG.info("columns=%s", columns)
            # Tail-friendly: start at end so we don't re-ship history on
            # restart unless the file is brand new (small).
            fh.seek(0, os.SEEK_END)
        line = fh.readline()
        if not line:
            time.sleep(0.2)
            continue
        payload = _row_to_json(line, columns)
        if payload is None:
            continue
        try:
            r.rpush(RAW_LIST, payload)
            pushed += 1
            if pushed % 100 == 0:
                LOG.info("pushed %d rows", pushed)
        except redis.RedisError as exc:
            LOG.warning("rpush failed (%s); reconnecting", exc)
            try:
                r.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                r = _connect_redis()
            except redis.RedisError:
                time.sleep(2.0)

    if fh:
        fh.close()
    LOG.info("feature_pusher exiting (pushed=%d)", pushed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
