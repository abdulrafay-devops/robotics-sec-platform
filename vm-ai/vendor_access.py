from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

STATE_FILE = Path("/var/lab/state/vendor_sessions.json")
AUDIT_FILE = Path("/var/lab/log/vendor-audit.jsonl")
GUAC_URL = os.environ.get("LAB_GUAC_BASE", "http://localhost:8081/#/")

# Map access levels to pre-configured Guacamole connection names.
# These connection names must exist in the Guacamole database (see 03-lab-connections.sql).
_ACCESS_LEVEL_CONNECTIONS = {
    "read_only":   os.environ.get("GUAC_CONN_READ_ONLY",   "OT-ReadOnly"),
    "maintenance": os.environ.get("GUAC_CONN_MAINTENANCE",  "OT-Maintenance"),
}


def _guac_connection_url(access_level: str, session_id: str) -> str:
    """Build a Guacamole client URL for the named connection."""
    conn_name = _ACCESS_LEVEL_CONNECTIONS.get(access_level, "OT-ReadOnly")
    # Guacamole client URL format: /#/client/<base64(connection_name + NUL + 'c' + NUL + source)>
    import base64
    conn_id = base64.b64encode(f"{conn_name}\x00c\x00postgresql".encode()).decode()
    return f"{GUAC_URL}client/{conn_id}?session={session_id}"


class CreateSessionIn(BaseModel):
    vendor_name: str = Field(..., min_length=2, max_length=100)
    vendor_email: str = Field(..., min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    justification: str = Field(..., min_length=4, max_length=400)
    duration_hours: int = Field(..., ge=1, le=8)
    access_level: str = Field(..., pattern=r"^(read_only|maintenance)$")


class VendorSession(BaseModel):
    session_id: str
    vendor_name: str
    vendor_email: str
    justification: str
    access_level: str
    created_at: str
    expires_at: str
    revoked_at: Optional[str] = None
    guacamole_connection_url: str
    audit_token: str
    active: bool


vendor_router = APIRouter()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_audit(action: str, vendor_name: str, session_id: str, request: Request, outcome: str) -> None:
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "timestamp": _now_iso(),
        "action": action,
        "vendor_name": vendor_name,
        "session_id": session_id,
        "operator_ip": request.client.host if request and request.client else None,
        "outcome": outcome,
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _read_state() -> List[Dict[str, Any]]:
    if not STATE_FILE.exists():
        return []
    try:
        return json.loads(STATE_FILE.read_text())
    except json.JSONDecodeError:
        return []


def _write_state(sessions: List[Dict[str, Any]]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(sessions, indent=2, sort_keys=True))


@vendor_router.post("/api/vendor/sessions")
async def create_session(payload: CreateSessionIn, request: Request) -> Dict[str, Any]:
    sessions = _read_state()
    sid = uuid.uuid4().hex[:10]
    audit_token = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=payload.duration_hours)

    guac_url = _guac_connection_url(payload.access_level, sid)

    rec: Dict[str, Any] = {
        "session_id": sid,
        "vendor_name": payload.vendor_name,
        "vendor_email": str(payload.vendor_email),
        "justification": payload.justification,
        "access_level": payload.access_level,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revoked_at": None,
        "guacamole_connection_url": guac_url,
        "audit_token": audit_token,
        "active": True,
    }
    sessions.append(rec)
    _write_state(sessions)
    _append_audit("create", payload.vendor_name, sid, request, "ok")
    return {
        "session_id": sid,
        "guacamole_connection_url": guac_url,
        "expires_at": rec["expires_at"],
        "audit_token": audit_token,
    }


@vendor_router.get("/api/vendor/sessions")
async def list_sessions() -> List[Dict[str, Any]]:
    sessions = _read_state()
    # Mark active flag based on time and revoked_at
    now = datetime.now(timezone.utc)
    for s in sessions:
        exp = datetime.fromisoformat(s["expires_at"].replace("Z", "+00:00"))
        s["active"] = s.get("revoked_at") is None and now < exp
    return sessions


@vendor_router.delete("/api/vendor/sessions/{session_id}")
async def revoke_session(session_id: str, audit_token: str, request: Request) -> Dict[str, Any]:
    sessions = _read_state()
    found = False
    now_iso = _now_iso()
    for s in sessions:
        if s.get("session_id") == session_id:
            if s.get("audit_token") != audit_token:
                _append_audit("revoke_denied", s.get("vendor_name", "?"), session_id, request, "invalid_token")
                raise HTTPException(status_code=403, detail="invalid audit token")
            s["revoked_at"] = now_iso
            s["active"] = False
            found = True
            break
    if not found:
        _append_audit("revoke", "?", session_id, request, "not_found")
        raise HTTPException(status_code=404, detail="session not found")
    _write_state(sessions)
    _append_audit("revoke", next((s["vendor_name"] for s in sessions if s["session_id"]==session_id), "?"), session_id, request, "ok")
    return {"status": "ok"}


@vendor_router.get("/api/vendor/audit")
async def get_audit() -> List[Dict[str, Any]]:
    if not AUDIT_FILE.exists():
        return []
    lines = AUDIT_FILE.read_text().splitlines()[-100:]
    out: List[Dict[str, Any]] = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out
