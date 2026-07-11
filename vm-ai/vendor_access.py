from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

# This module records the operator workflow only. Guacamole account administration
# remains in the DMZ bootstrap configuration: the submitted default-deny policy
# intentionally gives this AI service no control conduit to the DMZ gateway.
STATE_FILE = Path("/var/lab/state/vendor_sessions.json")
AUDIT_FILE = Path("/var/lab/log/vendor-audit.jsonl")
GUAC_PORTAL_URL = os.environ.get("LAB_GUAC_PORTAL_URL", "http://localhost:8081/")
_STATE_LOCK = threading.Lock()
_ACCESS_LEVELS = {"read_only", "maintenance"}


class CreateSessionIn(BaseModel):
    vendor_name: str = Field(..., min_length=2, max_length=100)
    vendor_email: str = Field(..., min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    justification: str = Field(..., min_length=4, max_length=400)
    duration_hours: int = Field(..., ge=1, le=8)
    access_level: str = Field(..., pattern=r"^(read_only|maintenance)$")


vendor_router = APIRouter()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _operator_identity(request: Request) -> Dict[str, str | None]:
    return {
        "operator_ip": request.client.host if request.client else None,
        "operator_user": request.headers.get("X-Operator-User"),
    }


def _read_state_unlocked() -> List[Dict[str, Any]]:
    if not STATE_FILE.exists():
        return []
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _write_state_unlocked(sessions: List[Dict[str, Any]]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(sessions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(STATE_FILE)


def _append_audit_unlocked(action: str, session: Dict[str, Any], request: Request | None, outcome: str) -> None:
    """Append a hash-chained event without recording a secret or token."""
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = ""
    if AUDIT_FILE.exists():
        try:
            for line in reversed(AUDIT_FILE.read_text(encoding="utf-8").splitlines()):
                if line.strip():
                    previous_hash = str(json.loads(line).get("event_hash", ""))
                    break
        except (OSError, json.JSONDecodeError):
            previous_hash = ""

    rec: Dict[str, Any] = {
        "timestamp": _iso(),
        "action": action,
        "session_id": session.get("session_id"),
        "vendor_name": session.get("vendor_name"),
        "access_level": session.get("access_level"),
        "status": session.get("status"),
        "outcome": outcome,
        "previous_event_hash": previous_hash or None,
        **(_operator_identity(request) if request else {"operator_ip": None, "operator_user": "system"}),
    }
    canonical = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    rec["event_hash"] = hashlib.sha256(f"{previous_hash}|{canonical}".encode("utf-8")).hexdigest()
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(rec, sort_keys=True) + "\n")


def _expire_due_unlocked(sessions: List[Dict[str, Any]]) -> bool:
    now = _now()
    changed = False
    for session in sessions:
        if session.get("status") != "approved" or not session.get("expires_at"):
            continue
        try:
            expiry = datetime.fromisoformat(str(session["expires_at"]).replace("Z", "+00:00"))
        except ValueError:
            continue
        if now >= expiry:
            session["status"] = "expired"
            session["ended_at"] = _iso(now)
            _append_audit_unlocked("window_expired", session, None, "record_closed")
            changed = True
    return changed


def _public(session: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(session)
    out["guacamole_portal_url"] = GUAC_PORTAL_URL
    out["active"] = out.get("status") == "approved"
    return out


def _load_and_expire() -> List[Dict[str, Any]]:
    with _STATE_LOCK:
        sessions = _read_state_unlocked()
        if _expire_due_unlocked(sessions):
            _write_state_unlocked(sessions)
        return sessions


def _find(sessions: List[Dict[str, Any]], session_id: str) -> Dict[str, Any]:
    for session in sessions:
        if session.get("session_id") == session_id:
            return session
    raise HTTPException(status_code=404, detail="vendor access request not found")


@vendor_router.post("/api/vendor/sessions")
async def create_session(payload: CreateSessionIn, request: Request) -> Dict[str, Any]:
    if payload.access_level not in _ACCESS_LEVELS:
        raise HTTPException(status_code=400, detail="unsupported access level")
    with _STATE_LOCK:
        sessions = _read_state_unlocked()
        _expire_due_unlocked(sessions)
        now = _now()
        record: Dict[str, Any] = {
            "session_id": uuid.uuid4().hex[:12],
            "vendor_name": payload.vendor_name.strip(),
            "vendor_email": str(payload.vendor_email),
            "justification": payload.justification.strip(),
            "access_level": payload.access_level,
            "duration_hours": payload.duration_hours,
            "created_at": _iso(now),
            "approved_at": None,
            "expires_at": None,
            "ended_at": None,
            "status": "pending",
        }
        sessions.append(record)
        _append_audit_unlocked("request_created", record, request, "pending_operator_approval")
        _write_state_unlocked(sessions)
        return _public(record)


@vendor_router.post("/api/vendor/sessions/{session_id}/approve")
async def approve_session(session_id: str, request: Request) -> Dict[str, Any]:
    with _STATE_LOCK:
        sessions = _read_state_unlocked()
        _expire_due_unlocked(sessions)
        session = _find(sessions, session_id)
        if session.get("status") != "pending":
            raise HTTPException(status_code=409, detail="only a pending request can be approved")
        now = _now()
        session["status"] = "approved"
        session["approved_at"] = _iso(now)
        session["expires_at"] = _iso(now + timedelta(hours=int(session["duration_hours"])))
        _append_audit_unlocked("request_approved", session, request, "approved_window_open")
        _write_state_unlocked(sessions)
        return _public(session)


@vendor_router.post("/api/vendor/sessions/{session_id}/decline")
async def decline_session(session_id: str, request: Request) -> Dict[str, Any]:
    with _STATE_LOCK:
        sessions = _read_state_unlocked()
        _expire_due_unlocked(sessions)
        session = _find(sessions, session_id)
        if session.get("status") != "pending":
            raise HTTPException(status_code=409, detail="only a pending request can be declined")
        session["status"] = "declined"
        session["ended_at"] = _iso()
        _append_audit_unlocked("request_declined", session, request, "record_closed")
        _write_state_unlocked(sessions)
        return _public(session)


@vendor_router.post("/api/vendor/sessions/{session_id}/end")
async def end_session(session_id: str, request: Request) -> Dict[str, Any]:
    with _STATE_LOCK:
        sessions = _read_state_unlocked()
        _expire_due_unlocked(sessions)
        session = _find(sessions, session_id)
        if session.get("status") != "approved":
            raise HTTPException(status_code=409, detail="only an approved window can be ended")
        session["status"] = "ended"
        session["ended_at"] = _iso()
        _append_audit_unlocked("window_ended", session, request, "record_closed")
        _write_state_unlocked(sessions)
        return _public(session)


@vendor_router.get("/api/vendor/sessions")
async def list_sessions() -> List[Dict[str, Any]]:
    return [_public(session) for session in _load_and_expire()]


@vendor_router.get("/api/vendor/audit")
async def get_audit() -> List[Dict[str, Any]]:
    if not AUDIT_FILE.exists():
        return []
    records: List[Dict[str, Any]] = []
    for line in AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-100:]:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records
