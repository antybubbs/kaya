import secrets
import time
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.models import AppSession, User

SESSION_SYNC_SECONDS = 60
ACTIVE_WINDOW_MINUTES = 30


def request_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:80]
    return request.client.host[:80] if request.client and request.client.host else None


def request_user_agent(request: Request) -> str | None:
    user_agent = request.headers.get("user-agent", "").strip()
    return user_agent[:500] or None


def start_user_session(db: Session, request: Request, user: User) -> None:
    session_id = secrets.token_urlsafe(32)
    request.session["session_id"] = session_id
    request.session["session_last_seen_sync"] = int(time.time())
    db.add(AppSession(
        session_id=session_id,
        user_id=user.id,
        ip_address=request_ip(request),
        user_agent=request_user_agent(request),
    ))
    db.commit()


def touch_user_session(db: Session, request: Request, user: User) -> None:
    session_id = request.session.get("session_id")
    if not session_id:
        start_user_session(db, request, user)
        return
    now = int(time.time())
    last_sync = int(request.session.get("session_last_seen_sync") or 0)
    if now - last_sync < SESSION_SYNC_SECONDS:
        return
    request.session["session_last_seen_sync"] = now
    row = db.query(AppSession).filter(AppSession.session_id == session_id).first()
    if not row:
        start_user_session(db, request, user)
        return
    row.user_id = user.id
    row.ip_address = request_ip(request)
    row.user_agent = request_user_agent(request)
    row.last_seen_at = datetime.utcnow()
    row.ended_at = None
    db.commit()


def end_user_session(db: Session, request: Request) -> None:
    session_id = request.session.get("session_id")
    if not session_id:
        return
    row = db.query(AppSession).filter(AppSession.session_id == session_id, AppSession.ended_at.is_(None)).first()
    if row:
        row.last_seen_at = datetime.utcnow()
        row.ended_at = datetime.utcnow()
        db.commit()


def active_since() -> datetime:
    return datetime.utcnow() - timedelta(minutes=ACTIVE_WINDOW_MINUTES)
