import secrets
import time
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.models import AppSession, User
from app.core.config import get_settings
from app.services.client_ip import client_ip

SESSION_SYNC_SECONDS = 60
ACTIVE_WINDOW_MINUTES = 30
SESSION_ABSOLUTE_HOURS = 8


def request_ip(request: Request) -> str | None:
    if get_settings().demo_mode:
        return None
    value = client_ip(request)
    return value[:80] if value else None


def request_user_agent(request: Request) -> str | None:
    if get_settings().demo_mode:
        return None
    user_agent = request.headers.get("user-agent", "").strip()
    return user_agent[:500] or None


def start_user_session(db: Session, request: Request, user: User) -> AppSession:
    session_id = secrets.token_urlsafe(32)
    request.session["session_id"] = session_id
    request.session["session_last_seen_sync"] = int(time.time())
    row = AppSession(
        session_id=session_id,
        user_id=user.id,
        ip_address=request_ip(request),
        user_agent=request_user_agent(request),
    )
    db.add(row)
    db.commit()
    return row


def active_user_session(db: Session, session_id: str | None, user_id: int | None) -> AppSession | None:
    if not session_id or not user_id:
        return None
    return (
        db.query(AppSession)
        .filter(
            AppSession.session_id == session_id,
            AppSession.user_id == user_id,
            AppSession.ended_at.is_(None),
            AppSession.created_at >= datetime.utcnow() - timedelta(hours=SESSION_ABSOLUTE_HOURS),
        )
        .first()
    )


def touch_user_session(db: Session, request: Request, user: User, row: AppSession | None = None) -> bool:
    session_id = request.session.get("session_id")
    row = row or active_user_session(db, session_id, user.id)
    if row is None:
        return False
    now = int(time.time())
    last_sync = int(request.session.get("session_last_seen_sync") or 0)
    if now - last_sync < SESSION_SYNC_SECONDS:
        return True
    request.session["session_last_seen_sync"] = now
    row.ip_address = request_ip(request)
    row.user_agent = request_user_agent(request)
    row.last_seen_at = datetime.utcnow()
    db.commit()
    return True


def revoke_user_sessions(db: Session, user_id: int, *, except_session_id: str | None = None) -> int:
    query = db.query(AppSession).filter(
        AppSession.user_id == user_id,
        AppSession.ended_at.is_(None),
    )
    if except_session_id:
        query = query.filter(AppSession.session_id != except_session_id)
    now = datetime.utcnow()
    return query.update(
        {
            AppSession.last_seen_at: now,
            AppSession.ended_at: now,
            AppSession.encrypted_oidc_id_token: None,
        },
        synchronize_session=False,
    )


def end_user_session(db: Session, request: Request) -> None:
    session_id = request.session.get("session_id")
    if not session_id:
        return
    row = db.query(AppSession).filter(AppSession.session_id == session_id, AppSession.ended_at.is_(None)).first()
    if row:
        row.last_seen_at = datetime.utcnow()
        row.ended_at = datetime.utcnow()
        row.encrypted_oidc_id_token = None
        db.commit()


def active_since() -> datetime:
    return datetime.utcnow() - timedelta(minutes=ACTIVE_WINDOW_MINUTES)
