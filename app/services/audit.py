import json
from contextvars import ContextVar
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.models.models import AuditLog, User


_request_context: ContextVar[dict | None] = ContextVar("audit_request_context", default=None)


def begin_request_context(**values):
    context = {**values, "event_written": False, "row_ids": []}
    return _request_context.set(context), context


def end_request_context(token) -> None:
    _request_context.reset(token)


def request_event_written(context: dict) -> bool:
    return bool(context.get("event_written"))


def category_for(action: str, entity: str) -> str:
    if action in {"login", "logout", "login_failed", "login_blocked", "2fa_failed", "2fa_challenge", "create_initial_admin"}:
        return "authentication"
    if action in {"change_password", "password_reset_completed", "password_reset_email_failed", "password_reset_requested", "start_2fa", "enable_2fa", "disable_2fa", "reveal"}:
        return "security"
    if action in {"import", "export"}:
        return "data"
    if action in {"request_failed", "request_error"}:
        return "request"
    if entity in {"remote_session", "rdp_session", "ssh_session", "remote_session_recording"}:
        return "remote_access"
    return "activity"


def severity_for(action: str, status_code: int | None = None) -> str:
    if status_code is not None and status_code >= 500:
        return "error"
    if status_code is not None and status_code >= 400:
        return "warning"
    if action in {"login_failed", "login_blocked", "2fa_failed", "delete", "reveal", "disable_2fa"}:
        return "warning"
    return "info"


def write_audit(
    db: Session,
    user: User | None,
    action: str,
    entity: str,
    entity_id: str | None = None,
    ip_address: str | None = None,
    detail: str | None = None,
    *,
    category: str | None = None,
    severity: str | None = None,
    status_code: int | None = None,
    metadata: dict | None = None,
):
    context = _request_context.get() or {}
    resolved_status = status_code if status_code is not None else context.get("status_code")
    row = AuditLog(
        user_id=user.id if user else context.get("user_id"),
        action=action,
        entity=entity,
        entity_id=entity_id,
        ip_address=ip_address or context.get("ip_address"),
        detail=detail,
        category=category or category_for(action, entity),
        severity=severity or severity_for(action, resolved_status),
        request_method=context.get("method"),
        request_path=context.get("path"),
        status_code=resolved_status,
        user_agent=context.get("user_agent"),
        request_id=context.get("request_id"),
        metadata_json=json.dumps(metadata, default=str, separators=(",", ":")) if metadata else None,
    )
    try:
        db.add(row)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return None
    context["event_written"] = True
    context.setdefault("row_ids", []).append(row.id)
    return row
