import json
from contextvars import ContextVar
from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.models.models import AuditLog, RemoteManagerSetting, User


_request_context: ContextVar[dict | None] = ContextVar("audit_request_context", default=None)

AUDIT_LEVELS = ("essential", "standard", "verbose", "diagnostic")
AUDIT_RETENTION_PRESETS = {"30": 30, "60": 60, "90": 90, "180": 180, "365": 365}
AUDIT_DEFAULT_LEVEL = "standard"
AUDIT_DEFAULT_RETENTION = "90"
AUDIT_MAX_CUSTOM_DAYS = 3650
AUDIT_SETTINGS_KEYS = {
    "audit_capture_level": AUDIT_DEFAULT_LEVEL,
    "audit_retention_mode": AUDIT_DEFAULT_RETENTION,
    "audit_retention_days": "90",
}
ESSENTIAL_ACTIONS = {
    "login", "logout", "login_failed", "login_blocked", "2fa_failed",
    "change_password", "password_reset_blocked", "password_reset_completed",
    "start_2fa", "enable_2fa", "disable_2fa", "module_access_denied",
    "module_access_granted", "module_access_removed", "delete", "reveal",
    "break_glass_login_succeeded", "break_glass_login_failed",
}


def begin_request_context(**values):
    context = {**values, "event_written": False, "row_ids": []}
    return _request_context.set(context), context


def end_request_context(token) -> None:
    _request_context.reset(token)


def request_event_written(context: dict) -> bool:
    return bool(context.get("event_written"))


def validate_audit_settings(level: str, retention_mode: str, retention_days: str | int | None) -> tuple[str, str, int | None]:
    level = str(level or "").strip().lower()
    retention_mode = str(retention_mode or "").strip().lower()
    if level not in AUDIT_LEVELS:
        raise ValueError("Choose a supported audit capture level.")
    if retention_mode not in {*AUDIT_RETENTION_PRESETS, "custom", "indefinite"}:
        raise ValueError("Choose a supported audit retention period.")
    if retention_mode == "custom":
        try:
            days = int(retention_days or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Custom audit retention must be a whole number of days.") from exc
        if not 1 <= days <= AUDIT_MAX_CUSTOM_DAYS:
            raise ValueError(f"Custom audit retention must be between 1 and {AUDIT_MAX_CUSTOM_DAYS} days.")
    else:
        days = AUDIT_RETENTION_PRESETS.get(retention_mode)
    return level, retention_mode, days


def get_audit_settings(db: Session) -> dict[str, str | int | None]:
    values = AUDIT_SETTINGS_KEYS.copy()
    rows = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key.in_(values)).all()
    for row in rows:
        values[row.key] = row.value or values[row.key]
    level, mode, days = validate_audit_settings(
        str(values["audit_capture_level"]),
        str(values["audit_retention_mode"]),
        values.get("audit_retention_days"),
    )
    return {"capture_level": level, "retention_mode": mode, "retention_days": days}


def _capture_tier(action: str, entity: str, category: str, request_path: str | None, status_code: int | None, requested: str | None) -> str:
    if requested:
        tier = str(requested).lower()
        if tier not in AUDIT_LEVELS:
            raise ValueError("Invalid audit capture tier")
    else:
        tier = "standard"
    if action in ESSENTIAL_ACTIONS or category in {"authentication", "security"} or status_code is not None and status_code >= 400:
        return "essential"
    if request_path and request_path.rstrip("/").endswith("/api/ha/agent/v1/heartbeat") and (status_code or 200) < 400:
        return "verbose"
    return tier


def _tier_allowed(tier: str, level: str) -> bool:
    return AUDIT_LEVELS.index(tier) <= AUDIT_LEVELS.index(level)


def category_for(action: str, entity: str) -> str:
    if action.startswith("oidc_") or action.startswith("break_glass_"):
        return "authentication"
    if action in {"login", "logout", "login_failed", "login_blocked", "2fa_failed", "2fa_challenge", "create_initial_admin"}:
        return "authentication"
    if action in {"change_password", "password_reset_blocked", "password_reset_completed", "password_reset_email_failed", "password_reset_requested", "start_2fa", "enable_2fa", "disable_2fa", "reveal", "module_access_denied", "module_access_granted", "module_access_removed"}:
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
    if action in {"login_failed", "login_blocked", "2fa_failed", "delete", "reveal", "disable_2fa", "break_glass_login_succeeded", "break_glass_login_failed", "oidc_link_failed", "module_access_denied", "module_access_removed"}:
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
    capture_tier: str | None = None,
    force: bool = False,
):
    context = _request_context.get() or {}
    resolved_status = status_code if status_code is not None else context.get("status_code")
    resolved_path = context.get("path")
    resolved_category = category or category_for(action, entity)
    tier = _capture_tier(action, entity, resolved_category, resolved_path, resolved_status, capture_tier)
    configured_level = (
        str(get_audit_settings(db)["capture_level"])
        if hasattr(db, "query")
        else AUDIT_DEFAULT_LEVEL
    )
    if not force and tier != "essential" and not _tier_allowed(tier, configured_level):
        return None
    resolved_ip_address = None if context.get("redact_client") else (ip_address or context.get("ip_address"))
    row = AuditLog(
        user_id=user.id if user else context.get("user_id"),
        action=action,
        entity=entity,
        entity_id=entity_id,
        ip_address=resolved_ip_address,
        detail=detail,
        category=resolved_category,
        severity=severity or severity_for(action, resolved_status),
        request_method=context.get("method"),
        request_path=context.get("path"),
        status_code=resolved_status,
        user_agent=context.get("user_agent"),
        request_id=context.get("request_id"),
        capture_tier=tier,
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


def save_audit_settings(db: Session, *, level: str, retention_mode: str, retention_days: str | int | None) -> tuple[dict, dict]:
    new_level, new_mode, new_days = validate_audit_settings(level, retention_mode, retention_days)
    old = get_audit_settings(db)
    values = {
        "audit_capture_level": new_level,
        "audit_retention_mode": new_mode,
        "audit_retention_days": str(new_days or ""),
    }
    for key, value in values.items():
        row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == key).first()
        if not row:
            row = RemoteManagerSetting(key=key)
            db.add(row)
        row.value = value
    db.commit()
    return old, {"capture_level": new_level, "retention_mode": new_mode, "retention_days": new_days}


def cleanup_audit_logs(db: Session, *, batch_size: int = 500) -> int:
    settings = get_audit_settings(db)
    if settings["retention_mode"] == "indefinite":
        return 0
    cutoff = datetime.utcnow() - timedelta(days=int(settings["retention_days"]))
    deleted = 0
    while True:
        ids = [
            row[0]
            for row in db.query(AuditLog.id)
            .filter(
                AuditLog.created_at < cutoff,
                AuditLog.capture_tier != "essential",
            )
            .order_by(AuditLog.id)
            .limit(batch_size)
            .all()
        ]
        if not ids:
            break
        db.query(AuditLog).filter(AuditLog.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        deleted += len(ids)
    return deleted


def audit_purge_query(db: Session, *, category: str = "", severity: str = "",
                      action: str = "", entity: str = "", actor: str = "",
                      date_from: str = "", date_to: str = "", older_than: str = ""):
    """Build the exact, bounded filter used by manual audit deletion and preview."""
    values = {
        "category": str(category or "").strip(),
        "severity": str(severity or "").strip(),
        "action": str(action or "").strip(),
        "entity": str(entity or "").strip(),
        "actor": str(actor or "").strip(),
        "date_from": str(date_from or "").strip(),
        "date_to": str(date_to or "").strip(),
        "older_than": str(older_than or "").strip(),
    }
    for key, value in values.items():
        if len(value) > (255 if key == "actor" else 80):
            raise ValueError(f"Audit purge filter '{key}' is too long.")
    if values["date_from"] and values["older_than"]:
        raise ValueError("Use either a start date or an older-than date, not both.")
    try:
        if values["date_from"]:
            start = datetime.strptime(values["date_from"], "%Y-%m-%d")
            db_query = db.query(AuditLog).filter(AuditLog.created_at >= start)
        else:
            db_query = db.query(AuditLog)
        if values["date_to"]:
            db_query = db_query.filter(
                AuditLog.created_at < datetime.strptime(values["date_to"], "%Y-%m-%d") + timedelta(days=1)
            )
        if values["older_than"]:
            db_query = db_query.filter(
                AuditLog.created_at < datetime.strptime(values["older_than"], "%Y-%m-%d")
            )
    except ValueError as exc:
        raise ValueError("Audit purge dates must use YYYY-MM-DD and be valid calendar dates.") from exc
    if values["date_from"] and values["date_to"] and values["date_from"] > values["date_to"]:
        raise ValueError("Audit purge start date must not be after the end date.")
    if values["category"]:
        db_query = db_query.filter(AuditLog.category == values["category"])
    if values["severity"]:
        if values["severity"] not in {"info", "warning", "error", "critical"}:
            raise ValueError("Choose a supported audit severity.")
        db_query = db_query.filter(AuditLog.severity == values["severity"])
    if values["action"]:
        db_query = db_query.filter(AuditLog.action == values["action"])
    if values["entity"]:
        db_query = db_query.filter(AuditLog.entity == values["entity"])
    if values["actor"]:
        db_query = db_query.filter(AuditLog.user.has(User.email == values["actor"]))
    return db_query, values


def preview_audit_purge(db: Session, **filters) -> dict:
    query, values = audit_purge_query(db, **filters)
    oldest, newest = query.with_entities(func.min(AuditLog.created_at), func.max(AuditLog.created_at)).one()
    return {"count": query.count(), "oldest": oldest, "newest": newest, "filters": values}


def purge_audit_logs(db: Session, user: User, *, batch_size: int = 500, **filters) -> int:
    query, values = audit_purge_query(db, **filters)
    batch_size = max(1, min(int(batch_size), 1000))
    deleted = 0
    while True:
        ids = [row[0] for row in query.with_entities(AuditLog.id).order_by(AuditLog.id).limit(batch_size).all()]
        if not ids:
            break
        db.query(AuditLog).filter(AuditLog.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        deleted += len(ids)
    event = write_audit(
        db, user, "audit_logs_purged", "audit_log", "manual_purge",
        detail=f"Deleted {deleted} audit log event(s).",
        category="security", severity="warning",
        metadata={"count": deleted, "filters": values},
        capture_tier="essential", force=True,
    )
    if event is None:
        raise RuntimeError("The audit purge completed but its mandatory record could not be written.")
    return deleted
