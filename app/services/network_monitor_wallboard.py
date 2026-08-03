"""Persistence and restricted-session primitives for the IP/WAN Wallboard."""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
import secrets
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decrypt_secret, encrypt_secret, hash_password, verify_password
from app.models.models import (
    DashboardPreference,
    NetworkMonitor,
    NetworkMonitorWallboard,
    NetworkMonitorWallboardAttempt,
    NetworkMonitorWallboardMembership,
    NetworkMonitorWallboardSession,
    User,
)

WALLBOARD_COOKIE = "kaya_ip_wan_wallboard"
WALLBOARD_PREFERENCE_KEY = "ip_wan_dashboard"
MAX_MONITOR_ORDER_ITEMS = 10_000
VALID_COLUMNS = {"auto", "2", "3", "4", "5", "6", "8"}
VALID_DENSITIES = {"comfortable", "compact", "dense"}
VALID_LIFETIMES = {3600, 28800, 86400, 604800, 2592000, 0}
DISPLAY_DEFAULTS = {
    "show_graphs": True,
    "show_summary": False,
    "show_actions": False,
    "show_ip_addresses": True,
    "show_last_result": True,
    "show_rolling_average": True,
    "show_availability": True,
    "show_header": True,
}
PERMISSION_DEFAULTS = {
    "allow_detail_links": False,
    "allow_check_now": False,
    "allow_pause": False,
    "allow_reorder": False,
    "allow_display_changes": True,
}
GENERIC_CREDENTIAL_ERROR = "The Wallboard credentials were not accepted."


def _json_object(value: str | None) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: str | None) -> list[Any]:
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def normalise_display_options(value: object, defaults: dict[str, bool] | None = None) -> dict[str, bool]:
    result = dict(DISPLAY_DEFAULTS if defaults is None else defaults)
    if isinstance(value, dict):
        for key in DISPLAY_DEFAULTS:
            if key in value:
                result[key] = bool(value[key])
    return result


def normalise_permissions(value: object) -> dict[str, bool]:
    result = dict(PERMISSION_DEFAULTS)
    if isinstance(value, dict):
        for key in PERMISSION_DEFAULTS:
            if key in value:
                result[key] = bool(value[key])
    return result


def get_wallboard(db: Session) -> NetworkMonitorWallboard | None:
    return db.query(NetworkMonitorWallboard).order_by(NetworkMonitorWallboard.id).first()


def ensure_wallboard(db: Session, updated_by: int | None = None) -> NetworkMonitorWallboard:
    row = get_wallboard(db)
    if row:
        return row
    row = NetworkMonitorWallboard(
        updated_by=updated_by,
        display_options_json=json.dumps(DISPLAY_DEFAULTS, separators=(",", ":")),
        permissions_json=json.dumps(PERMISSION_DEFAULTS, separators=(",", ":")),
    )
    db.add(row)
    db.flush()
    return row


def wallboard_display(row: NetworkMonitorWallboard | None) -> dict[str, Any]:
    if not row:
        return {"columns": "auto", "density": "comfortable", **DISPLAY_DEFAULTS}
    columns = row.default_columns if row.default_columns in VALID_COLUMNS else "auto"
    density = row.default_density if row.default_density in VALID_DENSITIES else "comfortable"
    return {"columns": columns, "density": density, **normalise_display_options(_json_object(row.display_options_json))}


def wallboard_permissions(row: NetworkMonitorWallboard | None) -> dict[str, bool]:
    return normalise_permissions(_json_object(row.permissions_json) if row else {})


def generate_public_token(row: NetworkMonitorWallboard) -> str:
    token = secrets.token_urlsafe(32)
    row.public_token_hash = hashlib.sha256(token.encode()).hexdigest()
    row.encrypted_public_token = encrypt_secret(token)
    row.session_revision = (row.session_revision or 0) + 1
    return token


def current_public_token(row: NetworkMonitorWallboard | None) -> str | None:
    if not row or not row.encrypted_public_token:
        return None
    token = decrypt_secret(row.encrypted_public_token)
    return None if token == "[decryption failed]" else token


def wallboard_for_token(db: Session, token: str) -> NetworkMonitorWallboard | None:
    if not token or len(token) > 80:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    return db.query(NetworkMonitorWallboard).filter_by(public_token_hash=digest).first()


def validate_passcode(passcode: str, passcode_type: str) -> str:
    value = passcode.strip()
    if passcode_type not in {"numeric", "alphanumeric"}:
        raise ValueError("Choose a supported passcode type.")
    if passcode_type == "numeric":
        if not value.isdigit() or len(value) < 6 or len(value) > 32:
            raise ValueError("Numeric PINs must contain 6 to 32 digits.")
    elif len(value) < 8 or len(value) > 128 or not any(char.isalpha() for char in value) or not any(char.isdigit() for char in value):
        raise ValueError("Alphanumeric passcodes must be 8 to 128 characters and include a letter and a number.")
    lowered = value.lower()
    obvious = {"000000", "111111", "123456", "654321", "12345678", "password", "password1", "admin123", "qwerty123"}
    if lowered in obvious or len(set(value)) == 1:
        raise ValueError("Choose a less predictable Wallboard passcode.")
    return value


def set_passcode(row: NetworkMonitorWallboard, passcode: str, passcode_type: str) -> None:
    row.passcode_hash = hash_password(validate_passcode(passcode, passcode_type))
    row.passcode_type = passcode_type
    row.session_revision = (row.session_revision or 0) + 1


def _source_hash(wallboard_id: int, source_ip: str | None) -> str:
    material = f"wallboard:{wallboard_id}:{source_ip or 'unknown'}".encode()
    return hashlib.sha256(get_settings().secret_key.encode() + material).hexdigest()


def attempt_state(db: Session, row: NetworkMonitorWallboard, source_ip: str | None) -> NetworkMonitorWallboardAttempt | None:
    return db.query(NetworkMonitorWallboardAttempt).filter_by(wallboard_id=row.id, source_hash=_source_hash(row.id, source_ip)).first()


def is_locked(db: Session, row: NetworkMonitorWallboard, source_ip: str | None, now: datetime | None = None) -> bool:
    attempt = attempt_state(db, row, source_ip)
    return bool(attempt and attempt.locked_until and attempt.locked_until > (now or datetime.utcnow()))


def record_failed_attempt(db: Session, row: NetworkMonitorWallboard, source_ip: str | None, now: datetime | None = None) -> bool:
    now = now or datetime.utcnow()
    attempt = attempt_state(db, row, source_ip)
    if not attempt:
        attempt = NetworkMonitorWallboardAttempt(wallboard_id=row.id, source_hash=_source_hash(row.id, source_ip), failed_attempts=0, window_started_at=now)
        db.add(attempt)
    if not attempt.window_started_at or attempt.window_started_at < now - timedelta(minutes=10):
        attempt.failed_attempts = 0
        attempt.window_started_at = now
        attempt.locked_until = None
    attempt.failed_attempts += 1
    if attempt.failed_attempts >= 5:
        attempt.locked_until = now + timedelta(minutes=15)
    db.commit()
    return bool(attempt.locked_until and attempt.locked_until > now)


def clear_attempts(db: Session, wallboard_id: int) -> int:
    count = db.query(NetworkMonitorWallboardAttempt).filter_by(wallboard_id=wallboard_id).delete(synchronize_session=False)
    db.commit()
    return count


def verify_challenge(db: Session, row: NetworkMonitorWallboard, passcode: str, source_ip: str | None) -> tuple[bool, bool]:
    if is_locked(db, row, source_ip):
        return False, True
    valid = bool(row.enabled and row.public_token_hash and row.passcode_hash and verify_password(passcode, row.passcode_hash))
    if not valid:
        return False, record_failed_attempt(db, row, source_ip)
    attempt = attempt_state(db, row, source_ip)
    if attempt:
        db.delete(attempt)
        db.commit()
    return True, False


def revoke_sessions(db: Session, row: NetworkMonitorWallboard, *, bump_revision: bool = True) -> int:
    now = datetime.utcnow()
    count = db.query(NetworkMonitorWallboardSession).filter_by(wallboard_id=row.id, revoked_at=None).update(
        {NetworkMonitorWallboardSession.revoked_at: now}, synchronize_session=False
    )
    if bump_revision:
        row.session_revision = (row.session_revision or 0) + 1
    db.commit()
    return count


def start_session(db: Session, row: NetworkMonitorWallboard, *, remembered: bool = False) -> tuple[str, str, NetworkMonitorWallboardSession]:
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    now = datetime.utcnow()
    lifetime = row.remember_display_lifetime_seconds if remembered and row.remember_display_enabled else row.session_lifetime_seconds
    expires_at = None if lifetime == 0 else now + timedelta(seconds=lifetime)
    session = NetworkMonitorWallboardSession(
        wallboard_id=row.id,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        csrf_hash=hashlib.sha256(csrf.encode()).hexdigest(),
        session_revision=row.session_revision,
        remembered=bool(remembered and row.remember_display_enabled),
        display_options_json="{}",
        monitor_order_json="[]",
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()
    return token, csrf, session


def active_session(db: Session, row: NetworkMonitorWallboard, token: str | None, now: datetime | None = None) -> NetworkMonitorWallboardSession | None:
    if not token or not row.enabled or not row.public_token_hash:
        return None
    now = now or datetime.utcnow()
    session = db.query(NetworkMonitorWallboardSession).filter_by(
        wallboard_id=row.id, token_hash=hashlib.sha256(token.encode()).hexdigest()
    ).first()
    if not session or session.revoked_at or session.session_revision != row.session_revision or (session.expires_at and session.expires_at <= now):
        return None
    session.last_seen_at = now
    db.commit()
    return session


def verify_session_csrf(session: NetworkMonitorWallboardSession, value: str | None) -> bool:
    return bool(value and secrets.compare_digest(session.csrf_hash, hashlib.sha256(value.encode()).hexdigest()))


def allowed_monitor_ids(db: Session, row: NetworkMonitorWallboard) -> list[int]:
    if row.all_active_monitors:
        query = db.query(NetworkMonitor)
        if not row.show_paused_monitors:
            query = query.filter(NetworkMonitor.is_enabled == True)  # noqa: E712
        monitors = query.order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()
        allowed = {monitor.id for monitor in monitors}
        configured = [item.monitor_id for item in db.query(NetworkMonitorWallboardMembership).filter_by(wallboard_id=row.id).order_by(NetworkMonitorWallboardMembership.display_order, NetworkMonitorWallboardMembership.id).all() if item.monitor_id in allowed]
        configured.extend(monitor.id for monitor in monitors if monitor.id not in configured)
        return configured
    memberships = db.query(NetworkMonitorWallboardMembership).join(NetworkMonitor).filter(
        NetworkMonitorWallboardMembership.wallboard_id == row.id
    )
    if not row.show_paused_monitors:
        memberships = memberships.filter(NetworkMonitor.is_enabled == True)  # noqa: E712
    return [item.monitor_id for item in memberships.order_by(NetworkMonitorWallboardMembership.display_order, NetworkMonitorWallboardMembership.id).all()]


def _raw_user_preferences(db: Session, user: User) -> tuple[DashboardPreference | None, dict[str, Any]]:
    row = db.query(DashboardPreference).filter_by(user_id=user.id).first()
    if not row:
        return None, {}
    try:
        value = json.loads(row.layout_json)
    except (TypeError, json.JSONDecodeError):
        return row, {}
    return row, value if isinstance(value, dict) else {}


def normalise_user_preferences(value: object, valid_monitor_ids: list[int], site_defaults: dict[str, Any]) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    allowed = set(valid_monitor_ids)
    order = []
    for item in raw.get("monitor_order", []) if isinstance(raw.get("monitor_order"), list) else []:
        if isinstance(item, int) and not isinstance(item, bool) and item in allowed and item not in order:
            order.append(item)
    order.extend(item for item in valid_monitor_ids if item not in order)
    columns = raw.get("columns", site_defaults["columns"])
    density = raw.get("density", site_defaults["density"])
    display = normalise_display_options(raw, {key: bool(site_defaults[key]) for key in DISPLAY_DEFAULTS})
    return {
        "monitor_order": order,
        "columns": columns if columns in VALID_COLUMNS else site_defaults["columns"],
        "density": density if density in VALID_DENSITIES else site_defaults["density"],
        **display,
    }


def user_preferences(db: Session, user: User, valid_monitor_ids: list[int], site_defaults: dict[str, Any]) -> dict[str, Any]:
    _, root = _raw_user_preferences(db, user)
    return normalise_user_preferences(root.get(WALLBOARD_PREFERENCE_KEY), valid_monitor_ids, site_defaults)


def save_user_preferences(db: Session, user: User, value: object, valid_monitor_ids: list[int], site_defaults: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Preferences must be a JSON object.")
    submitted_order = value.get("monitor_order")
    if not isinstance(submitted_order, list):
        raise ValueError("monitor_order must be a list of monitor IDs.")
    if len(submitted_order) > MAX_MONITOR_ORDER_ITEMS:
        raise ValueError("monitor_order contains too many entries.")
    if any(not isinstance(item, int) or isinstance(item, bool) for item in submitted_order):
        raise ValueError("monitor_order must contain integer monitor IDs only.")
    canonical = normalise_user_preferences(value, valid_monitor_ids, site_defaults)
    row, root = _raw_user_preferences(db, user)
    if not row:
        row = DashboardPreference(user_id=user.id, preference_version=1, layout_json="{}")
        db.add(row)
    root[WALLBOARD_PREFERENCE_KEY] = canonical
    row.layout_json = json.dumps(root, separators=(",", ":"))
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    return canonical


def reset_user_preferences(db: Session, user: User, valid_monitor_ids: list[int], site_defaults: dict[str, Any]) -> dict[str, Any]:
    row, root = _raw_user_preferences(db, user)
    existing = root.get(WALLBOARD_PREFERENCE_KEY) if isinstance(root.get(WALLBOARD_PREFERENCE_KEY), dict) else {}
    retained = {key: value for key, value in existing.items() if key != "monitor_order"}
    canonical = normalise_user_preferences(retained, valid_monitor_ids, site_defaults)
    if row and WALLBOARD_PREFERENCE_KEY in root:
        root[WALLBOARD_PREFERENCE_KEY] = retained
        row.layout_json = json.dumps(root, separators=(",", ":"))
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
    return canonical
