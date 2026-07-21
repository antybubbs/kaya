from pathlib import Path
import asyncio
from datetime import datetime
from time import perf_counter
from uuid import uuid4
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.demo import demo_request_is_blocked
from app.core.logging import install_sensitive_authentication_log_filter
from app.core.performance import begin_request_metrics, end_request_metrics, install_template_timing, log_request_metrics
from app.core.security import decrypt_secret, hash_password
from app.db.session import Base, engine, SessionLocal
from app.models.models import AuditLog, User, VLAN, VaultSession
from app.routers import auth, oidc, dashboard, licences, admin, ip_addresses, hardware_assets, network_monitor, remote_manager, runbooks, domain_manager, compute_manager, rack_manager, backup_manager, dns_manager, secret_vault, secure_send, high_availability, ha_agent_api
from app.services.secure_send import cleanup_loop as secure_send_cleanup_loop
from app.services.guacamole_bridge import stop_guacamole_bridge
from app.services.kaya_remote_service import start_kaya_remote_service, stop_kaya_remote_service
from app.services.network_monitor import monitor_loop
from app.services.domain_polling import domain_poll_loop
from app.services.compute_monitor import compute_monitor_loop
from app.services.dns_collector import dns_collector_loop
from app.services.audit import begin_request_context, end_request_context, request_event_written, write_audit
from app.services.client_ip import TrustedProxyMiddleware, client_ip
from app.services.site_settings import (
    effective_allowed_hosts,
    frame_ancestor_directive,
    host_is_allowed,
    hsts_header_value,
    load_security_settings,
    oidc_form_action_source,
    get_site_setting,
)
from app.services.version import refresh_latest_release, version_check_loop

settings = get_settings()
install_sensitive_authentication_log_filter()
install_template_timing()
app = FastAPI(
    title=settings.app_name,
    docs_url=None if settings.app_env == "production" else "/docs",
    root_path=settings.root_path,
)
monitor_task = None
domain_poll_task = None
compute_monitor_task = None
dns_collector_task = None
version_check_task = None
secure_send_cleanup_task = None
app.state.demo_mode = settings.demo_mode
app.state.demo_reset_schedule = settings.demo_reset_schedule

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    https_only=settings.session_cookie_secure,
    # OIDC authorization responses are cross-site top-level navigations. Lax
    # preserves CSRF protection for mutations while allowing the callback to
    # receive Kaya's signed transaction-binding cookie.
    same_site="lax",
    max_age=60 * 60 * 8,
)


@app.middleware("http")
async def secure_session_cookie_on_https(request: Request, call_next):
    response = await call_next(request)
    request_is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip() == "https"
    )
    if request_is_https:
        for index, (name, value) in enumerate(response.raw_headers):
            if name.lower() == b"set-cookie" and b"session=" in value and b" secure" not in value.lower():
                response.raw_headers[index] = (name, value + b"; Secure")
    return response


@app.exception_handler(PermissionError)
async def permission_handler(request: Request, exc: PermissionError):
    if request.session.get("user_id"):
        return PlainTextResponse("Forbidden", status_code=403)
    return RedirectResponse("/login", status_code=303)


@app.middleware("http")
async def protect_public_demo(request: Request, call_next):
    if demo_request_is_blocked(request.method, request.url.path):
        message = "This action is disabled in the public demo. Sample data resets daily."
        accepts_html = "text/html" in request.headers.get("accept", "")
        if accepts_html:
            from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
            redirect_to = request.headers.get("referer") or "/dashboard"
            parts = urlsplit(redirect_to)
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            query["demo_notice"] = "1"
            redirect_to = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
            return RedirectResponse(redirect_to, status_code=303)
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"error": message}, status_code=403)
        return PlainTextResponse(message, status_code=403)
    return await call_next(request)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    security = {}
    oidc_form_source = None
    request.state.high_availability_enabled = False
    request.state.backup_manager_enabled = True
    if not request.url.path.startswith("/static/"):
        db = SessionLocal()
        try:
            security = load_security_settings(db)
            oidc_form_source = oidc_form_action_source(db)
            request.state.high_availability_enabled = get_site_setting(db, "high_availability_enabled") == "1"
            request.state.backup_manager_enabled = get_site_setting(db, "backup_manager_enabled") == "1"
        finally:
            db.close()
        if security.get("trusted_hosts_enabled") == "1" or settings.allowed_hosts.strip():
            allowed_hosts = effective_allowed_hosts(security, settings)
            if not host_is_allowed(request.headers.get("host", ""), allowed_hosts):
                return PlainTextResponse("Invalid host header", status_code=400)

    response = await call_next(request)
    is_static_asset = request.url.path.startswith(f"{settings.root_path}/static") if settings.root_path else request.url.path.startswith("/static")
    path = request.url.path
    if settings.root_path and path.startswith(settings.root_path):
        path = path[len(settings.root_path):] or "/"
    is_remote_panel = path.startswith("/remote-manager/") and path.endswith("/panel")
    frame_ancestors = frame_ancestor_directive(security)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if frame_ancestors == "'none'":
        response.headers["X-Frame-Options"] = "DENY"
    elif frame_ancestors == "'self'":
        response.headers["X-Frame-Options"] = "SAMEORIGIN" if is_remote_panel else "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    ws_scheme = "wss" if request.url.scheme == "https" else "ws"
    form_action = f"'self' {oidc_form_source}" if oidc_form_source else "'self'"
    response.headers["Content-Security-Policy"] = (
    f"default-src 'self'; "
    f"connect-src 'self' {ws_scheme}://{request.url.netloc}; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "style-src-attr 'unsafe-inline'; "
    "script-src 'self'; "
    "worker-src 'self' blob:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    f"frame-ancestors {frame_ancestors}; "
    f"form-action {form_action}"
    )
    if is_static_asset:
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    else:
        response.headers["Cache-Control"] = "no-store"
    request_is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip() == "https"
    if request_is_https and (settings.session_cookie_secure or security.get("hsts_enabled") == "1"):
        response.headers["Strict-Transport-Security"] = hsts_header_value(security)
    return response


def audit_entity_for_path(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    return parts[0].replace("-", "_") if parts else "application"


@app.middleware("http")
async def audit_requests(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static/") or path == "/healthz":
        return await call_next(request)
    request_id = (request.headers.get("x-request-id") or uuid4().hex)[:64]
    token, context = begin_request_context(
        request_id=request_id,
        method=request.method,
        path=path,
        ip_address=None if settings.demo_mode else client_ip(request),
        user_agent=None if settings.demo_mode else ((request.headers.get("user-agent") or "")[:2000] or None),
        redact_client=settings.demo_mode,
    )
    started = perf_counter()
    response = None
    try:
        response = await call_next(request)
        context["status_code"] = response.status_code
        context["user_id"] = (request.scope.get("session") or {}).get("user_id")
        duration_ms = round((perf_counter() - started) * 1000, 1)
        high_frequency_success = response.status_code < 400 and (
            path.endswith("/api/summary") or path.endswith("/api/agent/checkin")
        )
        should_log = not request_event_written(context) and (
            response.status_code >= 400
            or (
                request.method not in {"GET", "HEAD", "OPTIONS"}
                and not high_frequency_success
            )
        )
        db = SessionLocal()
        try:
            if context["row_ids"]:
                db.query(AuditLog).filter(AuditLog.id.in_(context["row_ids"])).update(
                    {AuditLog.status_code: response.status_code},
                    synchronize_session=False,
                )
                db.commit()
            if should_log:
                user = db.get(User, context["user_id"]) if context.get("user_id") else None
                action = "request_failed" if response.status_code >= 400 else request.method.lower()
                write_audit(
                    db,
                    user,
                    action,
                    audit_entity_for_path(path),
                    ip_address=context.get("ip_address"),
                    detail=f"{request.method} {path} returned {response.status_code}",
                    status_code=response.status_code,
                    metadata={"duration_ms": duration_ms, "query_keys": sorted(request.query_params.keys())},
                )
        finally:
            db.close()
        response.headers["X-Request-ID"] = request_id
        return response
    except Exception as exc:
        context["status_code"] = 500
        context["user_id"] = (request.scope.get("session") or {}).get("user_id")
        db = SessionLocal()
        try:
            user = db.get(User, context["user_id"]) if context.get("user_id") else None
            write_audit(
                db,
                user,
                "request_error",
                audit_entity_for_path(path),
                ip_address=context.get("ip_address"),
                detail=f"{request.method} {path} raised {type(exc).__name__}",
                severity="error",
                status_code=500,
                metadata={"duration_ms": round((perf_counter() - started) * 1000, 1)},
            )
        finally:
            db.close()
        raise
    finally:
        end_request_context(token)


@app.middleware("http")
async def performance_diagnostics(request: Request, call_next):
    if not settings.performance_diagnostics or request.url.path.startswith("/static/"):
        return await call_next(request)
    token, metrics = begin_request_metrics()
    started = perf_counter()
    try:
        response = await call_next(request)
        log_request_metrics(
            request=request,
            response=response,
            metrics=metrics,
            total_duration_ms=(perf_counter() - started) * 1000,
        )
        return response
    finally:
        end_request_metrics(token)

app.add_middleware(TrustedProxyMiddleware, trusted_proxies=settings.forwarded_allow_ips)

Path("/app/uploads").mkdir(parents=True, exist_ok=True)
Path("/app/data").mkdir(parents=True, exist_ok=True)
Path("/app/data/remote-recordings").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/manifest.webmanifest", name="manifest", include_in_schema=False)
def pwa_manifest():
    return FileResponse("app/static/manifest.webmanifest", media_type="application/manifest+json")


@app.get("/service-worker.js", name="service_worker", include_in_schema=False)
def pwa_service_worker():
    return FileResponse(
        "app/static/service-worker.js",
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": settings.root_path or "/"},
    )


def bootstrap():
    Base.metadata.create_all(bind=engine)
    migrate_existing_database()
    # Vault unlocks are process-bound by policy. A restart never resurrects an
    # authenticated vault session from the database.
    with SessionLocal() as db:
        db.query(VaultSession).filter(VaultSession.revoked_at.is_(None)).update(
            {VaultSession.revoked_at: datetime.utcnow()}, synchronize_session=False
        )
        db.commit()

    db: Session = SessionLocal()
    try:
        default_vlan = db.query(VLAN).filter(VLAN.name == "VLAN 1").first()
        if not default_vlan:
            db.add(VLAN(name="VLAN 1"))
            db.commit()
    finally:
        db.close()


def migrate_existing_database():
    if not settings.database_url.startswith("sqlite"):
        return
    with engine.begin() as conn:
        dashboard_preference_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dashboard_preferences)"))}
        if not dashboard_preference_columns:
            conn.execute(text("CREATE TABLE dashboard_preferences (id INTEGER NOT NULL PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE, preference_version INTEGER DEFAULT 1 NOT NULL, layout_json TEXT NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE UNIQUE INDEX ix_dashboard_preferences_user_id ON dashboard_preferences (user_id)"))
        columns = {row[1] for row in conn.execute(text("PRAGMA table_info(users)"))}
        if "totp_secret" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret TEXT"))
        if "totp_enabled" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0 NOT NULL"))
        if "first_name" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN first_name VARCHAR(120)"))
        if "last_name" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN last_name VARCHAR(120)"))
        if "authentication_type" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN authentication_type VARCHAR(30) DEFAULT 'local' NOT NULL"))
            conn.execute(text("CREATE INDEX ix_users_authentication_type ON users (authentication_type)"))
        if "is_break_glass" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN is_break_glass BOOLEAN DEFAULT 0 NOT NULL"))
            conn.execute(text("CREATE INDEX ix_users_is_break_glass ON users (is_break_glass)"))
        if "role_source" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN role_source VARCHAR(30) DEFAULT 'local' NOT NULL"))
            conn.execute(text("CREATE INDEX ix_users_role_source ON users (role_source)"))
        if "updated_at" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN updated_at DATETIME"))
        conn.execute(text("UPDATE users SET authentication_type = 'local' WHERE authentication_type IS NULL OR authentication_type = ''"))
        conn.execute(text("UPDATE users SET role_source = 'local' WHERE role_source IS NULL OR role_source = ''"))
        conn.execute(text("UPDATE users SET is_break_glass = 0 WHERE is_break_glass IS NULL"))
        conn.execute(text("UPDATE users SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)"))
        password_reset_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(password_reset_tokens)"))}
        app_session_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(app_sessions)"))}
        if app_session_columns and "encrypted_oidc_id_token" not in app_session_columns:
            conn.execute(text("ALTER TABLE app_sessions ADD COLUMN encrypted_oidc_id_token TEXT"))
        if not password_reset_columns:
            conn.execute(text("CREATE TABLE password_reset_tokens (id INTEGER NOT NULL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), token_hash VARCHAR(64) NOT NULL UNIQUE, expires_at DATETIME NOT NULL, used_at DATETIME, created_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_password_reset_tokens_user_id ON password_reset_tokens (user_id)"))
            conn.execute(text("CREATE UNIQUE INDEX ix_password_reset_tokens_token_hash ON password_reset_tokens (token_hash)"))
            conn.execute(text("CREATE INDEX ix_password_reset_tokens_expires_at ON password_reset_tokens (expires_at)"))
            conn.execute(text("CREATE INDEX ix_password_reset_tokens_used_at ON password_reset_tokens (used_at)"))
            conn.execute(text("CREATE INDEX ix_password_reset_tokens_created_at ON password_reset_tokens (created_at)"))
        licence_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(licences)"))}
        if licence_columns and "is_favourite" not in licence_columns:
            conn.execute(text("ALTER TABLE licences ADD COLUMN is_favourite BOOLEAN DEFAULT 0 NOT NULL"))
            conn.execute(text("CREATE INDEX ix_licences_is_favourite ON licences (is_favourite)"))
        vlan_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(vlans)"))}
        if not vlan_columns:
            conn.execute(text("CREATE TABLE vlans (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(120) NOT NULL UNIQUE, description TEXT, subnet_cidr VARCHAR(80), created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_vlans_name ON vlans (name)"))
        elif "subnet_cidr" not in vlan_columns:
            conn.execute(text("ALTER TABLE vlans ADD COLUMN subnet_cidr VARCHAR(80)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vlans_subnet_cidr ON vlans (subnet_cidr)"))
        ip_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(ip_addresses)"))}
        if ip_columns and "vlan_id" not in ip_columns:
            conn.execute(text("ALTER TABLE ip_addresses ADD COLUMN vlan_id INTEGER REFERENCES vlans(id)"))
            conn.execute(text("CREATE INDEX ix_ip_addresses_vlan_id ON ip_addresses (vlan_id)"))
        if ip_columns and "category" not in ip_columns:
            conn.execute(text("ALTER TABLE ip_addresses ADD COLUMN category VARCHAR(120)"))
            conn.execute(text("CREATE INDEX ix_ip_addresses_category ON ip_addresses (category)"))
        if ip_columns and "mac_address" not in ip_columns:
            conn.execute(text("ALTER TABLE ip_addresses ADD COLUMN mac_address VARCHAR(17)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ip_addresses_mac_address ON ip_addresses (mac_address)"))
        conn.execute(text("INSERT INTO vlans (name, created_at, updated_at) SELECT 'VLAN 1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP WHERE NOT EXISTS (SELECT 1 FROM vlans)"))
        conn.execute(text("UPDATE ip_addresses SET vlan_id = (SELECT id FROM vlans ORDER BY id LIMIT 1) WHERE vlan_id IS NULL"))
        dhcp_range_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dhcp_ranges)"))}
        if not dhcp_range_columns:
            conn.execute(text("CREATE TABLE dhcp_ranges (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(120) NOT NULL UNIQUE, vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL, start_address VARCHAR(80) NOT NULL, end_address VARCHAR(80) NOT NULL, description TEXT, is_enabled BOOLEAN DEFAULT 1 NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            for column in ["name", "vlan_id", "start_address", "end_address", "is_enabled"]:
                conn.execute(text(f"CREATE INDEX ix_dhcp_ranges_{column} ON dhcp_ranges ({column})"))
        custom_field_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(custom_fields)"))}
        if not custom_field_columns:
            conn.execute(text("CREATE TABLE custom_fields (id INTEGER NOT NULL PRIMARY KEY, module VARCHAR(80) NOT NULL, label VARCHAR(120) NOT NULL, field_key VARCHAR(120) NOT NULL, field_type VARCHAR(30) NOT NULL DEFAULT 'text', options TEXT, is_required BOOLEAN DEFAULT 0 NOT NULL, is_active BOOLEAN DEFAULT 1 NOT NULL, sort_order INTEGER DEFAULT 0 NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE UNIQUE INDEX uq_custom_fields_module_key ON custom_fields (module, field_key)"))
            conn.execute(text("CREATE INDEX ix_custom_fields_module ON custom_fields (module)"))
            conn.execute(text("CREATE INDEX ix_custom_fields_field_key ON custom_fields (field_key)"))
        custom_value_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(custom_field_values)"))}
        if not custom_value_columns:
            conn.execute(text("CREATE TABLE custom_field_values (id INTEGER NOT NULL PRIMARY KEY, field_id INTEGER NOT NULL REFERENCES custom_fields(id), entity_type VARCHAR(80) NOT NULL, entity_id INTEGER NOT NULL, value TEXT, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE UNIQUE INDEX uq_custom_field_values_entity ON custom_field_values (field_id, entity_type, entity_id)"))
            conn.execute(text("CREATE INDEX ix_custom_field_values_field_id ON custom_field_values (field_id)"))
            conn.execute(text("CREATE INDEX ix_custom_field_values_entity_type ON custom_field_values (entity_type)"))
            conn.execute(text("CREATE INDEX ix_custom_field_values_entity_id ON custom_field_values (entity_id)"))
        hardware_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(hardware_assets)"))}
        if not hardware_columns:
            conn.execute(text("CREATE TABLE hardware_assets (id INTEGER NOT NULL PRIMARY KEY, asset_tag VARCHAR(120) UNIQUE, name VARCHAR(255) NOT NULL, category VARCHAR(120), status VARCHAR(80) NOT NULL DEFAULT 'In use', manufacturer VARCHAR(255), model VARCHAR(255), serial_number VARCHAR(255), location VARCHAR(255), assigned_to VARCHAR(255), purchase_date DATE, purchase_cost VARCHAR(80), warranty_expires DATE, supplier VARCHAR(255), photo_filename VARCHAR(255), notes TEXT, created_at DATETIME, updated_at DATETIME)"))
            for column in ["asset_tag", "name", "category", "status", "manufacturer", "model", "serial_number", "location", "assigned_to"]:
                conn.execute(text(f"CREATE INDEX ix_hardware_assets_{column} ON hardware_assets ({column})"))
        rack_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(racks)"))}
        if not rack_columns:
            conn.execute(text("CREATE TABLE racks (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, location VARCHAR(255), height_u INTEGER DEFAULT 42 NOT NULL, description TEXT, sort_order INTEGER DEFAULT 0 NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_racks_name ON racks (name)"))
            conn.execute(text("CREATE INDEX ix_racks_location ON racks (location)"))
            conn.execute(text("CREATE INDEX ix_racks_sort_order ON racks (sort_order)"))
        rack_item_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(rack_items)"))}
        if not rack_item_columns:
            conn.execute(text("CREATE TABLE rack_items (id INTEGER NOT NULL PRIMARY KEY, rack_id INTEGER NOT NULL REFERENCES racks(id), hardware_asset_id INTEGER REFERENCES hardware_assets(id), name VARCHAR(255) NOT NULL, start_u INTEGER NOT NULL, height_u INTEGER DEFAULT 1 NOT NULL, mount_side VARCHAR(20) DEFAULT 'front' NOT NULL, color VARCHAR(40), category VARCHAR(120), notes TEXT, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_rack_items_rack_id ON rack_items (rack_id)"))
            conn.execute(text("CREATE INDEX ix_rack_items_hardware_asset_id ON rack_items (hardware_asset_id)"))
            conn.execute(text("CREATE INDEX ix_rack_items_mount_side ON rack_items (mount_side)"))
            conn.execute(text("CREATE INDEX ix_rack_items_category ON rack_items (category)"))
        attachment_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(hardware_asset_attachments)"))}
        if not attachment_columns:
            conn.execute(text("CREATE TABLE hardware_asset_attachments (id INTEGER NOT NULL PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES hardware_assets(id), original_filename VARCHAR(255) NOT NULL, stored_filename VARCHAR(255) NOT NULL, content_type VARCHAR(120), uploaded_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_hardware_asset_attachments_asset_id ON hardware_asset_attachments (asset_id)"))
        managed_list_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(managed_list_items)"))}
        if not managed_list_columns:
            conn.execute(text("CREATE TABLE managed_list_items (id INTEGER NOT NULL PRIMARY KEY, module VARCHAR(80) NOT NULL, list_key VARCHAR(80) NOT NULL, value VARCHAR(120) NOT NULL, is_active BOOLEAN DEFAULT 1 NOT NULL, sort_order INTEGER DEFAULT 0 NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE UNIQUE INDEX uq_managed_list_items_value ON managed_list_items (module, list_key, value)"))
            conn.execute(text("CREATE INDEX ix_managed_list_items_module ON managed_list_items (module)"))
            conn.execute(text("CREATE INDEX ix_managed_list_items_list_key ON managed_list_items (list_key)"))
            conn.execute(text("CREATE INDEX ix_managed_list_items_value ON managed_list_items (value)"))
        monitor_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(network_monitors)"))}
        if not monitor_columns:
            conn.execute(text("CREATE TABLE network_monitors (id INTEGER NOT NULL PRIMARY KEY, ip_address_id INTEGER NOT NULL UNIQUE REFERENCES ip_addresses(id), check_type VARCHAR(30) DEFAULT 'icmp' NOT NULL, display_name VARCHAR(255), is_enabled BOOLEAN DEFAULT 1 NOT NULL, interval_seconds INTEGER DEFAULT 300 NOT NULL, timeout_ms INTEGER DEFAULT 2000 NOT NULL, notify_enabled BOOLEAN DEFAULT 0 NOT NULL, last_status VARCHAR(30), last_latency_ms INTEGER, last_error VARCHAR(500), last_checked_at DATETIME, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_network_monitors_ip_address_id ON network_monitors (ip_address_id)"))
            conn.execute(text("CREATE INDEX ix_network_monitors_is_enabled ON network_monitors (is_enabled)"))
            conn.execute(text("CREATE INDEX ix_network_monitors_last_status ON network_monitors (last_status)"))
            conn.execute(text("CREATE INDEX ix_network_monitors_last_checked_at ON network_monitors (last_checked_at)"))
            monitor_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(network_monitors)"))}
        for column, definition in {
            "failure_threshold": "INTEGER DEFAULT 3 NOT NULL",
            "latency_warning_ms": "INTEGER DEFAULT 150 NOT NULL",
            "latency_critical_ms": "INTEGER DEFAULT 500 NOT NULL",
            "packet_loss_warning_percent": "INTEGER DEFAULT 20 NOT NULL",
            "packet_loss_critical_percent": "INTEGER DEFAULT 60 NOT NULL",
            "consecutive_failures": "INTEGER DEFAULT 0 NOT NULL",
            "last_packet_loss_percent": "INTEGER",
        }.items():
            if column not in monitor_columns:
                conn.execute(text(f"ALTER TABLE network_monitors ADD COLUMN {column} {definition}"))
        monitor_check_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(network_monitor_checks)"))}
        if not monitor_check_columns:
            conn.execute(text("CREATE TABLE network_monitor_checks (id INTEGER NOT NULL PRIMARY KEY, monitor_id INTEGER NOT NULL REFERENCES network_monitors(id), status VARCHAR(30) NOT NULL, latency_ms INTEGER, error VARCHAR(500), checked_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_checks_monitor_id ON network_monitor_checks (monitor_id)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_checks_status ON network_monitor_checks (status)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_checks_checked_at ON network_monitor_checks (checked_at)"))
            monitor_check_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(network_monitor_checks)"))}
        for column in ("packet_loss_percent", "response_time_ms"):
            if column not in monitor_check_columns:
                conn.execute(text(f"ALTER TABLE network_monitor_checks ADD COLUMN {column} INTEGER"))
        if not conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='network_monitor_events'" )).first():
            conn.execute(text("CREATE TABLE network_monitor_events (id INTEGER NOT NULL PRIMARY KEY, monitor_id INTEGER NOT NULL REFERENCES network_monitors(id), event_type VARCHAR(40) NOT NULL, severity VARCHAR(20) DEFAULT 'info' NOT NULL, message VARCHAR(500) NOT NULL, occurred_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_events_monitor_id ON network_monitor_events (monitor_id)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_events_occurred_at ON network_monitor_events (occurred_at)"))
        if not conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='network_monitor_outages'" )).first():
            conn.execute(text("CREATE TABLE network_monitor_outages (id INTEGER NOT NULL PRIMARY KEY, monitor_id INTEGER NOT NULL REFERENCES network_monitors(id), started_at DATETIME NOT NULL, ended_at DATETIME, failure_reason VARCHAR(500))"))
            conn.execute(text("CREATE INDEX ix_network_monitor_outages_monitor_id ON network_monitor_outages (monitor_id)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_outages_started_at ON network_monitor_outages (started_at)"))
        if not conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='network_monitor_statistics'" )).first():
            conn.execute(text("CREATE TABLE network_monitor_statistics (id INTEGER NOT NULL PRIMARY KEY, monitor_id INTEGER NOT NULL REFERENCES network_monitors(id), bucket_start DATETIME NOT NULL, bucket_seconds INTEGER NOT NULL, sample_count INTEGER DEFAULT 0 NOT NULL, up_count INTEGER DEFAULT 0 NOT NULL, avg_latency_ms INTEGER, max_latency_ms INTEGER, avg_packet_loss_percent INTEGER)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_statistics_monitor_id ON network_monitor_statistics (monitor_id)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_statistics_bucket_start ON network_monitor_statistics (bucket_start)"))
        remote_access_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(remote_access)"))}
        if not remote_access_columns:
            conn.execute(text("CREATE TABLE remote_access (id INTEGER NOT NULL PRIMARY KEY, ip_address_id INTEGER NOT NULL UNIQUE REFERENCES ip_addresses(id), display_name VARCHAR(255), is_enabled BOOLEAN DEFAULT 1 NOT NULL, protocol VARCHAR(20) DEFAULT 'ssh' NOT NULL, port INTEGER DEFAULT 22 NOT NULL, username VARCHAR(120), host_key_fingerprint VARCHAR(120), terminal_settings TEXT, rdp_settings TEXT, notes TEXT, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_remote_access_ip_address_id ON remote_access (ip_address_id)"))
            conn.execute(text("CREATE INDEX ix_remote_access_is_enabled ON remote_access (is_enabled)"))
            conn.execute(text("CREATE INDEX ix_remote_access_protocol ON remote_access (protocol)"))
        elif "host_key_fingerprint" not in remote_access_columns:
            conn.execute(text("ALTER TABLE remote_access ADD COLUMN host_key_fingerprint VARCHAR(120)"))
        if remote_access_columns and "terminal_settings" not in remote_access_columns:
            conn.execute(text("ALTER TABLE remote_access ADD COLUMN terminal_settings TEXT"))
        if remote_access_columns and "rdp_settings" not in remote_access_columns:
            conn.execute(text("ALTER TABLE remote_access ADD COLUMN rdp_settings TEXT"))
        remote_settings_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(remote_manager_settings)"))}
        if not remote_settings_columns:
            conn.execute(text("CREATE TABLE remote_manager_settings (id INTEGER NOT NULL PRIMARY KEY, key VARCHAR(80) NOT NULL UNIQUE, value TEXT, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_remote_manager_settings_key ON remote_manager_settings (key)"))
        recording_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(remote_session_recordings)"))}
        if not recording_columns:
            conn.execute(text("CREATE TABLE remote_session_recordings (id INTEGER NOT NULL PRIMARY KEY, remote_access_id INTEGER REFERENCES remote_access(id) ON DELETE SET NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, remote_label VARCHAR(255) NOT NULL, remote_address VARCHAR(80), protocol VARCHAR(20) NOT NULL, category VARCHAR(120), trigger VARCHAR(30) DEFAULT 'manual' NOT NULL, status VARCHAR(30) DEFAULT 'complete' NOT NULL, stored_filename VARCHAR(500) NOT NULL, original_filename VARCHAR(255), content_type VARCHAR(120), size_bytes INTEGER DEFAULT 0 NOT NULL, duration_seconds FLOAT, started_at DATETIME, ended_at DATETIME, created_at DATETIME)"))
            for column in ["remote_access_id", "user_id", "remote_label", "protocol", "category", "trigger", "status", "started_at", "ended_at", "created_at"]:
                conn.execute(text(f"CREATE INDEX ix_remote_session_recordings_{column} ON remote_session_recordings ({column})"))
        runbook_space_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(runbook_spaces)"))}
        if not runbook_space_columns:
            conn.execute(text("CREATE TABLE runbook_spaces (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(160) NOT NULL UNIQUE, description TEXT, sort_order INTEGER DEFAULT 0 NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_runbook_spaces_name ON runbook_spaces (name)"))
        runbook_page_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(runbook_pages)"))}
        if not runbook_page_columns:
            conn.execute(text("CREATE TABLE runbook_pages (id INTEGER NOT NULL PRIMARY KEY, space_id INTEGER REFERENCES runbook_spaces(id), parent_id INTEGER REFERENCES runbook_pages(id), title VARCHAR(255) NOT NULL, slug VARCHAR(255) NOT NULL UNIQUE, summary VARCHAR(500), body TEXT, tags VARCHAR(500), is_pinned BOOLEAN DEFAULT 0 NOT NULL, view_count INTEGER DEFAULT 0 NOT NULL, last_viewed_at DATETIME, created_by_id INTEGER REFERENCES users(id), updated_by_id INTEGER REFERENCES users(id), created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_space_id ON runbook_pages (space_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_parent_id ON runbook_pages (parent_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_title ON runbook_pages (title)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_slug ON runbook_pages (slug)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_tags ON runbook_pages (tags)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_is_pinned ON runbook_pages (is_pinned)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_view_count ON runbook_pages (view_count)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_created_by_id ON runbook_pages (created_by_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_updated_by_id ON runbook_pages (updated_by_id)"))
        else:
            if "view_count" not in runbook_page_columns:
                conn.execute(text("ALTER TABLE runbook_pages ADD COLUMN view_count INTEGER DEFAULT 0 NOT NULL"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_runbook_pages_view_count ON runbook_pages (view_count)"))
            if "last_viewed_at" not in runbook_page_columns:
                conn.execute(text("ALTER TABLE runbook_pages ADD COLUMN last_viewed_at DATETIME"))
        runbook_history_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(runbook_page_history)"))}
        if not runbook_history_columns:
            conn.execute(text("CREATE TABLE runbook_page_history (id INTEGER NOT NULL PRIMARY KEY, page_id INTEGER NOT NULL REFERENCES runbook_pages(id), title VARCHAR(255) NOT NULL, summary VARCHAR(500), body TEXT, tags VARCHAR(500), saved_by_id INTEGER REFERENCES users(id), saved_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_runbook_page_history_page_id ON runbook_page_history (page_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_page_history_saved_by_id ON runbook_page_history (saved_by_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_page_history_saved_at ON runbook_page_history (saved_at)"))
        runbook_image_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(runbook_images)"))}
        if not runbook_image_columns:
            conn.execute(text("CREATE TABLE runbook_images (id INTEGER NOT NULL PRIMARY KEY, original_filename VARCHAR(255), content_type VARCHAR(120) NOT NULL, size_bytes INTEGER DEFAULT 0 NOT NULL, data BLOB, uploaded_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_runbook_images_uploaded_by_id ON runbook_images (uploaded_by_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_images_created_at ON runbook_images (created_at)"))
        elif "stored_filename" in runbook_image_columns:
            conn.execute(text("ALTER TABLE runbook_images RENAME TO runbook_images_legacy"))
            conn.execute(text("CREATE TABLE runbook_images (id INTEGER NOT NULL PRIMARY KEY, original_filename VARCHAR(255), content_type VARCHAR(120) NOT NULL, size_bytes INTEGER DEFAULT 0 NOT NULL, data BLOB, uploaded_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME)"))
            conn.execute(text("INSERT INTO runbook_images (id, original_filename, content_type, size_bytes, uploaded_by_id, created_at) SELECT id, original_filename, content_type, size_bytes, uploaded_by_id, created_at FROM runbook_images_legacy"))
            conn.execute(text("DROP TABLE runbook_images_legacy"))
            conn.execute(text("CREATE INDEX ix_runbook_images_uploaded_by_id ON runbook_images (uploaded_by_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_images_created_at ON runbook_images (created_at)"))
        elif "data" not in runbook_image_columns:
            conn.execute(text("ALTER TABLE runbook_images ADD COLUMN data BLOB"))
        domain_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(domain_records)"))}
        if not domain_columns:
            conn.execute(text("CREATE TABLE domain_records (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL UNIQUE, registrar VARCHAR(255), dns_provider VARCHAR(255), status VARCHAR(120), expires_at DATETIME, auto_renew BOOLEAN DEFAULT 0 NOT NULL, nameservers TEXT, lookup_registrar VARCHAR(255), lookup_dns_provider VARCHAR(255), lookup_status VARCHAR(120), lookup_expires_at DATETIME, lookup_nameservers TEXT, dns_records TEXT, lookup_error TEXT, last_lookup_at DATETIME, notes TEXT, created_at DATETIME, updated_at DATETIME)"))
            for column in ["name", "registrar", "dns_provider", "status", "expires_at", "auto_renew", "last_lookup_at"]:
                conn.execute(text(f"CREATE INDEX ix_domain_records_{column} ON domain_records ({column})"))
        else:
            for column, definition in {
                "lookup_registrar": "VARCHAR(255)",
                "lookup_dns_provider": "VARCHAR(255)",
                "lookup_status": "VARCHAR(120)",
                "lookup_expires_at": "DATETIME",
                "lookup_nameservers": "TEXT",
            }.items():
                if column not in domain_columns:
                    conn.execute(text(f"ALTER TABLE domain_records ADD COLUMN {column} {definition}"))

        dns_provider_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_providers)"))}
        if not dns_provider_columns:
            conn.execute(text("CREATE TABLE dns_providers (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, provider_type VARCHAR(40) DEFAULT 'pihole' NOT NULL, base_url VARCHAR(500) NOT NULL, auth_method VARCHAR(40) DEFAULT 'password' NOT NULL, encrypted_secret TEXT, ssl_verify BOOLEAN DEFAULT 1 NOT NULL, timeout_seconds INTEGER DEFAULT 10 NOT NULL, is_enabled BOOLEAN DEFAULT 1 NOT NULL, description TEXT, last_status VARCHAR(40), last_error TEXT, last_checked_at DATETIME, created_at DATETIME, updated_at DATETIME)"))
            for column in ["name", "provider_type", "is_enabled", "last_status", "last_checked_at"]:
                conn.execute(text(f"CREATE INDEX ix_dns_providers_{column} ON dns_providers ({column})"))

        dns_investigation_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_investigations)"))}
        if not dns_investigation_columns:
            conn.execute(text("CREATE TABLE dns_investigations (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, domain VARCHAR(500) NOT NULL, client_name VARCHAR(255), client_ip VARCHAR(80), query_type VARCHAR(40), status VARCHAR(40) DEFAULT 'open' NOT NULL, reply_type VARCHAR(120), reply_time VARCHAR(80), upstream VARCHAR(255), observed_at VARCHAR(80), notes TEXT, created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME, updated_at DATETIME)"))
            for column in ["provider_id", "domain", "client_name", "client_ip", "query_type", "status", "reply_type", "created_by_id", "created_at"]:
                conn.execute(text(f"CREATE INDEX ix_dns_investigations_{column} ON dns_investigations ({column})"))

        dns_insight_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_insights)"))}
        if not dns_insight_columns:
            conn.execute(text("CREATE TABLE dns_insights (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, insight_key VARCHAR(500) NOT NULL, rule_key VARCHAR(120) NOT NULL, category VARCHAR(40) NOT NULL, severity VARCHAR(20) NOT NULL, status VARCHAR(20) DEFAULT 'active' NOT NULL, title VARCHAR(255) NOT NULL, summary VARCHAR(1000) NOT NULL, detail TEXT, entity_type VARCHAR(40), entity_identifier VARCHAR(500), current_value VARCHAR(255), comparison_value VARCHAR(255), percentage_change FLOAT, action_type VARCHAR(60), metadata_json TEXT, first_detected_at DATETIME, last_detected_at DATETIME, resolved_at DATETIME, acknowledged_at DATETIME, acknowledged_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, dismissed_at DATETIME, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE UNIQUE INDEX uq_dns_insights_provider_key ON dns_insights (provider_id, insight_key)"))
            for column in ["provider_id", "insight_key", "rule_key", "category", "severity", "status", "entity_type", "entity_identifier", "first_detected_at", "last_detected_at", "resolved_at", "acknowledged_at", "acknowledged_by_id", "dismissed_at", "created_at"]:
                conn.execute(text(f"CREATE INDEX ix_dns_insights_{column} ON dns_insights ({column})"))

        dns_snapshot_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_statistics_snapshots)"))}
        if not dns_snapshot_columns:
            conn.execute(text("CREATE TABLE dns_statistics_snapshots (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, period_start DATETIME NOT NULL, period_end DATETIME NOT NULL, total_queries INTEGER, blocked_queries INTEGER, failed_queries INTEGER, cached_queries INTEGER, forwarded_queries INTEGER, active_clients INTEGER, blocking_enabled BOOLEAN, provider_connected BOOLEAN DEFAULT 1 NOT NULL, client_aggregates_json TEXT, domain_aggregates_json TEXT, response_aggregates_json TEXT, capabilities_json TEXT, analysis_summary_json TEXT, created_at DATETIME)"))
            conn.execute(text("CREATE UNIQUE INDEX uq_dns_snapshots_provider_period ON dns_statistics_snapshots (provider_id, period_start)"))
            for column in ["provider_id", "period_start", "period_end", "created_at"]:
                conn.execute(text(f"CREATE INDEX ix_dns_statistics_snapshots_{column} ON dns_statistics_snapshots ({column})"))
        else:
            if "capabilities_json" not in dns_snapshot_columns:
                conn.execute(text("ALTER TABLE dns_statistics_snapshots ADD COLUMN capabilities_json TEXT"))
            if "analysis_summary_json" not in dns_snapshot_columns:
                conn.execute(text("ALTER TABLE dns_statistics_snapshots ADD COLUMN analysis_summary_json TEXT"))

        dns_device_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_recognised_devices)"))}
        if not dns_device_columns:
            conn.execute(text("CREATE TABLE dns_recognised_devices (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, identity_type VARCHAR(30) NOT NULL, identity_value VARCHAR(500) NOT NULL, hostname VARCHAR(255), previous_hostname VARCHAR(255), current_ip VARCHAR(80), previous_ip VARCHAR(80), mac_address VARCHAR(120), provider_client_id VARCHAR(255), provider_type VARCHAR(40) DEFAULT 'pihole' NOT NULL, friendly_name VARCHAR(255), normalised_hostname VARCHAR(255), normalised_mac VARCHAR(17), is_known BOOLEAN DEFAULT 0 NOT NULL, is_ignored BOOLEAN DEFAULT 0 NOT NULL, last_synced_at DATETIME, linked_ip_record_id INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL, match_confidence INTEGER, match_method VARCHAR(80), observation_source VARCHAR(255), query_count INTEGER DEFAULT 0 NOT NULL, blocked_query_count INTEGER DEFAULT 0 NOT NULL, notes TEXT, hardware_asset_id INTEGER REFERENCES hardware_assets(id) ON DELETE SET NULL, first_seen_at DATETIME, last_seen_at DATETIME, is_suppressed BOOLEAN DEFAULT 0 NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE UNIQUE INDEX uq_dns_devices_provider_identity ON dns_recognised_devices (provider_id, identity_type, identity_value)"))
            for column in ["provider_id", "identity_type", "identity_value", "hostname", "current_ip", "mac_address", "provider_client_id", "hardware_asset_id", "first_seen_at", "last_seen_at", "is_suppressed"]:
                conn.execute(text(f"CREATE INDEX ix_dns_recognised_devices_{column} ON dns_recognised_devices ({column})"))
        else:
            dns_client_columns = {
                "provider_type": "VARCHAR(40) DEFAULT 'pihole' NOT NULL",
                "friendly_name": "VARCHAR(255)",
                "normalised_hostname": "VARCHAR(255)",
                "normalised_mac": "VARCHAR(17)",
                "is_known": "BOOLEAN DEFAULT 0 NOT NULL",
                "is_ignored": "BOOLEAN DEFAULT 0 NOT NULL",
                "last_synced_at": "DATETIME",
                "linked_ip_record_id": "INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL",
                "suggested_ip_record_id": "INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL",
                "match_confidence": "INTEGER",
                "match_method": "VARCHAR(80)",
                "observation_source": "VARCHAR(255)",
                "query_count": "INTEGER DEFAULT 0 NOT NULL",
                "blocked_query_count": "INTEGER DEFAULT 0 NOT NULL",
                "notes": "TEXT",
            }
            for column, definition in dns_client_columns.items():
                if column not in dns_device_columns:
                    conn.execute(text(f"ALTER TABLE dns_recognised_devices ADD COLUMN {column} {definition}"))
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_dns_recognised_devices_{column} ON dns_recognised_devices ({column})"))
            conn.execute(text("UPDATE dns_recognised_devices SET is_known = 1, is_ignored = COALESCE(is_suppressed, 0), normalised_hostname = LOWER(RTRIM(hostname, '.')), normalised_mac = LOWER(REPLACE(mac_address, '-', ':')), last_synced_at = COALESCE(last_synced_at, last_seen_at), provider_type = COALESCE(provider_type, 'pihole')"))
        refreshed_dns_device_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_recognised_devices)"))}
        if "suggested_ip_record_id" not in refreshed_dns_device_columns:
            conn.execute(text("ALTER TABLE dns_recognised_devices ADD COLUMN suggested_ip_record_id INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dns_recognised_devices_suggested_ip_record_id ON dns_recognised_devices (suggested_ip_record_id)"))
        dns_traffic_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_client_traffic_events)"))}
        if not dns_traffic_columns:
            conn.execute(text("CREATE TABLE dns_client_traffic_events (id INTEGER NOT NULL PRIMARY KEY, dns_client_id INTEGER NOT NULL REFERENCES dns_recognised_devices(id) ON DELETE CASCADE, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, dhcp_lease_id INTEGER REFERENCES dhcp_lease_history(id) ON DELETE SET NULL, event_key VARCHAR(64) NOT NULL, client_ip VARCHAR(80), domain VARCHAR(500) NOT NULL, query_type VARCHAR(40), status VARCHAR(80), reply_type VARCHAR(120), reply_time_ms FLOAT, upstream VARCHAR(255), is_blocked BOOLEAN DEFAULT 0 NOT NULL, observed_at DATETIME NOT NULL, created_at DATETIME NOT NULL)"))
            conn.execute(text("CREATE UNIQUE INDEX uq_dns_client_traffic_provider_event ON dns_client_traffic_events (provider_id, event_key)"))
            for column in ["dns_client_id", "provider_id", "event_key", "domain", "query_type", "status", "reply_type", "is_blocked", "observed_at", "created_at"]:
                conn.execute(text(f"CREATE INDEX ix_dns_client_traffic_events_{column} ON dns_client_traffic_events ({column})"))
        dhcp_lease_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dhcp_lease_history)"))}
        if not dhcp_lease_columns:
            conn.execute(text("CREATE TABLE dhcp_lease_history (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, dns_client_id INTEGER REFERENCES dns_recognised_devices(id) ON DELETE SET NULL, dhcp_range_id INTEGER REFERENCES dhcp_ranges(id) ON DELETE SET NULL, ip_address VARCHAR(80) NOT NULL, mac_address VARCHAR(17), hostname VARCHAR(255), provider_lease_id VARCHAR(255), lease_started_at DATETIME NOT NULL, first_seen_at DATETIME NOT NULL, last_seen_at DATETIME NOT NULL, expires_at DATETIME, ended_at DATETIME, is_active BOOLEAN DEFAULT 1 NOT NULL, source VARCHAR(255), created_at DATETIME, updated_at DATETIME)"))
            for column in ["provider_id", "dns_client_id", "dhcp_range_id", "ip_address", "mac_address", "hostname", "provider_lease_id", "lease_started_at", "first_seen_at", "last_seen_at", "expires_at", "ended_at", "is_active"]:
                conn.execute(text(f"CREATE INDEX ix_dhcp_lease_history_{column} ON dhcp_lease_history ({column})"))
        refreshed_traffic_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_client_traffic_events)"))}
        if "client_ip" not in refreshed_traffic_columns:
            conn.execute(text("ALTER TABLE dns_client_traffic_events ADD COLUMN client_ip VARCHAR(80)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dns_client_traffic_events_client_ip ON dns_client_traffic_events (client_ip)"))
        if "dhcp_lease_id" not in refreshed_traffic_columns:
            conn.execute(text("ALTER TABLE dns_client_traffic_events ADD COLUMN dhcp_lease_id INTEGER REFERENCES dhcp_lease_history(id) ON DELETE SET NULL"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dns_client_traffic_events_dhcp_lease_id ON dns_client_traffic_events (dhcp_lease_id)"))
        conn.execute(text("INSERT OR IGNORE INTO dns_client_ip_history (dns_client_id, ip_address, first_seen_at, last_seen_at, observation_count, provider_id, source, created_at, updated_at) SELECT id, current_ip, first_seen_at, last_seen_at, 1, provider_id, 'migration', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM dns_recognised_devices WHERE current_ip IS NOT NULL AND current_ip != ''"))
        conn.execute(text("INSERT OR IGNORE INTO dns_client_hostname_history (dns_client_id, hostname, normalised_hostname, first_seen_at, last_seen_at, observation_count, provider_id, source, created_at, updated_at) SELECT id, hostname, LOWER(RTRIM(hostname, '.')), first_seen_at, last_seen_at, 1, provider_id, 'migration', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM dns_recognised_devices WHERE hostname IS NOT NULL AND hostname != ''"))

        audit_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(audit_logs)"))}
        if audit_columns:
            for column, definition in {
                "category": "VARCHAR(40) DEFAULT 'activity' NOT NULL",
                "severity": "VARCHAR(20) DEFAULT 'info' NOT NULL",
                "request_method": "VARCHAR(10)",
                "request_path": "VARCHAR(500)",
                "status_code": "INTEGER",
                "user_agent": "TEXT",
                "request_id": "VARCHAR(64)",
                "metadata_json": "TEXT",
            }.items():
                if column not in audit_columns:
                    conn.execute(text(f"ALTER TABLE audit_logs ADD COLUMN {column} {definition}"))
            conn.execute(text("UPDATE audit_logs SET category = 'activity' WHERE category IS NULL"))
            conn.execute(text("UPDATE audit_logs SET severity = 'info' WHERE severity IS NULL"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_category ON audit_logs (category)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_severity ON audit_logs (severity)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs (user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_status_code ON audit_logs (status_code)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_request_id ON audit_logs (request_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs (created_at)"))

        compute_host_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(compute_hosts)"))}
        if compute_host_columns:
            if "agent_token_hash" not in compute_host_columns:
                conn.execute(text("ALTER TABLE compute_hosts ADD COLUMN agent_token_hash VARCHAR(64)"))
                compute_host_columns.add("agent_token_hash")
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_compute_hosts_agent_token_hash ON compute_hosts (agent_token_hash)"))

            legacy_columns = [name for name in ("agent_token", "encrypted_agent_token") if name in compute_host_columns]
            if legacy_columns:
                import hashlib
                selected = ", ".join(["id", "agent_token_hash", *legacy_columns])
                rows = conn.execute(text(f"SELECT {selected} FROM compute_hosts")).mappings().all()
                for row in rows:
                    token = row.get("agent_token") or ""
                    if not token and row.get("encrypted_agent_token"):
                        token = decrypt_secret(row["encrypted_agent_token"])
                    token_hash = row["agent_token_hash"]
                    if token and token != "[decryption failed]":
                        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
                    assignments = ["agent_token_hash = :token_hash", *[f"{name} = NULL" for name in legacy_columns]]
                    conn.execute(text(f"UPDATE compute_hosts SET {', '.join(assignments)} WHERE id = :id"), {"token_hash": token_hash, "id": row["id"]})

        backup_record_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(backup_records)"))}
        if not backup_record_columns:
            conn.execute(text("CREATE TABLE backup_records (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, source_type VARCHAR(40) DEFAULT 'manual' NOT NULL, source_ref VARCHAR(500), target VARCHAR(500), schedule VARCHAR(255), owner VARCHAR(255), last_status VARCHAR(40), last_run_at DATETIME, notes TEXT, is_enabled BOOLEAN DEFAULT 1 NOT NULL, created_at DATETIME, updated_at DATETIME)"))
            for column in ["name", "source_type", "source_ref", "owner", "last_status", "last_run_at", "is_enabled"]:
                conn.execute(text(f"CREATE INDEX ix_backup_records_{column} ON backup_records ({column})"))

        backup_job_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(backup_jobs)"))}
        if not backup_job_columns:
            conn.execute(text("CREATE TABLE backup_jobs (id INTEGER NOT NULL PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES compute_hosts(id), workload_id INTEGER REFERENCES compute_workloads(id), operation VARCHAR(30) NOT NULL, status VARCHAR(40) DEFAULT 'queued' NOT NULL, encryption_enabled BOOLEAN DEFAULT 1 NOT NULL, encrypted_backup_key TEXT, artifact_path VARCHAR(1000), size_bytes INTEGER, error TEXT, log TEXT, metadata_json TEXT, requested_by_id INTEGER REFERENCES users(id), created_at DATETIME, dispatched_at DATETIME, started_at DATETIME, finished_at DATETIME, updated_at DATETIME)"))
            for column in ["host_id", "workload_id", "operation", "status", "encryption_enabled", "requested_by_id", "created_at", "dispatched_at", "started_at", "finished_at"]:
                conn.execute(text(f"CREATE INDEX ix_backup_jobs_{column} ON backup_jobs ({column})"))

        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_provider_connections (id INTEGER NOT NULL PRIMARY KEY, public_id VARCHAR(36) NOT NULL UNIQUE, provider_key VARCHAR(40) NOT NULL, name VARCHAR(255) NOT NULL, api_base_url VARCHAR(500) NOT NULL, auth_method VARCHAR(40) DEFAULT 'password' NOT NULL, encrypted_secret TEXT, ssl_verify BOOLEAN DEFAULT 1 NOT NULL, timeout_seconds INTEGER DEFAULT 10 NOT NULL, created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME, updated_at DATETIME, deleted_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_clusters (id INTEGER NOT NULL PRIMARY KEY, public_id VARCHAR(36) NOT NULL UNIQUE, name VARCHAR(120) NOT NULL, description TEXT, provider_key VARCHAR(40) DEFAULT 'pihole' NOT NULL, status VARCHAR(40) DEFAULT 'DRAFT' NOT NULL, virtual_ip VARCHAR(80), prefix_length INTEGER, authoritative_node_id INTEGER REFERENCES ha_nodes(id) ON DELETE SET NULL, current_active_node_id INTEGER REFERENCES ha_nodes(id) ON DELETE SET NULL, automatic_failover_enabled BOOLEAN DEFAULT 0 NOT NULL, automatic_failback_enabled BOOLEAN DEFAULT 0 NOT NULL, sync_mode VARCHAR(40) DEFAULT 'active_authoritative' NOT NULL, sync_interval_seconds INTEGER DEFAULT 300 NOT NULL, drift_check_interval_seconds INTEGER DEFAULT 300 NOT NULL, maintenance_mode BOOLEAN DEFAULT 0 NOT NULL, cluster_generation INTEGER DEFAULT 1 NOT NULL, role_generation INTEGER DEFAULT 1 NOT NULL, desired_sync_generation INTEGER DEFAULT 0 NOT NULL, last_healthy_at DATETIME, last_failover_at DATETIME, created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME, updated_at DATETIME, deleted_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_nodes (id INTEGER NOT NULL PRIMARY KEY, cluster_id INTEGER NOT NULL REFERENCES ha_clusters(id) ON DELETE CASCADE, public_id VARCHAR(36) NOT NULL UNIQUE, display_name VARCHAR(255) NOT NULL, management_host VARCHAR(255), api_base_url VARCHAR(500) NOT NULL, integration_reference_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, ha_connection_id INTEGER REFERENCES ha_provider_connections(id) ON DELETE SET NULL, role VARCHAR(30) NOT NULL, desired_role VARCHAR(30) NOT NULL, status VARCHAR(40) DEFAULT 'UNVALIDATED' NOT NULL, network_interface VARCHAR(80), vrrp_priority INTEGER, agent_id VARCHAR(120), agent_version VARCHAR(80), provider_version VARCHAR(80), capabilities_json TEXT, configuration_snapshot_json TEXT, configuration_checksum VARCHAR(64), last_heartbeat_at DATETIME, last_health_at DATETIME, last_sync_at DATETIME, observed_role VARCHAR(30), observed_generation INTEGER DEFAULT 0 NOT NULL, vip_owned BOOLEAN DEFAULT 0 NOT NULL, dhcp_running BOOLEAN DEFAULT 0 NOT NULL, dns_healthy BOOLEAN, peer_reachable BOOLEAN, lease_generation INTEGER DEFAULT 0 NOT NULL, config_generation INTEGER DEFAULT 0 NOT NULL, created_at DATETIME, updated_at DATETIME, CONSTRAINT uq_ha_nodes_cluster_integration UNIQUE (cluster_id, integration_reference_id), CONSTRAINT uq_ha_nodes_cluster_connection UNIQUE (cluster_id, ha_connection_id))"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_health_checks (id INTEGER NOT NULL PRIMARY KEY, cluster_id INTEGER NOT NULL REFERENCES ha_clusters(id) ON DELETE CASCADE, node_id INTEGER REFERENCES ha_nodes(id) ON DELETE CASCADE, check_key VARCHAR(120) NOT NULL, status VARCHAR(30) NOT NULL, severity VARCHAR(20) NOT NULL, latency_ms INTEGER, summary VARCHAR(1000) NOT NULL, technical_detail_redacted TEXT, remediation TEXT, observed_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_agent_credentials (id INTEGER NOT NULL PRIMARY KEY, node_id INTEGER NOT NULL UNIQUE REFERENCES ha_nodes(id) ON DELETE CASCADE, agent_id VARCHAR(120) NOT NULL UNIQUE, public_key TEXT UNIQUE, bootstrap_token_hash VARCHAR(64) UNIQUE, bootstrap_expires_at DATETIME, registered_at DATETIME, revoked_at DATETIME, last_rotated_at DATETIME, created_at DATETIME, updated_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_agent_requests (id INTEGER NOT NULL PRIMARY KEY, credential_id INTEGER NOT NULL REFERENCES ha_agent_credentials(id) ON DELETE CASCADE, request_id VARCHAR(80) NOT NULL, request_timestamp DATETIME NOT NULL, received_at DATETIME, CONSTRAINT uq_ha_agent_request_replay UNIQUE (credential_id, request_id))"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_events (id INTEGER NOT NULL PRIMARY KEY, cluster_id INTEGER NOT NULL REFERENCES ha_clusters(id) ON DELETE CASCADE, node_id INTEGER REFERENCES ha_nodes(id) ON DELETE CASCADE, event_type VARCHAR(80) NOT NULL, severity VARCHAR(20) NOT NULL, source VARCHAR(40) NOT NULL, message VARCHAR(1000) NOT NULL, details_json_redacted TEXT, agent_event_id VARCHAR(80) UNIQUE, occurred_at DATETIME NOT NULL, received_at DATETIME, acknowledged_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, acknowledged_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_agent_action_results (id INTEGER NOT NULL PRIMARY KEY, action_id VARCHAR(180) NOT NULL UNIQUE, cluster_id INTEGER NOT NULL REFERENCES ha_clusters(id) ON DELETE CASCADE, node_id INTEGER NOT NULL REFERENCES ha_nodes(id) ON DELETE CASCADE, action_type VARCHAR(60) NOT NULL, generation INTEGER NOT NULL, status VARCHAR(30) NOT NULL, checksum VARCHAR(64), backup_reference VARCHAR(255), message_redacted VARCHAR(1000) NOT NULL, received_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_sync_runs (id INTEGER NOT NULL PRIMARY KEY, public_id VARCHAR(36) NOT NULL UNIQUE, cluster_id INTEGER NOT NULL REFERENCES ha_clusters(id) ON DELETE CASCADE, source_node_id INTEGER NOT NULL REFERENCES ha_nodes(id) ON DELETE CASCADE, target_node_id INTEGER NOT NULL REFERENCES ha_nodes(id) ON DELETE CASCADE, status VARCHAR(30) DEFAULT 'PLANNED' NOT NULL, plan_json TEXT NOT NULL, error_redacted VARCHAR(1000), created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, started_at DATETIME, completed_at DATETIME, created_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_backups (id INTEGER NOT NULL PRIMARY KEY, sync_run_id INTEGER NOT NULL REFERENCES ha_sync_runs(id) ON DELETE CASCADE, node_id INTEGER NOT NULL REFERENCES ha_nodes(id) ON DELETE CASCADE, encrypted_snapshot TEXT NOT NULL, checksum VARCHAR(64) NOT NULL, created_at DATETIME)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS ha_drift_items (id INTEGER NOT NULL PRIMARY KEY, sync_run_id INTEGER NOT NULL REFERENCES ha_sync_runs(id) ON DELETE CASCADE, group_key VARCHAR(80) NOT NULL, risk VARCHAR(20) NOT NULL, status VARCHAR(30) DEFAULT 'DRIFT' NOT NULL, source_checksum VARCHAR(64) NOT NULL, target_checksum VARCHAR(64) NOT NULL, message VARCHAR(1000) NOT NULL)"))
        ha_cluster_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(ha_clusters)"))}
        for column, definition in {"cluster_generation": "INTEGER DEFAULT 1 NOT NULL", "role_generation": "INTEGER DEFAULT 1 NOT NULL", "desired_sync_generation": "INTEGER DEFAULT 0 NOT NULL", "vrrp_router_id": "INTEGER", "keepalived_generation": "INTEGER DEFAULT 0 NOT NULL", "keepalived_status": "VARCHAR(40) DEFAULT 'NOT_CONFIGURED' NOT NULL", "keepalived_requested_at": "DATETIME", "keepalived_deployed_at": "DATETIME"}.items():
            if column not in ha_cluster_columns:
                conn.execute(text(f"ALTER TABLE ha_clusters ADD COLUMN {column} {definition}"))
        dns_provider_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(dns_providers)"))}
        if "ha_cluster_id" not in dns_provider_columns:
            conn.execute(text("ALTER TABLE dns_providers ADD COLUMN ha_cluster_id INTEGER REFERENCES ha_clusters(id) ON DELETE SET NULL"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dns_providers_ha_cluster_id ON dns_providers (ha_cluster_id)"))
        conn.execute(text("UPDATE ha_clusters SET authoritative_node_id = (SELECT id FROM ha_nodes WHERE ha_nodes.cluster_id = ha_clusters.id AND role = 'ACTIVE' ORDER BY id LIMIT 1) WHERE authoritative_node_id IS NULL"))
        ha_node_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(ha_nodes)"))}
        for column, definition in {
            "ha_connection_id": "INTEGER REFERENCES ha_provider_connections(id) ON DELETE SET NULL",
            "capabilities_json": "TEXT",
            "configuration_snapshot_json": "TEXT",
            "configuration_checksum": "VARCHAR(64)",
            "observed_role": "VARCHAR(30)",
            "observed_generation": "INTEGER DEFAULT 0 NOT NULL",
            "vip_owned": "BOOLEAN DEFAULT 0 NOT NULL",
            "dhcp_running": "BOOLEAN DEFAULT 0 NOT NULL",
            "dns_healthy": "BOOLEAN",
            "peer_reachable": "BOOLEAN",
            "lease_generation": "INTEGER DEFAULT 0 NOT NULL",
            "config_generation": "INTEGER DEFAULT 0 NOT NULL",
            "keepalived_status": "VARCHAR(40) DEFAULT 'NOT_CONFIGURED' NOT NULL",
            "keepalived_config_checksum": "VARCHAR(64)",
            "keepalived_backup_reference": "VARCHAR(255)",
            "keepalived_last_error": "VARCHAR(1000)",
            "keepalived_reported_at": "DATETIME",
            "keepalived_runtime_state": "VARCHAR(30) DEFAULT 'UNKNOWN' NOT NULL",
        }.items():
            if column not in ha_node_columns:
                conn.execute(text(f"ALTER TABLE ha_nodes ADD COLUMN {column} {definition}"))
        ha_check_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(ha_health_checks)"))}
        if "remediation" not in ha_check_columns:
            conn.execute(text("ALTER TABLE ha_health_checks ADD COLUMN remediation TEXT"))
        for table, columns in {
            "ha_provider_connections": ["public_id", "provider_key", "name", "created_by_user_id", "created_at", "deleted_at"],
            "ha_clusters": ["public_id", "name", "provider_key", "status", "created_by_user_id", "created_at", "deleted_at"],
            "ha_nodes": ["cluster_id", "public_id", "integration_reference_id", "ha_connection_id", "role", "desired_role", "status", "agent_id"],
            "ha_health_checks": ["cluster_id", "node_id", "check_key", "status", "severity", "observed_at"],
            "ha_agent_credentials": ["node_id", "agent_id", "bootstrap_token_hash", "bootstrap_expires_at", "revoked_at"],
            "ha_agent_requests": ["credential_id", "request_id", "request_timestamp", "received_at"],
            "ha_events": ["cluster_id", "node_id", "event_type", "severity", "source", "agent_event_id", "occurred_at", "received_at"],
            "ha_agent_action_results": ["action_id", "cluster_id", "node_id", "action_type", "generation", "status", "received_at"],
            "ha_sync_runs": ["public_id", "cluster_id", "source_node_id", "target_node_id", "status", "created_by_user_id", "created_at"],
            "ha_backups": ["sync_run_id", "node_id", "checksum", "created_at"],
            "ha_drift_items": ["sync_run_id", "group_key", "risk", "status"],
        }.items():
            for column in columns:
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_ha_clusters_active_virtual_ip ON ha_clusters (virtual_ip) WHERE virtual_ip IS NOT NULL AND deleted_at IS NULL"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_ha_nodes_cluster_connection ON ha_nodes (cluster_id, ha_connection_id) WHERE ha_connection_id IS NOT NULL"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_ha_agent_credentials_public_key ON ha_agent_credentials (public_key) WHERE public_key IS NOT NULL"))


@app.on_event("startup")
async def on_startup():
    bootstrap()
    await asyncio.to_thread(refresh_latest_release)
    global version_check_task
    version_check_task = asyncio.create_task(version_check_loop())
    if settings.demo_mode:
        return
    start_kaya_remote_service()
    global monitor_task, domain_poll_task, compute_monitor_task, dns_collector_task, secure_send_cleanup_task
    monitor_task = asyncio.create_task(monitor_loop())
    domain_poll_task = asyncio.create_task(domain_poll_loop())
    compute_monitor_task = asyncio.create_task(compute_monitor_loop())
    dns_collector_task = asyncio.create_task(dns_collector_loop())
    secure_send_cleanup_task = asyncio.create_task(secure_send_cleanup_loop())


@app.on_event("shutdown")
async def on_shutdown():
    if version_check_task:
        version_check_task.cancel()
    if monitor_task:
        monitor_task.cancel()
    if domain_poll_task:
        domain_poll_task.cancel()
    if compute_monitor_task:
        compute_monitor_task.cancel()
    if dns_collector_task:
        dns_collector_task.cancel()
    if secure_send_cleanup_task:
        secure_send_cleanup_task.cancel()
    stop_kaya_remote_service()
    stop_guacamole_bridge()


app.include_router(auth.router)
app.include_router(oidc.router)
app.include_router(dashboard.router)
app.include_router(licences.router)
app.include_router(ip_addresses.router)
app.include_router(hardware_assets.router)
app.include_router(network_monitor.router)
app.include_router(remote_manager.router)
app.include_router(runbooks.router)
app.include_router(domain_manager.router)
app.include_router(compute_manager.router)
app.include_router(rack_manager.router)
app.include_router(backup_manager.router)
app.include_router(dns_manager.router)
app.include_router(secret_vault.router)
app.include_router(secure_send.router)
app.include_router(high_availability.router)
app.include_router(ha_agent_api.router)
app.include_router(admin.router)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get("/api/site-timezone", include_in_schema=False)
def site_timezone():
    db = SessionLocal()
    try:
        return {"timezone": get_site_setting(db, "timezone_region") or "UTC"}
    finally:
        db.close()

@app.get("/")
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")
