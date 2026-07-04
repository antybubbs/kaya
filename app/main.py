from pathlib import Path
import asyncio
from time import perf_counter
from uuid import uuid4
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import get_settings, trusted_hosts
from app.core.demo import demo_request_is_blocked
from app.core.security import decrypt_secret, hash_password
from app.db.session import Base, engine, SessionLocal
from app.models.models import AuditLog, User, VLAN
from app.routers import auth, dashboard, licences, admin, ip_addresses, hardware_assets, network_monitor, remote_manager, runbooks, domain_manager, compute_manager, rack_manager
from app.services.guacamole_bridge import stop_guacamole_bridge
from app.services.kaya_remote_service import start_kaya_remote_service, stop_kaya_remote_service
from app.services.network_monitor import monitor_loop
from app.services.domain_polling import domain_poll_loop
from app.services.compute_monitor import compute_monitor_loop
from app.services.audit import begin_request_context, end_request_context, request_event_written, write_audit

settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    docs_url=None if settings.app_env == "production" else "/docs",
    root_path=settings.root_path,
)
monitor_task = None
domain_poll_task = None
compute_monitor_task = None
app.state.demo_mode = settings.demo_mode
app.state.demo_reset_schedule = settings.demo_reset_schedule

configured_trusted_hosts = trusted_hosts(settings)
if settings.app_env == "production" and configured_trusted_hosts:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=configured_trusted_hosts,
    )

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    https_only=settings.session_cookie_secure,
    same_site="strict",
    max_age=60 * 60 * 8,
)

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
    response = await call_next(request)
    is_static_asset = request.url.path.startswith(f"{settings.root_path}/static") if settings.root_path else request.url.path.startswith("/static")
    path = request.url.path
    if settings.root_path and path.startswith(settings.root_path):
        path = path[len(settings.root_path):] or "/"
    is_remote_panel = path.startswith("/remote-manager/") and path.endswith("/panel")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN" if is_remote_panel else "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    ws_scheme = "wss" if request.url.scheme == "https" else "ws"
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
    "frame-ancestors 'self'; "
    "form-action 'self'"
    )
    if is_static_asset:
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    else:
        response.headers["Cache-Control"] = "no-store"
    if settings.session_cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
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
        ip_address=None if settings.demo_mode else (request.client.host if request.client else None),
        user_agent=None if settings.demo_mode else ((request.headers.get("user-agent") or "")[:2000] or None),
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

Path("/app/uploads").mkdir(parents=True, exist_ok=True)
Path("/app/data").mkdir(parents=True, exist_ok=True)
Path("/app/data/remote-recordings").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


def bootstrap():
    Base.metadata.create_all(bind=engine)
    migrate_existing_database()

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
        columns = {row[1] for row in conn.execute(text("PRAGMA table_info(users)"))}
        if "totp_secret" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret TEXT"))
        if "totp_enabled" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0 NOT NULL"))
        if "first_name" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN first_name VARCHAR(120)"))
        if "last_name" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN last_name VARCHAR(120)"))
        password_reset_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(password_reset_tokens)"))}
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
            conn.execute(text("CREATE TABLE vlans (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(120) NOT NULL UNIQUE, description TEXT, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_vlans_name ON vlans (name)"))
        ip_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(ip_addresses)"))}
        if ip_columns and "vlan_id" not in ip_columns:
            conn.execute(text("ALTER TABLE ip_addresses ADD COLUMN vlan_id INTEGER REFERENCES vlans(id)"))
            conn.execute(text("CREATE INDEX ix_ip_addresses_vlan_id ON ip_addresses (vlan_id)"))
        if ip_columns and "category" not in ip_columns:
            conn.execute(text("ALTER TABLE ip_addresses ADD COLUMN category VARCHAR(120)"))
            conn.execute(text("CREATE INDEX ix_ip_addresses_category ON ip_addresses (category)"))
        conn.execute(text("INSERT OR IGNORE INTO vlans (name, created_at, updated_at) VALUES ('VLAN 1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        conn.execute(text("UPDATE ip_addresses SET vlan_id = (SELECT id FROM vlans WHERE name = 'VLAN 1') WHERE vlan_id IS NULL"))
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
        monitor_check_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(network_monitor_checks)"))}
        if not monitor_check_columns:
            conn.execute(text("CREATE TABLE network_monitor_checks (id INTEGER NOT NULL PRIMARY KEY, monitor_id INTEGER NOT NULL REFERENCES network_monitors(id), status VARCHAR(30) NOT NULL, latency_ms INTEGER, error VARCHAR(500), checked_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_checks_monitor_id ON network_monitor_checks (monitor_id)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_checks_status ON network_monitor_checks (status)"))
            conn.execute(text("CREATE INDEX ix_network_monitor_checks_checked_at ON network_monitor_checks (checked_at)"))
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
            conn.execute(text("CREATE TABLE runbook_pages (id INTEGER NOT NULL PRIMARY KEY, space_id INTEGER REFERENCES runbook_spaces(id), parent_id INTEGER REFERENCES runbook_pages(id), title VARCHAR(255) NOT NULL, slug VARCHAR(255) NOT NULL UNIQUE, summary VARCHAR(500), body TEXT, tags VARCHAR(500), is_pinned BOOLEAN DEFAULT 0 NOT NULL, created_by_id INTEGER REFERENCES users(id), updated_by_id INTEGER REFERENCES users(id), created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_space_id ON runbook_pages (space_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_parent_id ON runbook_pages (parent_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_title ON runbook_pages (title)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_slug ON runbook_pages (slug)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_tags ON runbook_pages (tags)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_is_pinned ON runbook_pages (is_pinned)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_created_by_id ON runbook_pages (created_by_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_pages_updated_by_id ON runbook_pages (updated_by_id)"))
        runbook_history_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(runbook_page_history)"))}
        if not runbook_history_columns:
            conn.execute(text("CREATE TABLE runbook_page_history (id INTEGER NOT NULL PRIMARY KEY, page_id INTEGER NOT NULL REFERENCES runbook_pages(id), title VARCHAR(255) NOT NULL, summary VARCHAR(500), body TEXT, tags VARCHAR(500), saved_by_id INTEGER REFERENCES users(id), saved_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_runbook_page_history_page_id ON runbook_page_history (page_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_page_history_saved_by_id ON runbook_page_history (saved_by_id)"))
            conn.execute(text("CREATE INDEX ix_runbook_page_history_saved_at ON runbook_page_history (saved_at)"))
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


@app.on_event("startup")
async def on_startup():
    bootstrap()
    if settings.demo_mode:
        return
    start_kaya_remote_service()
    global monitor_task, domain_poll_task, compute_monitor_task
    monitor_task = asyncio.create_task(monitor_loop())
    domain_poll_task = asyncio.create_task(domain_poll_loop())
    compute_monitor_task = asyncio.create_task(compute_monitor_loop())


@app.on_event("shutdown")
async def on_shutdown():
    if monitor_task:
        monitor_task.cancel()
    if domain_poll_task:
        domain_poll_task.cancel()
    if compute_monitor_task:
        compute_monitor_task.cancel()
    stop_kaya_remote_service()
    stop_guacamole_bridge()


app.include_router(auth.router)
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
app.include_router(admin.router)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}

@app.get("/")
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")
