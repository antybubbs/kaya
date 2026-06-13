from pathlib import Path
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import get_settings, trusted_hosts
from app.core.security import hash_password
from app.db.session import Base, engine, SessionLocal
from app.models.models import User, VLAN
from app.routers import auth, dashboard, licences, admin, ip_addresses, hardware_assets, network_monitor, remote_manager
from app.services.guacamole_bridge import stop_guacamole_bridge
from app.services.network_monitor import monitor_loop

settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    docs_url=None if settings.app_env == "production" else "/docs",
    root_path=settings.root_path,
)
monitor_task = None

if settings.app_env == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=trusted_hosts(settings),
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
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    response.headers["Cache-Control"] = "no-store"
    if settings.session_cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

Path("/app/uploads").mkdir(parents=True, exist_ok=True)
Path("/app/data").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


def bootstrap():
    Base.metadata.create_all(bind=engine)
    migrate_existing_database()
    db: Session = SessionLocal()
    try:
        admin_email = settings.admin_email.strip().lower()
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            db.add(User(email=admin_email, password_hash=hash_password(settings.admin_password), role="admin"))
            db.commit()
        default_vlan = db.query(VLAN).filter(VLAN.name == "VLAN 1").first()
        if not default_vlan:
            db.add(VLAN(name="VLAN 1"))
            db.commit()
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
            conn.execute(text("CREATE TABLE remote_access (id INTEGER NOT NULL PRIMARY KEY, ip_address_id INTEGER NOT NULL UNIQUE REFERENCES ip_addresses(id), display_name VARCHAR(255), is_enabled BOOLEAN DEFAULT 1 NOT NULL, protocol VARCHAR(20) DEFAULT 'ssh' NOT NULL, port INTEGER DEFAULT 22 NOT NULL, username VARCHAR(120), host_key_fingerprint VARCHAR(120), notes TEXT, created_at DATETIME, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_remote_access_ip_address_id ON remote_access (ip_address_id)"))
            conn.execute(text("CREATE INDEX ix_remote_access_is_enabled ON remote_access (is_enabled)"))
            conn.execute(text("CREATE INDEX ix_remote_access_protocol ON remote_access (protocol)"))
        elif "host_key_fingerprint" not in remote_access_columns:
            conn.execute(text("ALTER TABLE remote_access ADD COLUMN host_key_fingerprint VARCHAR(120)"))
        remote_settings_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(remote_manager_settings)"))}
        if not remote_settings_columns:
            conn.execute(text("CREATE TABLE remote_manager_settings (id INTEGER NOT NULL PRIMARY KEY, key VARCHAR(80) NOT NULL UNIQUE, value TEXT, updated_at DATETIME)"))
            conn.execute(text("CREATE INDEX ix_remote_manager_settings_key ON remote_manager_settings (key)"))


@app.on_event("startup")
async def on_startup():
    bootstrap()
    global monitor_task
    monitor_task = asyncio.create_task(monitor_loop())


@app.on_event("shutdown")
async def on_shutdown():
    if monitor_task:
        monitor_task.cancel()
    stop_guacamole_bridge()


app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(licences.router)
app.include_router(ip_addresses.router)
app.include_router(hardware_assets.router)
app.include_router(network_monitor.router)
app.include_router(remote_manager.router)
app.include_router(admin.router)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}

@app.get("/")
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")
