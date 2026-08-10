import asyncio
import logging
import re
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import get_settings
from app.core.logging import install_sensitive_authentication_log_filter
from app.core.paths import STATIC_DIR
from app.core.performance import (
    begin_request_metrics,
    end_request_metrics,
    install_template_timing,
    log_request_metrics,
)
from app.db.migrations import prepare_database
from app.db.seeds import initialise_application_defaults
from app.db.session import (
    SessionLocal,
    database_write_context,
    engine,
    verify_sqlite_pragmas,
)
from app.models.models import AuditLog, User
from app.routers import (
    admin,
    auth,
    backup_manager,
    backup_agent_v2,
    compute_manager,
    dashboard,
    dns_manager,
    domain_manager,
    ha_agent_api,
    hardware_assets,
    high_availability,
    ip_addresses,
    licences,
    network_monitor,
    notifications,
    oidc,
    rack_manager,
    remote_manager,
    runbooks,
    secret_vault,
    secure_send,
)
from app.services.audit import (
    cleanup_audit_logs,
    begin_request_context,
    end_request_context,
    request_event_written,
    write_audit,
)
from app.services.client_ip import TrustedProxyMiddleware, client_ip
from app.services.compute_monitor import compute_monitor_loop
from app.services.dns_collector import dns_collector_loop
from app.services.domain_polling import domain_poll_loop
from app.services.guacamole_bridge import stop_guacamole_bridge
from app.services.ha_lease_monitor import ha_lease_reconciliation_loop
from app.services.ha_sync_monitor import ha_sync_monitor_loop
from app.services.ha_watchdog import ha_watchdog_loop
from app.services.kaya_remote_service import (
    start_kaya_remote_service,
    stop_kaya_remote_service,
)
from app.services.modules import enabled_modules
from app.services.network_monitor import start_monitor_scheduler, stop_monitor_scheduler
from app.services.notification_runtime import (
    start_notification_runtime,
    stop_notification_runtime,
)
from app.services.notifications import cleanup_retention
from app.services.secure_send import cleanup_loop as secure_send_cleanup_loop
from app.services.site_settings import (
    cached_security_context,
    effective_allowed_hosts,
    frame_ancestor_directive,
    get_site_setting,
    host_is_allowed,
    hsts_header_value,
)
from app.services.version import refresh_latest_release, version_check_loop

settings = get_settings()
logger = logging.getLogger(__name__)
install_sensitive_authentication_log_filter()
install_template_timing()
app = FastAPI(
    title=settings.app_name,
    docs_url=None if settings.app_env == "production" else "/docs",
    root_path=settings.root_path,
)
domain_poll_task = None
compute_monitor_task = None
dns_collector_task = None
version_check_task = None
secure_send_cleanup_task = None
ha_lease_reconciliation_task = None
ha_sync_monitor_task = None
ha_watchdog_task = None
notification_runtime_task = None
notification_retention_task = None

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
async def security_headers(request: Request, call_next):
    security = {}
    oidc_form_source = None
    request.state.high_availability_enabled = False
    request.state.backup_manager_enabled = True
    request.state.accessible_module_keys = frozenset()
    request.state.module_landing_url = "/profile"
    request.state.enabled_modules = ()
    if not request.url.path.startswith("/static/"):
        file_only_request = request.url.path in {
            "/manifest.webmanifest",
            "/service-worker.js",
        }
        with database_write_context("http_request", f"{request.method} {request.url.path}"):
            db = SessionLocal()
            try:
                security, oidc_form_source = cached_security_context(db)
                if not file_only_request:
                    request.state.high_availability_enabled = get_site_setting(db, "high_availability_enabled") == "1"
                    request.state.backup_manager_enabled = get_site_setting(db, "backup_manager_enabled") == "1"
                    request.state.enabled_modules = enabled_modules(db)
            finally:
                db.close()
        if security.get("trusted_hosts_enabled") == "1" or settings.allowed_hosts.strip():
            allowed_hosts = effective_allowed_hosts(security, settings)
            if not host_is_allowed(request.headers.get("host", ""), allowed_hosts):
                return PlainTextResponse("Invalid host header", status_code=400)

    with database_write_context("http_request", f"{request.method} {request.url.path}"):
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


def audit_safe_path(path: str) -> str:
    """Redact bearer-like Wallboard URL identifiers before audit persistence."""
    return re.sub(
        r"(?<=/monitoring/ip-wan-monitor/wallboard/shared/)[A-Za-z0-9_-]{20,80}",
        "[redacted]",
        path,
        count=1,
    )


@app.middleware("http")
async def audit_requests(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static/") or path == "/healthz":
        return await call_next(request)
    request_id = (request.headers.get("x-request-id") or uuid4().hex)[:64]
    request.state.request_id = request_id
    safe_path = audit_safe_path(path)
    token, context = begin_request_context(
        request_id=request_id,
        method=request.method,
        path=safe_path,
        ip_address=client_ip(request),
        user_agent=((request.headers.get("user-agent") or "")[:2000] or None),
        redact_client=False,
    )
    started = perf_counter()
    response = None
    try:
        response = await call_next(request)
        context["status_code"] = response.status_code
        context["user_id"] = (request.scope.get("session") or {}).get("user_id")
        duration_ms = round((perf_counter() - started) * 1000, 1)
        high_frequency_success = response.status_code < 400 and path.endswith(
            ("/api/summary", "/api/agent/checkin")
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
                    detail=f"{request.method} {safe_path} returned {response.status_code}",
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

Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)
Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
Path(settings.recording_dir).mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/manifest.webmanifest", name="manifest", include_in_schema=False)
def pwa_manifest():
    return FileResponse(
        STATIC_DIR / "manifest.webmanifest",
        media_type="application/manifest+json",
    )


@app.get("/service-worker.js", name="service_worker", include_in_schema=False)
def pwa_service_worker():
    return FileResponse(
        STATIC_DIR / "service-worker.js",
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": settings.root_path or "/"},
    )


def bootstrap():
    stage = "Opening database"
    try:
        module_permissions_existed = inspect(engine).has_table("user_module_permissions")
        prepare_database(engine, settings)
        verify_sqlite_pragmas(engine)
        stage = "Running seed initialisation"
        logger.debug("Database migration stage: %s", stage)
        with SessionLocal() as db:
            initialise_application_defaults(
                db, module_permissions_existed=module_permissions_existed
            )
            from app.services.backup_agent_protocol import allow_legacy_inventory
            allow_legacy_inventory(db)
            db.commit()
        stage = "Warming security settings cache"
        with SessionLocal() as db:
            cached_security_context(db, max_age_seconds=0)
        stage = "Startup complete"
        logger.debug("Database migration stage: %s", stage)
    except Exception:
        logger.error("Application startup aborted at stage: %s", stage)
        # Uvicorn owns the full startup traceback. Logging it here as well would
        # produce duplicate container diagnostics.
        raise


@app.on_event("startup")
async def on_startup():
    bootstrap()
    await asyncio.to_thread(refresh_latest_release)
    global version_check_task
    version_check_task = asyncio.create_task(version_check_loop())
    start_kaya_remote_service()
    global domain_poll_task, compute_monitor_task, dns_collector_task, secure_send_cleanup_task, ha_lease_reconciliation_task, ha_sync_monitor_task, ha_watchdog_task, notification_runtime_task, notification_retention_task
    start_monitor_scheduler()
    domain_poll_task = asyncio.create_task(domain_poll_loop())
    compute_monitor_task = asyncio.create_task(compute_monitor_loop())
    dns_collector_task = asyncio.create_task(dns_collector_loop())
    secure_send_cleanup_task = asyncio.create_task(secure_send_cleanup_loop())
    ha_lease_reconciliation_task = asyncio.create_task(ha_lease_reconciliation_loop())
    ha_sync_monitor_task = asyncio.create_task(ha_sync_monitor_loop())
    ha_watchdog_task = asyncio.create_task(ha_watchdog_loop())
    notification_runtime_task = start_notification_runtime()
    async def notification_retention_loop():
        while True:
            await asyncio.sleep(3600)
            with SessionLocal() as notification_db:
                try:
                    cleanup_retention(notification_db)
                except Exception:
                    notification_db.rollback()
                    logger.exception("notification.retention.failed")
                try:
                    deleted = cleanup_audit_logs(notification_db)
                    if deleted:
                        logger.info("audit.retention.completed deleted=%s", deleted)
                except Exception:
                    notification_db.rollback()
                    logger.exception("audit.retention.failed")
    notification_retention_task = asyncio.create_task(notification_retention_loop())


@app.on_event("shutdown")
async def on_shutdown():
    if version_check_task:
        version_check_task.cancel()
    await stop_monitor_scheduler()
    if domain_poll_task:
        domain_poll_task.cancel()
    if compute_monitor_task:
        compute_monitor_task.cancel()
    if dns_collector_task:
        dns_collector_task.cancel()
    if secure_send_cleanup_task:
        secure_send_cleanup_task.cancel()
    if ha_lease_reconciliation_task:
        ha_lease_reconciliation_task.cancel()
    if ha_sync_monitor_task:
        ha_sync_monitor_task.cancel()
    if ha_watchdog_task:
        ha_watchdog_task.cancel()
    await stop_notification_runtime()
    if notification_retention_task:
        notification_retention_task.cancel()
    stop_kaya_remote_service()
    stop_guacamole_bridge()


app.include_router(auth.router)
app.include_router(oidc.router)
app.include_router(dashboard.router)
app.include_router(licences.router)
app.include_router(ip_addresses.router)
app.include_router(hardware_assets.router)
app.include_router(network_monitor.router)
app.include_router(network_monitor.wallboard_router)
app.include_router(remote_manager.router)
app.include_router(runbooks.router)
app.include_router(domain_manager.router)
app.include_router(compute_manager.router)
app.include_router(compute_manager.agent_router)
app.include_router(rack_manager.router)
app.include_router(backup_manager.router)
app.include_router(backup_agent_v2.router)
app.include_router(dns_manager.router)
app.include_router(secret_vault.router)
app.include_router(secure_send.router)
app.include_router(high_availability.router)
app.include_router(ha_agent_api.router)
app.include_router(notifications.router)
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
