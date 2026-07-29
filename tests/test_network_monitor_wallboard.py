import asyncio
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    DashboardPreference, IPAddress, NetworkMonitor, NetworkMonitorWallboardMembership, User,
)
from app.services.network_monitor_wallboard import (
    active_session, allowed_monitor_ids, ensure_wallboard, generate_public_token,
    is_locked, reset_user_preferences, save_user_preferences, set_passcode,
    start_session, user_preferences, validate_passcode, verify_challenge,
    verify_session_csrf, wallboard_display, wallboard_for_token,
)
from app.services import network_monitor as network_monitor_service
from app.db.session import get_db
from app.routers.network_monitor import wallboard_router
from app.routers.auth import require_user
from app.routers import admin as admin_module
from app.routers.admin import save_network_monitor_wallboard, wallboard_admin_context
from app.main import audit_safe_path


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def add_user(db, email):
    row = User(email=email, password_hash=None, role="viewer", is_active=True)
    db.add(row); db.commit()
    return row


def add_monitor(db, address, *, enabled=True, name=None):
    ip = IPAddress(address=address, name=name)
    db.add(ip); db.flush()
    monitor = NetworkMonitor(ip_address_id=ip.id, display_name=name, is_enabled=enabled)
    db.add(monitor); db.commit()
    return monitor


def test_passcodes_are_validated_and_only_hashed(db):
    row = ensure_wallboard(db)
    with pytest.raises(ValueError):
        validate_passcode("123456", "numeric")
    with pytest.raises(ValueError):
        validate_passcode("password1", "alphanumeric")
    set_passcode(row, "804291", "numeric")
    db.commit()
    assert row.passcode_hash != "804291"
    assert "804291" not in row.passcode_hash
    assert verify_challenge(db, row, "804291", "192.0.2.10") == (False, False)  # disabled remains deny-by-default


def test_token_is_unguessable_encrypted_and_not_sufficient_for_access(db):
    row = ensure_wallboard(db)
    token = generate_public_token(row)
    db.commit()
    assert len(token) >= 40
    assert row.public_token_hash != token
    assert row.encrypted_public_token != token
    assert wallboard_for_token(db, token).id == row.id
    assert active_session(db, row, token) is None


def test_challenge_locks_one_source_after_five_failures(db):
    row = ensure_wallboard(db)
    row.enabled = True
    generate_public_token(row)
    set_passcode(row, "804291", "numeric")
    db.commit()
    for index in range(4):
        assert verify_challenge(db, row, "wrong", "192.0.2.10") == (False, False)
    assert verify_challenge(db, row, "wrong", "192.0.2.10") == (False, True)
    assert is_locked(db, row, "192.0.2.10")
    assert verify_challenge(db, row, "804291", "192.0.2.10") == (False, True)
    assert verify_challenge(db, row, "804291", "192.0.2.11") == (True, False)


def test_restricted_session_is_hashed_csrf_bound_expiring_and_revision_bound(db):
    row = ensure_wallboard(db)
    row.enabled = True
    generate_public_token(row)
    db.commit()
    token, csrf, session = start_session(db, row)
    assert session.token_hash != token
    assert session.csrf_hash != csrf
    assert verify_session_csrf(session, csrf)
    assert not verify_session_csrf(session, "wrong")
    assert active_session(db, row, token).id == session.id
    session.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    assert active_session(db, row, token) is None
    token, _, session = start_session(db, row)
    row.session_revision += 1
    db.commit()
    assert active_session(db, row, token) is None


def test_selected_monitor_membership_is_an_object_level_allowlist(db):
    first = add_monitor(db, "192.0.2.10", name="First")
    second = add_monitor(db, "192.0.2.11", enabled=False, name="Second")
    third = add_monitor(db, "192.0.2.12", name="Third")
    row = ensure_wallboard(db)
    row.all_active_monitors = False
    row.show_paused_monitors = False
    db.add_all([
        NetworkMonitorWallboardMembership(wallboard_id=row.id, monitor_id=second.id, display_order=1),
        NetworkMonitorWallboardMembership(wallboard_id=row.id, monitor_id=first.id, display_order=2),
    ])
    db.commit()
    assert allowed_monitor_ids(db, row) == [first.id]
    row.show_paused_monitors = True
    db.commit()
    assert allowed_monitor_ids(db, row) == [second.id, first.id]
    assert third.id not in allowed_monitor_ids(db, row)


def test_preferences_are_per_user_append_new_monitors_and_remove_deleted_ids(db):
    first, second = add_user(db, "first@example.test"), add_user(db, "second@example.test")
    site = wallboard_display(None)
    saved = save_user_preferences(db, first, {"monitor_order": [2, 1], "columns": "4", "density": "dense"}, [1, 2], site)
    assert saved["monitor_order"] == [2, 1]
    assert user_preferences(db, second, [1, 2], site)["monitor_order"] == [1, 2]
    assert user_preferences(db, first, [1, 2, 3], site)["monitor_order"] == [2, 1, 3]
    assert user_preferences(db, first, [2, 3], site)["monitor_order"] == [2, 3]
    reset = reset_user_preferences(db, first, [2, 3], site)
    assert reset["monitor_order"] == [2, 3]
    assert reset["columns"] == "4" and reset["density"] == "dense"


def test_wallboard_preferences_coexist_with_main_dashboard_preferences(db):
    user = add_user(db, "viewer@example.test")
    db.add(DashboardPreference(user_id=user.id, preference_version=1, layout_json=json.dumps({"version": 1, "widgets": []})))
    db.commit()
    save_user_preferences(db, user, {"monitor_order": [4]}, [4], wallboard_display(None))
    stored = json.loads(db.query(DashboardPreference).filter_by(user_id=user.id).one().layout_json)
    assert stored["widgets"] == []
    assert stored["ip_wan_dashboard"]["monitor_order"] == [4]


def test_shared_route_requires_challenge_and_filters_monitor_data(db):
    network_monitor_service._dashboard_interval_leases.clear()
    allowed = add_monitor(db, "192.0.2.20", name="Allowed target")
    hidden = add_monitor(db, "192.0.2.21", name="Hidden target")
    wallboard = ensure_wallboard(db)
    wallboard.enabled = True
    wallboard.all_active_monitors = False
    token = generate_public_token(wallboard)
    set_passcode(wallboard, "804291", "numeric")
    db.add(NetworkMonitorWallboardMembership(wallboard_id=wallboard.id, monitor_id=allowed.id, display_order=1))
    db.commit()

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-session-key-that-is-long-enough")
    app.include_router(wallboard_router)
    @app.exception_handler(PermissionError)
    async def denied(_, __):
        return PlainTextResponse("Forbidden", status_code=403)
    @app.get("/normal-kaya-route")
    def normal_route(user=Depends(require_user)):
        return {"user": user.id}
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, base_url="http://testserver") as client:
        challenge = client.get(f"/monitoring/ip-wan-monitor/wallboard/shared/{token}")
        assert challenge.status_code == 200
        assert "Enter the Wallboard passcode" in challenge.text
        assert "Allowed target" not in challenge.text
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', challenge.text).group(1)
        authenticated = client.post(
            f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/authenticate",
            data={"passcode": "804291", "csrf_token": csrf}, follow_redirects=False,
        )
        assert authenticated.status_code == 303
        assert "kaya_ip_wan_wallboard=" in authenticated.headers["set-cookie"]
        assert client.get("/normal-kaya-route").status_code == 403
        page = client.get(f"/monitoring/ip-wan-monitor/wallboard/shared/{token}")
        assert page.status_code == 200
        assert "Allowed target" in page.text
        assert "Hidden target" not in page.text
        shared_csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        rate = client.post(
            f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/collection-rate",
            data={"mode": "live", "client_id": "fake-wallboard-client", "csrf_token": shared_csrf},
        )
        assert rate.status_code == 200
        assert rate.json()["effective_interval_seconds"] == 1
        assert network_monitor_service.active_dashboard_interval() == 1
        unsupported_rate = client.post(
            f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/collection-rate",
            data={"mode": "instant", "client_id": "fake-wallboard-client", "csrf_token": shared_csrf},
        )
        assert unsupported_rate.status_code == 400
        released = client.post(
            f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/collection-rate",
            data={"mode": "paused", "client_id": "fake-wallboard-client", "csrf_token": shared_csrf},
        )
        assert released.status_code == 200
        assert network_monitor_service.active_dashboard_interval() is None
        wallboard.permissions_json = json.dumps({"allow_display_changes": False})
        db.commit()
        denied_rate = client.post(
            f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/collection-rate",
            data={"mode": "live", "client_id": "fake-wallboard-client", "csrf_token": shared_csrf},
        )
        assert denied_rate.status_code == 403
        feed = client.get(f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/data")
        assert feed.status_code == 200
        assert [item["id"] for item in feed.json()["monitors"]] == [allowed.id]
        forbidden = client.post(
            f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/monitors/{allowed.id}/refresh",
            data={"csrf_token": "wrong"},
        )
        assert forbidden.status_code == 403
    network_monitor_service._dashboard_interval_leases.clear()


def test_wallboard_url_identifier_is_redacted_from_audit_paths():
    token = "A" * 43
    safe = audit_safe_path(f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/data")
    assert token not in safe
    assert safe.endswith("/shared/[redacted]/data")


def test_site_admin_context_exposes_url_without_passcode_or_hash(db):
    row = ensure_wallboard(db)
    token = generate_public_token(row)
    set_passcode(row, "804291", "numeric")
    db.commit()
    request = type("RequestStub", (), {"base_url": "https://kaya.example/"})()
    context = wallboard_admin_context(request, db)
    assert context["wallboard_url"].endswith(token)
    assert "passcode_hash" not in context
    assert row.passcode_hash not in json.dumps({key: value for key, value in context.items() if isinstance(value, (str, int, bool, type(None)))})


def test_admin_url_generation_returns_no_store_json_for_same_page_update(db, monkeypatch):
    user = add_user(db, "wallboard-admin@example.test")
    user.role = "admin"
    db.commit()
    monkeypatch.setattr(admin_module, "require_module_settings_access", lambda *_: None)
    monkeypatch.setattr(admin_module, "validate_csrf_token", lambda _request, token: token == "fake-csrf-token" or pytest.fail("CSRF token missing"))
    monkeypatch.setattr(admin_module, "write_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(admin_module, "load_site_settings", lambda _db: {"base_url": "https://kaya.example"})

    async def submit(action):
        body = f"csrf_token=fake-csrf-token&wallboard_action={action}".encode()
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        request = Request({
            "type": "http", "http_version": "1.1", "method": "POST",
            "scheme": "https", "path": "/system/site-administration/ip-wan-monitor/wallboard",
            "raw_path": b"/system/site-administration/ip-wan-monitor/wallboard", "query_string": b"",
            "headers": [(b"content-type", b"application/x-www-form-urlencoded"), (b"x-requested-with", b"XMLHttpRequest")],
            "client": ("192.0.2.10", 1234), "server": ("kaya.example", 443),
        }, receive)
        return await save_network_monitor_wallboard(request, db, user)

    generated = asyncio.run(submit("generate"))
    generated_payload = json.loads(generated.body)
    assert generated.status_code == 200
    assert generated.headers["cache-control"] == "no-store"
    assert generated_payload["url"].startswith("https://kaya.example/monitoring/ip-wan-monitor/wallboard/shared/")
    assert generated_payload["regenerated"] is False

    regenerated = asyncio.run(submit("regenerate"))
    regenerated_payload = json.loads(regenerated.body)
    assert regenerated_payload["regenerated"] is True
    assert regenerated_payload["url"] != generated_payload["url"]


def test_admin_url_generation_stays_on_page_and_switches_to_regeneration():
    root = Path(__file__).resolve().parents[1]
    template = (root / "app" / "templates" / "settings.html").read_text(encoding="utf-8")
    script = (root / "app" / "static" / "js" / "network_monitor_wallboard_admin.js").read_text(encoding="utf-8")
    assert "data-wallboard-generate-url" in template
    assert "Re-generate URL" in template
    assert "will immediately change the live Wallboard URL" in template
    assert 'event.preventDefault(); event.stopImmediatePropagation();' in script
    assert 'input.value = result.url' in script
    assert 'button.value = "regenerate"' in script


def test_site_admin_wallboard_uses_grouped_responsive_settings_ui():
    root = Path(__file__).resolve().parents[1]
    template = (root / "app" / "templates" / "settings.html").read_text(encoding="utf-8")
    script = (root / "app" / "static" / "js" / "network_monitor_wallboard_admin.js").read_text(encoding="utf-8")
    css = (root / "app" / "static" / "css" / "app.css").read_text(encoding="utf-8")
    for heading in ["Availability", "Identity and URL", "Authentication", "Session security", "Monitor access", "Display defaults", "Shared Wallboard permissions", "Session management"]:
        assert f">{heading}<" in template
    assert 'type="radio" name="wallboard_monitor_scope" value="all"' in template
    assert 'class="remote-switch" type="checkbox" name="wallboard_show_paused_monitors"' in template
    assert "Read-only by default" in template
    assert "data-wallboard-remember-lifetime" in template
    assert "rememberLifetime.disabled" in script
    assert "monitorSelection.hidden" in script
    assert "passcodeSubmit.disabled" in script
    assert "@media(max-width:650px)" in css
    assert ".wallboard-setup-summary" in css
    assert ".ip-wan-admin,.ip-wan-settings-card{box-sizing:border-box;max-width:none!important;width:100%}" in css


def test_site_admin_threshold_layout_has_groups_units_and_readable_timing():
    root = Path(__file__).resolve().parents[1]
    environment = Environment(loader=FileSystemLoader(root / "app" / "templates"), autoescape=True)
    rendered = environment.get_template("_network_monitor_threshold_fields.html").render(
        monitor_admin_layout=True,
        monitor_field_prefix="network_monitor_",
        monitor_thresholds=SimpleNamespace(
            latency_warning_ms=100, latency_critical_ms=250,
            packet_loss_warning_percent=5, packet_loss_critical_percent=25,
            degraded_threshold=2, failure_threshold=3, recovery_threshold=3,
            recovery_state_enabled=True,
        ),
    )
    assert "<fieldset" not in rendered
    assert ">Latency<" in rendered and ">Packet loss<" in rendered and ">State transitions<" in rendered
    assert rendered.count("input-with-unit") == 4
    assert "At the current 5-minute interval, this is approximately 10 minutes." in rendered
    assert 'class="remote-switch" name="network_monitor_recovery_state_enabled"' in rendered


def test_wallboard_refresh_cycle_is_in_controls_and_defaults_to_live():
    root = Path(__file__).resolve().parents[1]
    template = (root / "app" / "templates" / "network_monitor_wallboard.html").read_text(encoding="utf-8")
    script = (root / "app" / "static" / "js" / "network_monitor.js").read_text(encoding="utf-8")
    controls = template.index('class="wallboard-controls"')
    refresh = template.index("data-monitor-refresh-rate")
    main = template.index('class="wallboard-main"')
    assert controls < refresh < main
    assert '<option value="live" selected>Live</option>' in template
    assert "data-monitor-rate-endpoint" in template
    assert 'refreshSelect?.dataset.monitorRateEndpoint' in script
    assert 'fetch(collectionRateEndpoint' in script
    assert 'sharedWallboard ? "kaya.ipWanMonitor.wallboardRate"' in script


def test_wallboard_visibility_toggles_write_valid_data_attributes():
    root = Path(__file__).resolve().parents[1]
    script = (root / "app" / "static" / "js" / "network_monitor_wallboard.js").read_text(encoding="utf-8")
    assert 'body.setAttribute(`data-${key.replaceAll("_", "-")}`, value)' in script
    assert 'body.dataset[key.replaceAll("_", "-")]' not in script
