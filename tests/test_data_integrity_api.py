"""Data Integrity HTTP authorisation, CSRF, validation and lifecycle (Stages B and C).

Uses the real routers in a minimal app. Runs on SQLite and, when
KAYA_TEST_POSTGRES_URL is set, PostgreSQL. All data is synthetic.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

import app.routers.auth as auth
import app.routers.data_integrity as data_integrity_router
import tests.test_dhcp_identity_continuity as continuity
from app.core.csrf import CSRF_SESSION_KEY, csrf_context
from app.core.paths import STATIC_DIR
from app.core.templating import templates
from app.db.session import get_db
from app.models.models import AuditLog, DataIntegrityFinding, DataIntegrityRun, User, UserModulePermission
from app.services import data_integrity
from app.services.modules import grant_all_registered_modules
from tests.test_data_integrity import _affected, _asset, _audit, _evidence, _finding
from tests.test_dhcp_identity_continuity import STATIC_IP, _mac

db = continuity.db
TOKEN = "synthetic-csrf-token"
HEADERS = {"X-CSRF-Token": TOKEN}


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr(auth, "current_user", lambda request, db=None: db.get(User, request.session.get("user_id")) if request.session.get("user_id") else None)
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="synthetic-test-session-key-0123456789")

    @app.exception_handler(PermissionError)
    async def _forbidden(request: Request, exc: PermissionError):
        if request.session.get("user_id"):
            return PlainTextResponse("Forbidden", status_code=403)
        return RedirectResponse("/login", status_code=303)

    @app.get("/test-login/{user_id}")
    def _login(user_id: int, request: Request):
        request.session["user_id"] = user_id
        request.session[CSRF_SESSION_KEY] = TOKEN
        return {"ok": True}

    @app.get("/test-base")
    def _base(request: Request):
        user = db.get(User, request.session.get("user_id"))
        request.state.accessible_module_keys = frozenset()
        return templates.TemplateResponse(request, "base.html", {"user": user, **csrf_context(request)})

    @app.get("/manifest.webmanifest", name="manifest")
    def _manifest():
        return {}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(data_integrity_router.page_router)
    app.include_router(data_integrity_router.router)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _user(db, role="admin", *, repair=True, modules=True):
    user = User(email=f"synthetic-{role}-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role=role, is_active=True)
    db.add(user)
    db.flush()
    if modules:
        grant_all_registered_modules(db, user)
    db.flush()
    if not repair:
        db.query(UserModulePermission).filter_by(user_id=user.id, module_key="data_integrity.repair").delete()
    db.commit()
    return user


def _login(client, user):
    assert client.get(f"/test-login/{user.id}").status_code == 200


def _static_finding(db):
    mac, _vlan, _provider, _admin, asset, record = _affected(db)
    _audit(db)
    return _finding(db, "managed_static_assignment", f"{asset.id}|{mac}|{record.id}"), asset


READS = ["/data/data-integrity", "/api/data-integrity/summary", "/api/data-integrity/findings", "/api/data-integrity/audits/current",
         "/api/data-integrity/history", "/api/data-integrity/export?format=csv", "/api/data-integrity/export?format=json"]


def _writes(finding_id):
    return [
        ("/api/data-integrity/audits", None),
        (f"/api/data-integrity/findings/{finding_id}/revalidate", None),
        (f"/api/data-integrity/findings/{finding_id}/ignore", {"reason": "Synthetic reason"}),
        (f"/api/data-integrity/findings/{finding_id}/reopen", None),
        (f"/api/data-integrity/findings/{finding_id}/acknowledge", {"acknowledgement": "retain_hostname"}),
        (f"/api/data-integrity/findings/{finding_id}/preview", {"action": "repair_static_assignment"}),
        (f"/api/data-integrity/findings/{finding_id}/repair", {"action": "repair_static_assignment", "preview_token": "0" * 64}),
        ("/api/data-integrity/bulk/preview", {"finding_ids": [finding_id]}),
        ("/api/data-integrity/bulk/repair", {"items": [{"finding_id": finding_id, "preview_token": "0" * 64}]}),
        ("/api/data-integrity/settings", {"schedule_hours": "24", "notify_critical": True}),
    ]


def test_unauthenticated_requests_are_redirected_to_login(client, db):
    for path in READS:
        response = client.get(path)
        assert response.status_code == 303 and response.headers["location"] == "/login"
    assert client.post("/api/data-integrity/audits", headers=HEADERS).status_code == 303


@pytest.mark.parametrize("role", ["viewer", "editor"])
def test_non_administrators_cannot_reach_any_page_or_endpoint_even_with_the_repair_grant(client, db, role):
    finding, _asset_row = _static_finding(db)
    user = _user(db, role)
    db.add(UserModulePermission(user_id=user.id, module_key="data_integrity.repair", allowed=True))
    db.commit()
    _login(client, user)
    for path in READS + [f"/api/data-integrity/findings/{finding.id}"]:
        assert client.get(path).status_code == 403, path
    for path, body in _writes(finding.id):
        assert client.post(path, json=body, headers=HEADERS).status_code == 403, path
    assert db.query(DataIntegrityRun).count() == 1


def test_navigation_entry_is_shown_to_administrators_only(client, db):
    _login(client, _user(db, "viewer"))
    assert "/data/data-integrity" not in client.get("/test-base").text
    _login(client, _user(db, "admin"))
    assert 'href="/data/data-integrity"' in client.get("/test-base").text


def test_administrator_sees_the_dashboard_with_real_counts(client, db):
    finding, _asset_row = _static_finding(db)
    _login(client, _user(db))
    page = client.get("/data/data-integrity")
    assert page.status_code == 200 and "Data Integrity" in page.text
    assert f'data-di-row="{finding.id}"' in page.text
    summary = client.get("/api/data-integrity/summary").json()
    assert summary["counts"]["warning"] >= 1 and summary["freshness"] in {"current", "incomplete"}
    detail = client.get(f"/api/data-integrity/findings/{finding.id}").json()
    assert detail["live"]["detected"] is True and detail["actions"][0]["key"] == "repair_static_assignment"


def test_state_changing_requests_require_a_valid_csrf_token(client, db):
    _login(client, _user(db))
    assert client.post("/api/data-integrity/audits").status_code == 400
    assert client.post("/api/data-integrity/audits", headers={"X-CSRF-Token": "wrong"}).status_code == 400
    assert db.query(DataIntegrityRun).count() == 0


def test_duplicate_audit_requests_are_refused(client, db):
    _login(client, _user(db))
    assert client.post("/api/data-integrity/audits", headers=HEADERS).status_code == 202
    second = client.post("/api/data-integrity/audits", headers=HEADERS)
    assert second.status_code == 409 and second.json()["active"]["status"] == "queued"


def test_invalid_request_data_is_rejected(client, db):
    finding, _asset_row = _static_finding(db)
    _login(client, _user(db))
    base = f"/api/data-integrity/findings/{finding.id}"
    assert client.post(f"{base}/preview", json={"action": "repair_static_assignment", "extra": 1}, headers=HEADERS).status_code == 422
    assert client.post(f"{base}/preview", json={"action": "drop_tables"}, headers=HEADERS).status_code == 400
    assert client.post(f"{base}/repair", json={"action": "repair_static_assignment", "preview_token": "not-a-token"}, headers=HEADERS).status_code == 422
    assert client.post("/api/data-integrity/findings/0/preview", json={"action": "repair_static_assignment"}, headers=HEADERS).status_code == 422
    assert client.post(f"{base}/ignore", json={"reason": "no"}, headers=HEADERS).status_code == 400
    assert client.post("/api/data-integrity/bulk/preview", json={"finding_ids": list(range(1, 60))}, headers=HEADERS).status_code == 422
    assert client.post("/api/data-integrity/settings", json={"schedule_hours": "3", "notify_critical": True}, headers=HEADERS).status_code == 400
    assert client.get("/api/data-integrity/export?format=xlsx").status_code == 422


def test_findings_outside_the_administrators_module_grants_are_not_found(client, db):
    finding, _asset_row = _static_finding(db)
    admin = _user(db)
    db.query(UserModulePermission).filter_by(user_id=admin.id, module_key="vlan_ip_manager").update({"allowed": False})
    db.commit()
    _login(client, admin)
    assert client.get(f"/api/data-integrity/findings/{finding.id}").status_code == 404
    assert client.post(f"/api/data-integrity/findings/{finding.id}/preview", json={"action": "repair_static_assignment"}, headers=HEADERS).status_code == 404
    assert f'data-di-row="{finding.id}"' not in client.get("/data/data-integrity").text
    assert client.get("/api/data-integrity/findings/999999").status_code == 404


def test_administrator_without_repair_permission_can_preview_but_not_repair(client, db):
    finding, asset = _static_finding(db)
    _login(client, _user(db, repair=False))
    preview = client.post(f"/api/data-integrity/findings/{finding.id}/preview", json={"action": "repair_static_assignment"}, headers=HEADERS).json()
    assert preview["state"] == "ready" and preview["can_repair"] is False
    response = client.post(f"/api/data-integrity/findings/{finding.id}/repair", json={"action": "repair_static_assignment", "preview_token": preview["preview_token"]}, headers=HEADERS)
    assert response.status_code == 403
    bulk = client.post("/api/data-integrity/bulk/repair", json={"items": [{"finding_id": finding.id, "preview_token": preview["preview_token"]}]}, headers=HEADERS)
    assert bulk.status_code == 403
    assert STATIC_IP not in [row.address for row in continuity._rows(db, asset) if row.ended_at is None]


def test_set_asset_hostname_repair_over_http_is_csrf_protected_validated_and_attributed(client, db):
    from tests.test_data_integrity_repairs import _administrator_hostnames, _hostname_finding

    _record, asset, finding = _hostname_finding(db)
    admin = _user(db)
    _login(client, admin)
    base = f"/api/data-integrity/findings/{finding.id}"
    body = {"action": "set_asset_hostname", "params": {"hostname": "phone.example.invalid"}}
    assert client.post(f"{base}/preview", json={**body, "params": {"hostname": "not a hostname"}}, headers=HEADERS).status_code == 400
    preview = client.post(f"{base}/preview", json=body, headers=HEADERS).json()
    assert preview["state"] == "ready"
    repair = {**body, "preview_token": preview["preview_token"]}
    assert client.post(f"{base}/repair", json=repair).status_code == 400                                   # no CSRF token
    assert client.post(f"{base}/repair", json=repair, headers={"X-CSRF-Token": "wrong"}).status_code == 400
    assert _administrator_hostnames(db, asset) == []
    result = client.post(f"{base}/repair", json=repair, headers=HEADERS)
    assert result.status_code == 200, result.text
    assert result.json()["outcome"] == "applied"
    db.expire_all()
    (row,) = _administrator_hostnames(db, asset)
    assert (row.normalised_value, row.confirmed_by) == ("phone.example.invalid", admin.id)


def test_administrator_with_repair_permission_repairs_and_verifies_from_the_overview(client, db):
    finding, asset = _static_finding(db)
    _login(client, _user(db))
    preview = client.post(f"/api/data-integrity/findings/{finding.id}/preview", json={"action": "repair_static_assignment"}, headers=HEADERS).json()
    result = client.post(f"/api/data-integrity/findings/{finding.id}/repair", json={"action": "repair_static_assignment", "preview_token": preview["preview_token"]}, headers=HEADERS)
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["outcome"] == "applied" and body["verified"] is True and body["finding"]["status"] == "resolved"
    assert continuity._open(db, asset) == [STATIC_IP]
    retry = client.post(f"/api/data-integrity/findings/{finding.id}/repair", json={"action": "repair_static_assignment", "preview_token": preview["preview_token"]}, headers=HEADERS)
    assert retry.status_code == 200 and retry.json()["outcome"] == "not_active"
    assert continuity._open(db, asset) == [STATIC_IP]


def test_export_is_administrator_only_audited_and_formula_safe(client, db):
    mac = _mac()
    first, second = _asset(db, name="=HYPERLINK(\"https://example.invalid\")"), _asset(db)
    _evidence(db, first, mac)
    _evidence(db, second, mac, source="dhcp")
    db.commit()
    _audit(db)
    _login(client, _user(db))
    response = client.get("/api/data-integrity/export?format=csv&status=all")
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]
    assert ",=HYPERLINK" not in response.text and "\n=HYPERLINK" not in response.text
    json_export = client.get("/api/data-integrity/export?format=json")
    assert json_export.status_code == 200 and json_export.json()["findings"]
    assert db.query(AuditLog).filter(AuditLog.action == "data_integrity_export").count() == 2


def test_lifecycle_transitions_through_the_api(client, db):
    finding, _asset_row = _static_finding(db)
    _login(client, _user(db))
    base = f"/api/data-integrity/findings/{finding.id}"
    ignored = client.post(f"{base}/ignore", json={"reason": "Synthetic: device is being replaced."}, headers=HEADERS)
    assert ignored.status_code == 200 and ignored.json()["finding"]["status"] == "ignored"
    assert client.post(f"{base}/ignore", json={"reason": "Synthetic: device is being replaced."}, headers=HEADERS).json()["status"] == "ignored"
    reopened = client.post(f"{base}/reopen", headers=HEADERS)
    assert reopened.status_code == 200 and reopened.json()["finding"]["status"] == "open"
    assert client.post(f"{base}/acknowledge", json={"acknowledgement": "retain_hostname"}, headers=HEADERS).status_code == 400
    revalidated = client.post(f"{base}/revalidate", headers=HEADERS)
    assert revalidated.status_code == 200 and revalidated.json()["detected"] is True
    db.expire_all()
    assert db.get(DataIntegrityFinding, finding.id).status == "open"


def test_schedule_settings_are_validated_and_audited(client, db):
    _login(client, _user(db))
    response = client.post("/api/data-integrity/settings", json={"schedule_hours": "168", "notify_critical": False}, headers=HEADERS)
    assert response.status_code == 200 and response.json()["schedule_hours"] == "168" and response.json()["notify_critical"] is False
    assert db.query(AuditLog).filter(AuditLog.action == "data_integrity_schedule_updated").count() == 1
    assert data_integrity.schedule_settings(db)["schedule_hours"] == "168"
