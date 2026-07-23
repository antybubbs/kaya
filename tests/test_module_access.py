from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.db.session import Base
from app.models.models import AppSession, AuditLog, RemoteManagerSetting, User, UserModulePermission
from app.routers.auth import require_module_access
from app.services.modules import (
    MODULES,
    MODULE_ACCESS_EXEMPT_PATHS,
    MODULE_KEYS,
    accessible_module_keys,
    filter_search_results,
    grant_all_registered_modules,
    has_module_access,
    module_for_path,
    replace_module_access,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def account(db: Session, email: str, role: str = "viewer") -> User:
    row = User(email=email, password_hash="fake-password-hash", role=role, is_active=True)
    db.add(row)
    db.commit()
    return row


def request_for(db: Session, user: User, path: str = "/security/secret-vault") -> Request:
    session_id = f"fake-session-{user.id}"
    db.add(AppSession(session_id=session_id, user_id=user.id, created_at=datetime.utcnow()))
    db.commit()
    return Request({
        "type": "http", "method": "GET", "scheme": "https", "path": path,
        "raw_path": path.encode(), "query_string": b"", "headers": [],
        "client": ("192.0.2.10", 1234), "server": ("kaya.example.test", 443),
        "session": {"user_id": user.id, "session_id": session_id},
    })


def test_new_accounts_have_no_implicit_module_access(db):
    user = account(db, "new-user@example.test")
    assert accessible_module_keys(db, user) == frozenset()
    assert has_module_access(db, user, "dashboard") is False


def test_roles_and_module_access_remain_independent(db):
    admin = account(db, "admin@example.test", "admin")
    viewer = account(db, "viewer@example.test", "viewer")
    replace_module_access(db, viewer, {"secret_vault"}, admin)
    db.commit()
    assert viewer.role == "viewer"
    assert has_module_access(db, viewer, "secret_vault") is True
    assert has_module_access(db, viewer, "remote_manager") is False


def test_disabled_modules_are_not_assignable_or_exposed(db):
    admin = account(db, "admin@example.test", "admin")
    user = account(db, "user@example.test")
    db.add(RemoteManagerSetting(key="dns_manager_enabled", value=""))
    replace_module_access(db, user, {"dns_manager"}, admin)
    db.commit()
    assert db.query(UserModulePermission).filter_by(user_id=user.id, module_key="dns_manager").first() is None
    assert "dns_manager" not in accessible_module_keys(db, user)


def test_existing_install_backfill_grants_every_registered_module(db):
    user = account(db, "legacy@example.test")
    grant_all_registered_modules(db, user)
    db.commit()
    stored = {
        row.module_key
        for row in db.query(UserModulePermission).filter_by(user_id=user.id, allowed=True).all()
    }
    assert stored == set(MODULE_KEYS)


def test_module_dependency_denies_and_audits_direct_url_access(db):
    user = account(db, "denied@example.test")
    request = request_for(db, user)
    with pytest.raises(PermissionError, match="Module access required"):
        require_module_access("secret_vault")(request, db)
    event = db.query(AuditLog).filter_by(action="module_access_denied").one()
    assert event.entity_id == "secret_vault"
    assert event.status_code == 403
    assert "denied@example.test" not in (event.detail or "")


def test_search_filter_drops_results_from_inaccessible_modules(db):
    admin = account(db, "admin@example.test", "admin")
    user = account(db, "search@example.test")
    replace_module_access(db, user, {"runbooks"}, admin)
    db.commit()
    results = [
        {"module_key": "runbooks", "title": "Firewall runbook"},
        {"module_key": "secret_vault", "title": "Firewall credential"},
        {"module_key": "dns_manager", "title": "Firewall DNS record"},
    ]
    assert filter_search_results(db, user, results) == [results[0]]


def test_every_registered_route_prefix_maps_to_its_stable_module_key():
    for module in MODULES:
        for prefix in module.path_prefixes:
            assert module_for_path(prefix) == module
            assert module_for_path(f"{prefix}/api/example") == module
    assert "/infrastructure/vm-docker-manager/api/agent/checkin" in MODULE_ACCESS_EXEMPT_PATHS
