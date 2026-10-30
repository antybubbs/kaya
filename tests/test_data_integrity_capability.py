"""The ``data_integrity.repair`` capability and the module's route gates.

Capabilities share the per-user grant table with modules but never grant
module or route access, and count only for active administrators.
"""
from __future__ import annotations

import uuid

import pytest

import tests.test_dhcp_identity_continuity as continuity
from app.models.models import User, UserModulePermission
from app.routers.admin import selected_capability_keys
from app.routers.auth import require_admin
from app.services.modules import (
    accessible_module_keys,
    grant_all_registered_modules,
    granted_capability_keys,
    has_capability,
    module_access_counts,
    replace_capability_access,
    replace_module_access,
)

db = continuity.db
REPAIR = "data_integrity.repair"


def _user(db, role):
    user = User(email=f"synthetic-{role}-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role=role, is_active=True)
    db.add(user)
    db.flush()
    return user


def test_first_administrator_gets_the_capability_and_other_roles_do_not(db):
    admin, viewer = _user(db, "admin"), _user(db, "viewer")
    grant_all_registered_modules(db, admin)
    grant_all_registered_modules(db, viewer)
    db.commit()
    assert has_capability(db, admin, REPAIR)
    assert not has_capability(db, viewer, REPAIR)


def test_a_capability_row_never_authorises_a_non_administrator(db):
    editor = _user(db, "editor")
    db.add(UserModulePermission(user_id=editor.id, module_key=REPAIR, allowed=True))
    db.commit()
    assert not has_capability(db, editor, REPAIR)
    editor.role = "admin"
    editor.is_active = False
    db.commit()
    assert not has_capability(db, editor, REPAIR)


def test_capability_can_be_revoked_and_is_removed_when_a_user_stops_being_an_administrator(db):
    admin, actor = _user(db, "admin"), _user(db, "admin")
    granted, removed = replace_capability_access(db, admin, {REPAIR}, actor)
    db.commit()
    assert granted == {REPAIR} and removed == set() and has_capability(db, admin, REPAIR)
    granted, removed = replace_capability_access(db, admin, set(), actor)
    db.commit()
    assert removed == {REPAIR} and not has_capability(db, admin, REPAIR)
    replace_capability_access(db, admin, {REPAIR}, actor)
    admin.role = "viewer"
    replace_capability_access(db, admin, {REPAIR}, actor)
    db.commit()
    assert db.query(UserModulePermission).filter_by(user_id=admin.id, module_key=REPAIR).one().allowed is False


def test_capabilities_are_never_module_access(db):
    admin, actor = _user(db, "admin"), _user(db, "admin")
    grant_all_registered_modules(db, admin)
    db.commit()
    assert REPAIR not in accessible_module_keys(db, admin)
    replace_module_access(db, admin, set(), actor)
    db.commit()
    assert has_capability(db, admin, REPAIR)  # module edits leave capabilities alone
    assert module_access_counts(db, [admin])[admin.id] == 0
    assert granted_capability_keys(db, admin) == {REPAIR}


@pytest.mark.parametrize("values", [["unknown.capability"], [REPAIR, REPAIR], [1]])
def test_user_form_rejects_unknown_or_malformed_capability_selections(values):
    with pytest.raises(ValueError):
        selected_capability_keys(values)


def test_user_form_treats_a_missing_capability_field_as_no_selection():
    assert selected_capability_keys(None) == set()
    assert selected_capability_keys([REPAIR]) == {REPAIR}


def _flatten(routes):
    for route in routes:
        nested = getattr(getattr(route, "original_router", None), "routes", None)  # newer FastAPI wraps included routers
        if nested is not None:
            yield from _flatten(nested)
        else:
            yield route


def test_every_data_integrity_route_requires_the_administrator_role():
    from app.main import app

    routes = [route for route in _flatten(app.routes) if getattr(route, "path", "").startswith(("/data/data-integrity", "/api/data-integrity"))]
    assert len(routes) >= 15
    for route in routes:
        calls = [dependency.call for dependency in route.dependant.dependencies]
        assert require_admin in calls, f"{route.path} is missing require_admin"
