import json
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import AuditLog, DashboardPreference, RemoteManagerSetting, User
from app.services.dashboard import config, default_layout, normalise_layout, preferences, reset_preferences, save_preferences, snapshot
from app.services.modules import grant_all_registered_modules
import app.services.dashboard as dashboard_service

@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()

def user(db, email="viewer@example.test", role="viewer"):
    item=User(email=email,password_hash="x",role=role,is_active=True,created_at=datetime.utcnow());db.add(item);db.flush()
    grant_all_registered_modules(db,item);db.commit();return item

def test_preferences_are_per_user_and_persist(db):
    first=user(db); second=user(db,"second@example.test")
    layout=default_layout(db,first); layout["widgets"][0]["width"]="medium"
    saved=save_preferences(db,first,layout)
    assert preferences(db,first)["widgets"][0]["width"] == "medium"
    assert preferences(db,second)["widgets"][0]["width"] == default_layout(db,second)["widgets"][0]["width"]
    assert db.query(DashboardPreference).count() == 1
    assert saved["version"] == 1

def test_invalid_widget_key_size_and_position_are_rejected(db):
    account=user(db); layout=default_layout(db,account)
    bad=json.loads(json.dumps(layout)); bad["widgets"][0]["key"]="ssl_certificates"
    with pytest.raises(ValueError,match="Unknown"): normalise_layout(db,account,bad)
    bad=json.loads(json.dumps(layout)); bad["widgets"][0]["width"]="giant"
    with pytest.raises(ValueError,match="size"): normalise_layout(db,account,bad)
    bad=json.loads(json.dumps(layout)); bad["widgets"][0]["position"]=-1
    with pytest.raises(ValueError,match="position"): normalise_layout(db,account,bad)

def test_reset_restores_defaults(db):
    account=user(db); layout=default_layout(db,account); layout["monitor_mode"]=True
    save_preferences(db,account,layout); result=reset_preferences(db,account)
    assert result == default_layout(db,account)
    assert db.query(DashboardPreference).count() == 0

def test_restricted_widgets_are_not_returned(db):
    viewer=user(db); keys={item["key"] for item in config(db,viewer)["widgets"]}
    assert "team_users" not in keys and "recent_activity" not in keys
    assert set(snapshot(db,viewer)["widgets"]).issubset(keys)

def test_disabled_widget_is_excluded_from_snapshot(db):
    account=user(db); layout=default_layout(db,account); layout["widgets"][0]["enabled"]=False
    key=layout["widgets"][0]["key"]; save_preferences(db,account,layout)
    assert key not in snapshot(db,account)["widgets"]

def test_module_disabled_is_available_with_reason_but_not_enabled(db):
    account=user(db)
    assert "dns_summary" not in {item["key"] for item in config(db,account)["widgets"]}
    assert "dns_summary" not in {item["key"] for item in preferences(db,account)["widgets"]}

@pytest.mark.parametrize(("stored", "expected"), [("10", 10), ("30", 30), ("60", 60), ("300", 300), ("1", 10), ("broken", 10)])
def test_polling_interval_is_one_of_the_supported_choices(db, stored, expected):
    account=user(db); db.add(RemoteManagerSetting(key="dashboard_poll_interval_seconds",value=stored)); db.commit()
    assert config(db,account)["poll_interval_seconds"] == expected

def test_demo_hides_shared_dashboard_editing_controls(db, monkeypatch):
    account=user(db)
    db.add_all([
        RemoteManagerSetting(key="dashboard_customisation_enabled", value="1"),
        RemoteManagerSetting(key="dashboard_monitor_mode_enabled", value="1"),
    ])
    db.commit()
    monkeypatch.setattr(dashboard_service, "get_settings", lambda: type("Settings", (), {"demo_mode": True})())

    result = config(db, account)

    assert result["customisation_enabled"] is False
    assert result["monitor_mode_enabled"] is False

def test_malformed_preferences_fall_back_safely(db):
    account=user(db); db.add(DashboardPreference(user_id=account.id,preference_version=99,layout_json="not json"));db.commit()
    assert preferences(db,account) == default_layout(db,account)

def test_widget_failure_does_not_fail_snapshot(db, monkeypatch):
    account=user(db); original=dashboard_service._build
    def broken(session, current_user, key):
        if key == "infrastructure_summary": raise RuntimeError("secret provider detail")
        return original(session, current_user, key)
    monkeypatch.setattr(dashboard_service, "_build", broken)
    result=snapshot(db,account)
    assert result["widgets"]["infrastructure_summary"] == {"status":"error","reason":"Widget data is temporarily unavailable"}
    assert result["widgets"]["attention_required"]["status"] == "ok"

def test_snapshot_never_refreshes_external_dns_provider(db, monkeypatch):
    account=user(db)
    calls = []
    monkeypatch.setattr(
        "app.services.dns_dashboard_summary.analyse_provider",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    snapshot(db,account)
    assert calls == []

def test_recent_activity_filters_request_noise_and_groups_duplicates(db):
    account=user(db,role="admin")
    db.add_all([
        AuditLog(action="request_failed",entity="request",request_path="/.well-known/appspecific/com.chrome.devtools.json",severity="warning"),
        AuditLog(action="update",entity="settings",entity_id="dashboard",severity="info"),
        AuditLog(action="update",entity="settings",entity_id="dashboard",severity="info"),
    ]); db.commit()
    data=dashboard_service._build(db,account,"recent_activity")
    assert len(data["items"]) == 1
    assert data["items"][0]["summary"] == "Updated settings"
    assert data["items"][0]["count"] == 2
