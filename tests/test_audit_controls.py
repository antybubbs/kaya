from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import AuditLog, RemoteManagerSetting, User
from app.services.audit import (
    audit_purge_query,
    cleanup_audit_logs,
    end_request_context,
    get_audit_settings,
    preview_audit_purge,
    purge_audit_logs,
    begin_request_context,
    validate_audit_settings,
    write_audit,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_capture_tiers_filter_routine_heartbeat_but_keep_security(db):
    token, _ = begin_request_context(
        request_id="heartbeat-test",
        method="POST",
        path="/api/ha/agent/v1/heartbeat",
        status_code=200,
    )
    try:
        assert write_audit(db, None, "post", "api") is None
    finally:
        end_request_context(token)

    assert write_audit(db, None, "login_failed", "user") is not None
    assert db.query(AuditLog).filter_by(action="post").count() == 0
    assert db.query(AuditLog).filter_by(action="login_failed").one().capture_tier == "essential"


def test_capture_level_and_retention_validation():
    assert validate_audit_settings("standard", "90", "90") == ("standard", "90", 90)
    assert validate_audit_settings("diagnostic", "custom", "3650") == ("diagnostic", "custom", 3650)
    assert validate_audit_settings("essential", "indefinite", "") == ("essential", "indefinite", None)
    with pytest.raises(ValueError):
        validate_audit_settings("standard", "custom", "0")
    with pytest.raises(ValueError):
        validate_audit_settings("standard", "custom", "3651")


def test_retention_deletes_bounded_nonessential_rows_and_preserves_security_rows(db):
    db.add_all(
        [
            RemoteManagerSetting(key="audit_retention_mode", value="30"),
            RemoteManagerSetting(key="audit_retention_days", value="30"),
        ]
    )
    old = datetime.utcnow() - timedelta(days=31)
    db.add_all(
        [
            AuditLog(action="old_standard", entity="test", capture_tier="standard", created_at=old),
            AuditLog(action="old_essential", entity="test", capture_tier="essential", created_at=old),
            AuditLog(action="new_standard", entity="test", capture_tier="standard"),
        ]
    )
    db.commit()

    assert cleanup_audit_logs(db, batch_size=1) == 1
    assert db.query(AuditLog).filter_by(action="old_standard").count() == 0
    assert db.query(AuditLog).filter_by(action="old_essential").count() == 1
    assert db.query(AuditLog).filter_by(action="new_standard").count() == 1
    assert get_audit_settings(db)["capture_level"] == "standard"


def test_manual_filtered_purge_only_deletes_matches_and_records_event(db):
    admin = User(email="purge-admin@example.invalid", role="admin")
    db.add(admin)
    db.flush()
    db.add_all([
        AuditLog(action="old_match", entity="server", category="activity", user_id=admin.id),
        AuditLog(action="keep_action", entity="server", category="security", user_id=admin.id),
        AuditLog(action="old_match", entity="network", category="activity", user_id=admin.id),
    ])
    db.commit()

    preview = preview_audit_purge(db, action="old_match", entity="server")
    assert preview["count"] == 1
    assert purge_audit_logs(db, admin, batch_size=1, action="old_match", entity="server") == 1
    assert db.query(AuditLog).filter_by(action="old_match", entity="server").count() == 0
    assert db.query(AuditLog).filter_by(action="old_match", entity="network").count() == 1
    assert db.query(AuditLog).filter_by(action="keep_action").count() == 1
    purge_event = db.query(AuditLog).filter_by(action="audit_logs_purged").one()
    assert '"count":1' in purge_event.metadata_json
    assert purge_event.capture_tier == "essential"


def test_manual_purge_rejects_ambiguous_or_invalid_filters(db):
    with pytest.raises(ValueError):
        preview_audit_purge(db, date_from="2026-02-30")
    with pytest.raises(ValueError):
        preview_audit_purge(db, date_from="2026-01-02", date_to="2026-01-01")
    with pytest.raises(ValueError):
        preview_audit_purge(db, severity="not-a-severity")
    with pytest.raises(ValueError):
        audit_purge_query(db, date_from="2026-01-01", older_than="2026-02-01")


def test_manual_delete_all_leaves_only_new_purge_event(db):
    admin = User(email="purge-all-admin@example.invalid", role="admin")
    db.add(admin)
    db.add_all([AuditLog(action="one", entity="test"), AuditLog(action="two", entity="test")])
    db.commit()

    assert purge_audit_logs(db, admin, batch_size=1) == 2
    rows = db.query(AuditLog).all()
    assert len(rows) == 1
    assert rows[0].action == "audit_logs_purged"
