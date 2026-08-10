from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import AuditLog, RemoteManagerSetting
from app.services.audit import (
    cleanup_audit_logs,
    end_request_context,
    get_audit_settings,
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
