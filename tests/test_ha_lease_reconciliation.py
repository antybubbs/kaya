import sqlite3

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.db.session import (
    SQLITE_BUSY_TIMEOUT_MS,
    Base,
    configure_sqlite_connection,
)
from app.models.models import HACluster, HALeaseReplicationState, HANode, User
from app.services import ha_lease_monitor
from app.services.ha_leases import HALeaseError


def lease_database(tmp_path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'lease.sqlite3').as_posix()}",
        connect_args={"check_same_thread": False, "timeout": SQLITE_BUSY_TIMEOUT_MS / 1_000},
    )
    event.listen(engine, "connect", configure_sqlite_connection)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        user = User(email="lease@example.com", password_hash="x", role="admin", is_active=True)
        cluster = HACluster(
            name="HA DNS",
            provider_key="pihole",
            status="HEALTHY",
            virtual_ip="192.0.2.53",
            keepalived_status="DEPLOYED",
            created_by=user,
        )
        db.add_all([user, cluster])
        db.flush()
        source = HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="http://one.invalid", role="ACTIVE", desired_role="ACTIVE")
        target = HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="http://two.invalid", role="STANDBY", desired_role="STANDBY")
        db.add_all([source, target])
        db.flush()
        cluster.authoritative_node_id = source.id
        db.add(
            HALeaseReplicationState(
                cluster_id=cluster.id,
                source_node_id=source.id,
                target_node_id=target.id,
                status="PENDING",
                desired_generation=1,
            )
        )
        db.commit()
        cluster_id = cluster.id
    return factory, cluster_id


def locked_error():
    return OperationalError(
        "UPDATE ha_lease_replication_states", {}, sqlite3.OperationalError("database is locked")
    )


def test_reconcile_cluster_retries_after_transient_lock_then_succeeds(tmp_path, monkeypatch):
    factory, cluster_id = lease_database(tmp_path)
    seen_session_ids = []
    seen_cluster_ids = []
    calls = 0

    def fake_reconcile(db, cluster, *, client_factory=None):
        nonlocal calls
        calls += 1
        seen_session_ids.append(id(db))
        seen_cluster_ids.append(id(cluster))
        # Simulate work-in-progress mutation that must not survive a failed attempt.
        cluster.lease_replication.status = "BROKEN_IF_COMMITTED"
        if calls == 1:
            raise locked_error()
        cluster.lease_replication.status = "NOT_APPLICABLE"

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)

    ha_lease_monitor._reconcile_cluster_with_retry(factory, cluster_id)

    assert calls == 2
    assert len(set(seen_session_ids)) == 2, "each attempt must use a distinct SQLAlchemy session"
    assert len(set(seen_cluster_ids)) == 2, "each attempt must re-load the cluster from scratch"
    with factory() as db:
        state = db.query(HALeaseReplicationState).filter_by(cluster_id=cluster_id).one()
        assert state.status == "NOT_APPLICABLE"


def test_reconcile_cluster_retry_exhaustion_raises_final_error(tmp_path, monkeypatch):
    factory, cluster_id = lease_database(tmp_path)
    seen_session_ids = []
    calls = 0

    def fake_reconcile(db, cluster, *, client_factory=None):
        nonlocal calls
        calls += 1
        seen_session_ids.append(db)
        cluster.lease_replication.status = "BROKEN_IF_COMMITTED"
        raise locked_error()

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)

    with pytest.raises(OperationalError):
        ha_lease_monitor._reconcile_cluster_with_retry(factory, cluster_id)

    assert calls == 3, "retries must be bounded, not unlimited"
    assert len({id(db) for db in seen_session_ids}) == 3
    for db in seen_session_ids:
        assert not db.in_transaction(), "every failed session must be rolled back"

    with factory() as db:
        state = db.query(HALeaseReplicationState).filter_by(cluster_id=cluster_id).one()
        assert state.status == "PENDING", "no partial state may be committed across failed attempts"


def test_reconcile_cluster_does_not_retry_non_lock_errors(tmp_path, monkeypatch):
    factory, cluster_id = lease_database(tmp_path)
    calls = 0

    def fake_reconcile(db, cluster, *, client_factory=None):
        nonlocal calls
        calls += 1
        raise ValueError("synthetic programming error")

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)

    with pytest.raises(ValueError):
        ha_lease_monitor._reconcile_cluster_with_retry(factory, cluster_id)

    assert calls == 1, "non-lock errors must not be retried"


def test_reconcile_cluster_normal_path_commits_without_retry(tmp_path, monkeypatch):
    factory, cluster_id = lease_database(tmp_path)
    calls = 0

    def fake_reconcile(db, cluster, *, client_factory=None):
        nonlocal calls
        calls += 1
        cluster.lease_replication.status = "CURRENT"

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)

    ha_lease_monitor._reconcile_cluster_with_retry(factory, cluster_id)

    assert calls == 1
    with factory() as db:
        state = db.query(HALeaseReplicationState).filter_by(cluster_id=cluster_id).one()
        assert state.status == "CURRENT"


def test_pass_treats_lease_error_as_safely_blocked_without_retry(tmp_path, monkeypatch):
    factory, _cluster_id = lease_database(tmp_path)
    calls = 0

    def fake_reconcile(db, cluster, *, client_factory=None):
        nonlocal calls
        calls += 1
        raise HALeaseError("synthetic validation failure")

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)
    monkeypatch.setattr(ha_lease_monitor, "get_site_setting", lambda db, key: "1")

    ha_lease_monitor.run_ha_lease_reconciliation_pass(factory)

    assert calls == 1


def test_pass_logs_final_failure_after_retry_exhaustion(tmp_path, monkeypatch, caplog):
    factory, _cluster_id = lease_database(tmp_path)

    def fake_reconcile(db, cluster, *, client_factory=None):
        raise locked_error()

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)
    monkeypatch.setattr(ha_lease_monitor, "get_site_setting", lambda db, key: "1")

    with caplog.at_level("WARNING"):
        ha_lease_monitor.run_ha_lease_reconciliation_pass(factory)

    assert "HA lease reconciliation failed" in caplog.text
    assert any("retry_count=1" in record.message for record in caplog.records)
    assert any("retry_count=2" in record.message for record in caplog.records)


def test_overlapping_reconciliation_pass_is_skipped(tmp_path, monkeypatch, caplog):
    factory, _cluster_id = lease_database(tmp_path)
    calls = 0

    def fake_reconcile(db, cluster, *, client_factory=None):
        nonlocal calls
        calls += 1

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)
    monkeypatch.setattr(ha_lease_monitor, "get_site_setting", lambda db, key: "1")

    acquired = ha_lease_monitor._pass_lock.acquire(blocking=False)
    assert acquired
    try:
        with caplog.at_level("DEBUG"):
            result = ha_lease_monitor.run_ha_lease_reconciliation_pass(factory)
        assert result == ha_lease_monitor.CHECK_INTERVAL_SECONDS
        assert calls == 0, "an in-progress pass must not run a second reconciliation body"
        assert "skipped" in caplog.text
    finally:
        ha_lease_monitor._pass_lock.release()

    ha_lease_monitor.run_ha_lease_reconciliation_pass(factory)
    assert calls == 1, "a later pass is allowed once the earlier one has finished"


def test_pass_lock_is_released_after_an_unexpected_failure(tmp_path, monkeypatch):
    factory, _cluster_id = lease_database(tmp_path)

    def broken_get_site_setting(db, key):
        raise RuntimeError("synthetic failure before any reconciliation begins")

    monkeypatch.setattr(ha_lease_monitor, "get_site_setting", broken_get_site_setting)

    with pytest.raises(RuntimeError):
        ha_lease_monitor.run_ha_lease_reconciliation_pass(factory)

    assert ha_lease_monitor._pass_lock.acquire(blocking=False)
    ha_lease_monitor._pass_lock.release()
