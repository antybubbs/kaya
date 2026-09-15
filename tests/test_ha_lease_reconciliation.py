import json
import sqlite3

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import decrypt_secret
from app.db.session import (
    SQLITE_BUSY_TIMEOUT_MS,
    Base,
    configure_sqlite_connection,
)
from app.models.models import (
    HACluster,
    HALeaseReplicationState,
    HALeaseSnapshot,
    HANode,
    HAProviderConnection,
    User,
)
from app.services import ha_lease_monitor
from app.services.dns_providers import DNSProviderResult
from app.services.ha_leases import HALeaseError, reconcile_cluster_leases


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

    def fake_reconcile(db, cluster, *, client_factory=None, precomputed_inspection=None):
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

    def fake_reconcile(db, cluster, *, client_factory=None, precomputed_inspection=None):
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

    def fake_reconcile(db, cluster, *, client_factory=None, precomputed_inspection=None):
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

    def fake_reconcile(db, cluster, *, client_factory=None, precomputed_inspection=None):
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

    def fake_reconcile(db, cluster, *, client_factory=None, precomputed_inspection=None):
        nonlocal calls
        calls += 1
        raise HALeaseError("synthetic validation failure")

    monkeypatch.setattr(ha_lease_monitor, "reconcile_cluster_leases", fake_reconcile)
    monkeypatch.setattr(ha_lease_monitor, "get_site_setting", lambda db, key: "1")

    ha_lease_monitor.run_ha_lease_reconciliation_pass(factory)

    assert calls == 1


def test_pass_logs_final_failure_after_retry_exhaustion(tmp_path, monkeypatch, caplog):
    factory, _cluster_id = lease_database(tmp_path)

    def fake_reconcile(db, cluster, *, client_factory=None, precomputed_inspection=None):
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

    def fake_reconcile(db, cluster, *, client_factory=None, precomputed_inspection=None):
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


# --- Connection-pool-holding regression coverage -----------------------------
#
# The tests below exercise the real inspect/persist split in
# `_reconcile_cluster_with_retry` end to end (no monkeypatching of
# `reconcile_cluster_leases` itself), using a real Pi-hole-connected node so
# `inspect_lease_plan` actually runs. They prove (1) the split path produces
# identical results to the pre-refactor single-call path for both the
# success and the HALeaseError/BLOCKED outcome, and (2) no database
# connection is held while the (mocked) Pi-hole HTTP calls are in flight.


def lease_database_with_pihole_connection(tmp_path, db_name: str):
    engine = create_engine(
        f"sqlite:///{(tmp_path / db_name).as_posix()}",
        connect_args={"check_same_thread": False, "timeout": SQLITE_BUSY_TIMEOUT_MS / 1_000},
    )
    event.listen(engine, "connect", configure_sqlite_connection)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        user = User(email=f"{db_name}@example.com", password_hash="x", role="admin", is_active=True)
        connection = HAProviderConnection(provider_key="pihole", name="Primary", api_base_url="https://pihole.invalid")
        cluster = HACluster(
            name="HA DNS",
            provider_key="pihole",
            status="HEALTHY",
            virtual_ip="192.0.2.53",
            keepalived_status="DEPLOYED",
            created_by=user,
        )
        db.add_all([user, connection, cluster])
        db.flush()
        source = HANode(
            cluster_id=cluster.id,
            display_name="Primary",
            api_base_url="http://one.invalid",
            ha_connection_id=connection.id,
            role="ACTIVE",
            desired_role="ACTIVE",
        )
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
                desired_generation=0,
            )
        )
        db.commit()
        cluster_id = cluster.id
    return engine, factory, cluster_id


class RecordingPiHole:
    """A Pi-hole client double shared by the identical-outcome tests below."""

    active = True
    leases = [{"expires": 2000000000, "name": "laptop", "hwaddr": "AA-BB-CC-DD-EE-FF", "ip": "192.0.2.120", "clientid": "client-one"}]
    hosts = []
    fail_configuration = False

    def __init__(self, connection):
        self.connection = connection

    def get_ha_configuration(self):
        if self.fail_configuration:
            return DNSProviderResult(False, "Pi-hole configuration fetch failed", {})
        value = {"config": {"dhcp": {"active": self.active, "start": "192.0.2.100", "end": "192.0.2.200", "hosts": self.hosts}}}
        return DNSProviderResult(True, "loaded", {"configuration": {"dhcp": value}})

    def get_dhcp_leases(self):
        return DNSProviderResult(True, "loaded", {"leases": self.leases})


def _state_snapshot(db, cluster_id):
    """Summarise reconciliation results in a form comparable across two
    independently-created clusters (different public_id/node id values,
    which legitimately flow into the checksum and payload identity, are
    normalised away; the content that matters -- lease data, counts,
    status, generation -- is compared as-is).
    """
    state = db.query(HALeaseReplicationState).filter_by(cluster_id=cluster_id).one()
    snapshots = db.query(HALeaseSnapshot).filter_by(cluster_id=cluster_id).order_by(HALeaseSnapshot.generation).all()
    return {
        "status": state.status,
        "source_node_id_is_set": state.source_node_id is not None,
        "target_node_id_is_set": state.target_node_id is not None,
        "desired_generation": state.desired_generation,
        "lease_count": state.lease_count,
        "difference_count": state.difference_count,
        "conflict_count": state.conflict_count,
        "last_error_redacted": state.last_error_redacted,
        "snapshots": [
            {
                "generation": snapshot.generation,
                "lease_count": snapshot.lease_count,
                "status": snapshot.status,
                "leases": json.loads(decrypt_secret(snapshot.encrypted_payload))["leases"],
            }
            for snapshot in snapshots
        ],
    }


def test_split_path_success_matches_direct_single_call_reconciliation(tmp_path):
    """Item 1: successful reconciliation is identical between the two call shapes."""
    RecordingPiHole.fail_configuration = False
    RecordingPiHole.active = True
    RecordingPiHole.hosts = []
    RecordingPiHole.leases = [{"expires": 2000000000, "name": "laptop", "hwaddr": "AA-BB-CC-DD-EE-FF", "ip": "192.0.2.120", "clientid": "client-one"}]

    direct_engine, direct_factory, direct_cluster_id = lease_database_with_pihole_connection(tmp_path, "direct.sqlite3")
    with direct_factory() as db:
        cluster = db.query(HACluster).filter_by(id=direct_cluster_id).one()
        reconcile_cluster_leases(db, cluster, client_factory=RecordingPiHole)
        direct_result = _state_snapshot(db, direct_cluster_id)

    split_engine, split_factory, split_cluster_id = lease_database_with_pihole_connection(tmp_path, "split.sqlite3")
    ha_lease_monitor._reconcile_cluster_with_retry(split_factory, split_cluster_id, client_factory=RecordingPiHole)
    with split_factory() as db:
        split_result = _state_snapshot(db, split_cluster_id)

    assert split_result == direct_result
    assert split_result["status"] == "PENDING"
    assert split_result["desired_generation"] == 1
    assert len(split_result["snapshots"]) == 1
    assert split_result["snapshots"][0]["leases"][0]["hwaddr"] == "aa:bb:cc:dd:ee:ff"


def test_split_path_pihole_error_matches_direct_blocked_state(tmp_path):
    """Item 2: an inspection failure still lands in the same BLOCKED state."""
    RecordingPiHole.fail_configuration = True

    direct_db = Session(create_engine("sqlite:///:memory:"))
    Base.metadata.create_all(direct_db.get_bind())
    try:
        user = User(email="direct-blocked@example.com", password_hash="x", role="admin", is_active=True)
        connection = HAProviderConnection(provider_key="pihole", name="Primary", api_base_url="https://pihole.invalid")
        cluster = HACluster(name="HA DNS", provider_key="pihole", status="HEALTHY", virtual_ip="192.0.2.53", keepalived_status="DEPLOYED", created_by=user)
        direct_db.add_all([user, connection, cluster])
        direct_db.flush()
        source = HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="http://one.invalid", ha_connection_id=connection.id, role="ACTIVE", desired_role="ACTIVE")
        target = HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="http://two.invalid", role="STANDBY", desired_role="STANDBY")
        direct_db.add_all([source, target])
        direct_db.flush()
        cluster.authoritative_node_id = source.id
        # Match lease_database_with_pihole_connection's starting state exactly
        # so the two BLOCKED-state outcomes are compared from identical priors.
        direct_db.add(
            HALeaseReplicationState(
                cluster_id=cluster.id,
                source_node_id=source.id,
                target_node_id=target.id,
                status="PENDING",
                desired_generation=0,
            )
        )
        direct_db.commit()

        with pytest.raises(HALeaseError, match="Pi-hole configuration fetch failed"):
            reconcile_cluster_leases(direct_db, cluster, client_factory=RecordingPiHole)
        direct_result = _state_snapshot(direct_db, cluster.id)
    finally:
        direct_db.close()

    split_engine, split_factory, split_cluster_id = lease_database_with_pihole_connection(tmp_path, "split_blocked.sqlite3")
    with pytest.raises(HALeaseError, match="Pi-hole configuration fetch failed"):
        ha_lease_monitor._reconcile_cluster_with_retry(split_factory, split_cluster_id, client_factory=RecordingPiHole)
    with split_factory() as db:
        split_result = _state_snapshot(db, split_cluster_id)

    assert split_result == direct_result
    assert split_result["status"] == "BLOCKED"
    assert split_result["snapshots"] == []
    assert "Pi-hole configuration fetch failed" in split_result["last_error_redacted"]


def test_no_database_connection_is_held_during_pihole_http_calls(tmp_path):
    """Item 3: proves the performance invariant with pool checkout/checkin hooks.

    A connection checked out while `GuardedPiHole`'s methods run would fail
    the assertion inside them -- this does not rely on source-level call
    ordering, only on what the connection pool actually observes.
    """
    engine, factory, cluster_id = lease_database_with_pihole_connection(tmp_path, "guarded.sqlite3")

    checked_out = {"count": 0}

    @event.listens_for(engine, "checkout")
    def _on_checkout(dbapi_connection, connection_record, connection_proxy):
        checked_out["count"] += 1

    @event.listens_for(engine, "checkin")
    def _on_checkin(dbapi_connection, connection_record):
        checked_out["count"] -= 1

    network_in_progress = {"active": False}
    sql_during_network_calls = []

    @event.listens_for(engine, "before_cursor_execute")
    def _guard_sql_during_network(conn, cursor, statement, parameters, context, executemany):
        if network_in_progress["active"]:
            sql_during_network_calls.append(statement)

    class GuardedPiHole:
        active = True
        leases = []
        hosts = []

        def __init__(self, connection):
            self.connection = connection

        def _assert_pool_is_idle(self):
            assert checked_out["count"] == 0, (
                "a database connection was checked out from the pool while "
                "Pi-hole HTTP inspection was in progress"
            )

        def get_ha_configuration(self):
            self._assert_pool_is_idle()
            network_in_progress["active"] = True
            try:
                value = {"config": {"dhcp": {"active": self.active, "start": "192.0.2.100", "end": "192.0.2.200", "hosts": self.hosts}}}
                return DNSProviderResult(True, "loaded", {"configuration": {"dhcp": value}})
            finally:
                network_in_progress["active"] = False

        def get_dhcp_leases(self):
            self._assert_pool_is_idle()
            network_in_progress["active"] = True
            try:
                return DNSProviderResult(True, "loaded", {"leases": self.leases})
            finally:
                network_in_progress["active"] = False

    ha_lease_monitor._reconcile_cluster_with_retry(factory, cluster_id, client_factory=GuardedPiHole)

    assert sql_during_network_calls == [], "SQL executed on the pool's connection while Pi-hole I/O was in flight"
    with factory() as db:
        state = db.query(HALeaseReplicationState).filter_by(cluster_id=cluster_id).one()
        # active=True with no leases still exercises both Pi-hole calls
        # (get_ha_configuration and get_dhcp_leases), which is what this test
        # needs to guard -- the resulting status is a secondary sanity check.
        assert state.status == "PENDING"
        assert state.lease_count == 0
