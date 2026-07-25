from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import (
    HAAgentCredential,
    HACluster,
    HALeaseReplicationState,
    HAMaintenanceRun,
    HANode,
    HASyncRun,
    User,
)
from app.services.ha_maintenance import (
    advance_reinitialisation,
    desired_maintenance_action,
    inspect_cluster,
    reconcile_cluster_state,
    record_maintenance_action_result,
    start_reconciliation,
    start_reinitialisation,
)


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def pair(db: Session, *, split: bool = False):
    now = datetime.utcnow()
    user = User(email="ha-maintenance@example.test", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(
        name="Synthetic HA",
        provider_key="pihole",
        deployment_mode="DNS_DHCP",
        status="DEGRADED" if split else "HEALTHY",
        virtual_ip="192.0.2.53",
        prefix_length=24,
        keepalived_status="DEPLOYED",
        keepalived_generation=4,
        cluster_generation=4,
        role_generation=4,
        automatic_failover_enabled=True,
        automatic_sync_enabled=True,
    )
    db.add_all([user, cluster])
    db.flush()
    first = HANode(
        cluster_id=cluster.id,
        display_name="Pi-hole One",
        management_host="192.0.2.10",
        api_base_url="http://192.0.2.10",
        network_interface="eth0",
        role="ACTIVE",
        desired_role="ACTIVE",
        observed_role="STANDBY" if split else "ACTIVE",
        observed_generation=4,
        vip_owned=not split,
        dhcp_running=True,
        dns_healthy=True,
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
        config_generation=4,
        lease_generation=8,
        recovery_state="ACTIVE",
        last_heartbeat_at=now,
    )
    second = HANode(
        cluster_id=cluster.id,
        display_name="Pi-hole Two",
        management_host="192.0.2.11",
        api_base_url="http://192.0.2.11",
        network_interface="eth0",
        role="STANDBY",
        desired_role="STANDBY",
        observed_role="ACTIVE" if split else "STANDBY",
        observed_generation=4,
        vip_owned=split,
        dhcp_running=False,
        dns_healthy=True,
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
        config_generation=4,
        lease_generation=8,
        recovery_state="STANDBY_READY",
        last_heartbeat_at=now,
    )
    db.add_all([first, second])
    db.flush()
    cluster.preferred_node_id = first.id
    cluster.current_active_node_id = cluster.authoritative_node_id = first.id
    db.add_all([
        HAAgentCredential(node_id=first.id, agent_id="maint-agent-one", public_key="fake-maint-key-one", registered_at=now),
        HAAgentCredential(node_id=second.id, agent_id="maint-agent-two", public_key="fake-maint-key-two", registered_at=now),
        HALeaseReplicationState(
            cluster_id=cluster.id,
            source_node_id=first.id,
            target_node_id=second.id,
            status="CURRENT",
            desired_generation=8,
            applied_generation=8,
        ),
    ])
    db.commit()
    return user, cluster, first, second


def fresh_after(run: HAMaintenanceRun, *nodes: HANode):
    timestamp = run.started_at + timedelta(seconds=1)
    for node in nodes:
        node.last_heartbeat_at = timestamp


def fake_backup(db: Session, run: HAMaintenanceRun) -> HASyncRun:
    sync = HASyncRun(
        cluster_id=run.cluster_id,
        source_node_id=run.authoritative_node_id,
        target_node_id=next(node.id for node in run.cluster.nodes if node.id != run.authoritative_node_id),
        status="IN_SYNC",
        plan_json='{"groups":[]}',
        created_by_user_id=run.requested_by_user_id,
        completed_at=datetime.utcnow(),
    )
    db.add(sync)
    db.flush()
    run.sync_run_id = sync.id
    db.commit()
    return sync


def test_healthy_cluster_reconciliation_is_idempotent_and_moves_no_service():
    with database() as db:
        user, cluster, first, second = pair(db)
        run = start_reconciliation(db, cluster, user)
        fresh_after(run, first, second)
        before = (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)
        reconcile_cluster_state(db, run)
        assert run.status == "SUCCEEDED", run.error_redacted
        assert before == (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)
        assert cluster.status == "HEALTHY"

        second_run = start_reconciliation(db, cluster, user)
        fresh_after(second_run, first, second)
        reconcile_cluster_state(db, second_run)
        assert second_run.status == "SUCCEEDED"
        assert cluster.current_active_node_id == first.id


def test_reconciliation_clears_stale_recovery_metadata_without_service_move():
    with database() as db:
        user, cluster, first, second = pair(db)
        second.recovery_state = "RECOVERING"
        second.recovery_started_at = datetime.utcnow() - timedelta(minutes=10)
        db.add(HASyncRun(
            cluster_id=cluster.id,
            source_node_id=first.id,
            target_node_id=second.id,
            status="IN_SYNC",
            plan_json='{"groups":[]}',
            completed_at=datetime.utcnow(),
        ))
        db.commit()
        run = start_reconciliation(db, cluster, user)
        fresh_after(run, first, second)
        reconcile_cluster_state(db, run)
        assert second.recovery_state == "STANDBY_READY"
        assert first.vip_owned and first.dhcp_running
        assert not second.vip_owned and not second.dhcp_running


def test_reconciliation_adopts_newer_generation_reported_by_both_nodes():
    with database() as db:
        user, cluster, first, second = pair(db)
        cluster.cluster_generation = 3
        cluster.keepalived_generation = 3
        first.observed_generation = second.observed_generation = 8
        first.config_generation = second.config_generation = 8
        db.commit()
        run = start_reconciliation(db, cluster, user)
        fresh_after(run, first, second)
        reconcile_cluster_state(db, run)
        assert run.status == "SUCCEEDED"
        assert cluster.cluster_generation == 8
        assert cluster.keepalived_generation == 8
        assert first.vip_owned and first.dhcp_running
        assert not second.vip_owned and not second.dhcp_running


def test_split_ownership_is_explicit_and_reconcile_does_not_move_services():
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        inspection = inspect_cluster(cluster)
        assert "OWNERSHIP_MISMATCH" in {issue.code for issue in inspection.issues}
        run = start_reconciliation(db, cluster, user)
        fresh_after(run, first, second)
        reconcile_cluster_state(db, run)
        assert run.status == "SUCCEEDED"
        assert first.dhcp_running and not first.vip_owned
        assert second.vip_owned and not second.dhcp_running
        assert "OWNERSHIP_MISMATCH" in {issue.code for issue in inspect_cluster(cluster).issues}


def drive_to_runtime_rebuild(db, monkeypatch, run, first, second):
    monkeypatch.setattr("app.services.ha_maintenance._create_two_node_backups", fake_backup)
    def stage_leases(_db, cluster):
        state = cluster.lease_replication
        standby = next(node for node in cluster.nodes if node.id != run.desired_active_node_id)
        state.status = "PENDING_AGENT"
        state.target_node_id = standby.id
        state.desired_generation += 1
        state.conflict_count = 0
        _db.commit()
        return state
    monkeypatch.setattr("app.services.ha_maintenance.reconcile_cluster_leases", stage_leases)
    fresh_after(run, first, second)
    advance_reinitialisation(db, run)  # fresh reports
    advance_reinitialisation(db, run)  # backups
    advance_reinitialisation(db, run)  # sync
    advance_reinitialisation(db, run)  # lease capture
    state = run.cluster.lease_replication
    standby = next(node for node in run.cluster.nodes if node.id != run.desired_active_node_id)
    state.status = "CURRENT"
    state.target_node_id = standby.id
    state.applied_generation = state.desired_generation
    standby.lease_generation = state.desired_generation
    db.commit()
    advance_reinitialisation(db, run)  # lease staged
    advance_reinitialisation(db, run)  # normalise standby


def complete_runtime(db, run, target, standby):
    if run.phase == "REBUILDING_HA":
        advance_reinitialisation(db, run)
    target.vip_owned = True
    standby.vip_owned = False
    for node in (target, standby):
        node.keepalived_status = "DEPLOYED"
        node.keepalived_runtime_state = "RUNNING"
        node.config_generation = run.cluster.keepalived_generation
        node.observed_generation = run.cluster.role_generation
        node.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
    db.commit()
    advance_reinitialisation(db, run)
    if run.phase == "PROMOTING_ACTIVE":
        action = desired_maintenance_action(run.cluster, target)
        record_maintenance_action_result(
            db,
            target,
            action_type=action["action_type"],
            generation=action["generation"],
            checksum=action["checksum"],
            status="APPLIED",
            message="started",
        )
    for node in (target, standby):
        node.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
    db.commit()
    advance_reinitialisation(db, run)


def test_reinitialise_can_select_first_node_and_preserves_history(monkeypatch):
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
        drive_to_runtime_rebuild(db, monkeypatch, run, first, second)
        complete_runtime(db, run, first, second)
        assert run.status == "SUCCEEDED", run.error_redacted
        assert first.vip_owned and first.dhcp_running and first.recovery_state == "ACTIVE"
        assert not second.vip_owned and not second.dhcp_running and second.recovery_state == "STANDBY_READY"
        assert cluster.current_active_node_id == first.id
        assert cluster.automatic_failover_enabled and cluster.automatic_sync_enabled
        assert any(event.event_type == "cluster_reinitialisation_completed" for event in cluster.events)


def test_reinitialise_can_select_second_node_without_hardcoded_primary(monkeypatch):
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        run = start_reinitialisation(db, cluster, user, desired_active=second, authority=second, acknowledged=True)
        drive_to_runtime_rebuild(db, monkeypatch, run, first, second)
        assert run.phase == "DEMOTING_STANDBY", run.error_redacted
        action = desired_maintenance_action(cluster, first)
        record_maintenance_action_result(
            db,
            first,
            action_type=action["action_type"],
            generation=action["generation"],
            checksum=action["checksum"],
            status="APPLIED",
            message="stopped",
        )
        complete_runtime(db, run, second, first)
        assert run.status == "SUCCEEDED"
        assert second.vip_owned and second.dhcp_running
        assert not first.vip_owned and not first.dhcp_running


def test_backup_failure_changes_no_runtime_ownership(monkeypatch):
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
        fresh_after(run, first, second)
        advance_reinitialisation(db, run)
        monkeypatch.setattr("app.services.ha_maintenance._create_two_node_backups", lambda db, run: (_ for _ in ()).throw(ValueError("Synthetic backup failure")))
        before = (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)
        advance_reinitialisation(db, run)
        assert run.status == "FAILED_SAFE"
        assert before == (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)


def test_failed_standby_dhcp_stop_never_promotes_target(monkeypatch):
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        run = start_reinitialisation(db, cluster, user, desired_active=second, authority=second, acknowledged=True)
        drive_to_runtime_rebuild(db, monkeypatch, run, first, second)
        action = desired_maintenance_action(cluster, first)
        record_maintenance_action_result(
            db,
            first,
            action_type=action["action_type"],
            generation=action["generation"],
            checksum=action["checksum"],
            status="FAILED",
            message="Synthetic DHCP stop failure",
        )
        assert run.status == "FAILED_SAFE"
        assert not second.dhcp_running


def test_vip_non_convergence_fails_without_starting_another_dhcp(monkeypatch):
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
        drive_to_runtime_rebuild(db, monkeypatch, run, first, second)
        advance_reinitialisation(db, run)
        run.phase_started_at = datetime.utcnow() - timedelta(seconds=91)
        for node in (first, second):
            node.last_heartbeat_at = datetime.utcnow()
            node.keepalived_status = "DEPLOYED"
        db.commit()
        advance_reinitialisation(db, run)
        assert run.status == "FAILED_SAFE"
        assert not second.dhcp_running


def test_sync_failure_stops_before_runtime_change(monkeypatch):
    with database() as db:
        user, cluster, first, second = pair(db, split=True)

        def planned_backup(db, run):
            sync = fake_backup(db, run)
            sync.status = "PLANNED"
            db.commit()
            return sync

        monkeypatch.setattr("app.services.ha_maintenance._create_two_node_backups", planned_backup)
        monkeypatch.setattr("app.services.ha_maintenance.execute_sync", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("Synthetic sync failure")))
        run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
        fresh_after(run, first, second)
        advance_reinitialisation(db, run)
        advance_reinitialisation(db, run)
        before = (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)
        advance_reinitialisation(db, run)
        assert run.status == "FAILED_SAFE"
        assert before == (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)


def test_restart_or_delay_does_not_advance_without_post_start_reports():
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
        first.last_heartbeat_at = run.started_at - timedelta(seconds=1)
        second.last_heartbeat_at = run.started_at - timedelta(seconds=1)
        db.commit()
        advance_reinitialisation(db, run)
        assert run.phase == "WAITING_FOR_REPORTS"
        assert first.vip_owned is False and second.vip_owned is True


def test_process_restart_rewinds_incomplete_repair_to_fresh_inspection(monkeypatch):
    with database() as db:
        user, cluster, first, second = pair(db, split=True)
        run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
        drive_to_runtime_rebuild(db, monkeypatch, run, first, second)
        assert run.phase == "REBUILDING_HA"
        ownership_before = (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)
        monkeypatch.setattr(
            "app.services.ha_maintenance.PROCESS_STARTED_AT",
            datetime.utcnow() + timedelta(seconds=1),
        )
        advance_reinitialisation(db, run)
        assert run.phase == "WAITING_FOR_REPORTS"
        assert ownership_before == (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)
