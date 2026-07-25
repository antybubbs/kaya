from datetime import datetime, timedelta
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import (
    HAAgentCredential,
    HACluster,
    HAEvent,
    HALeaseReplicationState,
    HAMaintenanceRun,
    HANode,
    HASyncRun,
    User,
)
from app.services.ha_maintenance import (
    active_maintenance,
    advance_dhcp_self_heal,
    advance_reinitialisation,
    desired_maintenance_action,
    inspect_cluster,
    maintenance_status,
    reconcile_cluster_state,
    record_maintenance_action_result,
    start_reconciliation,
    start_dhcp_self_heal,
    start_reinitialisation,
)
from app.services.ha_watchdog import reconcile_cluster as watchdog_reconcile_cluster
from app.services.ha_recovery import evaluate_recovery
from app.services.ha_topology import reconcile_topology


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
        agent_version="0.2.11",
        vip_owned=not split,
        dhcp_running=True,
        dhcp_configured=True,
        dhcp_listener_active=True,
        ftl_active=True,
        dhcp_runtime_state="RUNNING",
        dhcp_observation_status="FRESH",
        dhcp_observed_at=now,
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
        agent_version="0.2.11",
        vip_owned=split,
        dhcp_running=False,
        dhcp_configured=False,
        dhcp_listener_active=False,
        ftl_active=True,
        dhcp_runtime_state="STOPPED",
        dhcp_observation_status="FRESH",
        dhcp_observed_at=now,
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
        node.dhcp_observed_at = timestamp


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


def test_reinitialisation_repairs_metadata_without_moving_an_already_correct_topology():
    with database() as db:
        user, cluster, first, second = pair(db)
        cluster.current_active_node_id = second.id
        cluster.authoritative_node_id = second.id
        first.role = first.desired_role = "STANDBY"
        second.role = second.desired_role = "ACTIVE"
        db.commit()
        before = (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)

        run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
        fresh_after(run, first, second)
        advance_reinitialisation(db, run)

        assert run.status == "SUCCEEDED"
        assert json.loads(run.result_json)["service_movement_performed"] is False
        assert before == (first.vip_owned, first.dhcp_running, second.vip_owned, second.dhcp_running)
        assert cluster.current_active_node_id == first.id
        assert first.role == first.desired_role == "ACTIVE"
        assert second.role == second.desired_role == "STANDBY"


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
        assert run.status == "FAILED_SAFE"
        assert run.phase == "PAUSED"
        assert "currently owned by different nodes" in run.error_redacted
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
        node.dhcp_observed_at = node.last_heartbeat_at
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
        target.dhcp_running = target.dhcp_configured = target.dhcp_listener_active = target.ftl_active = True
        target.dhcp_runtime_state = "RUNNING"
        target.dhcp_observation_status = "FRESH"
    for node in (target, standby):
        node.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
        node.dhcp_observed_at = node.last_heartbeat_at
    db.commit()
    advance_reinitialisation(db, run)
    if run.phase == "VERIFYING":
        for node in (target, standby):
            node.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
            node.dhcp_observed_at = node.last_heartbeat_at
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
        first.dhcp_running = first.dhcp_configured = first.dhcp_listener_active = False
        first.dhcp_runtime_state = "STOPPED"
        first.dhcp_observation_status = "FRESH"
        first.dhcp_observed_at = datetime.utcnow()
        first.last_heartbeat_at = datetime.utcnow()
        advance_reinitialisation(db, run)
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


def test_failed_standby_dhcp_stop_waits_for_observed_release_and_never_promotes_target(monkeypatch):
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
        assert run.status == "RUNNING"
        assert run.phase == "VERIFYING_DHCP_RELEASE"
        assert not second.dhcp_running

        first.dhcp_running = False
        first.dhcp_configured = False
        first.dhcp_listener_active = False
        first.dhcp_runtime_state = "STOPPED"
        first.dhcp_observation_status = "FRESH"
        first.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
        first.dhcp_observed_at = first.last_heartbeat_at
        second.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
        second.dhcp_observed_at = second.last_heartbeat_at
        db.commit()
        advance_reinitialisation(db, run)

        assert run.phase == "REBUILDING_HA"


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


def test_watchdog_automatically_repairs_active_configuration_drift_without_moving_vip():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.agent_version = second.agent_version = "0.2.11"
        now = datetime.utcnow()
        second.recovery_state = "STANDBY_READY"
        second.recovery_started_at = now - timedelta(minutes=3)
        second.recovery_stable_since = now - timedelta(minutes=2)
        db.add(HASyncRun(
            cluster_id=cluster.id,
            source_node_id=first.id,
            target_node_id=second.id,
            status="IN_SYNC",
            plan_json="{}",
            completed_at=now - timedelta(minutes=2),
        ))
        first.dhcp_configured = False
        first.dhcp_running = True
        first.dhcp_listener_active = True
        first.dhcp_runtime_state = "RUNNING"
        db.commit()
        recovery_events_before = db.query(HAEvent).filter(
            HAEvent.node_id == second.id,
            HAEvent.event_type.in_(["node_recovery_synchronising", "node_recovery_verifying", "node_standby_ready"]),
        ).count()

        watchdog_reconcile_cluster(db, cluster)
        run = active_maintenance(cluster)

        assert run is not None
        assert json.loads(run.result_json)["classification"] == "SAFE_ACTIVE_DHCP_CONFIGURATION_DRIFT"
        assert run.desired_active_node_id == first.id
        assert desired_maintenance_action(cluster, first)["action_type"] == "DHCP_PROMOTE"
        action = desired_maintenance_action(cluster, first)
        assert action["configuration_only"] is True
        record_maintenance_action_result(db, first, action_type=action["action_type"], generation=action["generation"], checksum=action["checksum"], status="APPLIED", message="accepted")
        first.dhcp_configured = True
        first.dhcp_running = True
        first.dhcp_listener_active = True
        first.dhcp_runtime_state = "RUNNING"
        first.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
        first.dhcp_observed_at = first.last_heartbeat_at
        second.last_heartbeat_at = run.phase_started_at + timedelta(seconds=1)
        second.dhcp_observed_at = second.last_heartbeat_at
        db.commit()

        advance_dhcp_self_heal(db, run)

        assert run.status == "SUCCEEDED"
        assert run.phase == "COMPLETE"
        assert first.vip_owned is True and second.vip_owned is False
        assert first.dhcp_configured is True and first.dhcp_listener_active is True
        assert second.dhcp_configured is False and second.dhcp_listener_active is False
        assert cluster.maintenance_mode is False
        assert cluster.status == "HEALTHY"
        final_topology = reconcile_topology(cluster)
        assert final_topology.service_availability == "HEALTHY"
        assert final_topology.configuration_state == "CONSISTENT"
        assert final_topology.topology_safe is True
        completed_status = maintenance_status(run)
        assert completed_status["progress_percent"] == 100
        assert completed_status["visible"] is True
        assert completed_status["message"] == "HA configuration repaired"
        assert "Network service was not interrupted" in completed_status["detail"]

        watchdog_reconcile_cluster(db, cluster)
        recovery = evaluate_recovery(db, cluster, now=datetime.utcnow())[second.id]
        assert db.query(HAMaintenanceRun).filter(HAMaintenanceRun.operation == "DHCP_SELF_HEAL").count() == 1
        assert second.recovery_state == "STANDBY_READY", [
            (check.key, check.passed, check.required) for check in recovery.checks
        ]
        assert db.query(HAEvent).filter(
            HAEvent.node_id == second.id,
            HAEvent.event_type.in_(["node_recovery_synchronising", "node_recovery_verifying", "node_standby_ready"]),
        ).count() == recovery_events_before


def test_maintenance_live_driver_stops_at_terminal_state_and_only_advances_new_phases():
    script = Path("app/static/js/ha_maintenance.js").read_text(encoding="utf-8")

    assert 'phase === lastPhase' in script
    assert 'terminal || advancing' in script
    assert 'window.clearTimeout(advanceTimer)' in script
    assert 'window.location.reload()' not in script
    for status in ("SUCCEEDED", "FAILED", "FAILED_SAFE", "PAUSED", "NEEDS_ATTENTION", "CANCELLED"):
        assert f'"{status}"' in script


def _failed_active_dhcp_self_heal(db, cluster, first):
    watchdog_reconcile_cluster(db, cluster)
    run = active_maintenance(cluster)
    action = desired_maintenance_action(cluster, first)
    record_maintenance_action_result(
        db,
        first,
        action_type=action["action_type"],
        generation=action["generation"],
        checksum=action["checksum"],
        status="FAILED",
        message="Synthetic bounded repair failure.",
    )
    run.phase_started_at = datetime.utcnow() - timedelta(seconds=46)
    db.commit()
    advance_dhcp_self_heal(db, run)
    return run


def test_failed_self_heal_latches_and_identical_heartbeats_do_not_retry():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.dhcp_configured = False
        db.commit()
        run = _failed_active_dhcp_self_heal(db, cluster, first)

        assert run.status == "FAILED_SAFE"
        failed_result = json.loads(run.result_json)
        assert failed_result["latch_active"] is True
        assert failed_result["action_result"]["status"] == "FAILED"
        assert failed_result["action_result"]["message"] == "Synthetic bounded repair failure."
        assert first.vip_owned is True and first.dhcp_configured is False
        assert maintenance_status(run)["message"] == "Self-heal paused"
        assert maintenance_status(run)["visible"] is True

        first.last_heartbeat_at = first.dhcp_observed_at = datetime.utcnow()
        second.last_heartbeat_at = second.dhcp_observed_at = datetime.utcnow()
        db.commit()
        watchdog_reconcile_cluster(db, cluster)

        assert db.query(HAMaintenanceRun).filter(HAMaintenanceRun.operation == "DHCP_SELF_HEAL").count() == 1
        assert active_maintenance(cluster) is None


def test_manual_retry_uses_same_controller_for_one_new_bounded_attempt():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.dhcp_configured = False
        db.commit()
        failed = _failed_active_dhcp_self_heal(db, cluster, first)

        retried = start_dhcp_self_heal(db, cluster, force_retry=True, requested_by=user)

        assert retried is not None
        assert retried.requested_by_user_id == user.id
        assert desired_maintenance_action(cluster, first)["action_type"] == "DHCP_PROMOTE"
        assert json.loads(failed.result_json)["latch_active"] is False
        assert json.loads(failed.result_json)["latch_cleared_reason"] == "administrator_retry"
        assert db.query(HAMaintenanceRun).filter(HAMaintenanceRun.operation == "DHCP_SELF_HEAL").count() == 2


def test_material_agent_change_allows_failed_repair_to_be_reconsidered():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.dhcp_configured = False
        first.agent_version = second.agent_version = "0.2.11"
        db.commit()
        failed = _failed_active_dhcp_self_heal(db, cluster, first)

        first.agent_version = "0.2.12"
        db.commit()
        watchdog_reconcile_cluster(db, cluster)

        assert active_maintenance(cluster) is not None
        assert json.loads(failed.result_json)["latch_active"] is False
        assert json.loads(failed.result_json)["latch_cleared_reason"] == "material_topology_change"


def test_independently_resolved_drift_clears_failed_repair_latch():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.dhcp_configured = False
        db.commit()
        failed = _failed_active_dhcp_self_heal(db, cluster, first)

        first.dhcp_configured = True
        first.last_heartbeat_at = first.dhcp_observed_at = datetime.utcnow()
        second.last_heartbeat_at = second.dhcp_observed_at = datetime.utcnow()
        db.commit()
        watchdog_reconcile_cluster(db, cluster)

        assert active_maintenance(cluster) is None
        assert json.loads(failed.result_json)["latch_active"] is False
        assert reconcile_topology(cluster).configuration_state == "CONSISTENT"
        assert maintenance_status(failed)["visible"] is False


def test_self_heal_refuses_ambiguous_dual_dhcp_runtime():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.dhcp_configured = False
        second.dhcp_configured = True
        second.dhcp_running = True
        second.dhcp_listener_active = True
        second.dhcp_runtime_state = "RUNNING"
        db.commit()

        assert start_dhcp_self_heal(db, cluster) is None
        assert not cluster.maintenance_mode


def test_self_heal_refuses_agents_without_bounded_dhcp_repair_capability():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.agent_version = "0.2.7"
        first.dhcp_configured = False
        first.dhcp_running = True
        first.dhcp_listener_active = True
        first.dhcp_runtime_state = "RUNNING"
        db.commit()

        watchdog_reconcile_cluster(db, cluster)

        assert active_maintenance(cluster) is None
        assert first.vip_owned is True and second.vip_owned is False
        assert cluster.maintenance_mode is False


def test_proven_hard_failover_can_repair_surviving_owner_with_peer_offline():
    with database() as db:
        user, cluster, first, second = pair(db)
        now = datetime.utcnow()
        first.dhcp_configured = False
        first.dhcp_running = False
        first.dhcp_listener_active = False
        first.dhcp_runtime_state = "STOPPED"
        second.last_heartbeat_at = now - timedelta(minutes=2)
        second.dhcp_observed_at = second.last_heartbeat_at
        db.add(HAEvent(
            cluster_id=cluster.id,
            node_id=first.id,
            event_type="automatic_failover_completed",
            severity="warning",
            source="agent",
            message="Synthetic local failover proof.",
            details_json_redacted=json.dumps({"generation": cluster.keepalived_generation}),
            agent_event_id="synthetic-hard-failover-proof",
            occurred_at=now,
        ))
        db.commit()

        run = start_dhcp_self_heal(db, cluster)

        assert run is not None
        assert desired_maintenance_action(cluster, first)["action_type"] == "DHCP_PROMOTE"


def test_offline_peer_without_signed_failover_proof_blocks_self_heal():
    with database() as db:
        user, cluster, first, second = pair(db)
        first.dhcp_configured = False
        first.dhcp_running = False
        first.dhcp_listener_active = False
        first.dhcp_runtime_state = "STOPPED"
        second.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=2)
        second.dhcp_observed_at = second.last_heartbeat_at
        db.commit()

        assert start_dhcp_self_heal(db, cluster) is None
