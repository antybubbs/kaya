from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import Base
from app.models.models import (
    HACluster,
    HAFailoverRun,
    HALeaseReplicationState,
    HANode,
    NotificationCategoryPolicy,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationPreference,
    PushSubscription,
    RemoteManagerSetting,
    User,
    UserModulePermission,
    UserNotification,
)
from app.services.ha_dhcp_safety import authorise_dhcp_demotion
from app.services.ha_failover import HAFailoverError, advance_failover, automatic_failover_blockers, desired_failover_action, failover_readiness, failover_status, record_failover_action_result, request_failover_rollback, set_automatic_failover, start_controlled_failover
from app.services.notification_outbox import process_outbox


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def ready_pair(db, *, managed=True):
    user = User(email="failover@example.test", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(name="Test Pair", provider_key="pihole", deployment_mode="DNS_DHCP" if managed else "DNS_ONLY", status="HEALTHY", virtual_ip="192.168.50.53", prefix_length=24, keepalived_status="DEPLOYED", keepalived_generation=4)
    db.add_all([user, cluster])
    db.flush()
    now = datetime.utcnow()
    source = HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="http://192.168.50.2", role="ACTIVE", desired_role="ACTIVE", vip_owned=True, dhcp_running=managed, dhcp_configured=managed, dhcp_listener_active=managed, ftl_active=True, dhcp_runtime_state="RUNNING" if managed else "STOPPED", dhcp_observation_status="FRESH", dhcp_observed_at=now, dns_healthy=True, keepalived_status="DEPLOYED", keepalived_runtime_state="RUNNING", config_generation=4, lease_generation=7, agent_version="0.2.13", last_heartbeat_at=now)
    target = HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="http://192.168.50.3", role="STANDBY", desired_role="STANDBY", vip_owned=False, dhcp_running=False, dhcp_configured=False, dhcp_listener_active=False, ftl_active=True, dhcp_runtime_state="STOPPED", dhcp_observation_status="FRESH", dhcp_observed_at=now, dns_healthy=True, keepalived_status="DEPLOYED", keepalived_runtime_state="RUNNING", config_generation=4, lease_generation=7, agent_version="0.2.13", last_heartbeat_at=now)
    db.add_all([source, target])
    db.flush()
    cluster.current_active_node_id = cluster.authoritative_node_id = cluster.preferred_node_id = source.id
    db.add(HALeaseReplicationState(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="CURRENT" if managed else "NOT_APPLICABLE", desired_generation=7 if managed else 0, applied_generation=7 if managed else 0))
    db.commit()
    return user, cluster, source, target


def observe_dhcp(node, running: bool):
    now = datetime.utcnow()
    node.dhcp_running = running
    node.dhcp_configured = running
    node.dhcp_listener_active = running
    node.ftl_active = True
    node.dhcp_runtime_state = "RUNNING" if running else "STOPPED"
    node.dhcp_observation_status = "FRESH"
    node.dhcp_observed_at = now
    node.last_heartbeat_at = now


def enable_ha_notifications(db, recipient, event_types):
    db.add(UserModulePermission(user_id=recipient.id, module_key="high_availability", allowed=True, created_by=recipient.id))
    db.add_all([
        RemoteManagerSetting(key="high_availability_enabled", value="1"),
        RemoteManagerSetting(key="notifications_push_enabled", value="1"),
        RemoteManagerSetting(key="notifications_email_enabled", value="1"),
        PushSubscription(
            user_id=recipient.id,
            endpoint_hash="a" * 64,
            encrypted_subscription="clearly-fake-encrypted-subscription",
            status="active",
        ),
    ])
    for identifier in event_types:
        db.add(NotificationCategoryPolicy(
            event_type=identifier,
            enabled=True,
            in_app_allowed=True,
            push_allowed=True,
            email_allowed=True,
            default_enabled=True,
        ))
        db.add(NotificationPreference(
            user_id=recipient.id,
            event_type=identifier,
            in_app_enabled=True,
            push_enabled=True,
            email_enabled=True,
        ))
    db.commit()


def test_controlled_failover_publishes_each_lifecycle_stage_once_with_channel_diagnostics(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        excluded_admin = User(email="excluded@example.test", password_hash="x", role="admin", is_active=True)
        db.add(excluded_admin)
        db.flush()
        enable_ha_notifications(db, user, {"pihole.failover.started", "pihole.failover.completed"})
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)

        run = start_controlled_failover(db, cluster, target, user, confirmation=cluster.name, acknowledged=True)
        source.vip_owned = False
        observe_dhcp(source, False)
        target.vip_owned = True
        observe_dhcp(target, True)
        advance_failover(db, cluster)
        advance_failover(db, cluster)
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()

        events = db.query(NotificationEvent).filter_by(correlation_id=run.public_id).order_by(NotificationEvent.id).all()
        assert [event.event_type for event in events] == ["pihole.failover.started", "pihole.failover.completed"]
        assert all(db.query(UserNotification).filter_by(notification_event_id=event.id, user_id=user.id).count() == 1 for event in events)
        assert all(db.query(UserNotification).filter_by(notification_event_id=event.id, user_id=excluded_admin.id).count() == 1 for event in events)
        for event in events:
            notification = db.query(UserNotification).filter_by(notification_event_id=event.id, user_id=user.id).one()
            assert {row.channel for row in db.query(NotificationDeliveryAttempt).filter_by(user_notification_id=notification.id)} == {"push", "email"}
        diagnostics = failover_status(run, db=db)["notifications"]
        assert diagnostics["started"]["delivery"]["push"]["queued"] == 1
        assert diagnostics["completed"]["delivery"]["email"]["queued"] == 2


def test_notification_failure_does_not_roll_back_failover_state(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        monkeypatch.setattr("app.services.ha_notifications.enqueue_notification", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic notification failure")))

        run = start_controlled_failover(db, cluster, target, user, confirmation=cluster.name, acknowledged=True)
        assert run.status == "RUNNING"
        assert failover_status(run)["notifications"]["started"] == {
            "event_type": "pihole.failover.started",
            "status": "failed",
            "reason": "publication_error",
        }
        source.vip_owned = False
        observe_dhcp(source, False)
        target.vip_owned = True
        observe_dhcp(target, True)
        advance_failover(db, cluster)
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()
        assert db.get(HAFailoverRun, run.id).status == "SUCCEEDED"


def test_failed_controlled_failover_publishes_failure_and_degraded_events(monkeypatch):
    with database() as db:
        user, cluster, _source, target = ready_pair(db, managed=False)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation=cluster.name, acknowledged=True)

        # Simulate discovering that a legacy DNS-only transition was actually
        # operating a Pi-hole-managed DHCP topology. The state machine fails safe.
        cluster.deployment_mode = "DNS_DHCP"
        advance_failover(db, cluster)
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()

        assert run.status == "FAILED_SAFE"
        event_types = {
            row.event_type
            for row in db.query(NotificationEvent).filter_by(correlation_id=run.public_id)
        }
        assert {"pihole.failover.failed", "pihole.cluster.degraded"} <= event_types
        assert failover_status(run, db=db)["notifications"]["failed"]["status"] == "created"
        assert failover_status(run, db=db)["notifications"]["cluster_degraded"]["status"] == "created"


def test_preflight_requires_current_agent_and_exactly_one_dhcp_owner():
    with database() as db:
        _, cluster, source, target = ready_pair(db)
        assert failover_readiness(cluster).ready
        target.agent_version = "0.2.12"
        assert "agent 0.2.13" in " ".join(failover_readiness(cluster).blockers)
        target.agent_version = "0.2.13"
        target.dhcp_running = target.dhcp_configured = target.dhcp_listener_active = True
        target.dhcp_runtime_state = "RUNNING"
        assert "Exactly the current VIP owner" in " ".join(failover_readiness(cluster).blockers)


def test_managed_failover_orders_dhcp_stop_vip_move_then_dhcp_start(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        with pytest.raises(HAFailoverError, match="Type Test Pair"):
            start_controlled_failover(db, cluster, target, user, confirmation="wrong", acknowledged=True)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        assert run.source_node_id == source.id
        assert run.target_node_id == target.id
        assert run.preferred_node_id == source.id
        assert run.phase == "DEMOTING_SOURCE"
        assert desired_failover_action(cluster, source)["action_type"] == "DHCP_DEMOTE"
        assert desired_failover_action(cluster, target) is None

        action = desired_failover_action(cluster, source)
        from app.services.ha_failover import record_failover_action_result
        record_failover_action_result(db, source, action_type="DHCP_DEMOTE", generation=action["generation"], checksum=action["checksum"], status="APPLIED", message="stopped")
        assert run.phase == "VERIFYING_SOURCE_DHCP_RELEASE"
        observe_dhcp(source, False)
        advance_failover(db, cluster)
        assert run.phase == "MOVING_VIP" and source.dhcp_running is False
        assert desired_failover_action(cluster, target) is None

        for node in cluster.nodes:
            node.keepalived_status = "DEPLOYED"
        source.vip_owned = False
        target.vip_owned = True
        advance_failover(db, cluster)
        assert run.phase == "PROMOTING_TARGET"
        action = desired_failover_action(cluster, target)
        record_failover_action_result(db, target, action_type="DHCP_PROMOTE", generation=action["generation"], checksum=action["checksum"], status="APPLIED", message="started")
        observe_dhcp(target, True)
        advance_failover(db, cluster)
        assert run.status == "SUCCEEDED"
        assert cluster.current_active_node_id == target.id
        assert target.dhcp_running and not source.dhcp_running
        assert cluster.automatic_failback_enabled is False
        assert cluster.keepalived_status == "PENDING_AGENT"
        assert all(node.keepalived_status == "PENDING_AGENT" for node in cluster.nodes)


def test_sole_dhcp_owner_cannot_be_demoted_by_routine_work():
    with database() as db:
        _, cluster, source, target = ready_pair(db)
        decision = authorise_dhcp_demotion(cluster, source, replacement=target, owner_handover=False)
        assert decision.allowed is False
        assert "Routine work" in decision.reason


def test_controlled_owner_demotion_waits_for_replacement_prerequisites(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)

        target.dns_healthy = False
        assert desired_failover_action(cluster, source) is None
        assert source.dhcp_running is True

        target.dns_healthy = True
        action = desired_failover_action(cluster, source)
        assert action["action_type"] == "DHCP_DEMOTE"
        assert action["owner_handover_authorised"] is True
        assert action["run_id"] == run.public_id


def test_agent_rejects_unverified_owner_demotion_and_accepts_bound_handover():
    from ha_agent.failover_runtime import FailoverRuntimeError, apply_failover_action

    class State:
        def __init__(self):
            self.values = {"vip_owned": True, "dhcp_running": True, "failover_generation": 0}

        def get(self, key, default=None):
            return self.values.get(key, default)

        def set(self, key, value):
            self.values[key] = value

    class Result:
        returncode = 0
        stderr = ""
        stdout = '{"status":"applied","configured":false,"listening":false,"service_active":true,"runtime_state":"STOPPED","observation_status":"FRESH","dhcp_running":false}'

    base = {
        "action_id": "failover:fake:dhcp_demote:node",
        "action_type": "DHCP_DEMOTE",
        "generation": 2,
        "checksum": "a" * 64,
        "automatic": False,
    }
    with pytest.raises(FailoverRuntimeError, match="sole owner"):
        apply_failover_action(State(), base, runner=lambda command: Result())

    result = apply_failover_action(
        State(),
        {**base, "run_id": "00000000-0000-0000-0000-000000000001", "owner_handover_authorised": True},
        runner=lambda command: Result(),
    )
    assert result["status"] == "APPLIED"


def test_transient_dhcp_release_error_continues_after_explicit_source_reports_release(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        action = desired_failover_action(cluster, source)

        record_failover_action_result(
            db,
            source,
            action_type="DHCP_DEMOTE",
            generation=action["generation"],
            checksum=action["checksum"],
            status="FAILED",
            message="Synthetic delayed UDP/67 release",
        )

        assert run.status == "RUNNING"
        assert run.phase == "VERIFYING_SOURCE_DHCP_RELEASE"
        observe_dhcp(source, False)
        advance_failover(db, cluster)
        assert run.phase == "MOVING_VIP"
        assert "Synthetic delayed UDP/67 release" in run.report_json


def test_transient_promotion_error_is_success_when_final_two_node_topology_is_verified(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        observe_dhcp(source, False)
        source.vip_owned = False
        target.vip_owned = True
        target.keepalived_status = source.keepalived_status = "DEPLOYED"
        run.phase = "PROMOTING_TARGET"
        action = desired_failover_action(cluster, target)

        record_failover_action_result(
            db,
            target,
            action_type="DHCP_PROMOTE",
            generation=action["generation"],
            checksum=action["checksum"],
            status="FAILED",
            message="Synthetic response timeout after apply",
        )
        observe_dhcp(target, True)
        target.dns_healthy = True
        advance_failover(db, cluster)

        assert run.status == "SUCCEEDED"
        assert cluster.current_active_node_id == target.id
        assert "Synthetic response timeout after apply" in run.report_json


def test_failback_repairs_false_dhcp_flag_when_runtime_and_vip_already_moved(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        observe_dhcp(source, False)
        source.vip_owned = False
        target.vip_owned = True
        target.dhcp_running = True
        target.dhcp_configured = False
        target.dhcp_listener_active = True
        target.ftl_active = True
        target.dhcp_runtime_state = "RUNNING"
        target.dhcp_observation_status = "FRESH"
        target.dhcp_observed_at = target.last_heartbeat_at = datetime.utcnow()
        run.phase = "VERIFYING_TARGET"
        run.report_json = '{"verification_started_at":"2020-01-01T00:00:00"}'
        db.commit()

        advance_failover(db, cluster)

        assert run.status == "RUNNING"
        assert run.phase == "PROMOTING_TARGET"
        repair = desired_failover_action(cluster, target)
        assert repair["action_type"] == "DHCP_PROMOTE"
        record_failover_action_result(db, target, action_type=repair["action_type"], generation=repair["generation"], checksum=repair["checksum"], status="APPLIED", message="configuration repaired")
        observe_dhcp(target, True)
        advance_failover(db, cluster)
        assert run.status == "SUCCEEDED"
        assert cluster.current_active_node_id == target.id


def test_final_verification_never_accepts_two_udp_67_listeners(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        run.phase = "VERIFYING_TARGET"
        run.report_json = '{"verification_started_at":"2020-01-01T00:00:00"}'
        source.vip_owned = False
        target.vip_owned = True
        observe_dhcp(source, True)
        observe_dhcp(target, True)

        advance_failover(db, cluster)

        assert run.status == "FAILED_SAFE"
        assert "current DHCP owners: Primary, Standby" in run.error_redacted


def test_external_dhcp_failover_never_emits_dhcp_action():
    with database() as db:
        user, cluster, source, target = ready_pair(db, managed=False)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        assert run.phase == "MOVING_VIP"
        assert desired_failover_action(cluster, source) is None
        assert desired_failover_action(cluster, target) is None


def test_legacy_dns_only_misclassification_stops_for_safe_rollback():
    with database() as db:
        user, cluster, source, target = ready_pair(db, managed=False)
        cluster.deployment_mode = None
        source.dhcp_running = True
        run = HAFailoverRun(
            cluster_id=cluster.id,
            source_node_id=source.id,
            target_node_id=target.id,
            status="RUNNING",
            phase="MOVING_VIP",
            dhcp_managed=False,
            lease_generation=0,
            role_generation=cluster.role_generation,
            requested_by_user_id=user.id,
        )
        db.add(run)
        db.commit()

        advance_failover(db, cluster)

        assert run.status == "FAILED_SAFE"
        assert run.dhcp_managed is True
        assert "started as DNS-only" in run.error_redacted


def test_virtual_ip_move_times_out_with_actionable_status():
    with database() as db:
        user, cluster, source, target = ready_pair(db, managed=False)
        run = HAFailoverRun(
            cluster_id=cluster.id,
            source_node_id=source.id,
            target_node_id=target.id,
            status="RUNNING",
            phase="MOVING_VIP",
            dhcp_managed=False,
            lease_generation=0,
            role_generation=cluster.role_generation,
            requested_by_user_id=user.id,
            started_at=datetime.utcnow() - timedelta(seconds=61),
        )
        source.vip_owned = True
        target.vip_owned = False
        source.keepalived_status = "DEPLOYED"
        target.keepalived_status = "PENDING_AGENT"
        db.add(run)
        db.commit()

        advance_failover(db, cluster)

        assert run.status == "FAILED_SAFE"
        assert "did not converge within 60 seconds" in run.error_redacted
        assert "Primary: deployed" in run.error_redacted
        assert "Standby: pending agent" in run.error_redacted


def test_vip_timeout_automatically_restores_dhcp_when_original_owner_is_exclusive():
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        source.dhcp_running = False
        run = HAFailoverRun(
            cluster_id=cluster.id,
            source_node_id=source.id,
            target_node_id=target.id,
            status="RUNNING",
            phase="MOVING_VIP",
            dhcp_managed=True,
            lease_generation=7,
            role_generation=cluster.role_generation,
            requested_by_user_id=user.id,
            started_at=datetime.utcnow() - timedelta(seconds=61),
        )
        source.vip_owned = True
        target.vip_owned = False
        source.keepalived_status = target.keepalived_status = "DEPLOYED"
        db.add(run)
        db.commit()

        advance_failover(db, cluster)

        assert run.status == "ROLLING_BACK"
        assert run.phase == "ROLLBACK_PROMOTING_SOURCE"
        assert desired_failover_action(cluster, source)["action_type"] == "DHCP_PROMOTE"


def test_vip_timeout_does_not_restore_dhcp_when_ownership_is_ambiguous():
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        source.dhcp_running = False
        source.vip_owned = target.vip_owned = True
        run = HAFailoverRun(
            cluster_id=cluster.id,
            source_node_id=source.id,
            target_node_id=target.id,
            status="RUNNING",
            phase="MOVING_VIP",
            dhcp_managed=True,
            lease_generation=7,
            role_generation=cluster.role_generation,
            requested_by_user_id=user.id,
            started_at=datetime.utcnow() - timedelta(seconds=61),
        )
        source.keepalived_status = target.keepalived_status = "DEPLOYED"
        db.add(run)
        db.commit()

        advance_failover(db, cluster)

        assert run.status == "FAILED_SAFE"
        assert desired_failover_action(cluster, source) is None


def test_live_failover_page_can_reveal_failure_and_rollback_without_reload():
    template = Path("app/templates/high_availability_cluster_testing.html").read_text(encoding="utf-8")
    script = Path("app/static/js/ha_live.js").read_text(encoding="utf-8")

    assert "data-ha-failover-diagnostic" in template
    assert "data-ha-failover-error" in template
    assert "data-ha-failover-warning-message" in template
    assert "data-ha-failover-rollback" in template
    assert 'data.failover.status !== "FAILED_SAFE"' in script
    assert "data.failover.error" in script
    assert "data.failover.warnings" in script


def test_unhealthy_dns_cannot_complete_promotion(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        run.phase = "VERIFYING_TARGET"
        run.report_json = '{"verification_started_at":"2020-01-01T00:00:00"}'
        source.dhcp_running = False
        source.vip_owned = False
        target.dhcp_running = True
        target.vip_owned = True
        target.dns_healthy = False

        advance_failover(db, cluster)

        assert run.status == "FAILED_SAFE"
        assert "healthy DNS" in run.error_redacted


def test_lease_replacement_preserves_service_ownership_and_mode(tmp_path, monkeypatch):
    import os
    from ha_agent import kaya_ha_failover_helper as helper

    lease_file = tmp_path / "dhcp.leases"
    lease_file.write_text("old\n", encoding="utf-8")
    os.chmod(lease_file, 0o640)
    before = lease_file.stat()
    service_owner = (before.st_uid, before.st_gid, 0o640)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda name: type("User", (), {"pw_uid": service_owner[0]})())
    monkeypatch.setattr(helper.grp, "getgrnam", lambda name: type("Group", (), {"gr_gid": service_owner[1]})())

    helper._atomic_write(lease_file, "new\n")

    after = lease_file.stat()
    assert lease_file.read_text(encoding="utf-8") == "new\n"
    assert (after.st_uid, after.st_gid, after.st_mode & 0o777) == service_owner


def test_configuration_only_dhcp_repair_never_reads_or_replaces_live_leases(tmp_path, monkeypatch, capsys):
    from ha_agent import kaya_ha_failover_helper as helper

    monkeypatch.setattr(helper, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(helper, "LOCK_FILE", tmp_path / "dhcp.lock")
    monkeypatch.setattr(helper.sys, "argv", ["helper", "promote", "7"])
    values = {
        "failover_generation": 7,
        "failover_configuration_only": True,
        "dns_healthy": True,
    }
    monkeypatch.setattr(helper, "_state", lambda key, default=None: values.get(key, default))
    monkeypatch.setattr(helper, "_owns_vip", lambda: True)
    monkeypatch.setattr(
        helper,
        "_backup",
        lambda generation: pytest.fail("configuration-only repair must not access the lease file"),
    )
    expected = {
        "configured": True,
        "service_active": True,
        "listening": True,
        "runtime_state": "RUNNING",
        "observation_status": "FRESH",
        "dhcp_running": True,
    }
    monkeypatch.setattr(helper, "_set_dhcp", lambda enabled: expected)
    monkeypatch.setattr(helper, "_wait_for_dns", lambda: None)

    helper.main()

    output = __import__("json").loads(capsys.readouterr().out)
    assert output == {"status": "applied", **expected, "backup_reference": None}


def test_dhcp_status_requires_the_service_and_udp_67_listener(tmp_path, monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    udp = tmp_path / "udp"
    udp.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        "  12: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1\n",
        encoding="ascii",
    )
    monkeypatch.setattr(helper, "PROC_UDP", (udp,))
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "dhcp.active = true" if command[0] == helper.FTL else "active\n",
            },
        )(),
    )

    status = helper._dhcp_status()

    assert status == {
        "configured": True,
        "service_active": True,
        "listening": True,
        "runtime_state": "RUNNING",
        "observation_status": "FRESH",
        "dhcp_running": True,
    }


def test_dhcp_status_does_not_treat_config_flag_as_runtime_health(tmp_path, monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    udp = tmp_path / "udp"
    udp.write_text("  sl  local_address rem_address st\n", encoding="ascii")
    monkeypatch.setattr(helper, "PROC_UDP", (udp,))
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "dhcp.active = true" if command[0] == helper.FTL else "active\n",
            },
        )(),
    )

    status = helper._dhcp_status()

    assert status["configured"] is True
    assert status["service_active"] is True
    assert status["listening"] is False
    assert status["dhcp_running"] is False


def test_dhcp_status_reports_real_runtime_when_configuration_flag_drifted_false(tmp_path, monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    udp = tmp_path / "udp"
    udp.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        "  12: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1\n",
        encoding="ascii",
    )
    monkeypatch.setattr(helper, "PROC_UDP", (udp,))
    monkeypatch.setattr(helper, "_run", lambda command: type("Result", (), {
        "returncode": 0,
        "stdout": "dhcp.active = false" if command[0] == helper.FTL else "active\n",
    })())

    status = helper._dhcp_status()

    assert status["configured"] is False
    assert status["dhcp_running"] is True
    assert status["runtime_state"] == "RUNNING"
    assert "configuration_consistency" not in status


def test_agent_reports_dhcp_configuration_listener_and_ftl_separately():
    from ha_agent.failover_runtime import refresh_dhcp_state

    values = {}
    state = type("State", (), {"set": lambda self, key, value: values.__setitem__(key, value)})()
    result = type("Result", (), {
        "returncode": 0,
        "stdout": '{"configured":true,"service_active":true,"listening":false,"runtime_state":"STOPPED","observation_status":"FRESH","dhcp_running":false}',
    })()

    refresh_dhcp_state(state, runner=lambda command: result)

    assert values == {
        "dhcp_configured": True,
        "dhcp_listener_active": False,
        "ftl_active": True,
        "dhcp_runtime_state": "STOPPED",
        "dhcp_observation_status": "FRESH",
        "dhcp_observed_at": values["dhcp_observed_at"],
        "dhcp_running": False,
    }


def test_agent_preserves_last_runtime_boolean_when_dhcp_probe_is_unavailable():
    from ha_agent.failover_runtime import refresh_dhcp_state

    values = {"dhcp_running": True}
    state = type("State", (), {
        "get": lambda self, key, default=None: values.get(key, default),
        "set": lambda self, key, value: values.__setitem__(key, value),
    })()
    result = type("Result", (), {
        "returncode": 0,
        "stdout": '{"configured":null,"service_active":null,"listening":null,"runtime_state":"UNKNOWN","observation_status":"UNAVAILABLE","dhcp_running":null}',
    })()

    refresh_dhcp_state(state, runner=lambda command: result)

    assert values["dhcp_running"] is True
    assert values["dhcp_runtime_state"] == "UNKNOWN"
    assert values["dhcp_observation_status"] == "UNAVAILABLE"
    assert values["dhcp_configured"] is None
    assert values["dhcp_listener_active"] is None


def test_dhcp_promotion_fails_closed_when_udp_67_never_starts(monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    monkeypatch.setattr(helper.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        helper,
        "_dhcp_status",
        lambda: {
            "configured": True,
            "service_active": True,
            "listening": False,
            "dhcp_running": False,
        },
    )

    with pytest.raises(RuntimeError, match="UDP port 67"):
        helper._wait_for_dhcp(True)


def test_dhcp_promotion_requires_configured_true_even_when_udp_67_is_already_listening(monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    monkeypatch.setattr(helper.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        helper,
        "_dhcp_status",
        lambda: {
            "configured": False,
            "service_active": True,
            "listening": True,
            "runtime_state": "RUNNING",
            "observation_status": "FRESH",
            "dhcp_running": True,
        },
    )

    with pytest.raises(RuntimeError, match="did not start serving"):
        helper._wait_for_dhcp(True)


def test_dhcp_promotion_succeeds_only_with_enabled_running_postconditions(monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    expected = {
        "configured": True,
        "service_active": True,
        "listening": True,
        "runtime_state": "RUNNING",
        "observation_status": "FRESH",
        "dhcp_running": True,
    }
    monkeypatch.setattr(helper, "_dhcp_status", lambda: expected)

    assert helper._wait_for_dhcp(True) == expected


def test_dhcp_demotion_succeeds_only_when_configuration_and_udp_67_are_stopped(monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    expected = {
        "configured": False,
        "service_active": True,
        "listening": False,
        "runtime_state": "STOPPED",
        "observation_status": "FRESH",
        "dhcp_running": False,
    }
    monkeypatch.setattr(helper, "_dhcp_status", lambda: expected)

    assert helper._wait_for_dhcp(False) == expected


def test_dhcp_demotion_rejects_udp_67_still_listening(monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    monkeypatch.setattr(helper.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(helper, "_dhcp_status", lambda: {
        "configured": False,
        "service_active": True,
        "listening": True,
        "runtime_state": "RUNNING",
        "observation_status": "FRESH",
        "dhcp_running": True,
    })

    with pytest.raises(RuntimeError, match="still in use"):
        helper._wait_for_dhcp(False)


def test_standby_disabled_and_not_listening_is_reported_as_factual_safe_state(tmp_path, monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    udp = tmp_path / "udp"
    udp.write_text("  sl  local_address rem_address st\n", encoding="ascii")
    monkeypatch.setattr(helper, "PROC_UDP", (udp,))
    monkeypatch.setattr(helper, "_run", lambda command: type("Result", (), {
        "returncode": 0,
        "stdout": "dhcp.active = false" if command[0] == helper.FTL else "active\n",
    })())

    status = helper._dhcp_status()

    assert status["configured"] is False
    assert status["listening"] is False
    assert status["runtime_state"] == "STOPPED"
    assert status["dhcp_running"] is False
    assert "configuration_consistency" not in status


def test_completed_failover_can_return_safely_if_promoted_dns_later_fails(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        run.status = "SUCCEEDED"
        run.phase = "COMPLETE"
        source.vip_owned = False
        source.dhcp_running = False
        source.dns_healthy = True
        target.vip_owned = True
        target.dhcp_running = True
        target.dns_healthy = False
        db.commit()

        request_failover_rollback(db, run, acknowledged=True)

        assert run.status == "ROLLING_BACK"
        assert run.phase == "ROLLBACK_DEMOTING_TARGET"
        assert desired_failover_action(cluster, target)["action_type"] == "DHCP_DEMOTE"


def test_failed_vip_move_rolls_back_to_existing_owner_and_restores_dhcp(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        cluster.vrrp_router_id = 51
        for address, node in zip(("192.168.50.2", "192.168.50.3"), (source, target)):
            node.management_host = address
            node.network_interface = "eth0"
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        from app.services.ha_failover import record_failover_action_result
        demote = desired_failover_action(cluster, source)
        record_failover_action_result(db, source, action_type="DHCP_DEMOTE", generation=demote["generation"], checksum=demote["checksum"], status="APPLIED", message="stopped")
        observe_dhcp(source, False)
        advance_failover(db, cluster)
        run.report_json = '{"vip_move_started_at":"2020-01-01T00:00:00"}'
        for node in cluster.nodes:
            node.keepalived_status = "DEPLOYED"
        advance_failover(db, cluster)
        assert run.status == "ROLLING_BACK"
        assert run.phase == "ROLLBACK_PROMOTING_SOURCE"
        assert source.vip_owned and not source.dhcp_running

        promote = desired_failover_action(cluster, source)
        record_failover_action_result(db, source, action_type="DHCP_PROMOTE", generation=promote["generation"], checksum=promote["checksum"], status="APPLIED", message="started")
        observe_dhcp(source, True)
        advance_failover(db, cluster)

        assert run.status == "ROLLED_BACK"
        assert source.vip_owned and source.dhcp_running
        assert not target.vip_owned and not target.dhcp_running
        assert cluster.keepalived_status == "PENDING_AGENT"


def test_in_progress_rollback_skips_vip_redeployment_when_source_still_owns_it():
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        observe_dhcp(source, False)
        run = HAFailoverRun(
            cluster_id=cluster.id,
            source_node_id=source.id,
            target_node_id=target.id,
            status="ROLLING_BACK",
            phase="ROLLBACK_DEMOTING_TARGET",
            dhcp_managed=True,
            lease_generation=7,
            role_generation=3,
            requested_by_user_id=user.id,
        )
        db.add(run)
        db.commit()

        advance_failover(db, cluster)

        assert run.phase == "ROLLBACK_PROMOTING_SOURCE"
        assert desired_failover_action(cluster, source)["action_type"] == "DHCP_PROMOTE"


def test_automatic_failover_requires_current_agents_and_successful_controlled_test():
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        assert "successful controlled failover" in " ".join(automatic_failover_blockers(cluster))
        source.agent_version = target.agent_version = "0.2.13"
        db.add(HAFailoverRun(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="SUCCEEDED", phase="COMPLETE", dhcp_managed=True, lease_generation=7, role_generation=2, requested_by_user_id=user.id))
        db.commit()
        assert automatic_failover_blockers(cluster) == []
        set_automatic_failover(db, cluster, enabled=True, confirmation="Test Pair", acknowledged=True)
        assert cluster.automatic_failover_enabled is True
        assert cluster.automatic_failback_enabled is False
        assert cluster.keepalived_status == "PENDING_AGENT"
        assert all(node.keepalived_status == "PENDING_AGENT" for node in cluster.nodes)
        set_automatic_failover(db, cluster, enabled=False, confirmation="", acknowledged=False)
        assert cluster.automatic_failover_enabled is False
