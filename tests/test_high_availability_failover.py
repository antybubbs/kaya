from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import HACluster, HAFailoverRun, HALeaseReplicationState, HANode, User
from app.services.ha_failover import HAFailoverError, advance_failover, automatic_failover_blockers, desired_failover_action, failover_readiness, request_failover_rollback, set_automatic_failover, start_controlled_failover


def database():
    engine = create_engine("sqlite:///:memory:")
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record): connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    return Session(engine)


def ready_pair(db, *, managed=True):
    user = User(email="failover@example.test", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(name="Test Pair", provider_key="pihole", deployment_mode="DNS_DHCP" if managed else "DNS_ONLY", status="HEALTHY", virtual_ip="192.168.50.53", prefix_length=24, keepalived_status="DEPLOYED", keepalived_generation=4)
    db.add_all([user, cluster]); db.flush()
    source = HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="http://192.168.50.2", role="ACTIVE", desired_role="ACTIVE", vip_owned=True, dhcp_running=managed, dns_healthy=True, keepalived_status="DEPLOYED", keepalived_runtime_state="RUNNING", config_generation=4, lease_generation=7, agent_version="0.1.5", last_heartbeat_at=datetime.utcnow())
    target = HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="http://192.168.50.3", role="STANDBY", desired_role="STANDBY", vip_owned=False, dhcp_running=False, dns_healthy=True, keepalived_status="DEPLOYED", keepalived_runtime_state="RUNNING", config_generation=4, lease_generation=7, agent_version="0.1.5", last_heartbeat_at=datetime.utcnow())
    db.add_all([source, target]); db.flush()
    cluster.current_active_node_id = cluster.authoritative_node_id = source.id
    db.add(HALeaseReplicationState(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="CURRENT" if managed else "NOT_APPLICABLE", desired_generation=7 if managed else 0, applied_generation=7 if managed else 0))
    db.commit()
    return user, cluster, source, target


def test_preflight_requires_current_agent_and_exactly_one_dhcp_owner():
    with database() as db:
        _, cluster, source, target = ready_pair(db)
        assert failover_readiness(cluster).ready
        target.agent_version = "0.1.4"
        assert "agent 0.1.5" in " ".join(failover_readiness(cluster).blockers)
        target.agent_version = "0.1.5"; target.dhcp_running = True
        assert "Exactly the current VIP owner" in " ".join(failover_readiness(cluster).blockers)


def test_managed_failover_orders_dhcp_stop_vip_move_then_dhcp_start(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        with pytest.raises(HAFailoverError, match="Type Test Pair"):
            start_controlled_failover(db, cluster, target, user, confirmation="wrong", acknowledged=True)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        assert run.phase == "DEMOTING_SOURCE"
        assert desired_failover_action(cluster, source)["action_type"] == "DHCP_DEMOTE"
        assert desired_failover_action(cluster, target) is None

        action = desired_failover_action(cluster, source)
        from app.services.ha_failover import record_failover_action_result
        record_failover_action_result(db, source, action_type="DHCP_DEMOTE", generation=action["generation"], checksum=action["checksum"], status="APPLIED", message="stopped")
        assert run.phase == "MOVING_VIP" and source.dhcp_running is False
        assert desired_failover_action(cluster, target) is None

        for node in cluster.nodes: node.keepalived_status = "DEPLOYED"
        source.vip_owned = False; target.vip_owned = True
        advance_failover(db, cluster)
        assert run.phase == "PROMOTING_TARGET"
        action = desired_failover_action(cluster, target)
        record_failover_action_result(db, target, action_type="DHCP_PROMOTE", generation=action["generation"], checksum=action["checksum"], status="APPLIED", message="started")
        advance_failover(db, cluster)
        assert run.status == "SUCCEEDED"
        assert cluster.current_active_node_id == target.id
        assert target.dhcp_running and not source.dhcp_running
        assert cluster.automatic_failback_enabled is False


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


def test_live_failover_page_can_reveal_failure_and_rollback_without_reload():
    template = Path("app/templates/high_availability_cluster_testing.html").read_text(encoding="utf-8")
    script = Path("app/static/js/ha_live.js").read_text(encoding="utf-8")

    assert "data-ha-failover-diagnostic" in template
    assert "data-ha-failover-error" in template
    assert "data-ha-failover-rollback" in template
    assert 'data.failover.status !== "FAILED_SAFE"' in script
    assert "data.failover.error" in script


def test_unhealthy_dns_cannot_complete_promotion(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        run.phase = "VERIFYING_TARGET"
        run.report_json = '{"verification_started_at":"2020-01-01T00:00:00"}'
        source.dhcp_running = False; source.vip_owned = False
        target.dhcp_running = True; target.vip_owned = True; target.dns_healthy = False

        advance_failover(db, cluster)

        assert run.status == "FAILED_SAFE"
        assert "did not report healthy DNS" in run.error_redacted


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


def test_completed_failover_can_return_safely_if_promoted_dns_later_fails(monkeypatch):
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        monkeypatch.setattr("app.services.ha_failover.reconcile_cluster_leases", lambda db, cluster: cluster.lease_replication)
        run = start_controlled_failover(db, cluster, target, user, confirmation="Test Pair", acknowledged=True)
        run.status = "SUCCEEDED"; run.phase = "COMPLETE"
        source.vip_owned = False; source.dhcp_running = False; source.dns_healthy = True
        target.vip_owned = True; target.dhcp_running = True; target.dns_healthy = False
        db.commit()

        request_failover_rollback(db, run, acknowledged=True)

        assert run.status == "ROLLING_BACK"
        assert run.phase == "ROLLBACK_DEMOTING_TARGET"
        assert desired_failover_action(cluster, target)["action_type"] == "DHCP_DEMOTE"


def test_automatic_failover_requires_current_agents_and_successful_controlled_test():
    with database() as db:
        user, cluster, source, target = ready_pair(db)
        assert "successful controlled failover" in " ".join(automatic_failover_blockers(cluster))
        source.agent_version = target.agent_version = "0.2.1"
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
