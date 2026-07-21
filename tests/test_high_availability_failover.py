from datetime import datetime

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import HACluster, HALeaseReplicationState, HANode, User
from app.services.ha_failover import HAFailoverError, advance_failover, desired_failover_action, failover_readiness, start_controlled_failover


def database():
    engine = create_engine("sqlite:///:memory:")
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record): connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    return Session(engine)


def ready_pair(db, *, managed=True):
    user = User(email="failover@example.test", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(name="Test Pair", provider_key="pihole", status="HEALTHY", virtual_ip="192.168.50.53", prefix_length=24, keepalived_status="DEPLOYED", keepalived_generation=4)
    db.add_all([user, cluster]); db.flush()
    source = HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="http://192.168.50.2", role="ACTIVE", desired_role="ACTIVE", vip_owned=True, dhcp_running=managed, dns_healthy=True, keepalived_status="DEPLOYED", keepalived_runtime_state="RUNNING", config_generation=4, lease_generation=7, agent_version="0.1.4", last_heartbeat_at=datetime.utcnow())
    target = HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="http://192.168.50.3", role="STANDBY", desired_role="STANDBY", vip_owned=False, dhcp_running=False, dns_healthy=True, keepalived_status="DEPLOYED", keepalived_runtime_state="RUNNING", config_generation=4, lease_generation=7, agent_version="0.1.4", last_heartbeat_at=datetime.utcnow())
    db.add_all([source, target]); db.flush()
    cluster.current_active_node_id = cluster.authoritative_node_id = source.id
    db.add(HALeaseReplicationState(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="CURRENT" if managed else "NOT_APPLICABLE", desired_generation=7 if managed else 0, applied_generation=7 if managed else 0))
    db.commit()
    return user, cluster, source, target


def test_preflight_requires_current_agent_and_exactly_one_dhcp_owner():
    with database() as db:
        _, cluster, source, target = ready_pair(db)
        assert failover_readiness(cluster).ready
        target.agent_version = "0.1.3"
        assert "agent 0.1.4" in " ".join(failover_readiness(cluster).blockers)
        target.agent_version = "0.1.4"; target.dhcp_running = True
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
