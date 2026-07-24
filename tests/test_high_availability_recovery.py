from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import (
    HAAgentCredential,
    HACluster,
    HALeaseReplicationState,
    HANode,
    HASyncRun,
    User,
)
from app.services.ha_failover import HAFailoverError, failover_status, start_controlled_failover
from app.services.ha_recovery import evaluate_recovery, peer_diagnostic, preferred_node


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def recovered_pair(db: Session, now: datetime):
    user = User(email="recovery@example.test", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(
        name="Recovery Pair",
        provider_key="pihole",
        deployment_mode="DNS_DHCP",
        status="HEALTHY",
        virtual_ip="192.0.2.53",
        prefix_length=24,
        keepalived_status="DEPLOYED",
        keepalived_generation=7,
        role_generation=3,
    )
    db.add_all([user, cluster])
    db.flush()
    preferred = HANode(
        cluster_id=cluster.id,
        display_name="Preferred",
        management_host="192.0.2.10",
        api_base_url="http://192.0.2.10",
        network_interface="eth0",
        role="STANDBY",
        desired_role="STANDBY",
        observed_role="STANDBY",
        observed_generation=3,
        vip_owned=False,
        dhcp_running=False,
        dns_healthy=True,
        peer_reachable=True,
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
        config_generation=7,
        lease_generation=11,
        agent_version="0.1.5",
        recovery_state="OFFLINE",
    )
    active = HANode(
        cluster_id=cluster.id,
        display_name="Current Active",
        management_host="192.0.2.11",
        api_base_url="http://192.0.2.11",
        network_interface="eth0",
        role="ACTIVE",
        desired_role="ACTIVE",
        observed_role="ACTIVE",
        observed_generation=3,
        vip_owned=True,
        dhcp_running=True,
        dns_healthy=True,
        peer_reachable=True,
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
        config_generation=7,
        lease_generation=11,
        agent_version="0.1.5",
        last_heartbeat_at=now,
    )
    db.add_all([preferred, active])
    db.flush()
    cluster.preferred_node_id = preferred.id
    cluster.current_active_node_id = cluster.authoritative_node_id = active.id
    db.add_all(
        [
            HAAgentCredential(
                node_id=preferred.id,
                agent_id="preferred-agent",
                public_key="fake-public-key-preferred",
                registered_at=now,
            ),
            HAAgentCredential(
                node_id=active.id,
                agent_id="active-agent",
                public_key="fake-public-key-active",
                registered_at=now,
            ),
            HALeaseReplicationState(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=preferred.id,
                status="CURRENT",
                desired_generation=11,
                applied_generation=11,
            ),
        ]
    )
    db.commit()
    return user, cluster, preferred, active


def test_recovered_node_advances_only_after_sync_and_stability():
    now = datetime.utcnow()
    with database() as db:
        _, cluster, recovered, active = recovered_pair(db, now)
        assert evaluate_recovery(db, cluster, now=now)[recovered.id].state == "OFFLINE"

        recovered.last_heartbeat_at = now + timedelta(seconds=1)
        db.commit()
        result = evaluate_recovery(db, cluster, now=now + timedelta(seconds=1))[recovered.id]
        assert result.state == "SYNCHRONISING"
        assert not result.ready

        db.add(
            HASyncRun(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=recovered.id,
                status="IN_SYNC",
                plan_json="{}",
                completed_at=now + timedelta(seconds=2),
            )
        )
        db.commit()
        assert evaluate_recovery(db, cluster, now=now + timedelta(seconds=2))[recovered.id].state == "VERIFYING"
        recovered.last_heartbeat_at = now + timedelta(seconds=63)
        active.last_heartbeat_at = now + timedelta(seconds=63)
        db.commit()
        ready = evaluate_recovery(db, cluster, now=now + timedelta(seconds=63))[recovered.id]
        assert ready.state == "STANDBY_READY"
        assert ready.ready


def test_dhcp_generation_mismatch_prevents_standby_ready():
    now = datetime.utcnow()
    with database() as db:
        _, cluster, recovered, active = recovered_pair(db, now)
        recovered.last_heartbeat_at = now
        recovered.lease_generation = 10
        db.add(
            HASyncRun(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=recovered.id,
                status="IN_SYNC",
                plan_json="{}",
            )
        )
        db.commit()
        result = evaluate_recovery(db, cluster, now=now)[recovered.id]
        assert result.state == "SYNCHRONISING"
        assert not next(check for check in result.checks if check.key == "lease_sync").passed


def test_controlled_failback_is_blocked_until_preferred_node_is_ready():
    now = datetime.utcnow()
    with database() as db:
        user, cluster, recovered, _ = recovered_pair(db, now)
        recovered.last_heartbeat_at = now
        db.commit()
        with pytest.raises(HAFailoverError, match="Controlled failback is not ready"):
            start_controlled_failover(
                db,
                cluster,
                recovered,
                user,
                confirmation=cluster.name,
                acknowledged=True,
            )


def test_ready_preferred_node_reuses_the_existing_controlled_transition(monkeypatch):
    now = datetime.utcnow()
    with database() as db:
        user, cluster, recovered, active = recovered_pair(db, now)
        recovered.last_heartbeat_at = now
        recovered.recovery_started_at = now - timedelta(minutes=2)
        recovered.recovery_stable_since = now - timedelta(seconds=61)
        recovered.recovery_state = "STANDBY_READY"
        db.add(
            HASyncRun(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=recovered.id,
                status="IN_SYNC",
                plan_json="{}",
                completed_at=now,
            )
        )
        db.commit()
        monkeypatch.setattr(
            "app.services.ha_failover.create_live_sync_plan",
            lambda db, cluster, user: SimpleNamespace(status="IN_SYNC"),
        )
        monkeypatch.setattr(
            "app.services.ha_failover.reconcile_cluster_leases",
            lambda db, cluster: cluster.lease_replication,
        )

        run = start_controlled_failover(
            db,
            cluster,
            recovered,
            user,
            confirmation=cluster.name,
            acknowledged=True,
        )

        assert run.phase == "DEMOTING_SOURCE"
        assert failover_status(run)["transition_kind"] == "FAILBACK"
        assert run.source_node_id == active.id
        assert run.target_node_id == recovered.id


def test_preferred_node_does_not_follow_current_active_role():
    now = datetime.utcnow()
    with database() as db:
        _, cluster, preferred, active = recovered_pair(db, now)
        preferred.role = preferred.desired_role = "STANDBY"
        active.role = active.desired_role = "ACTIVE"
        db.commit()
        assert preferred_node(cluster).id == preferred.id


def test_peer_diagnostic_reports_ping_dns_and_signed_heartbeat_independently():
    now = datetime.utcnow()
    with database() as db:
        _, _, node, peer = recovered_pair(db, now)
        node.last_peer_attempt_at = now
        node.peer_reachable = False
        node.last_peer_dns_attempt_at = now
        node.peer_dns_reachable = True
        diagnostic = peer_diagnostic(node, peer, now=now)
        assert diagnostic["status"] == "PING_UNAVAILABLE"
        assert diagnostic["display_label"] == "Ping unavailable"
        assert diagnostic["severity"] == "info"
        assert diagnostic["probe"] == "Optional ICMP ping"
        assert "informational" in diagnostic["explanation"]
        assert diagnostic["dns_status"] == "REACHABLE"
        assert diagnostic["dns_display_label"] == "DNS port 53 reachable"
        assert diagnostic["peer_kaya_status"] == "REPORTING"
        assert diagnostic["peer_kaya_display_label"] == "Reporting to Kaya"


def test_peer_diagnostic_reports_local_icmp_permission_failure_without_blaming_peer():
    now = datetime.utcnow()
    with database() as db:
        _, _, node, peer = recovered_pair(db, now)
        node.last_peer_attempt_at = now
        node.peer_reachable = None
        node.peer_icmp_probe_status = "UNAVAILABLE"

        diagnostic = peer_diagnostic(node, peer, now=now)

        assert diagnostic["status"] == "ICMP_PROBE_UNAVAILABLE"
        assert diagnostic["display_label"] == "ICMP probe unavailable"
        assert diagnostic["severity"] == "info"
        assert "local ICMP probe" in diagnostic["explanation"]
        assert "does not mean the peer is unreachable" in diagnostic["explanation"]


def test_unavailable_ping_does_not_block_recovery_or_failback_readiness():
    now = datetime.utcnow()
    with database() as db:
        _, cluster, standby, active = recovered_pair(db, now)
        standby.peer_reachable = False
        standby.last_peer_attempt_at = now
        standby.last_heartbeat_at = now
        standby.recovery_stable_since = now - timedelta(seconds=61)
        db.add(
            HASyncRun(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=standby.id,
                status="IN_SYNC",
                plan_json="{}",
                completed_at=now,
            )
        )
        db.commit()

        recovery = evaluate_recovery(db, cluster, now=now)[standby.id]

        peer_check = next(check for check in recovery.checks if check.key == "peer_reachability")
        assert peer_check.passed is False
        assert peer_check.required is False
        assert recovery.ready is True
        assert recovery.state == "STANDBY_READY"
