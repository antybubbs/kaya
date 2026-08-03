import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import Base
from app.models.models import (
    HAAgentCredential,
    HACluster,
    HAEvent,
    HALeaseReplicationState,
    HANode,
    HASyncRun,
    NotificationEvent,
    NotificationOutbox,
    User,
)
from app.routers.high_availability import cluster_live_status
from app.services.ha_failover import HAFailoverError, advance_failover, failover_status, start_controlled_failover
from app.services.ha_recovery import evaluate_recovery, peer_diagnostic, preferred_node
from app.services.notification_outbox import process_outbox


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
        dhcp_configured=False,
        dhcp_listener_active=False,
        ftl_active=True,
        dhcp_runtime_state="STOPPED",
        dhcp_observation_status="FRESH",
        dhcp_observed_at=now,
        dns_healthy=True,
        peer_reachable=True,
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
        config_generation=7,
        lease_generation=11,
        agent_version="0.2.13",
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
        dhcp_configured=True,
        dhcp_listener_active=True,
        ftl_active=True,
        dhcp_runtime_state="RUNNING",
        dhcp_observation_status="FRESH",
        dhcp_observed_at=now,
        dns_healthy=True,
        peer_reachable=True,
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
        config_generation=7,
        lease_generation=11,
        agent_version="0.2.13",
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
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()
        unreachable = db.query(NotificationEvent).filter_by(event_type="pihole.node.unreachable").one()
        assert unreachable.resolved_at is None

        recovered.last_heartbeat_at = now + timedelta(seconds=1)
        db.commit()
        result = evaluate_recovery(db, cluster, now=now + timedelta(seconds=1))[recovered.id]
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()
        assert result.state == "SYNCHRONISING"
        assert not result.ready
        db.refresh(unreachable)
        assert unreachable.resolved_at is not None

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
        recovered.last_heartbeat_at = recovered.dhcp_observed_at = now + timedelta(seconds=63)
        active.last_heartbeat_at = active.dhcp_observed_at = now + timedelta(seconds=63)
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
        assert result.operational_readiness == "NOT_READY"
        assert not next(check for check in result.checks if check.key == "lease_sync").passed


def test_inactive_ftl_prevents_operational_standby_readiness():
    now = datetime.utcnow()
    with database() as db:
        _, cluster, standby, active = recovered_pair(db, now)
        standby.last_heartbeat_at = now
        standby.ftl_active = False
        db.add(HASyncRun(
            cluster_id=cluster.id,
            source_node_id=active.id,
            target_node_id=standby.id,
            status="IN_SYNC",
            plan_json="{}",
            completed_at=now,
        ))
        db.commit()

        result = evaluate_recovery(db, cluster, now=now)[standby.id]

        assert result.operational_readiness == "NOT_READY"
        assert not next(check for check in result.checks if check.key == "dns").passed


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
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()
        assert db.query(NotificationEvent).filter_by(
            event_type="pihole.failback.started",
            correlation_id=run.public_id,
        ).one()
        assert run.source_node_id == active.id
        assert run.target_node_id == recovered.id

        active.vip_owned = False
        active.dhcp_running = active.dhcp_configured = active.dhcp_listener_active = False
        active.dhcp_runtime_state = "STOPPED"
        active.dhcp_observation_status = "FRESH"
        active.dhcp_observed_at = active.last_heartbeat_at = datetime.utcnow()
        recovered.vip_owned = True
        recovered.dhcp_running = recovered.dhcp_configured = recovered.dhcp_listener_active = True
        recovered.ftl_active = True
        recovered.dhcp_runtime_state = "RUNNING"
        recovered.dhcp_observation_status = "FRESH"
        recovered.dhcp_observed_at = recovered.last_heartbeat_at = datetime.utcnow()
        advance_failover(db, cluster)
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()

        assert run.status == "SUCCEEDED"
        assert db.query(NotificationEvent).filter_by(
            event_type="pihole.failback.completed",
            correlation_id=run.public_id,
        ).one()


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


def test_ready_standby_ignores_later_failed_sync_check_without_recovery_loop():
    now = datetime.utcnow()
    with database() as db:
        _, cluster, standby, active = recovered_pair(db, now)
        standby.last_heartbeat_at = standby.dhcp_observed_at = now
        standby.recovery_started_at = now - timedelta(minutes=3)
        standby.recovery_stable_since = now - timedelta(minutes=2)
        standby.recovery_state = "STANDBY_READY"
        db.add_all([
            HASyncRun(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=standby.id,
                status="IN_SYNC",
                plan_json="{}",
                created_at=now - timedelta(minutes=2),
                completed_at=now - timedelta(minutes=2),
            ),
            HASyncRun(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=standby.id,
                status="ROLLED_BACK",
                plan_json="{}",
                created_at=now - timedelta(seconds=5),
                completed_at=now - timedelta(seconds=5),
                error_redacted="Synthetic later diagnostic failure.",
            ),
        ])
        db.commit()
        event_count = db.query(HAEvent).filter(HAEvent.node_id == standby.id).count()

        for offset in (0, 5, 10):
            observed = now + timedelta(seconds=offset)
            standby.last_heartbeat_at = standby.dhcp_observed_at = observed
            active.last_heartbeat_at = active.dhcp_observed_at = observed
            db.commit()
            result = evaluate_recovery(db, cluster, now=observed)[standby.id]
            assert result.state == "STANDBY_READY"
            assert result.ready is True

        assert db.query(HAEvent).filter(HAEvent.node_id == standby.id).count() == event_count


def test_live_snapshot_separates_operational_readiness_from_routine_sync_workflow():
    now = datetime.utcnow()
    with database() as db:
        user, cluster, standby, active = recovered_pair(db, now)
        standby.last_heartbeat_at = standby.dhcp_observed_at = now
        standby.recovery_started_at = now - timedelta(minutes=10)
        standby.recovery_stable_since = now - timedelta(minutes=2)
        standby.recovery_state = "SYNCHRONISING"
        db.add(HASyncRun(
            cluster_id=cluster.id,
            source_node_id=active.id,
            target_node_id=standby.id,
            status="IN_SYNC",
            plan_json='{"groups":[],"required_sync_generation":0,"verified_sync_generation":0}',
            created_at=now - timedelta(minutes=2),
            completed_at=now - timedelta(minutes=2),
        ))
        db.commit()

        routine = HASyncRun(
            cluster_id=cluster.id,
            source_node_id=active.id,
            target_node_id=standby.id,
            status="PENDING",
            plan_json='{"groups":[],"required_sync_generation":0}',
            created_at=now,
        )
        db.add(routine)
        db.commit()

        for status, expected_sync_state in (
            ("PENDING", "CHECKING"),
            ("RUNNING", "RUNNING"),
            ("IN_SYNC", "IN_SYNC"),
        ):
            routine.status = status
            if status == "IN_SYNC":
                routine.plan_json = '{"groups":[],"required_sync_generation":0,"verified_sync_generation":0}'
                routine.completed_at = now + timedelta(seconds=15)
            standby.last_heartbeat_at = standby.dhcp_observed_at = now + timedelta(seconds=15)
            active.last_heartbeat_at = active.dhcp_observed_at = now + timedelta(seconds=15)
            db.commit()

            payload = json.loads(cluster_live_status(cluster.public_id, db, user).body)
            standby_payload = next(node for node in payload["nodes"] if node["id"] == standby.public_id)

            assert payload["cluster"]["operational_readiness"] == "READY"
            assert payload["cluster"]["ha_readiness"] == "READY"
            assert payload["operational_readiness"]["ready"] is True
            assert payload["readiness"]["ready"] is False
            assert payload["sync"]["sync_state"] == expected_sync_state
            assert standby_payload["operational_readiness"] == "READY"
            assert standby_payload["recovery_workflow_state"] == "SYNCHRONISING"
            assert standby_payload["sync_state"] == expected_sync_state
            assert payload["consistency"]["issues"] == []
            assert payload["cluster"]["unacknowledged_alerts"] == 0

        assert db.query(HAEvent).count() == 0
        assert db.query(NotificationEvent).count() == 0
        assert db.query(NotificationOutbox).count() == 0


def test_ready_standby_remains_quiescent_through_a_week_of_observation_then_real_drift():
    start = datetime.utcnow()
    with database() as db:
        _, cluster, standby, active = recovered_pair(db, start)
        cluster.automatic_sync_enabled = True
        standby.last_heartbeat_at = standby.dhcp_observed_at = start
        standby.recovery_started_at = start - timedelta(minutes=3)
        standby.recovery_stable_since = start - timedelta(minutes=2)
        standby.recovery_state = "STANDBY_READY"
        stable_since = standby.recovery_stable_since
        db.add(HASyncRun(
            cluster_id=cluster.id,
            source_node_id=active.id,
            target_node_id=standby.id,
            status="IN_SYNC",
            plan_json='{"groups":[],"required_sync_generation":0,"verified_sync_generation":0}',
            completed_at=start,
        ))
        db.commit()
        lifecycle_events = {
            "node_recovery_synchronising",
            "node_recovery_verifying",
            "node_standby_ready",
        }
        initial_events = db.query(HAEvent).filter(
            HAEvent.node_id == standby.id,
            HAEvent.event_type.in_(lifecycle_events),
        ).count()

        observed = start
        # Hourly PENDING -> RUNNING -> SUCCEEDED checks exercise a simulated
        # week without coupling this state-machine regression to wall time.
        for _ in range(24 * 7):
            run = HASyncRun(
                cluster_id=cluster.id,
                source_node_id=active.id,
                target_node_id=standby.id,
                status="PENDING",
                plan_json='{"groups":[],"required_sync_generation":0}',
            )
            db.add(run)
            for status in ("PENDING", "RUNNING", "SUCCEEDED"):
                observed += timedelta(minutes=20)
                run.status = status
                if status == "SUCCEEDED":
                    run.plan_json = '{"groups":[],"required_sync_generation":0,"verified_sync_generation":0}'
                    run.completed_at = observed
                standby.last_heartbeat_at = standby.dhcp_observed_at = observed
                active.last_heartbeat_at = active.dhcp_observed_at = observed
                db.commit()
                result = evaluate_recovery(db, cluster, now=observed)[standby.id]
                assert result.state == "STANDBY_READY"
                assert result.operational_readiness == "READY"
                assert standby.recovery_stable_since == stable_since
            # Exercise the existing periodic reconciliation path as a no-op.
            from app.services.ha_watchdog import reconcile_cluster
            from app.services.ha_agents import desired_state
            reconcile_cluster(db, cluster)
            assert active.dhcp_running is True
            assert active.dhcp_configured is True
            assert active.dhcp_listener_active is True
            assert desired_state(active)["failover"] is None

        assert db.query(HAEvent).filter(
            HAEvent.node_id == standby.id,
            HAEvent.event_type.in_(lifecycle_events),
        ).count() == initial_events

        drift = HASyncRun(
            cluster_id=cluster.id,
            source_node_id=active.id,
            target_node_id=standby.id,
            status="PLANNED",
            plan_json=(
                '{"groups":[{"key":"local_dns","writable":true}],'
                '"required_sync_generation":0}'
            ),
        )
        db.add(drift)
        observed += timedelta(seconds=15)
        standby.last_heartbeat_at = standby.dhcp_observed_at = observed
        active.last_heartbeat_at = active.dhcp_observed_at = observed
        db.commit()

        degraded = evaluate_recovery(db, cluster, now=observed)[standby.id]
        assert degraded.state == "SYNCHRONISING"
        assert degraded.operational_readiness == "NOT_READY"
        assert not next(
            check for check in degraded.checks if check.key == "configuration_sync"
        ).passed
        assert standby.recovery_stable_since is None

        cluster.desired_sync_generation = 1
        drift.status = "SUCCEEDED"
        drift.plan_json = (
            '{"groups":[{"key":"local_dns","writable":true}],'
            '"required_sync_generation":0,"verified_sync_generation":1}'
        )
        drift.completed_at = observed + timedelta(seconds=15)
        observed += timedelta(seconds=15)
        standby.last_heartbeat_at = standby.dhcp_observed_at = observed
        active.last_heartbeat_at = active.dhcp_observed_at = observed
        db.commit()

        assert evaluate_recovery(db, cluster, now=observed)[standby.id].state == "VERIFYING"
        observed += timedelta(seconds=61)
        standby.last_heartbeat_at = standby.dhcp_observed_at = observed
        active.last_heartbeat_at = active.dhcp_observed_at = observed
        db.commit()
        assert evaluate_recovery(db, cluster, now=observed)[standby.id].state == "STANDBY_READY"

        final_events = db.query(HAEvent).filter(
            HAEvent.node_id == standby.id,
            HAEvent.event_type.in_(lifecycle_events),
        ).count()
        assert final_events == initial_events + 3
        for _ in range(8):
            observed += timedelta(seconds=15)
            standby.last_heartbeat_at = standby.dhcp_observed_at = observed
            active.last_heartbeat_at = active.dhcp_observed_at = observed
            db.commit()
            assert evaluate_recovery(db, cluster, now=observed)[standby.id].state == "STANDBY_READY"
        assert db.query(HAEvent).filter(
            HAEvent.node_id == standby.id,
            HAEvent.event_type.in_(lifecycle_events),
        ).count() == final_events
