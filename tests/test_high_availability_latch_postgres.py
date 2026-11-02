"""PostgreSQL concurrency acceptance for the HA failed-safe latch workflow."""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.models import HACluster, HAEvent, HAMaintenanceRun, HANode, HASyncRun, User
from app.services import ha_maintenance
from app.services.ha_maintenance import (
    HAMaintenanceError,
    acknowledge_failed_safe_latch,
    latch_preview,
    release_maintenance_latch,
    start_reconciliation,
)
from app.services.ha_sync import HASyncError, execute_sync
from app.services import ha_failover
from app.services.ha_failover import FailoverReadiness, start_controlled_failover


POSTGRES_URL = os.environ.get("KAYA_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="KAYA_TEST_POSTGRES_URL is not configured")


@pytest.fixture(scope="module")
def db_factory():
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True, isolation_level="READ COMMITTED")
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    engine.dispose()


def _state(factory, suffix: str):
    db = factory()
    user = User(email=f"latch-{suffix}@example.invalid", password_hash="synthetic", role="admin", is_active=True)
    cluster = HACluster(
        public_id=f"pg-latch-{suffix}",
        name=f"Synthetic latch {suffix}",
        provider_key="pihole",
        status="HEALTHY",
        automatic_failover_enabled=True,
        automatic_sync_enabled=True,
        maintenance_mode=True,
        keepalived_status="DEPLOYED",
        cluster_generation=4,
        role_generation=4,
        keepalived_generation=4,
    )
    db.add_all([user, cluster])
    db.flush()
    first = HANode(
        cluster_id=cluster.id,
        public_id=f"pg-node-{suffix}-one",
        display_name="Synthetic One",
        api_base_url="http://192.0.2.10",
        role="ACTIVE",
        desired_role="ACTIVE",
        status="HEALTHY",
        observed_generation=4,
        vip_owned=True,
        dhcp_running=True,
        dhcp_runtime_state="RUNNING",
        dhcp_observation_status="FRESH",
        last_report_sequence=1,
        lease_generation=1,
        config_generation=4,
        recovery_state="ACTIVE",
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
    )
    second = HANode(
        cluster_id=cluster.id,
        public_id=f"pg-node-{suffix}-two",
        display_name="Synthetic Two",
        api_base_url="http://192.0.2.11",
        role="STANDBY",
        desired_role="STANDBY",
        status="HEALTHY",
        observed_generation=4,
        vip_owned=False,
        dhcp_running=False,
        dhcp_runtime_state="STOPPED",
        dhcp_observation_status="FRESH",
        last_report_sequence=1,
        lease_generation=1,
        config_generation=4,
        recovery_state="STANDBY_READY",
        keepalived_status="DEPLOYED",
        keepalived_runtime_state="RUNNING",
    )
    db.add_all([first, second])
    db.flush()
    failed = HAMaintenanceRun(
        cluster_id=cluster.id,
        operation="REINITIALISE",
        status="FAILED_SAFE",
        phase="PAUSED",
        error_redacted="Synthetic failed-safe state.",
        completed_at=datetime.utcnow(),
        requested_by_user_id=user.id,
    )
    db.add(failed)
    db.commit()
    ids = (cluster.id, user.id, failed.id, first.id, second.id)
    db.close()
    return ids


def _synthetic_evidence(db: Session, cluster: HACluster):
    failed = max(
        (run for run in cluster.maintenance_runs if run.operation == "REINITIALISE" and run.status == "FAILED_SAFE"),
        key=lambda run: run.created_at,
    )
    active = ha_maintenance.active_maintenance(cluster)
    from app.services.ha_failover import active_failover

    failover = active_failover(cluster)
    passed = not active and not failover and cluster.maintenance_mode and cluster.role_generation == 4
    checks = [{"code": "SYNTHETIC_VERIFIED_STATE", "passed": passed, "detail": "Synthetic signed topology and fencing state."}]
    return {
        "checks": checks,
        "release_allowed": passed,
        "failed_run": failed,
        "active_run": active,
        "latest_reconcile": None,
        "recovery": {},
        "unsafe_actions": [],
        "automatic_sync_enabled": bool(cluster.automatic_sync_enabled),
        "automatic_sync_hold": bool(cluster.automatic_sync_hold),
        "authority": "Synthetic Active",
        "generated_at": datetime.utcnow(),
    }


def _patch_evidence(monkeypatch):
    monkeypatch.setattr(ha_maintenance, "_latch_evidence", _synthetic_evidence)


def test_two_release_requests_serialize_and_audit_one_commit(db_factory, monkeypatch):
    _patch_evidence(monkeypatch)
    cluster_id, user_id, *_ = _state(db_factory, "release-race")
    setup = db_factory()
    cluster = setup.get(HACluster, cluster_id)
    user = setup.get(User, user_id)
    acknowledge_failed_safe_latch(setup, cluster, user)
    setup.close()

    barrier = threading.Barrier(2)
    results = []

    def worker():
        db = db_factory()
        try:
            cluster = db.get(HACluster, cluster_id)
            user = db.get(User, user_id)
            barrier.wait()
            release_maintenance_latch(db, cluster, user)
            results.append("released")
        except HAMaintenanceError:
            db.rollback()
            results.append("blocked")
        finally:
            db.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    [thread.start() for thread in threads]
    [thread.join() for thread in threads]
    assert sorted(results) == ["blocked", "released"]

    check = db_factory()
    assert check.scalar(select(func.count()).select_from(HAEvent).where(HAEvent.cluster_id == cluster_id, HAEvent.event_type == "maintenance_latch_released")) == 1
    cluster = check.get(HACluster, cluster_id)
    assert cluster.automatic_sync_hold is True
    assert cluster.automatic_failover_enabled is False
    check.close()


def test_stale_preview_and_generation_change_block_release(db_factory, monkeypatch):
    _patch_evidence(monkeypatch)
    cluster_id, user_id, *_ = _state(db_factory, "stale-preview")
    preview_db = db_factory()
    preview_cluster = preview_db.get(HACluster, cluster_id)
    preview = latch_preview(preview_db, preview_cluster)
    assert preview["release_allowed"] is True
    preview_db.close()

    change = db_factory()
    changed = change.get(HACluster, cluster_id)
    changed.role_generation = 5
    change.commit()
    user = change.get(User, user_id)
    acknowledge_failed_safe_latch(change, changed, user)
    with pytest.raises(HAMaintenanceError, match="SYNTHETIC_VERIFIED_STATE"):
        release_maintenance_latch(change, changed, user)
    change.rollback()
    assert change.get(HACluster, cluster_id).maintenance_mode is True
    change.close()


def test_release_racing_maintenance_operation_cannot_both_commit(db_factory, monkeypatch):
    _patch_evidence(monkeypatch)
    cluster_id, user_id, *_ = _state(db_factory, "maintenance-race")
    setup = db_factory()
    cluster = setup.get(HACluster, cluster_id)
    user = setup.get(User, user_id)
    acknowledge_failed_safe_latch(setup, cluster, user)
    setup.close()

    maintenance_result = []

    def start_maintenance():
        db = db_factory()
        try:
            start_reconciliation(db, db.get(HACluster, cluster_id), db.get(User, user_id))
            maintenance_result.append("started")
        except HAMaintenanceError:
            db.rollback()
            maintenance_result.append("blocked")
        finally:
            db.close()

    thread = threading.Thread(target=start_maintenance)
    thread.start()
    time.sleep(0.15)
    release_db = db_factory()
    with pytest.raises(HAMaintenanceError, match="SYNTHETIC_VERIFIED_STATE"):
        release_maintenance_latch(release_db, release_db.get(HACluster, cluster_id), release_db.get(User, user_id))
    thread.join()
    release_db.close()
    assert maintenance_result == ["started"]


def test_failed_release_transaction_rolls_back_all_state(db_factory, monkeypatch):
    _patch_evidence(monkeypatch)
    cluster_id, user_id, *_ = _state(db_factory, "rollback")
    db = db_factory()
    cluster = db.get(HACluster, cluster_id)
    user = db.get(User, user_id)
    acknowledge_failed_safe_latch(db, cluster, user)
    original_commit = db.commit

    def fail_commit():
        raise RuntimeError("synthetic commit failure")

    db.commit = fail_commit
    with pytest.raises(RuntimeError, match="synthetic commit failure"):
        release_maintenance_latch(db, cluster, user)
    db.rollback()
    db.commit = original_commit
    fresh = db_factory()
    persisted = fresh.get(HACluster, cluster_id)
    assert persisted.maintenance_mode is True
    assert persisted.automatic_sync_hold is False
    assert fresh.scalar(select(func.count()).select_from(HAEvent).where(HAEvent.cluster_id == cluster_id, HAEvent.event_type == "maintenance_latch_released")) == 0
    fresh.close()
    db.close()


def test_automatic_sync_hold_is_enforced_by_an_independent_session(db_factory, monkeypatch):
    _patch_evidence(monkeypatch)
    cluster_id, _, _, first_id, second_id = _state(db_factory, "sync-hold")
    writer = db_factory()
    cluster = writer.get(HACluster, cluster_id)
    cluster.maintenance_mode = False
    cluster.automatic_sync_hold = True
    run = HASyncRun(
        cluster_id=cluster_id,
        source_node_id=first_id,
        target_node_id=second_id,
        status="PLANNED",
        plan_json='{"groups": [], "blocked_groups": [], "deletion_count": 0}',
    )
    writer.add(run)
    writer.commit()
    writer.close()

    independent = db_factory()
    with pytest.raises(HASyncError, match="held pending explicit administrator approval"):
        execute_sync(independent, independent.get(HACluster, cluster_id), independent.get(HASyncRun, run.id), automatic=True)
    independent.rollback()
    independent.close()


def test_latch_release_is_blocked_after_controlled_failover_initiation(db_factory, monkeypatch):
    _patch_evidence(monkeypatch)
    cluster_id, user_id, _, first_id, second_id = _state(db_factory, "failover-race")
    db = db_factory()
    cluster = db.get(HACluster, cluster_id)
    user = db.get(User, user_id)
    acknowledge_failed_safe_latch(db, cluster, user)
    cluster = db.get(HACluster, cluster_id)
    first = next(node for node in cluster.nodes if node.id == first_id)
    second = next(node for node in cluster.nodes if node.id == second_id)
    monkeypatch.setattr(
        ha_failover,
        "failover_readiness",
        lambda current: FailoverReadiness(first, second, False, [], []),
    )
    monkeypatch.setattr(ha_failover, "_move_vip", lambda *_args: None)
    start_controlled_failover(db, cluster, second, user, confirmation=cluster.name, acknowledged=True)

    release_db = db_factory()
    with pytest.raises(HAMaintenanceError, match="SYNTHETIC_VERIFIED_STATE"):
        release_maintenance_latch(release_db, release_db.get(HACluster, cluster_id), release_db.get(User, user_id))
    release_db.rollback()
    assert release_db.get(HACluster, cluster_id).maintenance_mode is True
    release_db.close()
    db.close()
