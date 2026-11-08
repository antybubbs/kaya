"""Lost update: two nodes' Keepalived results committed concurrently left the cluster PENDING_AGENT forever.

Found in the isolated DHCP handover lab (both agents reported within the same second).  Each result
decided "are all nodes deployed?" from its own transaction's view, so each saw the other still pending,
and nothing ever re-checked.  Effects: the periodic pass skipped the cluster (ownership alerts stopped)
and repairs needing a deployed Keepalived stayed blocked.  Synthetic data only.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.models import HACluster, HAEvent, HANode
from app.schemas.high_availability import HAAgentActionResult
from app.services import ha_agents
from app.services.ha_agents import record_action_result, record_heartbeat
from app.services.ha_keepalived import desired_keepalived_action
from app.services.ha_ownership_alerts import MISMATCH_CONFIRM_SECONDS
from app.services.ha_watchdog import drain_evaluations, periodic_clusters, reconcile_cluster
from ha_simulation import hal_like_cluster, heartbeat_for, sqlite_session


def pending_cluster(db, suffix):
    sim = hal_like_cluster(db, maintenance_mode=False, suffix=suffix)
    sim.cluster.keepalived_status = "PENDING_AGENT"
    for node in (sim.one, sim.two):
        node.keepalived_status = "PENDING_AGENT"
    db.commit()
    return sim


def result_for(action):
    return HAAgentActionResult(action_id=action["action_id"], action_type="KEEPALIVED_APPLY", generation=action["generation"],
                               status="APPLIED", checksum=action["checksum"], backup_reference=None, message="applied")


def simultaneous_results(factory, cluster_id, node_ids, actions):
    """Both results decide before either commits (the lab's simultaneous reports)."""
    barrier = threading.Barrier(2)
    real_phase = ha_agents.performance_phase
    errors = []

    @contextmanager
    def phase(name):
        if name == "action_result.commit":
            barrier.wait(10)
        with real_phase(name):
            yield

    def worker(node_id):
        session = factory()
        try:
            record_action_result(session, session.get(HANode, node_id), result_for(actions[node_id]))
        except Exception as exc:  # surfaced by the caller
            errors.append(exc)
        finally:
            session.close()

    ha_agents.performance_phase = phase
    try:
        threads = [threading.Thread(target=worker, args=(node_id,)) for node_id in node_ids]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
    finally:
        ha_agents.performance_phase = real_phase
    return errors


def test_concurrent_keepalived_results_still_complete_the_deployment(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'race.db').as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    setup = factory()
    sim = pending_cluster(setup, "race")
    cluster_id, ids = sim.cluster.id, (sim.one.id, sim.two.id)
    actions = {node_id: desired_keepalived_action(sim.cluster, setup.get(HANode, node_id)) for node_id in ids}
    setup.close()
    assert simultaneous_results(factory, cluster_id, ids, actions) == []
    check = factory()
    assert check.get(HACluster, cluster_id).keepalived_status == "DEPLOYED"
    check.close()


def left_pending_by_a_crash():
    """Both nodes' results committed, but Kaya stopped before completing the deployment."""
    sim = pending_cluster(sqlite_session(), "restart")
    for node in (sim.one, sim.two):
        node.keepalived_status = "DEPLOYED"
        node.config_generation = sim.cluster.keepalived_generation
    sim.db.commit()
    return sim


def test_a_deployment_left_pending_by_a_restart_completes_on_the_next_heartbeat():
    sim = left_pending_by_a_crash()
    record_heartbeat(sim.db, sim.one, heartbeat_for(sim.sim_one))
    drain_evaluations(sim.db)
    assert sim.cluster.keepalived_status == "DEPLOYED"


def test_the_periodic_pass_completes_a_pending_deployment_without_any_report():
    sim = left_pending_by_a_crash()
    assert sim.cluster in periodic_clusters(sim.db)
    reconcile_cluster(sim.db, sim.cluster)
    assert sim.cluster.keepalived_status == "DEPLOYED"


def test_a_genuinely_pending_deployment_is_never_completed_early():
    sim = pending_cluster(sqlite_session(), "genuine")
    sim.one.keepalived_status = "DEPLOYED"
    sim.one.config_generation = sim.cluster.keepalived_generation
    sim.db.commit()
    reconcile_cluster(sim.db, sim.cluster)
    assert sim.cluster.keepalived_status == "PENDING_AGENT"  # lab-b has not applied it


def test_ownership_alerts_and_repairs_resume_after_recovery():
    from app.services.ha_alignment import alignment_preview

    sim = left_pending_by_a_crash()
    reconcile_cluster(sim.db, sim.cluster)
    # A VIP/DHCP split that persists past the confirmation window is notified again.
    sim.vrrp.stop("SimPiHole1")
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    sim.cluster.ownership_mismatch_since = datetime.utcnow() - timedelta(seconds=MISMATCH_CONFIRM_SECONDS + 5)
    sim.db.commit()
    reconcile_cluster(sim.db, sim.cluster)
    assert sim.db.query(HAEvent).filter(HAEvent.event_type == "ownership_mismatch_confirmed").count() == 1
    keepalived = next(check for check in alignment_preview(sim.db, sim.cluster).checks if check.code == "KEEPALIVED")
    assert keepalived.passed  # repairs that need a deployed Keepalived are no longer blocked
