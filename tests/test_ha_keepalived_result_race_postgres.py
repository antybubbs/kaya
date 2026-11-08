"""PostgreSQL: simultaneous Keepalived results from both agents always complete the deployment.

Separate sessions and connections stand in for two request workers receiving both agents' results
at the same instant (both decide before either commits).  Repeated to cover interleavings.
Synthetic data only.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from app.models.models import HACluster, HANode
from app.services.ha_keepalived import desired_keepalived_action
from test_ha_keepalived_result_race import pending_cluster, simultaneous_results
from test_ha_p2a_coordination_postgres import pg, pytestmark  # noqa: F401


def test_simultaneous_results_never_leave_the_cluster_pending(pg):  # noqa: F811 (imported fixture)
    factory, _admin = pg
    for _round in range(5):
        db = factory(expire_on_commit=False)
        try:
            sim = pending_cluster(db, uuid4().hex[:8])
            cluster_id, ids = sim.cluster.id, (sim.one.id, sim.two.id)
            actions = {node_id: desired_keepalived_action(sim.cluster, db.get(HANode, node_id)) for node_id in ids}
        finally:
            db.rollback()
            db.close()
        assert simultaneous_results(factory, cluster_id, ids, actions) == []
        check = factory()
        try:
            cluster = check.get(HACluster, cluster_id)
            assert cluster.keepalived_status == "DEPLOYED", [(n.display_name, n.keepalived_status) for n in cluster.nodes]
            cluster.deleted_at = datetime.utcnow()  # one active cluster per synthetic VIP: retire it before the next round
            check.commit()
        finally:
            check.close()
