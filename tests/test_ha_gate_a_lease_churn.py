"""Gate A: lease-replication behaviour that drives standby recovery churn.

Uses the real ``reconcile_cluster_leases`` with a precomputed synthetic
``LeasePlan`` (no Pi-hole call).  Per the Gate A instruction, lease expiry is
NOT excluded from the checksum: renewals are staged for expiry continuity,
but since P4 they no longer reset standby readiness (material generation).
"""

from __future__ import annotations

import ipaddress

import pytest

from app.models.models import HALeaseSnapshot
from app.services.ha_leases import HALeaseError, LeasePlan, reconcile_cluster_leases
from ha_simulation import hal_like_cluster, sqlite_session


def plan(sim, expires: int) -> LeasePlan:
    lease = {"expires": expires, "hwaddr": "02:00:00:00:00:21", "ip": "192.0.2.50", "name": "synthetic-client", "clientid": ""}
    return LeasePlan(True, sim.one.id, sim.one.public_id, sim.two.id, [lease], set(),
                     ipaddress.IPv4Address("192.0.2.20"), ipaddress.IPv4Address("192.0.2.200"),
                     sim.cluster.role_generation, sim.cluster.keepalived_generation, sim.cluster.cluster_generation)


def healthy():
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False)
    sim.report_both(2)
    return sim


def test_unchanged_leases_do_not_create_a_new_generation():
    sim = healthy()
    first = reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=plan(sim, 2_000_000_000)).desired_generation
    second = reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=plan(sim, 2_000_000_000)).desired_generation
    assert first == second


def test_lease_reconciliation_is_blocked_while_vip_and_dhcp_owners_differ():
    sim = healthy()
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    with pytest.raises(HALeaseError, match="cannot verify one safe VIP owner"):
        reconcile_cluster_leases(sim.db, sim.cluster)
    assert sim.cluster.lease_replication.status == "BLOCKED"


def lease_ready(sim, now=None) -> bool:
    from app.services.ha_recovery import recovery_checks

    checks = {check.key: check for check in recovery_checks(sim.db, sim.cluster, sim.two, now=now)}
    return checks["lease_sync"].passed


def stage(sim, generation: int) -> None:
    """The standby agent stages a generation (as its signed acknowledgement records)."""
    state = sim.cluster.lease_replication
    state.applied_generation = generation
    state.status = "CURRENT"
    sim.two.lease_generation = generation
    for snapshot in sim.db.query(HALeaseSnapshot).filter(HALeaseSnapshot.generation == generation):
        snapshot.status = "STAGED"
    sim.db.commit()


def test_d17_expiry_only_renewal_does_not_reset_standby_readiness():
    """Fixed in P4 with a refined invariant (Gate A asked for no new generation at all).

    The failover helper writes the staged expiry times straight into dnsmasq's
    lease file, so a standby holding stale expiry times could let a still-live
    address be reissued.  Renewals therefore still produce a new staged
    generation, but only a change to the lease set advances the material
    generation that standby readiness depends on.  A refresh the standby has not
    staged within LEASE_REFRESH_GRACE_SECONDS does make it not ready.
    """
    from datetime import datetime, timedelta

    from app.services.ha_recovery import LEASE_REFRESH_GRACE_SECONDS

    sim = healthy()
    first = reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=plan(sim, 2_000_000_000))
    first_generation, material = first.desired_generation, first.material_generation
    stage(sim, first_generation)
    assert lease_ready(sim)

    renewed = reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=plan(sim, 2_000_003_600))
    assert renewed.desired_generation == first_generation + 1  # expiry continuity is still staged
    assert renewed.material_generation == material
    assert renewed.status == "PENDING"
    assert lease_ready(sim)  # a renewal alone does not reset readiness
    later = datetime.utcnow() + timedelta(seconds=LEASE_REFRESH_GRACE_SECONDS + 1)
    assert not lease_ready(sim, now=later)  # but a standby that stops staging refreshes is not ready
    stage(sim, renewed.desired_generation)
    assert lease_ready(sim, now=later)


def test_a_lease_set_change_requires_staging_before_readiness():
    sim = healthy()
    first = reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=plan(sim, 2_000_000_000))
    first_generation = first.desired_generation
    stage(sim, first_generation)
    changed = plan(sim, 2_000_000_000)
    changed.leases.append({"expires": 2_000_000_000, "hwaddr": "02:00:00:00:00:22", "ip": "192.0.2.51", "name": "synthetic-client-2", "clientid": ""})
    state = reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=changed)
    assert state.material_generation == state.desired_generation == first_generation + 1
    assert not lease_ready(sim)
    stage(sim, state.desired_generation)
    assert lease_ready(sim)
