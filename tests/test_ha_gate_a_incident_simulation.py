"""Gate A: reproduce the 4 November 2026 ownership incident with simulated agents.

Conventions
-----------
* Plain tests are CHARACTERISATION tests: they pin protections that must stay.
* ``xfail(strict=True)`` tests assert the DESIRED invariant and currently fail,
  documenting a known defect (Dn ids match the Gate A report).  When Gate B
  fixes a defect the test XPASSes, strict mode fails the run, and the marker
  must be removed deliberately.

The VRRP behaviour here comes from ``ha_simulation.VRRPModel`` (a model, not
Keepalived).  These tests prove Kaya's decisions for the modelled
observations only.  All data is synthetic.
"""

from __future__ import annotations

import pytest

from app.models.models import NotificationOutbox
from app.services.ha_agents import desired_state
from app.services.ha_failover import failover_readiness
from app.services.ha_keepalived import desired_keepalived_action
from ha_simulation import hal_like_cluster, ownership_snapshot, sqlite_session

DHCP_ACTIONS = {"DHCP_PROMOTE", "DHCP_DEMOTE"}


def assert_no_dhcp_or_keepalived_action(sim) -> None:
    for node in (sim.one, sim.two):
        state = desired_state(node)
        assert not DHCP_ACTIONS.intersection(state["allowed_actions"]), state["allowed_actions"]
        assert state["failover"] is None
        assert desired_keepalived_action(sim.cluster, node) is None


def incident(maintenance_mode: bool = True, automatic_failover: bool = False):
    """Steady state, then Keepalived restarts on the MASTER (node one)."""
    db = sqlite_session()
    sim = hal_like_cluster(db, maintenance_mode=maintenance_mode, automatic_failover=automatic_failover)
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)  # node one reports first: no transient dual owner
    sim.report(sim.sim_two)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(3)
    return sim


def test_fixture_starts_healthy_with_one_vip_and_one_dhcp_owner():
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    snapshot = ownership_snapshot(sim)
    assert snapshot["status"] == "HEALTHY"
    assert snapshot["vip_owners"] == snapshot["dhcp_owners"] == ["SimPiHole1"]
    assert snapshot["recovery"] == {"SimPiHole1": "ACTIVE", "SimPiHole2": "STANDBY_READY"}


@pytest.mark.parametrize("maintenance_mode", [True, False], ids=["maintenance-on", "maintenance-off"])
def test_master_keepalived_restart_moves_vip_and_leaves_dhcp_on_original_owner(maintenance_mode):
    sim = incident(maintenance_mode=maintenance_mode)
    snapshot = ownership_snapshot(sim)
    # Modelled VRRP: priority-0 advert hands the VIP over; nopreempt keeps node one BACKUP.
    assert sim.sim_one.vrrp_state == "BACKUP" and sim.sim_two.vrrp_state == "MASTER"
    assert [(call.node, call.transition, call.generation) for call in sim.vrrp.notify] == [
        ("SimPiHole2", "master", 37),
        ("SimPiHole1", "backup", 37),
    ]
    # Kaya: degraded with an explicit mismatch, DHCP untouched, authority untouched.
    assert snapshot["status"] == "DEGRADED"
    assert "OWNERSHIP_MISMATCH" in snapshot["issues"]
    assert snapshot["topology_safe"] is False
    assert snapshot["vip_owners"] == ["SimPiHole2"]
    assert snapshot["dhcp_owners"] == ["SimPiHole1"]
    assert snapshot["authority"] == "SimPiHole1"
    assert snapshot["automatic_failover"] is False
    assert sim.sim_one.dhcp_running and not sim.sim_two.dhcp_running
    assert_no_dhcp_or_keepalived_action(sim)


def test_mismatch_publishes_one_specific_notification_and_does_not_flood():
    """Since P5 the incident raises only the confirmed ownership alert, never also a generic degraded one."""
    from datetime import timedelta

    from app.services.ha_ownership_alerts import MISMATCH_CONFIRM_SECONDS

    sim = incident()
    before_events = len(sim.events())
    sim.report_both(10)
    assert len(sim.events()) == before_events  # steady mismatch does not churn events
    sim.cluster.ownership_mismatch_since -= timedelta(seconds=MISMATCH_CONFIRM_SECONDS + 1)  # it has persisted
    sim.db.commit()
    sim.report_both(10)
    by_type = {}
    for row in sim.db.query(NotificationOutbox).all():
        by_type[row.event_type] = by_type.get(row.event_type, 0) + 1
    assert by_type == {"pihole.ownership.mismatch": 1}


def test_steady_mismatch_keeps_degraded_state_without_any_automatic_vip_return():
    """No auto-return exists today: Kaya never queues a Keepalived change on its own."""
    sim = incident()
    sim.report_both(5)
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole2"]
    assert_no_dhcp_or_keepalived_action(sim)


def test_automatic_failover_enabled_does_not_adopt_vip_owner_without_dhcp():
    sim = incident(maintenance_mode=False, automatic_failover=True)
    snapshot = ownership_snapshot(sim)
    assert snapshot["status"] == "DEGRADED"
    assert snapshot["roles"] == {"SimPiHole1": "ACTIVE", "SimPiHole2": "STANDBY"}
    assert snapshot["authority"] == "SimPiHole1"
    assert_no_dhcp_or_keepalived_action(sim)


def test_supervised_standby_restart_restores_single_owner_but_readiness_still_needs_attention():
    """Mirrors the 15:31 manual recovery and explains the residual NEEDS_ATTENTION."""
    sim = incident()
    sim.vrrp.restart("SimPiHole2")
    sim.report(sim.sim_two)
    sim.report(sim.sim_one)
    sim.report_both(2)
    snapshot = ownership_snapshot(sim)
    assert snapshot["status"] == "HEALTHY"
    assert snapshot["vip_owners"] == snapshot["dhcp_owners"] == ["SimPiHole1"]
    assert snapshot["stored_active"] == "SimPiHole1"
    # The standby restarted its recovery clock, so it needs a fresh post-recovery
    # configuration comparison before it can be STANDBY_READY again ...
    assert snapshot["recovery"]["SimPiHole2"] in {"RECOVERING", "SYNCHRONISING"}
    # ... and the retained maintenance latch is reported as "in progress".
    assert "Cluster maintenance is in progress." in failover_readiness(sim.cluster).blockers


def test_observation_sequential_handover_can_raise_transient_split_brain_event():
    """OBSERVATION: the old owner's last report still claims the VIP while it is fresh.

    If the new owner reports first, Kaya sees two fresh VIP claims and records a
    critical split_brain_detected event even though VRRP handed over cleanly.
    Kaya cannot distinguish this from a real dual MASTER without more evidence.
    """
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_two)
    assert ownership_snapshot(sim)["status"] == "ERROR"
    assert sim.events("split_brain_detected")
    sim.report(sim.sim_one)
    assert ownership_snapshot(sim)["status"] == "DEGRADED"
    assert_no_dhcp_or_keepalived_action(sim)


def test_dual_vip_ownership_is_error_and_blocks_every_dhcp_action():
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    sim.vrrp.partition()
    sim.report_both(2)
    snapshot = ownership_snapshot(sim)
    assert snapshot["vip_owners"] == ["SimPiHole1", "SimPiHole2"]
    assert snapshot["status"] == "ERROR"
    assert sim.events("split_brain_detected")
    assert sim.cluster.current_active_node_id == sim.one.id  # assignment kept, never cleared (D1)
    assert_no_dhcp_or_keepalived_action(sim)


def test_missing_vip_owner_is_not_healthy_and_blocks_dhcp_actions():
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.vrrp.stop("SimPiHole2")
    sim.report_both(2)
    snapshot = ownership_snapshot(sim)
    assert snapshot["vip_owners"] == []
    assert snapshot["status"] != "HEALTHY"
    assert sim.cluster.current_active_node_id == sim.one.id  # assignment kept, never cleared (D1)
    assert_no_dhcp_or_keepalived_action(sim)


def test_dhcp_owner_dns_fault_moves_vip_but_never_moves_dhcp():
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    sim.vrrp.dns_fault("SimPiHole1")
    sim.report_both(3)
    snapshot = ownership_snapshot(sim)
    assert sim.sim_one.vrrp_state == "FAULT"
    assert snapshot["vip_owners"] == ["SimPiHole2"]
    assert snapshot["dhcp_owners"] == ["SimPiHole1"]
    assert snapshot["status"] != "HEALTHY"
    assert_no_dhcp_or_keepalived_action(sim)


def test_stale_vip_owner_agent_is_not_trusted_and_blocks_dhcp_actions():
    sim = incident()
    sim.make_stale(sim.sim_two)
    sim.report(sim.sim_one)
    snapshot = ownership_snapshot(sim)
    assert snapshot["vip_owners"] == []  # stale claims are not counted
    assert snapshot["status"] != "HEALTHY"
    assert_no_dhcp_or_keepalived_action(sim)


def test_inconsistent_keepalived_generation_is_not_healthy():
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    sim.report(sim.sim_two, config_generation=36)
    sim.report(sim.sim_one)
    assert ownership_snapshot(sim)["status"] != "HEALTHY"
    assert_no_dhcp_or_keepalived_action(sim)


# --------------------------------------------------------------------------
# Documented defects (desired invariants; currently failing)
# --------------------------------------------------------------------------


def test_d1_stored_active_is_not_overwritten_by_an_unverified_vip_move():
    sim = incident()
    assert ownership_snapshot(sim)["stored_active"] == "SimPiHole1"


def test_d2_sole_dhcp_owner_is_not_placed_into_standby_recovery():
    sim = incident()
    assert ownership_snapshot(sim)["recovery"]["SimPiHole1"] not in {"RECOVERING", "SYNCHRONISING", "VERIFYING", "STANDBY_READY"}
    assert not sim.events("node_recovered")


def test_d3_mismatch_notification_names_observed_owners():
    """Fixed in P4: a confirmed mismatch raises one notification naming both owners and the next safe step.

    (The generic degraded notification fires on the first report, when node one
    has released the VIP and node two has not yet reported, so at that moment
    no node holds the VIP; it cannot name both owners truthfully.)
    """
    from datetime import timedelta

    from app.services.ha_ownership_alerts import MISMATCH_CONFIRM_SECONDS, update_ownership_alerts

    sim = incident()
    sim.cluster.ownership_mismatch_since -= timedelta(seconds=MISMATCH_CONFIRM_SECONDS + 1)  # it has persisted
    update_ownership_alerts(sim.db, sim.cluster)
    notification = sim.db.query(NotificationOutbox).filter(NotificationOutbox.event_type == "pihole.ownership.mismatch").one()
    text = f"{notification.title} {notification.message}"
    assert "SimPiHole1" in text and "SimPiHole2" in text
    assert "Align service ownership" in text  # the assessment's own explanation of the safe path (P6)
