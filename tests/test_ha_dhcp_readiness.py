"""DHCP protocol release readiness (PROPOSAL; not approved): rollout safety and Health & Repair.

* Older agents never receive authority instructions.
* A node whose Pi-hole FTL started DNS-only is reported, explained and never chosen as DHCP target.
* Every blocked DHCP handover says what is wrong, whether DNS and DHCP still work, whether recovery is
  automatic, what was attempted, and one next step that can succeed (never reinitialisation).
* The read-only rollout preflight blocks unsafe steps.
Synthetic data only.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

pytest.importorskip("fcntl")

from app.models.models import HAFailoverRun  # noqa: E402
from app.services.ha_agents import desired_state, record_heartbeat  # noqa: E402
from app.services.ha_assessment import APPROVAL_REQUIRED, BLOCKED, SELF_HEALING, assess_cluster  # noqa: E402
from app.services.ha_dhcp_handover import handover_assessment  # noqa: E402
from app.services.ha_dhcp_preflight import preflight  # noqa: E402
from ha_simulation import heartbeat_for, ownership_snapshot  # noqa: E402
from app.services.ha_watchdog import reconcile_cluster  # noqa: E402
from test_ha_dhcp_handover_protocol import AGENT, age_vip, apply_dhcp_actions, automatic_cluster, drive, pairs, report, stage_snapshot  # noqa: E402


def _finding(sim, code):
    return next((f for f in assess_cluster(sim.db, sim.cluster).findings if f.code == code), None)


def _report_with(sim, updates):
    for simnode, node in pairs(sim):
        beat = heartbeat_for(simnode, observed_generation=sim.cluster.role_generation).model_copy(
            update={"agent_version": AGENT, **updates.get(simnode.name, {})})
        record_heartbeat(sim.db, node, beat)


def _assert_actionable(finding):
    assert finding is not None
    assert "DNS is unaffected" in finding.impact or "DNS on" in finding.impact  # says what still works
    assert finding.no_repair_reason and "Reinitialise" not in finding.no_repair_reason  # a next step; never reinitialisation
    assert finding.disposition in {BLOCKED, SELF_HEALING, APPROVAL_REQUIRED} or finding.disposition == "TRANSIENT"


# --------------------------------------------------------------------------------------
# Rollout: older agents
# --------------------------------------------------------------------------------------


def test_older_agents_never_receive_authority_instructions():
    sim = automatic_cluster()
    assert "dhcp_authority" in desired_state(sim.one) and desired_state(sim.one)["accepts_dhcp_authority_report"] is True
    _report_with(sim, {"SimPiHole2": {"agent_version": "0.2.15"}})
    old = desired_state(sim.two)
    assert "dhcp_authority" not in old and "accepts_dhcp_authority_report" not in old
    assert "dhcp_authority" in desired_state(sim.one)  # the upgraded node still does


# --------------------------------------------------------------------------------------
# DNS-only fallback
# --------------------------------------------------------------------------------------


def test_a_dns_only_node_is_reported_and_never_chosen_as_dhcp_target():
    sim = automatic_cluster()
    _report_with(sim, {"SimPiHole2": {"dhcp_guard_mode": "dns_only"}})
    assert sim.two.dhcp_guard_mode == "dns_only"
    finding = _finding(sim, "DHCP_DNS_ONLY_FALLBACK")
    _assert_actionable(finding)
    assert finding.node == "SimPiHole2" and "restart pihole-FTL" in finding.no_repair_reason
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    for _ in range(4):
        age_vip(sim)
        _report_with(sim, {"SimPiHole2": {"dhcp_guard_mode": "dns_only"}})
        reconcile_cluster(sim.db, sim.cluster)
        apply_dhcp_actions(sim)
    state = handover_assessment(sim.cluster)
    assert state.state == "BLOCKED" and "DNS-only" in state.detail
    assert sim.db.query(HAFailoverRun).count() == 0  # never a promotion that the node would refuse
    blocked = _finding(sim, "DHCP_HANDOVER_BLOCKED")
    _assert_actionable(blocked)
    assert blocked.disposition == BLOCKED and "pihole.toml writable" in blocked.no_repair_reason


# --------------------------------------------------------------------------------------
# Blocked handovers: one explanation and one valid next step each
# --------------------------------------------------------------------------------------


def test_mixed_agent_versions_explain_which_node_to_update():
    sim = automatic_cluster()
    _report_with(sim, {"SimPiHole1": {"agent_version": "0.2.15"}})  # SimPiHole1 was rolled back to the older agent
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    for _ in range(4):
        age_vip(sim)
        _report_with(sim, {"SimPiHole1": {"agent_version": "0.2.15"}})
        reconcile_cluster(sim.db, sim.cluster)
        apply_dhcp_actions(sim)
    assert ownership_snapshot(sim)["dhcp_owners"] == []  # no automatic handover across protocol versions
    finding = _finding(sim, "DHCP_HANDOVER_BLOCKED")
    _assert_actionable(finding)
    assert finding.disposition == BLOCKED and "Update the agent on SimPiHole1" in finding.no_repair_reason
    assert finding.severity == "critical" and "cannot get addresses" in finding.impact  # nobody serves DHCP


def test_missing_leases_explain_the_wait_and_record_the_failed_attempt():
    sim = automatic_cluster()
    stage_snapshot(sim, sim.two, sim.two)  # the staged snapshot is not SimPiHole1's leases
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    drive(sim, rounds=4)
    sim.db.add(HAFailoverRun(cluster_id=sim.cluster.id, source_node_id=sim.one.id, target_node_id=sim.two.id, status="FAILED_SAFE",
                             phase="FAILED_SAFE", dhcp_managed=True, role_generation=sim.cluster.role_generation,
                             error_redacted="The staged lease snapshot failed its checksum; the live lease file was not changed.",
                             report_json=json.dumps({"transition_kind": "AUTOMATIC_DHCP_HANDOVER"}),
                             created_at=datetime.utcnow() - timedelta(minutes=20), completed_at=datetime.utcnow() - timedelta(minutes=19)))
    sim.db.commit()
    sim.db.expire_all()  # as a fresh request session would load it
    finding = _finding(sim, "DHCP_HANDOVER_BLOCKED")
    _assert_actionable(finding)
    assert "Waiting for leases" in finding.condition and "restart Keepalived on SimPiHole2" in finding.no_repair_reason
    assert any("failed safe" in attempt and "checksum" in attempt for attempt in finding.automatic_attempts)


def test_cooldown_is_reported_as_self_healing_and_does_clear_automatically():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    drive(sim)
    sim.vrrp.start("SimPiHole1")
    sim.vrrp.stop("SimPiHole2")
    sim.sim_two.dhcp_running = False
    drive(sim)
    assert handover_assessment(sim.cluster).state == "COOLDOWN"
    finding = _finding(sim, "DHCP_HANDOVER_BLOCKED")
    _assert_actionable(finding)
    assert finding.disposition == SELF_HEALING and "No action is needed" in finding.no_repair_reason
    # The claim holds: once the window has passed (and SimPiHole2's leases are staged), DHCP moves back by itself.
    stage_snapshot(sim, sim.two, sim.one)
    for run in sim.db.query(HAFailoverRun).all():
        run.created_at -= timedelta(minutes=11)
    sim.db.commit()
    assert drive(sim) == 0
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole1"]


def test_a_silent_holder_keeps_the_fencing_explanation():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.make_stale(sim.sim_one)
    for _ in range(4):
        drive(sim, rounds=1, silent={"SimPiHole1"})
    finding = _finding(sim, "DHCP_HANDOVER_BLOCKED")
    _assert_actionable(finding)
    assert finding.disposition == BLOCKED and "not verified" in finding.condition and "fencing provider" in finding.no_repair_reason


# --------------------------------------------------------------------------------------
# Rollout preflight (read-only)
# --------------------------------------------------------------------------------------


def test_preflight_allows_rollout_only_from_a_verified_aligned_cluster_with_staged_leases():
    sim = automatic_cluster()
    result = preflight(sim.cluster, "agent_rollout")
    assert result["safe"], result["blockers"]
    stage_snapshot(sim, sim.two, sim.two)
    blocked = preflight(sim.cluster, "agent_rollout")
    assert not blocked["safe"] and any("lease snapshot" in item for item in blocked["blockers"])


def test_preflight_for_kaya_rollback_warns_to_reinstall_the_agents_straight_after():
    sim = automatic_cluster()
    result = preflight(sim.cluster, "kaya_rollback")
    assert result["safe"] and "run the agent update on SimPiHole1, SimPiHole2" in result["warnings"][0]
    _report_with(sim, {"SimPiHole1": {"agent_version": "0.2.15"}, "SimPiHole2": {"agent_version": "0.2.15"}})
    assert preflight(sim.cluster, "kaya_rollback")["warnings"] == []


def test_preflight_blocks_any_step_while_dhcp_and_the_vip_are_split_or_an_operation_runs():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")  # Virtual IP moves; DHCP still on SimPiHole1
    report(sim)
    for step in ("agent_rollout", "agent_rollback", "kaya_rollback"):
        result = preflight(sim.cluster, step)
        assert not result["safe"] and any("Virtual IP" in item for item in result["blockers"])
    with pytest.raises(ValueError):
        preflight(sim.cluster, "delete_everything")


# --------------------------------------------------------------------------------------
# A promotion the node refuses (lab finding): the reason, the real impact, and a rollback that can work
# --------------------------------------------------------------------------------------


def _refused_promotion(sim, *, source_down):
    from app.services.ha_failover import active_failover, desired_failover_action, record_failover_action_result

    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    for _ in range(6):
        age_vip(sim)
        report(sim)
        reconcile_cluster(sim.db, sim.cluster)
        action = desired_failover_action(sim.cluster, sim.two)
        if action and action["action_type"] == "DHCP_PROMOTE":
            break
    record_failover_action_result(sim.db, sim.two, action_type="DHCP_PROMOTE", generation=action["generation"], checksum=action["checksum"],
                                  status="FAILED", message="The staged lease snapshot failed its checksum; the live lease file was not changed.")
    sim.db.commit()
    for _ in range(4):  # verification times out, the bounded repair is refused too, then it stops safely
        run = active_failover(sim.cluster)
        if run is None:
            break
        data = json.loads(run.report_json or "{}")
        data["verification_started_at"] = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        run.report_json = json.dumps(data)
        sim.db.commit()
        if source_down:
            sim.make_stale(sim.sim_one)
        report(sim, silent={"SimPiHole1"} if source_down else frozenset())
        reconcile_cluster(sim.db, sim.cluster)
        repair = desired_failover_action(sim.cluster, sim.two)
        if repair and repair["action_type"] == "DHCP_PROMOTE":
            record_failover_action_result(sim.db, sim.two, action_type="DHCP_PROMOTE", generation=repair["generation"], checksum=repair["checksum"],
                                          status="FAILED", message="The staged lease snapshot failed its checksum; the live lease file was not changed.")
            sim.db.commit()
    sim.db.expire_all()
    run = sim.db.query(HAFailoverRun).order_by(HAFailoverRun.id.desc()).first()
    assert run.status == "FAILED_SAFE", (run.status, run.phase)
    return run


def test_a_refused_promotion_reports_the_nodes_reason_and_the_real_dhcp_impact():
    sim = automatic_cluster()
    run = _refused_promotion(sim, source_down=True)
    assert "failed its checksum" in run.error_redacted  # the node's own reason, not only "did not converge"
    hold = _finding(sim, "MAINTENANCE_HOLD")
    assert hold is not None and "failed its checksum" in hold.condition
    assert "No node serves DHCP" in hold.impact and hold.severity == "critical"  # never "DNS and DHCP keep running"
    assert hold.repair is None and "Bring SimPiHole1 back first" in hold.no_repair_reason  # rollback cannot work yet


def test_rollback_is_offered_once_the_original_node_can_take_services_back():
    sim = automatic_cluster()
    _refused_promotion(sim, source_down=False)
    sim.sim_one.vrrp_state = "BACKUP"
    sim.vrrp.start("SimPiHole1")  # Keepalived running again on the original node
    report(sim)
    sim.db.expire_all()
    hold = _finding(sim, "MAINTENANCE_HOLD")
    assert hold is not None and hold.repair is not None and hold.repair.key == "FAILOVER_ROLLBACK"
