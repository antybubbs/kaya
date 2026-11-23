"""Revised automatic DHCP handover protocol (PROPOSAL, not approved): verified release, never silence.

A node never promotes DHCP on its own.  Kaya promotes the Virtual IP owner only after positive,
fresh, signed evidence that the other node is not serving DHCP (or fresh, positive external fencing
evidence; an administrator's typed confirmation is recorded only).  Silence, an unanswered ARP probe or an unanswered DHCPDISCOVER is never
treated as release.  Synthetic data only.
"""

from __future__ import annotations

import json
import subprocess
from datetime import timedelta

import pytest

pytest.importorskip("fcntl")

from ha_agent import kaya_ha_transition as transition  # noqa: E402
from app.models.models import AuditLog, HAFailoverRun, HAMaintenanceRun  # noqa: E402
from app.services.ha_agents import desired_state, record_heartbeat  # noqa: E402
from app.services.ha_assessment import BLOCKED, assess_cluster  # noqa: E402
from app.services.ha_dhcp_handover import (  # noqa: E402
    HANDOVER_AGENT_VERSION,
    HADHCPHandoverError,
    handover_assessment,
    record_physical_check,
)
from app.services.ha_failover import active_failover, desired_failover_action, record_failover_action_result  # noqa: E402
from app.services.ha_watchdog import drain_evaluations, reconcile_cluster  # noqa: E402
from ha_simulation import hal_like_cluster, heartbeat_for, ownership_snapshot, sqlite_session  # noqa: E402
from test_ha_gate_a_agent_defects import agent_state, read_state, run_hook  # noqa: E402

AGENT = ".".join(str(part) for part in HANDOVER_AGENT_VERSION)
AUTOMATIC = {"automatic_failover": True, "maintenance_mode": False, "dhcp_managed": True}


# --------------------------------------------------------------------------------------
# Node side
# --------------------------------------------------------------------------------------


def test_master_hook_never_promotes_dhcp_even_with_automatic_failover_on(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    agent_state(root, observed_role="STANDBY", vip_owned=False, dns_healthy=True, **AUTOMATIC)
    code, commands = run_hook(monkeypatch, root, "master", 37)
    assert code == 0
    assert not any("promote" in " ".join(command) for command in commands)
    state = read_state(root)
    assert state["observed_role"] == "ACTIVE" and state["vip_owned"] is True


def test_stop_hook_releases_dhcp_under_the_gates_and_fence(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    agent_state(root, observed_role="ACTIVE", vip_owned=True, dhcp_running=True, **AUTOMATIC)
    code, commands = run_hook(monkeypatch, root, "stop", 37)
    assert code == 0 and any("automatic-demote" in command for command in commands)
    assert read_state(root)["keepalived_runtime_state"] == "STOPPED"
    gated = tmp_path / "gated"
    agent_state(gated, observed_role="ACTIVE", vip_owned=True, **{**AUTOMATIC, "maintenance_mode": True})
    assert run_hook(monkeypatch, gated, "stop", 37) == (0, [])
    stale = tmp_path / "stale"
    agent_state(stale, observed_role="ACTIVE", vip_owned=True, **AUTOMATIC)
    assert run_hook(monkeypatch, stale, "stop", 36) == (3, [])


def _helper(tmp_path, monkeypatch, argv, values, probe_result):
    from ha_agent import kaya_ha_failover_helper as helper

    monkeypatch.setattr(helper, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(helper, "LOCK_FILE", tmp_path / "dhcp.lock")
    monkeypatch.setattr(helper, "AUTHORITY_FILE", tmp_path / "dhcp-authority.json")
    monkeypatch.setattr(helper, "GUARD_ENV", tmp_path / "guard" / "ftl.env")
    (tmp_path / "boot_id").write_text("00000000-0000-4000-8000-00000000b007")
    monkeypatch.setattr(helper, "BOOT_ID", tmp_path / "boot_id")
    monkeypatch.setattr(helper, "_address_present", lambda address: True)
    monkeypatch.setattr(helper, "_environment_forces_dhcp", lambda: False)
    monkeypatch.setattr(helper.sys, "argv", argv)
    monkeypatch.setattr(helper.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(helper, "_state", lambda key, default=None: values.get(key, default))
    monkeypatch.setattr(helper, "_owns_vip", lambda: True)
    calls = {"set_dhcp": [], "lease_writes": 0, "lease_sources": []}
    monkeypatch.setattr(helper, "_set_dhcp", lambda enabled: calls["set_dhcp"].append(enabled) or {"configured": enabled, "listening": enabled})
    monkeypatch.setattr(helper, "_wait_for_dns", lambda: None)
    monkeypatch.setattr(helper, "_backup", lambda generation: (tmp_path / "backup", (0, 0, 0o644)))
    monkeypatch.setattr(helper, "_lease_lines", lambda generation, source=None: calls["lease_sources"].append(source) or "")
    monkeypatch.setattr(helper, "_atomic_write", lambda *args, **kwargs: calls.__setitem__("lease_writes", calls["lease_writes"] + 1))
    monkeypatch.setattr(helper, "_other_dhcp_server", lambda interface: probe_result)
    monkeypatch.setattr(helper, "_dhcp_status", lambda: {"listening": False, "runtime_state": "STOPPED", "observation_status": "FRESH"})
    return helper, calls


def test_node_local_automatic_promotion_is_refused(tmp_path, monkeypatch):
    values = {**AUTOMATIC, "keepalived_generation": 37, "dns_healthy": True, "observed_role": "ACTIVE", "vip_owned": True}
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "automatic-promote", "37"], values, False)
    with pytest.raises(RuntimeError) as raised:
        helper.main()
    assert "Kaya" in str(raised.value) and calls["set_dhcp"] == [] and calls["lease_writes"] == 0


def test_kaya_granted_promotion_is_vetoed_by_another_server_but_never_proven_by_silence(tmp_path, monkeypatch, capsys):
    values = {"failover_generation": 9, "failover_authority_epoch": 1, "dns_healthy": True, "observed_role": "ACTIVE", "vip_owned": True,
              "network_interface": "eth0", "failover_lease_generation": 8}
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], values, "192.0.2.2")
    with pytest.raises(RuntimeError) as raised:
        helper.main()
    assert "still answering" in str(raised.value) and calls["set_dhcp"] == []
    # An unavailable or silent probe is not evidence either way: Kaya's verified release is.
    for silent in (False, None):
        helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], values, silent)
        helper.main()
        output = json.loads(capsys.readouterr().out)
        assert calls["set_dhcp"] == [True] and output["status"] == "applied"
        assert output["discovery_check"] == ("no_offer" if silent is False else "unavailable")


def test_sudo_policy_no_longer_allows_node_local_promotion():
    from app.services.ha_agent_installer import agent_file

    sudoers = agent_file("kaya-ha-agent.sudoers").decode()
    assert "automatic-promote" not in sudoers and "automatic-demote" in sudoers


def test_older_agents_never_receive_the_automatic_gate():
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False, automatic_failover=True, suffix="gate")
    for simnode, node in ((sim.sim_one, sim.one), (sim.sim_two, sim.two)):
        record_heartbeat(sim.db, node, heartbeat_for(simnode).model_copy(update={"agent_version": "0.2.15"}))
    assert desired_state(sim.one)["automatic_failover"] is False
    for simnode, node in ((sim.sim_one, sim.one), (sim.sim_two, sim.two)):
        record_heartbeat(sim.db, node, heartbeat_for(simnode).model_copy(update={"agent_version": AGENT}))
    assert desired_state(sim.one)["automatic_failover"] is True


# --------------------------------------------------------------------------------------
# Kaya side: verified release, never silence
# --------------------------------------------------------------------------------------


def stage_snapshot(sim, source, target, generation=None):
    """Kaya captured ``source``'s leases and the agent on ``target`` staged them (as the lease monitor does)."""
    import hashlib

    from app.models.models import HALeaseSnapshot
    from app.core.security import encrypt_secret

    replication = sim.cluster.lease_replication
    generation = generation or int(replication.applied_generation or 0) + 1
    payload = json.dumps({"version": 1, "cluster_id": sim.cluster.public_id, "source_node_id": source.public_id, "leases": []},
                         sort_keys=True, separators=(",", ":"))
    sim.db.add(HALeaseSnapshot(cluster_id=sim.cluster.id, source_node_id=source.id, target_node_id=target.id, generation=generation,
                               checksum=hashlib.sha256(payload.encode()).hexdigest(), encrypted_payload=encrypt_secret(payload),
                               lease_count=0, status="STAGED"))
    replication.source_node_id, replication.target_node_id = source.id, target.id
    replication.desired_generation = replication.applied_generation = generation
    sim.db.commit()


def automatic_cluster():
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False, automatic_failover=True, suffix="handover")
    stage_snapshot(sim, sim.one, sim.two)
    sim.offered = []
    report(sim)
    report(sim)
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole1"] and ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole1"]
    return sim


def pairs(sim):
    return ((sim.sim_one, sim.one), (sim.sim_two, sim.two))


def report(sim, *, silent=frozenset()):
    for simnode, node in pairs(sim):
        if simnode.name in silent:
            continue
        # Like the agent, report the role generation learned from Kaya's desired state.
        record_heartbeat(sim.db, node, heartbeat_for(simnode, observed_generation=sim.cluster.role_generation).model_copy(update={"agent_version": AGENT}))
        sim.offered.extend(desired_state(node)["allowed_actions"])
    drain_evaluations(sim.db)


def apply_dhcp_actions(sim, *, silent=frozenset()):
    """The agents carry out Kaya's DHCP actions (promotion only on the VIP owner, as the runtime enforces)."""
    for simnode, node in pairs(sim):
        action = desired_failover_action(sim.cluster, node)
        if action is None or simnode.name in silent:
            continue
        if action["action_type"] == "DHCP_PROMOTE" and not simnode.vip_owned:
            continue
        simnode.dhcp_running = action["action_type"] == "DHCP_PROMOTE"
        record_failover_action_result(sim.db, node, action_type=action["action_type"], generation=action["generation"],
                                      checksum=action["checksum"], status="APPLIED", message="synthetic")
    drain_evaluations(sim.db)


def age_vip(sim, seconds=15):
    for node in sim.cluster.nodes:
        if node.vip_stable_since:
            node.vip_stable_since -= timedelta(seconds=seconds)
    sim.db.commit()


def drive(sim, *, rounds=8, silent=frozenset()):
    dual = 0
    for _ in range(rounds):
        age_vip(sim)
        report(sim, silent=silent)
        reconcile_cluster(sim.db, sim.cluster)
        apply_dhcp_actions(sim, silent=silent)
        dual += sum(simnode.dhcp_running for simnode, _node in pairs(sim)) > 1
    return dual


def test_graceful_stop_with_verified_release_hands_dhcp_to_the_vip_owner():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False  # the stop hook released DHCP locally
    assert drive(sim) == 0
    snapshot = ownership_snapshot(sim)
    assert snapshot["vip_owners"] == ["SimPiHole2"] and snapshot["dhcp_owners"] == ["SimPiHole2"]
    run = sim.db.query(HAFailoverRun).order_by(HAFailoverRun.id.desc()).first()
    report_json = json.loads(run.report_json)
    assert run.status == "SUCCEEDED" and report_json["transition_kind"] == "AUTOMATIC_DHCP_HANDOVER"
    assert report_json["release_evidence"] == "verified_signed_report"
    assert sim.cluster.maintenance_mode is False


def test_a_peer_still_serving_without_the_vip_is_demoted_and_verified_before_promotion():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")  # its hook failed: it still serves DHCP (as with a silent, ignore-unknown server)
    assert sim.sim_one.dhcp_running
    assert drive(sim) == 0  # never two DHCP servers at any step
    snapshot = ownership_snapshot(sim)
    assert snapshot["dhcp_owners"] == ["SimPiHole2"] and not sim.sim_one.dhcp_running


@pytest.mark.parametrize("cause", ["agent_crash_or_partition", "host_dead"])
def test_a_silent_peer_is_never_treated_as_released(cause):
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    if cause == "host_dead":
        sim.sim_one.dhcp_running = False  # really gone, but Kaya cannot know it
    sim.make_stale(sim.sim_one)
    assert drive(sim, silent={"SimPiHole1"}) == 0
    assert active_failover(sim.cluster) is None and not sim.sim_two.dhcp_running  # fail closed: no promotion
    assert not {"DHCP_PROMOTE"} & set(sim.offered)
    assert not any(run.operation == "DHCP_SELF_HEAL" and run.status != "FAILED_SAFE"
                   for run in sim.db.query(HAMaintenanceRun).all() if run.status == "SUCCEEDED")
    state = handover_assessment(sim.cluster)
    assert state.state == "BLOCKED_SOURCE_SILENT" and state.source.display_name == "SimPiHole1"
    finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "DHCP_HANDOVER_BLOCKED")
    assert finding.severity == "critical" and finding.disposition == BLOCKED
    assert "not verified" in finding.condition and "fencing provider" in finding.no_repair_reason
    assert "recorded only" in finding.no_repair_reason


def test_dual_vip_never_starts_a_handover():
    sim = automatic_cluster()
    sim.vrrp.partition()
    assert drive(sim) == 0
    assert active_failover(sim.cluster) is None


def test_an_unstable_vip_owner_does_not_start_a_handover():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    report(sim)
    reconcile_cluster(sim.db, sim.cluster)  # VIP owner stable for less than the window
    assert active_failover(sim.cluster) is None


def test_one_automatic_handover_per_incident():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    drive(sim)
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole2"]
    # The next unplanned move inside the cooldown is not handled automatically.
    sim.vrrp.start("SimPiHole1")
    sim.vrrp.stop("SimPiHole2")
    sim.sim_two.dhcp_running = False
    drive(sim)
    assert handover_assessment(sim.cluster).state == "COOLDOWN"
    assert not sim.sim_one.dhcp_running


def test_self_heal_never_promotes_on_peer_silence():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.make_stale(sim.sim_one)
    for _ in range(4):
        age_vip(sim)
        report(sim, silent={"SimPiHole1"})
        reconcile_cluster(sim.db, sim.cluster)
    assert not any(run.operation == "DHCP_SELF_HEAL" for run in sim.db.query(HAMaintenanceRun).all())


# --------------------------------------------------------------------------------------
# Manual recovery: administrator fencing confirmation
# --------------------------------------------------------------------------------------


def silent_peer():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.make_stale(sim.sim_one)
    drive(sim, rounds=3, silent={"SimPiHole1"})
    return sim


def test_a_typed_physical_check_is_recorded_and_audited_but_never_promotes():
    sim = silent_peer()
    with pytest.raises(HADHCPHandoverError):
        record_physical_check(sim.db, sim.cluster, sim.admin, checked_node_public_id=sim.one.public_id,
                              confirmation="wrong", acknowledged=True)
    record_physical_check(sim.db, sim.cluster, sim.admin, checked_node_public_id=sim.one.public_id,
                          confirmation=sim.cluster.name, acknowledged=True)
    audit = sim.db.query(AuditLog).filter(AuditLog.entity == "ha_dhcp_handover", AuditLog.action == "physical_check_recorded").one()
    metadata = json.loads(audit.metadata_json)
    assert metadata["checked_node_id"] == sim.one.public_id and metadata["authorises_dhcp"] is False
    drive(sim, silent={"SimPiHole1"})
    assert active_failover(sim.cluster) is None and not sim.sim_two.dhcp_running  # still fail closed
    assert handover_assessment(sim.cluster).state == "BLOCKED_SOURCE_SILENT"


def test_a_physical_check_is_refused_for_a_node_outside_the_cluster():
    sim = silent_peer()
    with pytest.raises(HADHCPHandoverError):
        record_physical_check(sim.db, sim.cluster, sim.admin, checked_node_public_id="not-a-node",
                              confirmation=sim.cluster.name, acknowledged=True)


def test_hook_refused_promotion_never_reports_dhcp_running(monkeypatch):
    """Compatibility: an older hook calling the removed command records the refusal, never success."""
    from test_high_availability_automatic import state_database

    db = state_database()
    monkeypatch.setattr(transition.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(transition.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, '{"status":"applied"}', ""))
    transition.automatic_transition(db, "master", 8)
    assert db.execute("SELECT value FROM state WHERE key='dhcp_running'").fetchone() is None


def test_handover_bounds_are_explicit():
    from app.services.ha_dhcp_handover import COOLDOWN_SECONDS, STABILITY_SECONDS

    assert STABILITY_SECONDS == 10 and COOLDOWN_SECONDS == 600  # the lab measures end-to-end time


def test_fencing_route_is_admin_only_csrf_protected_validated_and_rendered(monkeypatch):
    import asyncio

    from fastapi import HTTPException

    from app.routers import high_availability as router
    from test_ha_p6_align_ownership import form_request, page_request

    async def inline(function, *args, **kwargs):  # in-memory SQLite cannot cross threads
        return function(*args, **kwargs)

    monkeypatch.setattr(router, "run_in_threadpool", inline)
    route = next(item for item in router.router.routes if getattr(item, "path", "") == "/high-availability/clusters/{public_id}/maintenance/dhcp-fencing")
    assert any(getattr(dependency.call, "__name__", "") == "require_ha_admin" for dependency in route.dependant.dependencies)
    sim = silent_peer()
    base = f"/high-availability/clusters/{sim.cluster.public_id}"
    body = router.cluster_maintenance(sim.cluster.public_id, page_request(base + "/maintenance"), db=sim.db, user=sim.admin).body.decode()
    assert 'id="dhcp-fencing"' in body and "data-ha-dhcp-fencing-form" in body and "Record physical check" in body
    assert "does not start DHCP" in body and "No fencing provider is configured" in body
    path = base + "/maintenance/dhcp-fencing"
    good = {"csrf_token": "csrf", "fenced_node_id": sim.one.public_id, "confirmation": sim.cluster.name, "acknowledge_fencing": "1"}
    for bad in ({"csrf_token": "forged"}, {"fenced_node_id": "../x"}, {"confirmation": "x" * 201}):
        with pytest.raises(HTTPException) as raised:
            asyncio.run(router.confirm_dhcp_fencing(sim.cluster.public_id, form_request(path, {**good, **bad}), db=sim.db, user=sim.admin))
        assert raised.value.status_code == 400
    refused = asyncio.run(router.confirm_dhcp_fencing(sim.cluster.public_id, form_request(path, {**good, "acknowledge_fencing": ""}), db=sim.db, user=sim.admin))
    assert refused.status_code == 409 and active_failover(sim.cluster) is None
    accepted = asyncio.run(router.confirm_dhcp_fencing(sim.cluster.public_id, form_request(path, good), db=sim.db, user=sim.admin))
    assert accepted.status_code == 303 and accepted.headers["location"].endswith("fencing=recorded#dhcp-fencing")
    assert active_failover(sim.cluster) is None and not sim.sim_two.dhcp_running  # recorded, never promoted


def test_no_handover_unless_the_target_is_verified_released():
    """Lab finding: a target whose DHCP state was briefly not 'active' (but not proven stopped) got a promotion."""
    from app.services.ha_dhcp_handover import handover_assessment as assess

    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    report(sim)
    age_vip(sim)
    sim.two.dhcp_observation_status = "UNAVAILABLE"
    sim.two.dhcp_runtime_state = "UNKNOWN"
    sim.two.dhcp_listener_active = None  # no listener observation: the target's DHCP state is genuinely unknown
    sim.db.commit()
    assert assess(sim.cluster).state not in {"READY_PROMOTE", "READY_DEMOTE_FIRST"}


def test_helper_never_replaces_the_lease_file_of_a_node_already_serving(tmp_path, monkeypatch, capsys):
    values = {"failover_generation": 9, "failover_authority_epoch": 1, "dns_healthy": True, "observed_role": "ACTIVE", "vip_owned": True,
              "network_interface": "eth0", "failover_lease_generation": 8}
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], values, False)
    monkeypatch.setattr(helper, "_dhcp_status", lambda: {"listening": True, "runtime_state": "RUNNING", "observation_status": "FRESH", "configured": True})
    helper.main()
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "applied" and output.get("already_serving") is True
    assert calls["lease_writes"] == 0  # live leases untouched


def test_start_up_convergence_does_not_block_a_later_genuine_failover():
    """Lab finding: Keepalived start-up releases DHCP on the future master (backup hook) and Kaya re-promotes it.
    That convergence must not consume the anti-flap cooldown for the next, genuine failover."""
    sim = automatic_cluster()
    sim.sim_one.dhcp_running = False  # start-up: lab-a's backup hook released DHCP before it became master
    drive(sim)
    assert sim.sim_one.dhcp_running and active_failover(sim.cluster) is None  # Kaya re-promoted the VIP owner (A -> A)
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False  # genuine failover: stop hook released DHCP
    drive(sim)
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole2"]  # not blocked by the cooldown
