"""DHCP continuity revision (DHCP handover PROPOSAL; not approved): leases, DNS-only start, Kaya outages.

* A node keeps its live lease file when authority never left it, and installs only a verified
  snapshot of the previous holder when authority moves; a failed promotion never leaves a partial
  or stale lease file behind.
* "Released" means DHCP configured off *and* not listening: a holder whose FTL is restarting (still
  configured on) is never treated as having handed over.
* A node that has seen a newer authority epoch than Kaya's record (database restore) makes Kaya
  stop sending authority instructions and re-establish authority above that epoch.
Synthetic data only.
"""

from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest

pytest.importorskip("fcntl")

from app.schemas.high_availability import HAAgentHeartbeat  # noqa: E402
from app.services.ha_agents import desired_state, record_heartbeat  # noqa: E402
from app.services.ha_assessment import assess_cluster  # noqa: E402
from app.services.ha_dhcp_authority import (  # noqa: E402
    authority,
    authority_behind,
    authority_for_node,
    grant_authority,
    promotion_terms,
)
from app.services.ha_dhcp_handover import handover_assessment  # noqa: E402
from app.services.ha_failover import active_failover, desired_failover_action, record_failover_action_result  # noqa: E402
from app.services.ha_topology import dhcp_observation  # noqa: E402
from app.services.ha_watchdog import drain_evaluations, reconcile_cluster  # noqa: E402
from ha_simulation import heartbeat_for, ownership_snapshot  # noqa: E402
from test_ha_dhcp_handover_protocol import AGENT, _helper, age_vip, automatic_cluster, pairs, report  # noqa: E402

BOOT = "00000000-0000-4000-8000-00000000b007"  # the boot id the _helper fixture installs


def _record(tmp_path, **values):
    (tmp_path / "dhcp-authority.json").write_text(json.dumps(values))


def _promote_values(**extra):
    return {"failover_generation": 9, "failover_authority_epoch": 12, "dns_healthy": True, "observed_role": "ACTIVE",
            "vip_owned": True, "network_interface": "eth0", "failover_lease_generation": 8, **extra}


# --------------------------------------------------------------------------------------
# Node: which lease file a promotion uses
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("record, extra, installs", [
    # Authority never left this node: its live leases are newer than any snapshot.
    ({"epoch": 11, "state": "HELD"}, {"failover_lease_mode": "continue", "failover_previous_epoch": 11, "failover_holder_since": 9}, False),
    ({"epoch": 10, "state": "VOIDED"}, {"failover_lease_mode": "continue", "failover_previous_epoch": 11, "failover_holder_since": 9}, False),
    ({"epoch": 11, "state": "RELEASED"}, {"failover_lease_mode": "continue", "failover_previous_epoch": 11, "failover_holder_since": None}, False),
    (None, {"failover_lease_mode": "continue", "failover_previous_epoch": 11, "failover_holder_since": 9}, False),
    # This node's own record contradicts "continue": it never served since authority came to it.
    ({"epoch": 11, "state": "REVOKED"}, {"failover_lease_mode": "continue", "failover_previous_epoch": 11, "failover_holder_since": 9}, True),
    ({"epoch": 8, "state": "VOIDED"}, {"failover_lease_mode": "continue", "failover_previous_epoch": 11, "failover_holder_since": 9}, True),
    ({"epoch": 11, "state": "FAILED"}, {"failover_lease_mode": "continue", "failover_previous_epoch": 11, "failover_holder_since": 9}, True),
    # Authority moves to this node: the previous holder's verified snapshot.
    ({"epoch": 11, "state": "REVOKED"}, {"failover_lease_mode": "transfer", "failover_lease_source": "node-a"}, True),
    (None, {}, True),  # no lease instruction at all: transfer (verified snapshot only)
    # A rollback keeps this node's original leases, as before.
    ({"epoch": 11, "state": "REVOKED"}, {"failover_lease_mode": "transfer", "failover_restore_original": True}, False),
])
def test_promotion_keeps_live_leases_only_when_authority_never_left_the_node(tmp_path, monkeypatch, capsys, record, extra, installs):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], _promote_values(**extra), False)
    if record is not None:
        _record(tmp_path, **record)
    helper.main()
    output = json.loads(capsys.readouterr().out)
    assert calls["set_dhcp"] == [True]
    assert calls["lease_writes"] == (1 if installs else 0)
    assert output["leases"] == ("installed" if installs else "kept")
    if installs:
        assert calls["lease_sources"] == [extra.get("failover_lease_source")]  # verified against the previous holder


def _snapshot(path, *, generation=8, source="node-a", leases=None, checksum=None):
    payload = {"version": 1, "cluster_id": "cluster", "source_node_id": source,
               "leases": leases if leases is not None else [{"ip": "192.0.2.120", "hwaddr": "02:00:00:00:00:41", "expires": 2000000000,
                                                             "name": "synthetic-client", "clientid": "*"}]}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generation": generation, "checksum": checksum or digest, "payload": payload}))


def test_only_a_verified_snapshot_of_the_previous_holder_is_ever_installed(tmp_path, monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    snapshot = tmp_path / "lease-snapshots" / "current.json"
    monkeypatch.setattr(helper, "SNAPSHOT", snapshot)
    _snapshot(snapshot)
    assert helper._lease_lines(8, "node-a") == "2000000000 02:00:00:00:00:41 192.0.2.120 synthetic-client *\n"
    assert helper._lease_lines(8) == helper._lease_lines(8, "node-a")  # no source named: checksum and generation only
    _snapshot(snapshot, generation=11)  # staged after the run started (a renewal): newer, same holder
    assert helper._lease_lines(8, "node-a") == "2000000000 02:00:00:00:00:41 192.0.2.120 synthetic-client *\n"
    for case, kwargs, generation, source in (
        ("wrong source (stale holder)", {"source": "node-c"}, 8, "node-a"),
        ("stale generation", {"generation": 7}, 8, "node-a"),
        ("checksum mismatch (corrupted or tampered)", {"checksum": "0" * 64}, 8, "node-a"),
    ):
        _snapshot(snapshot, **kwargs)
        with pytest.raises(RuntimeError) as raised:
            helper._lease_lines(generation, source)
        assert any(word in str(raised.value) for word in ("not captured", "older", "checksum")), case
    snapshot.write_text('{"generation": 8, "checksum": "')  # truncated on disk
    with pytest.raises(RuntimeError, match="live lease file was not changed"):
        helper._lease_lines(8, "node-a")
    snapshot.unlink()  # lost
    with pytest.raises(RuntimeError, match="live lease file was not changed"):
        helper._lease_lines(8, "node-a")


def test_a_failed_promotion_restores_the_exact_live_lease_file_and_marks_the_grant_failed(tmp_path, monkeypatch):
    values = _promote_values(failover_lease_mode="transfer", failover_lease_source="node-a")
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], values, False)
    backup = tmp_path / "backup"
    backup.write_text("1999999999 02:00:00:00:00:51 192.0.2.121 live-client *\n")
    writes = []
    monkeypatch.setattr(helper, "_atomic_write", lambda path, content, ownership=None: writes.append(content))
    monkeypatch.setattr(helper, "_lease_lines", lambda generation, source=None: "snapshot-content\n")

    def set_dhcp(enabled):
        calls["set_dhcp"].append(enabled)
        if enabled:
            raise RuntimeError("Pi-hole accepted the DHCP setting but did not start serving on UDP port 67.")
        return {"configured": False, "listening": False}

    monkeypatch.setattr(helper, "_set_dhcp", set_dhcp)
    with pytest.raises(RuntimeError):
        helper.main()
    assert writes == ["snapshot-content\n", backup.read_text()]  # replaced, then restored byte for byte
    assert calls["set_dhcp"] == [True, False]
    assert json.loads((tmp_path / "dhcp-authority.json").read_text())["state"] == "FAILED"  # never continued or trusted


def test_a_snapshot_that_fails_verification_leaves_the_live_lease_file_untouched(tmp_path, monkeypatch):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], _promote_values(failover_lease_mode="transfer"), False)

    def unverified(generation, source=None):
        raise RuntimeError("The staged lease snapshot failed its checksum; the live lease file was not changed.")

    monkeypatch.setattr(helper, "_lease_lines", unverified)
    with pytest.raises(RuntimeError, match="checksum"):
        helper.main()
    assert calls["lease_writes"] == 0 and calls["set_dhcp"] == [False]  # nothing written; DHCP stays off


def test_atomic_lease_write_never_leaves_a_partial_file(tmp_path, monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    live = tmp_path / "dhcp.leases"
    live.write_text("1999999999 02:00:00:00:00:51 192.0.2.121 live-client *\n")
    original = live.read_bytes()

    def failing_replace(source, destination):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(helper.os, "replace", failing_replace)
    with pytest.raises(OSError):
        helper._atomic_write(live, "new content\n", (os.getuid(), os.getgid(), 0o644))
    assert live.read_bytes() == original and sorted(item.name for item in tmp_path.iterdir()) == ["dhcp.leases"]


# --------------------------------------------------------------------------------------
# Node: what "configured" means, and what the agent reports
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("environment, on_disk, expected", [
    ((True, "false"), True, False),   # FTL started DNS-only: its environment wins over pihole.toml
    ((True, "true"), False, True),
    ((True, "0"), False, True),       # unfamiliar spelling: counted as on, never as released
    ((False, None), True, True),
    ((False, None), False, False),
])
def test_effective_dhcp_setting_is_what_the_running_ftl_obeys(monkeypatch, environment, on_disk, expected):
    from ha_agent import kaya_ha_failover_helper as helper

    monkeypatch.setattr(helper, "_ftl_environment_value", lambda: environment)
    monkeypatch.setattr(helper, "_configured_on_disk", lambda extra_env=None: on_disk)
    assert helper._dhcp_active() is expected


def test_helper_commands_never_inherit_ftl_environment_settings(monkeypatch):
    from ha_agent import kaya_ha_failover_helper as helper

    seen = {}
    monkeypatch.setenv("FTLCONF_dhcp_active", "true")
    monkeypatch.setattr(helper.subprocess, "run", lambda command, **kwargs: seen.update(kwargs["env"]) or SimpleNamespace(returncode=0, stdout="false"))
    helper._run(["pihole-FTL", "--config", "dhcp.active"])
    assert "FTLCONF_dhcp_active" not in seen
    helper._run(["pihole-FTL", "--config", "dhcp.active"], {"FTLCONF_dhcp_active": "false"})
    assert seen["FTLCONF_dhcp_active"] == "false"


class _State(dict):
    def get(self, key, default=None):
        return super().get(key, default)

    def set(self, key, value):
        self[key] = value


@pytest.mark.parametrize("reported, stored", [(7, 7), (None, None), (0, None), (True, None), (2**31, None), ("7", None)])
def test_agent_reports_only_a_valid_authority_epoch(reported, stored):
    from ha_agent.failover_runtime import refresh_dhcp_state

    state = _State()
    output = {"configured": True, "service_active": True, "listening": True, "runtime_state": "RUNNING", "observation_status": "FRESH",
              "dhcp_running": True, "authority_epoch": reported}
    refresh_dhcp_state(state, runner=lambda command: SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr=""))
    assert state["dhcp_authority_epoch"] == stored


@pytest.mark.parametrize("action, expected", [
    ({"lease_mode": "continue", "lease_source": None, "previous_epoch": 4, "holder_since": 2},
     {"lease_mode": "continue", "lease_source": None, "previous_epoch": 4, "holder_since": 2}),
    ({"lease_mode": "transfer", "lease_source": "0b6c1a52-3f0e-4c55-9a8e-7d1f2e3a4b5c"},
     {"lease_mode": "transfer", "lease_source": "0b6c1a52-3f0e-4c55-9a8e-7d1f2e3a4b5c", "previous_epoch": None, "holder_since": None}),
    ({"lease_mode": "keep-everything", "lease_source": "../../etc/passwd", "previous_epoch": True, "holder_since": -1},
     {"lease_mode": "transfer", "lease_source": None, "previous_epoch": None, "holder_since": None}),
    ({}, {"lease_mode": "transfer", "lease_source": None, "previous_epoch": None, "holder_since": None}),
])
def test_runtime_validates_the_lease_instruction_and_defaults_to_a_verified_transfer(action, expected):
    from ha_agent.failover_runtime import _lease_handover

    assert _lease_handover(action) == expected


# --------------------------------------------------------------------------------------
# Kaya: released means configured off and not listening
# --------------------------------------------------------------------------------------


def _restarting_ftl(sim, simnode):
    """Heartbeat of a node whose FTL is restarting: DHCP still configured on, nothing listening."""
    return heartbeat_for(simnode, observed_generation=sim.cluster.role_generation).model_copy(update={
        "agent_version": AGENT, "dhcp_running": False, "dhcp_configured": True, "dhcp_listener_active": False,
        "ftl_active": False, "dhcp_runtime_state": "STOPPED"})


def test_a_holder_restarting_ftl_is_never_treated_as_released():
    sim = automatic_cluster()
    record_heartbeat(sim.db, sim.one, _restarting_ftl(sim, sim.sim_one))
    from datetime import datetime

    observation = dhcp_observation(sim.one, datetime.utcnow())
    assert observation.state == "INACTIVE" and not observation.released and observation.stopped


def test_no_handover_while_the_old_holder_still_has_dhcp_configured_on():
    sim = automatic_cluster()
    epoch = authority(sim.cluster)["epoch"]
    sim.vrrp.stop("SimPiHole1")  # the Virtual IP moves while the holder's FTL is restarting
    sim.sim_one.dhcp_running = False
    for _ in range(4):
        age_vip(sim)
        record_heartbeat(sim.db, sim.one, _restarting_ftl(sim, sim.sim_one))
        record_heartbeat(sim.db, sim.two, heartbeat_for(sim.sim_two, observed_generation=sim.cluster.role_generation)
                         .model_copy(update={"agent_version": AGENT}))
        drain_evaluations(sim.db)
        reconcile_cluster(sim.db, sim.cluster)
    assert active_failover(sim.cluster) is None and handover_assessment(sim.cluster).state == "BLOCKED"
    assert authority(sim.cluster)["epoch"] == epoch and authority(sim.cluster)["node_id"] == sim.one.public_id
    # Kaya's only action is to turn DHCP off on the old holder (it no longer has the Virtual IP);
    # nothing is promoted until that release is verified.
    from app.services.ha_maintenance import desired_maintenance_action

    assert (desired_maintenance_action(sim.cluster, sim.one) or {}).get("action_type") == "DHCP_DEMOTE"
    assert desired_maintenance_action(sim.cluster, sim.two) is None and desired_failover_action(sim.cluster, sim.two) is None


# --------------------------------------------------------------------------------------
# Kaya: grant history and lease terms
# --------------------------------------------------------------------------------------


def _promotions(sim, rounds=8):
    """Drive the cluster and collect every DHCP_PROMOTE action Kaya offers."""
    seen = []
    for _ in range(rounds):
        age_vip(sim)
        report(sim)
        reconcile_cluster(sim.db, sim.cluster)
        for simnode, node in pairs(sim):
            action = desired_failover_action(sim.cluster, node)
            if action is None or (action["action_type"] == "DHCP_PROMOTE" and not simnode.vip_owned):
                continue
            if action["action_type"] == "DHCP_PROMOTE":
                seen.append((simnode.name, action))
            simnode.dhcp_running = action["action_type"] == "DHCP_PROMOTE"
            record_failover_action_result(sim.db, node, action_type=action["action_type"], generation=action["generation"],
                                          checksum=action["checksum"], status="APPLIED", message="synthetic")
        drain_evaluations(sim.db)
    return seen


def test_start_up_convergence_re_promotes_the_holder_with_its_own_live_leases():
    sim = automatic_cluster()
    established = authority(sim.cluster)
    assert established["holder_since"] is None  # established from a node already serving: its own record decides
    sim.sim_one.dhcp_running = False  # Keepalived start: the backup hook released DHCP; the Virtual IP stays
    promotions = _promotions(sim)
    assert [name for name, _action in promotions] == ["SimPiHole1"]
    action = promotions[0][1]
    assert action["lease_mode"] == "continue" and action["lease_source"] is None
    assert action["previous_epoch"] == established["epoch"] and action["authority_epoch"] == established["epoch"] + 1


def test_a_real_handover_installs_the_previous_holders_snapshot():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    promotions = _promotions(sim)
    assert [name for name, _action in promotions] == ["SimPiHole2"]
    action = promotions[0][1]
    assert action["lease_mode"] == "transfer" and action["lease_source"] == sim.one.public_id
    assert authority(sim.cluster)["holder_since"] == action["authority_epoch"]


def test_grant_history_tracks_an_unbroken_run_of_grants_to_one_node():
    sim = automatic_cluster()
    first = grant_authority(sim.cluster, sim.two, evidence="test")
    again = grant_authority(sim.cluster, sim.two, evidence="test")
    assert first["holder_since"] == first["epoch"] and again["holder_since"] == first["epoch"]
    assert promotion_terms(sim.cluster, sim.two)["lease_mode"] == "continue"
    moved = grant_authority(sim.cluster, sim.one, evidence="test")
    assert moved["previous_node_id"] == sim.two.public_id and moved["holder_since"] == moved["epoch"]
    assert promotion_terms(sim.cluster, sim.one) == {"authority_epoch": moved["epoch"], "previous_epoch": again["epoch"],
                                                     "holder_since": moved["epoch"], "lease_mode": "transfer",
                                                     "lease_source": sim.two.public_id}
    assert promotion_terms(sim.cluster, sim.two) is None  # never offered to a node without authority


# --------------------------------------------------------------------------------------
# Kaya: database restore (record older than what nodes have seen)
# --------------------------------------------------------------------------------------


def _report_epochs(sim, epochs):
    for simnode, node in pairs(sim):
        beat = heartbeat_for(simnode, observed_generation=sim.cluster.role_generation).model_copy(
            update={"agent_version": AGENT, "dhcp_authority_epoch": epochs.get(simnode.name)})
        record_heartbeat(sim.db, node, beat)
    drain_evaluations(sim.db)


def test_a_restored_older_record_is_suspended_then_re_established_above_the_reported_epoch():
    sim = automatic_cluster()
    restored = authority(sim.cluster)["epoch"]
    # The nodes have since seen epoch restored + 5 (grants made after the backup was taken).
    for simnode, node in pairs(sim):
        node.dhcp_authority_epoch = restored + 5 if simnode.name == "SimPiHole1" else restored + 4
    sim.db.commit()
    assert authority_behind(sim.cluster)
    assert authority_for_node(sim.cluster, sim.one) is None and authority_for_node(sim.cluster, sim.two) is None
    assert desired_state(sim.one)["dhcp_authority"] is None  # agents take no authority action
    codes = {finding.code for finding in assess_cluster(sim.db, sim.cluster).findings}
    assert "DHCP_AUTHORITY_RECORD_BEHIND" in codes and "DHCP_SERVED_WITHOUT_AUTHORITY" not in codes
    # The next verified report re-establishes authority above everything the nodes have seen.
    _report_epochs(sim, {"SimPiHole1": restored + 5, "SimPiHole2": restored + 4})
    reconcile_cluster(sim.db, sim.cluster)
    current = authority(sim.cluster)
    assert current["epoch"] == restored + 6 and current["node_id"] == sim.one.public_id
    assert current["previous_node_id"] is None and current["holder_since"] is None  # older history is not trusted
    assert not authority_behind(sim.cluster) and desired_state(sim.one)["dhcp_authority"] == {"epoch": restored + 6, "holder": True}


def test_a_grant_while_behind_is_numbered_above_every_reported_epoch():
    sim = automatic_cluster()
    sim.two.dhcp_authority_epoch = 40
    sim.db.commit()
    record = grant_authority(sim.cluster, sim.two, evidence="test")
    assert record["epoch"] == 41 and record["previous_node_id"] is None


def test_heartbeat_epoch_is_validated_and_offered_only_by_kaya_that_accepts_it():
    sim = automatic_cluster()
    assert desired_state(sim.one)["accepts_dhcp_authority_report"] is True
    base = heartbeat_for(sim.sim_one).model_dump()
    for bad in (0, -1, 2**31):
        with pytest.raises(ValueError):
            HAAgentHeartbeat(**{**base, "dhcp_authority_epoch": bad})
    assert HAAgentHeartbeat(**base).dhcp_authority_epoch is None  # older agents send nothing
    _report_epochs(sim, {"SimPiHole1": 3})
    assert sim.one.dhcp_authority_epoch == 3 and sim.two.dhcp_authority_epoch is None


# --------------------------------------------------------------------------------------
# Regressions found by the Kaya-in-the-loop lab with real FTL
# --------------------------------------------------------------------------------------


def test_a_promotion_that_failed_may_be_retried_under_the_same_grant_but_a_voided_one_may_not(tmp_path, monkeypatch, capsys):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], _promote_values(), False)
    _record(tmp_path, epoch=12, state="FAILED")  # e.g. no snapshot was staged yet; the node never served under epoch 12
    helper.main()
    assert calls["set_dhcp"] == [True] and json.loads((tmp_path / "dhcp-authority.json").read_text())["state"] == "HELD"
    capsys.readouterr()
    for state in ("VOIDED", "RELEASED", "REVOKED"):
        helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], _promote_values(), False)
        _record(tmp_path, epoch=12, state=state)
        with pytest.raises(RuntimeError, match="stale"):
            helper.main()
        assert calls["set_dhcp"] == []


def test_no_transfer_starts_until_the_previous_holders_snapshot_is_staged_on_the_target():
    from test_ha_dhcp_handover_protocol import drive, stage_snapshot

    sim = automatic_cluster()
    stage_snapshot(sim, sim.two, sim.two)  # the staged snapshot is not loop-one's leases
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    assert drive(sim) == 0
    state = handover_assessment(sim.cluster)
    assert state.state == "BLOCKED" and "Waiting for leases" in state.detail
    from app.models.models import HAFailoverRun

    assert sim.db.query(HAFailoverRun).count() == 0  # no run, so no failed-safe hold either
    stage_snapshot(sim, sim.one, sim.two)  # Kaya captured the holder's leases and loop-two staged them
    assert drive(sim) == 0
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole2"]


def test_a_vip_on_the_other_node_never_demotes_the_only_dhcp_server_without_staged_leases():
    from test_ha_dhcp_handover_protocol import drive, stage_snapshot

    sim = automatic_cluster()
    stage_snapshot(sim, sim.two, sim.two)
    sim.vrrp.stop("SimPiHole1")  # Virtual IP moves; loop-one keeps serving (hook did not release it)
    assert sim.sim_one.dhcp_running
    assert drive(sim) == 0
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole1"]  # DHCP keeps working where it is


@pytest.mark.parametrize("state, adopts", [
    ({"dhcp_listener_active": True, "dhcp_running": True, "dhcp_configured": True}, True),        # established holder, no local record
    ({"dhcp_listener_active": True, "dhcp_running": True, "dhcp_configured": True,
      "dhcp_authority_epoch": 4, "dhcp_authority_state": "HELD"}, True),                           # record from an older epoch
    ({"dhcp_listener_active": True, "dhcp_running": True, "dhcp_configured": True,
      "dhcp_authority_epoch": 5, "dhcp_authority_state": "HELD"}, False),                          # already recorded
    ({"dhcp_listener_active": False, "dhcp_running": False, "dhcp_configured": True}, False),     # not serving: never adopted
])
def test_an_established_holder_already_serving_records_its_grant(state, adopts):
    from ha_agent.failover_runtime import enforce_dhcp_authority

    calls = []
    store = _State(state)
    enforce_dhcp_authority(store, {"epoch": 5, "holder": True},
                           runner=lambda command, **kw: calls.append(command) or SimpleNamespace(returncode=0, stdout="{}", stderr=""))
    assert [command[-2:] for command in calls] == ([["adopt", "5"]] if adopts else [])
    if adopts:
        assert store["dhcp_authority_epoch"] == 5 and store["dhcp_authority_state"] == "HELD"


def test_adopt_only_records_a_grant_on_a_node_already_serving_and_never_changes_dhcp(tmp_path, monkeypatch, capsys):
    values = {"desired_virtual_ip": "192.0.2.10/24"}
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "adopt", "5"], values, False)
    monkeypatch.setattr(helper, "_dhcp_status", lambda: {"runtime_state": "RUNNING", "configured": True, "listening": True})
    helper.main()
    record = json.loads((tmp_path / "dhcp-authority.json").read_text())
    assert {key: record[key] for key in ("epoch", "state", "boot_id", "vip")} == {"epoch": 5, "state": "HELD", "boot_id": BOOT, "vip": "192.0.2.10"}
    assert calls["set_dhcp"] == [] and calls["lease_writes"] == 0
    for status, existing in (({"runtime_state": "STOPPED", "configured": False, "listening": False}, None),  # not serving
                             ({"runtime_state": "RUNNING", "configured": True, "listening": True}, {"epoch": 6, "state": "REVOKED"})):  # stale
        helper, calls = _helper(tmp_path, monkeypatch, ["helper", "adopt", "5"], values, False)
        monkeypatch.setattr(helper, "_dhcp_status", lambda status=status: status)
        if existing:
            _record(tmp_path, **existing)
        with pytest.raises(RuntimeError):
            helper.main()
        assert calls["set_dhcp"] == []


def test_sudo_policy_allows_adopt_with_an_epoch_only():
    from app.services.ha_agent_installer import agent_file

    assert "kaya_ha_failover_helper.py adopt [0-9]*" in agent_file("kaya-ha-agent.sudoers").decode()
