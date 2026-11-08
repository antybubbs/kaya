"""DHCP authority, boot guard and agent enforcement (DHCP handover PROPOSAL; not approved).

* A node never serves DHCP from saved configuration after a boot or FTL restart: the boot guard
  disables it before FTL starts, and only a fresh Kaya grant enables it again.
* Kaya records an explicit, epoch-numbered DHCP authority.  It moves only when Kaya promotes a node
  after verified release (or with external fencing evidence), and is never derived from roles.
* Each agent cycle releases DHCP if this node serves it while Kaya says another node holds a newer
  authority (a resumed frozen host, a returning node), independent of Keepalived hooks.
* An administrator's typed physical check is recorded only; it never promotes.
Synthetic data only.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

pytest.importorskip("fcntl")

from app.models.models import AuditLog  # noqa: E402
from app.services.ha_agents import desired_state  # noqa: E402
from app.services.ha_dhcp_authority import authority, authority_for_node, grant_authority  # noqa: E402
from app.services.ha_failover import active_failover, desired_failover_action  # noqa: E402
from test_ha_dhcp_handover_protocol import (  # noqa: E402
    _helper,
    apply_dhcp_actions,
    automatic_cluster,
    drive,
    ownership_snapshot,
    report,
    silent_peer,
)


# --------------------------------------------------------------------------------------
# Node: boot guard, authority record, revoke
# --------------------------------------------------------------------------------------


BOOT = "00000000-0000-4000-8000-00000000b007"  # the boot id the _helper fixture installs


def _record(tmp_path, **values):
    (tmp_path / "dhcp-authority.json").write_text(json.dumps(values))


def _read_record(tmp_path):
    return json.loads((tmp_path / "dhcp-authority.json").read_text())


def test_boot_guard_disables_saved_dhcp_after_a_reboot_and_voids_the_old_grant(tmp_path, monkeypatch, capsys):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "boot-guard"], {}, False)
    _record(tmp_path, epoch=7, state="HELD", boot_id="00000000-0000-4000-8000-0000000000aa", vip="192.0.2.10")  # previous boot
    configured = []
    monkeypatch.setattr(helper, "_configure_dhcp", lambda enabled: configured.append(enabled) or enabled)
    helper.main()
    assert configured == [False]  # persisted setting off before FTL reads it
    record = _read_record(tmp_path)
    assert record["state"] == "VOIDED" and record["epoch"] == 7  # the old grant can never authorise DHCP again
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "applied" and output["mode"] == "dhcp_off" and "restarted" in output["reason"]
    assert not (tmp_path / "guard" / "ftl.env").exists()


def test_boot_guard_keeps_dhcp_only_for_an_ftl_restart_under_a_held_grant_with_the_vip(tmp_path, monkeypatch, capsys):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "boot-guard"], {}, False)
    _record(tmp_path, epoch=7, state="HELD", boot_id=BOOT, vip="192.0.2.10")
    configured = []
    monkeypatch.setattr(helper, "_configure_dhcp", lambda enabled: configured.append(enabled) or enabled)
    helper.main()
    assert configured == [] and calls["set_dhcp"] == []  # continuing: nothing is changed, nothing is enabled
    assert json.loads(capsys.readouterr().out)["mode"] == "continuing" and _read_record(tmp_path)["state"] == "HELD"


@pytest.mark.parametrize("record, vip_present, forced", [
    ({"epoch": 7, "state": "HELD", "boot_id": BOOT, "vip": "192.0.2.10"}, False, False),   # Virtual IP lost
    ({"epoch": 7, "state": "HELD", "boot_id": BOOT, "vip": "192.0.2.10"}, True, True),     # unit environment sets dhcp.active
    ({"epoch": 7, "state": "HELD", "boot_id": BOOT, "vip": "192.0.2.10"}, True, None),     # environment cannot be inspected
    ({"epoch": 7, "state": "HELD", "boot_id": BOOT}, True, False),                         # no Virtual IP recorded
    ({"epoch": 7, "state": "RELEASED", "boot_id": BOOT, "vip": "192.0.2.10"}, True, False),
    ({"epoch": 7, "state": "REVOKED", "boot_id": BOOT, "vip": "192.0.2.10"}, True, False),
    ({"epoch": 7, "state": "FAILED", "boot_id": BOOT, "vip": "192.0.2.10"}, True, False),
    ({"epoch": 7, "state": "VOIDED", "boot_id": BOOT, "vip": "192.0.2.10"}, True, False),
    (None, True, False),                                                                   # lost record
])
def test_boot_guard_never_continues_without_every_condition(tmp_path, monkeypatch, capsys, record, vip_present, forced):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "boot-guard"], {}, False)
    if record is not None:
        _record(tmp_path, **record)
    monkeypatch.setattr(helper, "_address_present", lambda address: vip_present)
    monkeypatch.setattr(helper, "_environment_forces_dhcp", lambda: forced)
    monkeypatch.setattr(helper, "_configure_dhcp", lambda enabled: enabled)
    monkeypatch.setattr(helper, "_configured_on_disk", lambda extra_env=None: False)
    helper.main()
    output = json.loads(capsys.readouterr().out)
    assert output["configured"] is False and calls["set_dhcp"] == []
    assert output["mode"] == ("dhcp_off" if forced is False else "dns_only")
    if record is not None and record["state"] in {"HELD", "RELEASED"}:
        assert _read_record(tmp_path)["state"] == "VOIDED"


def test_boot_guard_starts_dns_only_when_pihole_toml_cannot_be_made_safe(tmp_path, monkeypatch, capsys):
    helper, _calls = _helper(tmp_path, monkeypatch, ["helper", "boot-guard"], {}, False)
    _record(tmp_path, epoch=7, state="HELD", boot_id="00000000-0000-4000-8000-0000000000aa", vip="192.0.2.10")

    def read_only(enabled):
        raise RuntimeError("Pi-hole dhcp.active could not be set to false (return code 0, observed True).")

    seen = []
    monkeypatch.setattr(helper, "_configure_dhcp", read_only)
    monkeypatch.setattr(helper, "_configured_on_disk", lambda extra_env=None: seen.append(extra_env) or False)
    helper.main()
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "dns_only" and "could not be set" in output["reason"]
    assert (tmp_path / "guard" / "ftl.env").read_text() == "FTLCONF_dhcp_active=false\nKAYA_HA_DHCP_GUARD=dns-only\n"
    assert seen == [{"FTLCONF_dhcp_active": "false"}]  # FTL itself confirmed its environment overrides pihole.toml
    assert _read_record(tmp_path)["state"] == "VOIDED"


def test_boot_guard_fails_closed_when_dns_only_cannot_be_confirmed(tmp_path, monkeypatch):
    helper, _calls = _helper(tmp_path, monkeypatch, ["helper", "boot-guard"], {}, False)

    def broken(enabled):
        raise RuntimeError("read-only file system")

    monkeypatch.setattr(helper, "_configure_dhcp", broken)
    monkeypatch.setattr(helper, "_configured_on_disk", lambda extra_env=None: True)  # FTL ignores the override
    with pytest.raises(SystemExit) as stopped:
        helper.main()
    assert stopped.value.code == 3  # "DHCP not confirmed off": the drop-in does not start FTL
    (tmp_path / "guard" / "ftl.env").unlink()
    (tmp_path / "guard").rmdir()
    (tmp_path / "guard").write_text("not a directory")  # the fallback file cannot be written
    monkeypatch.setattr(helper, "_configured_on_disk", lambda extra_env=None: False)
    with pytest.raises(SystemExit) as stopped:
        helper.main()
    assert stopped.value.code == 3


def test_kaya_granted_promotion_records_the_authority_epoch_and_refuses_a_stale_grant(tmp_path, monkeypatch, capsys):
    values = {"failover_generation": 9, "failover_authority_epoch": 5, "dns_healthy": True, "observed_role": "ACTIVE", "vip_owned": True,
              "network_interface": "eth0", "failover_lease_generation": 8, "desired_virtual_ip": "192.0.2.10/24"}
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], values, False)
    helper.main()
    record = _read_record(tmp_path)
    assert {key: record[key] for key in ("epoch", "state", "generation", "boot_id", "vip")} == {
        "epoch": 5, "state": "HELD", "generation": 9, "boot_id": BOOT, "vip": "192.0.2.10"}
    capsys.readouterr()
    _record(tmp_path, epoch=6, state="REVOKED")
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], values, False)
    with pytest.raises(RuntimeError) as raised:
        helper.main()
    assert "stale" in str(raised.value) and calls["set_dhcp"] == []


def test_promotion_is_refused_while_ftl_runs_dns_only(tmp_path, monkeypatch):
    values = {"failover_generation": 9, "failover_authority_epoch": 5, "dns_healthy": True, "observed_role": "ACTIVE", "vip_owned": True,
              "network_interface": "eth0", "failover_lease_generation": 8}
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "promote", "9"], values, False)
    (tmp_path / "guard").mkdir()
    (tmp_path / "guard" / "ftl.env").write_text("FTLCONF_dhcp_active=false\n")
    with pytest.raises(RuntimeError) as raised:
        helper.main()
    assert "DNS-only" in str(raised.value) and calls["set_dhcp"] == [] and calls["lease_writes"] == 0


def test_demotion_marks_a_held_grant_released(tmp_path, monkeypatch, capsys):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "demote", "9"], {"failover_generation": 9}, False)
    _record(tmp_path, epoch=5, state="HELD", boot_id=BOOT, vip="192.0.2.10")
    helper.main()
    assert calls["set_dhcp"] == [False] and _read_record(tmp_path)["state"] == "RELEASED"


def test_revoke_only_ever_disables_dhcp(tmp_path, monkeypatch, capsys):
    helper, calls = _helper(tmp_path, monkeypatch, ["helper", "revoke", "8"], {}, False)
    monkeypatch.setattr(helper, "AUTHORITY_FILE", tmp_path / "dhcp-authority.json")
    helper.main()
    assert calls["set_dhcp"] == [False] and calls["lease_writes"] == 0
    assert json.loads((tmp_path / "dhcp-authority.json").read_text())["state"] == "REVOKED"


def test_sudo_policy_allows_revoke_but_never_local_promotion():
    from app.services.ha_agent_installer import agent_file

    sudoers = agent_file("kaya-ha-agent.sudoers").decode()
    assert "kaya_ha_failover_helper.py revoke [0-9]*" in sudoers and "automatic-promote" not in sudoers
    assert "boot-guard" not in sudoers  # runs from systemd as root, never from the agent


def test_ftl_drop_in_runs_the_boot_guard_before_ftl_and_blocks_it_on_failure():
    from app.services.ha_agent_installer import agent_file

    drop_in = agent_file("kaya-ha-dhcp-guard.conf").decode()
    assert "ExecStartPre=+/bin/sh -c 'H=/usr/lib/kaya-ha-agent/kaya_ha_failover_helper.py;" in drop_in
    assert '"$$H" boot-guard; rc=$$?;' in drop_in
    assert '! grep -q "boot-guard" "$$H"; then rm -f "$$E"' in drop_in  # an older agent's helper: pihole.toml decides
    assert "ExecStartPre=-" not in drop_in  # a failure is never ignored
    assert '[ "$$rc" -eq 3 ] && exit 1' in drop_in  # helper says DHCP is not confirmed off: FTL does not start
    assert "echo FTLCONF_dhcp_active=false; echo KAYA_HA_DHCP_GUARD=dns-only;" in drop_in  # helper missing: DNS-only
    assert "EnvironmentFile=-/run/kaya-ha-dhcp-guard/ftl.env" in drop_in  # the DNS-only fallback
    for script in ("install.sh", "update.sh", "uninstall.sh"):
        assert "pihole-FTL.service.d/zz-kaya-ha-dhcp-guard.conf" in agent_file(script).decode()  # read after other drop-ins


# --------------------------------------------------------------------------------------
# Agent enforcement (independent of Keepalived hooks)
# --------------------------------------------------------------------------------------


def _enforce(state, authority_view):
    from ha_agent import failover_runtime

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout='{"status": "applied", "configured": false, "listening": false}', stderr="")

    failover_runtime.enforce_dhcp_authority(state, authority_view, runner=runner)
    return calls


class _State(dict):
    def get(self, key, default=None):
        return super().get(key, default)

    def set(self, key, value):
        self[key] = value


@pytest.mark.parametrize("view, serving, expected", [
    ({"epoch": 8, "holder": False}, True, True),      # another node holds a newer authority: release now
    ({"epoch": 8, "holder": True}, True, False),      # this node holds it
    (None, True, False),                              # not established (upgrade): never cause an outage
    ({"epoch": 8, "holder": False}, False, False),    # not serving: nothing to do
], ids=["revoke", "holder", "unknown", "idle"])
def test_agent_enforcement_releases_dhcp_only_when_another_node_holds_authority(view, serving, expected):
    state = _State(dhcp_listener_active=serving, dhcp_running=serving)
    calls = _enforce(state, view)
    assert bool(calls) is expected
    if expected:
        assert calls[0][-2:] == ["revoke", "8"]


# --------------------------------------------------------------------------------------
# Kaya: explicit authority, never from roles
# --------------------------------------------------------------------------------------


def test_authority_is_established_once_from_a_fully_verified_aligned_topology():
    sim = automatic_cluster()
    assert authority(sim.cluster)["node_id"] == sim.one.public_id and authority(sim.cluster)["evidence"] == "established_verified_topology"
    assert desired_state(sim.one)["dhcp_authority"] == {"epoch": authority(sim.cluster)["epoch"], "holder": True}
    assert desired_state(sim.two)["dhcp_authority"]["holder"] is False


def test_authority_is_never_established_from_a_split_topology():
    from test_ha_p6_align_ownership import mismatch

    sim = mismatch()
    sim.cluster.dhcp_authority_json = None
    sim.db.commit()
    report(sim)
    assert authority(sim.cluster) is None  # VIP and DHCP on different nodes: nothing is inferred


def test_a_handover_moves_authority_before_the_promotion_is_offered():
    sim = automatic_cluster()
    before = authority(sim.cluster)["epoch"]
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    assert drive(sim) == 0
    held = authority(sim.cluster)
    assert held["node_id"] == sim.two.public_id and held["epoch"] > before and held["evidence"] == "verified_release"
    assert desired_state(sim.one)["dhcp_authority"]["holder"] is False


def test_no_promotion_is_offered_to_a_node_without_authority():
    from app.services.ha_watchdog import reconcile_cluster

    from test_ha_dhcp_handover_protocol import age_vip

    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    for _ in range(3):
        age_vip(sim)
        report(sim)
        reconcile_cluster(sim.db, sim.cluster)
        if active_failover(sim.cluster) is not None:
            break
    run = active_failover(sim.cluster)
    assert run is not None and run.phase == "PROMOTING_TARGET"
    action = desired_failover_action(sim.cluster, sim.two)
    assert action["action_type"] == "DHCP_PROMOTE" and action["authority_epoch"] == authority(sim.cluster)["epoch"]
    grant_authority(sim.cluster, sim.one, evidence="test")  # authority elsewhere
    sim.db.commit()
    assert desired_failover_action(sim.cluster, sim.two) is None


def test_a_resumed_node_serving_without_authority_is_flagged_and_told_to_release():
    sim = automatic_cluster()
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False
    drive(sim)
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole2"]
    sim.sim_one.dhcp_running = True  # a frozen host resumes with DHCP still running in memory
    report(sim)
    assert desired_state(sim.one)["dhcp_authority"]["holder"] is False  # its agent releases on the next cycle
    from app.services.ha_assessment import assess_cluster

    codes = {item.code for item in assess_cluster(sim.db, sim.cluster).findings}
    assert "DHCP_SERVED_WITHOUT_AUTHORITY" in codes


def test_an_outdated_role_assignment_alone_never_authorises_dhcp():
    sim = automatic_cluster()
    grant_authority(sim.cluster, sim.two, evidence="test")
    sim.one.role = sim.one.desired_role = "ACTIVE"  # stale role still says node one
    sim.cluster.current_active_node_id = sim.one.id
    sim.db.commit()
    assert authority_for_node(sim.cluster, sim.one)["holder"] is False


# --------------------------------------------------------------------------------------
# Fencing: a typed physical check is a record, never a fence
# --------------------------------------------------------------------------------------


def test_a_physical_check_is_recorded_but_never_promotes():
    from app.services.ha_dhcp_handover import record_physical_check

    sim = silent_peer()
    record_physical_check(sim.db, sim.cluster, sim.admin, checked_node_public_id=sim.one.public_id, confirmation=sim.cluster.name, acknowledged=True)
    assert active_failover(sim.cluster) is None and not sim.sim_two.dhcp_running
    row = sim.db.query(AuditLog).filter(AuditLog.entity == "ha_dhcp_handover", AuditLog.action == "physical_check_recorded").one()
    assert json.loads(row.metadata_json)["authorises_dhcp"] is False


@pytest.mark.parametrize("evidence, promoted", [
    (None, False),                                                                  # no fencing provider configured
    ({"fenced": True, "method": "power_off", "age_seconds": 5}, True),             # independent, fresh, positive
    ({"fenced": True, "method": "power_off", "age_seconds": 600}, False),          # stale
    ({"fenced": False, "method": "power_off", "age_seconds": 5}, False),           # the fence did not take
    ("error", False),                                                               # provider failed
], ids=["none", "valid", "stale", "not-fenced", "provider-error"])
def test_only_fresh_positive_external_fencing_evidence_allows_promotion(monkeypatch, evidence, promoted):
    from app.services import ha_dhcp_handover

    sim = silent_peer()

    def provider(cluster, node):
        if evidence == "error":
            raise RuntimeError("fencing device unreachable")
        if evidence is None:
            return None
        return ha_dhcp_handover.FenceEvidence(provider="synthetic-pdu", node_public_id=node.public_id, fenced=evidence["fenced"],
                                              method=evidence["method"], verified_at=datetime.utcnow() - timedelta(seconds=evidence["age_seconds"]))

    monkeypatch.setattr(ha_dhcp_handover, "external_fence_evidence", provider)
    from app.services.ha_watchdog import reconcile_cluster

    for _ in range(3):
        report(sim, silent={"SimPiHole1"})
        reconcile_cluster(sim.db, sim.cluster)
        apply_dhcp_actions(sim, silent={"SimPiHole1"})
    assert sim.sim_two.dhcp_running is promoted
    if promoted:
        assert authority(sim.cluster)["evidence"] == "external_fence"
