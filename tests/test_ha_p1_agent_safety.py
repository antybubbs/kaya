"""P1 regression tests for agent 0.2.15: pending generation, no restart, gate reporting.

Real agent modules with an isolated temporary state directory and stubbed
process execution; no Keepalived, sudo or Pi-hole is invoked.  Linux-only
because the agent imports ``fcntl``.  Synthetic data only.
"""

from __future__ import annotations

import json
import subprocess
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

pytest.importorskip("fcntl")

from ha_agent.kaya_ha_agent import State  # noqa: E402
from ha_agent.keepalived_runtime import KeepalivedRuntimeError, apply_desired_keepalived  # noqa: E402

from app.models.models import HANode  # noqa: E402
from app.schemas.high_availability import HAAgentAutomationGates, HAAgentHeartbeat  # noqa: E402
from app.services.ha_agents import desired_state, record_heartbeat  # noqa: E402
from app.services.ha_keepalived import desired_keepalived_action, prepare_deployment, render_keepalived_config  # noqa: E402
from ha_simulation import hal_like_cluster, heartbeat_for, sqlite_session  # noqa: E402
from test_ha_gate_a_agent_defects import agent_state, read_state, run_hook  # noqa: E402
from test_high_availability_keepalived import database, ready_cluster  # noqa: E402


def keepalived_action():
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        return desired_keepalived_action(cluster, cluster.nodes[0])


def state_at(tmp_path, generation: int) -> State:
    state = State(tmp_path)
    state.set("keepalived_generation", generation)
    state.set("config_generation", generation)
    state.set("observed_role", "STANDBY")
    state.set("vip_owned", False)
    return state


# --- D10: pending Keepalived generation -------------------------------------

WINDOW = 60  # PENDING_GENERATION_WINDOW_SECONDS


def pending(generation, *, seconds_left: float = 30):
    return {"generation": generation, "expires_at": time.time() + seconds_left}


@pytest.mark.parametrize("failure", ["helper_failed", "invalid_output", "not_executable"])
def test_failed_apply_clears_pending_generation_so_later_hooks_are_fenced(tmp_path, monkeypatch, failure):
    action = keepalived_action()
    state = state_at(tmp_path, action["generation"] - 1)

    def runner(argv, **kwargs):
        marker = state.get("pending_keepalived_generation")
        assert marker["generation"] == action["generation"]
        assert 0 < marker["expires_at"] - time.time() <= WINDOW
        if failure == "not_executable":
            raise OSError("synthetic")
        stdout = "not-json" if failure == "invalid_output" else json.dumps({"ok": False, "message": "synthetic rollback"})
        return subprocess.CompletedProcess(argv, 1, stdout, "")

    if failure == "helper_failed":
        assert apply_desired_keepalived(state, action, runner=runner)["status"] == "FAILED"
    else:
        with pytest.raises(KeepalivedRuntimeError):
            apply_desired_keepalived(state, action, runner=runner)
    assert state.get("pending_keepalived_generation") is None
    assert state.get("keepalived_generation") == action["generation"] - 1
    code, _ = run_hook(monkeypatch, tmp_path, "master", action["generation"])
    assert code == 3 and state.get("observed_role") == "STANDBY"
    state.db.close()


@pytest.mark.parametrize(
    "marker",
    [
        pytest.param(lambda: pending(38, seconds_left=-1), id="expired"),
        pytest.param(lambda: pending(38, seconds_left=WINDOW + 30), id="beyond-window-clock-went-back"),
        pytest.param(lambda: pending(37), id="not-newer"),
        pytest.param(lambda: pending(36), id="older"),
        pytest.param(lambda: pending(39), id="different-generation"),
        pytest.param(lambda: {"generation": True, "expires_at": time.time() + 30}, id="bool-generation"),
        pytest.param(lambda: {"generation": "38", "expires_at": time.time() + 30}, id="string-generation"),
        pytest.param(lambda: {"generation": 38}, id="no-expiry"),
        pytest.param(lambda: {"generation": 38, "expires_at": "soon"}, id="string-expiry"),
        pytest.param(lambda: 38, id="bare-integer"),
        pytest.param(lambda: None, id="cleared"),
    ],
)
def test_hook_rejects_any_pending_marker_that_is_not_a_live_newer_generation(tmp_path, monkeypatch, marker):
    root = tmp_path / "agent"
    agent_state(root, keepalived_generation=37, pending_keepalived_generation=marker())
    code, _ = run_hook(monkeypatch, root, "master", 38)
    assert code == 3
    assert read_state(root)["observed_role"] == "STANDBY"


def test_hook_accepts_the_deployed_generation_and_a_live_pending_one(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    agent_state(root, keepalived_generation=37, pending_keepalived_generation=pending(38))
    assert run_hook(monkeypatch, root, "backup", 37)[0] == 0
    assert run_hook(monkeypatch, root, "master", 38)[0] == 0


def test_marker_left_by_a_crashed_apply_expires(tmp_path, monkeypatch):
    """The agent dies mid-apply (no cleanup runs); the marker stops authorising on its own."""
    import ha_agent.kaya_ha_transition as transition

    action = keepalived_action()
    state = state_at(tmp_path, action["generation"] - 1)

    def crashing_runner(argv, **kwargs):
        raise SystemExit("synthetic agent crash during helper call")

    with pytest.raises(SystemExit):
        apply_desired_keepalived(state, action, runner=crashing_runner)
    assert state.get("pending_keepalived_generation")["generation"] == action["generation"]
    assert run_hook(monkeypatch, tmp_path, "master", action["generation"])[0] == 0  # still inside the window
    later = time.time() + WINDOW + 1
    monkeypatch.setattr(transition.time, "time", lambda: later)
    assert run_hook(monkeypatch, tmp_path, "backup", action["generation"])[0] == 3
    state.db.close()


def test_daemon_start_clears_a_pending_marker(tmp_path, monkeypatch):
    from ha_agent import kaya_ha_agent as agent

    state = State(tmp_path)
    state.set("pending_keepalived_generation", pending(38))
    state.db.close()

    class Stop(Exception):
        pass

    seen = {}

    def run_once(started):
        seen["pending"] = started.get("pending_keepalived_generation")
        raise Stop

    monkeypatch.setattr(agent, "run_once", run_once)
    monkeypatch.setattr(agent.sys, "argv", ["kaya_ha_agent.py", "--state-dir", str(tmp_path), "run"])
    with pytest.raises(Stop):
        agent.main()
    assert seen["pending"] is None


def test_successful_apply_promotes_and_clears_pending(tmp_path):
    action = keepalived_action()
    state = state_at(tmp_path, action["generation"] - 1)
    ok = json.dumps({"ok": True, "backup_reference": "keepalived-synthetic"})
    result = apply_desired_keepalived(state, action, runner=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, ok, ""))
    assert result["status"] == "APPLIED"
    assert state.get("keepalived_generation") == action["generation"]
    assert state.get("pending_keepalived_generation") is None
    state.db.close()


# --- D11: helper never restarts Keepalived; rollback outcome is reported honestly


@pytest.fixture
def helper_paths(tmp_path, monkeypatch):
    import ha_agent.kaya_ha_keepalived_helper as helper

    source = tmp_path / "pending-keepalived.conf"
    main = tmp_path / "keepalived.conf"
    target = tmp_path / "conf.d" / "kaya-ha.conf"
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        source.write_text(render_keepalived_config(cluster, cluster.nodes[0]).content, encoding="utf-8")
    main.write_text("global_defs { router_id EXISTING }\n", encoding="utf-8")
    target.parent.mkdir(parents=True)
    target.write_text("# previous synthetic include\n", encoding="utf-8")
    for name, value in {"SOURCE": source, "MAIN": main, "TARGET": target, "BACKUPS": tmp_path / "backups"}.items():
        monkeypatch.setattr(helper, name, value)
    return helper, source, target


def run_helper(monkeypatch, capsys, helper, source, *, active, config_test=0, reload=(), start=()):
    """Scripted systemctl: ``active`` lists is-active answers in call order;
    ``reload``/``start`` list return codes in call order (default success)."""
    calls = []
    answers = {"is-active": list(active), "reload": list(reload), "start": list(start)}

    def command(argv, timeout=15):
        calls.append(argv)
        if argv[0] == "keepalived":
            return subprocess.CompletedProcess(argv, config_test, "", "synthetic config error" if config_test else "")
        verb = argv[1]
        if verb == "is-active":
            return subprocess.CompletedProcess(argv, 0 if answers["is-active"].pop(0) else 3, "", "")
        code = answers[verb].pop(0) if answers.get(verb) else 0
        return subprocess.CompletedProcess(argv, code, "", "synthetic failure" if code else "")

    monkeypatch.setattr(helper, "command", command)
    helper.apply(str(source))
    systemctl = [argv[1] for argv in calls if argv[0] == "systemctl" and argv[1] != "is-active"]
    return systemctl, json.loads(capsys.readouterr().out)


def test_failed_reload_of_running_keepalived_rolls_back_without_restart(helper_paths, monkeypatch, capsys):
    helper, source, target = helper_paths
    systemctl, output = run_helper(monkeypatch, capsys, helper, source, active=[True], reload=[1, 0])
    assert output["ok"] is False
    assert systemctl == ["reload", "reload"]  # activation, then rollback; never restart or start
    assert output["runtime_state_after_failure"] == "PREVIOUS_CONFIGURATION_RESTORED"
    assert target.read_text(encoding="utf-8") == "# previous synthetic include\n"


def test_failed_reload_and_failed_rollback_reload_reports_uncertainty(helper_paths, monkeypatch, capsys):
    helper, source, target = helper_paths
    systemctl, output = run_helper(monkeypatch, capsys, helper, source, active=[True], reload=[1, 1])
    assert output["ok"] is False
    assert systemctl == ["reload", "reload"]
    assert output["runtime_state_after_failure"] == "UNCERTAIN"
    assert "running Keepalived configuration is unknown" in output["message"]
    assert "previous configuration was restored" not in output["message"]
    assert target.read_text(encoding="utf-8") == "# previous synthetic include\n"  # files restored even so


def test_rejected_configuration_never_touches_the_running_service(helper_paths, monkeypatch, capsys):
    helper, source, target = helper_paths
    systemctl, output = run_helper(monkeypatch, capsys, helper, source, active=[], config_test=1)
    assert output["ok"] is False and systemctl == []
    assert output["runtime_state_after_failure"] == "NOT_CHANGED"
    assert target.read_text(encoding="utf-8") == "# previous synthetic include\n"


@pytest.mark.parametrize(("still_running", "outcome"), [(False, "STOPPED"), (True, "UNCERTAIN")])
def test_failed_start_of_stopped_keepalived_reports_what_is_known(helper_paths, monkeypatch, capsys, still_running, outcome):
    helper, source, _ = helper_paths
    systemctl, output = run_helper(monkeypatch, capsys, helper, source, active=[False, still_running], start=[1])
    assert output["ok"] is False and systemctl == ["start"]
    assert output["runtime_state_after_failure"] == outcome


def test_rollback_file_restore_failure_reports_uncertainty(helper_paths, monkeypatch, capsys):
    helper, source, _ = helper_paths
    real_copy = helper.shutil.copy2

    def copy2(src, dst, *args, **kwargs):
        if str(src).endswith(".include"):  # restoring the backup fails
            raise OSError("synthetic disk error")
        return real_copy(src, dst, *args, **kwargs)

    monkeypatch.setattr(helper.shutil, "copy2", copy2)
    systemctl, output = run_helper(monkeypatch, capsys, helper, source, active=[True], reload=[1])
    assert output["ok"] is False and output["runtime_state_after_failure"] == "UNCERTAIN"
    assert systemctl == ["reload"]  # no rollback reload of half-restored files


def test_stopped_keepalived_is_started_not_restarted(helper_paths, monkeypatch, capsys):
    helper, source, _ = helper_paths
    systemctl, output = run_helper(monkeypatch, capsys, helper, source, active=[False])
    assert output["ok"] is True and systemctl == ["start"]


def test_successful_reload_of_running_keepalived_issues_only_a_reload(helper_paths, monkeypatch, capsys):
    helper, source, _ = helper_paths
    systemctl, output = run_helper(monkeypatch, capsys, helper, source, active=[True])
    assert output["ok"] is True and systemctl == ["reload"]


def test_agent_forwards_rollback_uncertainty_to_kaya(tmp_path):
    action = keepalived_action()
    state = state_at(tmp_path, action["generation"] - 1)
    helper_output = json.dumps({
        "ok": False,
        "message": "Keepalived could not be reloaded. Rollback could not be confirmed, so the running Keepalived configuration is unknown.",
        "runtime_state_after_failure": "UNCERTAIN",
    })
    result = apply_desired_keepalived(state, action, runner=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, helper_output, ""))
    assert result["status"] == "FAILED" and "configuration is unknown" in result["message"]
    state.db.close()


# --- D12: signed reporting of local automation gates ------------------------


def test_heartbeat_schema_validates_gate_report_strictly():
    sim = hal_like_cluster(sqlite_session())
    base = heartbeat_for(sim.sim_one).model_dump()
    gates = {"automatic_failover": False, "maintenance_mode": True, "dhcp_managed": True}
    assert HAAgentHeartbeat(**{**base, "automation_gates": gates}).automation_gates.maintenance_mode is True
    with pytest.raises(ValidationError):
        HAAgentHeartbeat(**{**base, "automation_gates": {**gates, "unexpected": True}})
    with pytest.raises(ValidationError):
        HAAgentHeartbeat(**{**base, "automation_gates": {"automatic_failover": False}})


def test_server_records_reported_gates_and_clears_them_when_not_reported():
    sim = hal_like_cluster(sqlite_session())
    gates = {"automatic_failover": False, "dhcp_managed": True, "maintenance_mode": True}
    heartbeat = heartbeat_for(sim.sim_one).model_copy(update={"automation_gates": HAAgentAutomationGates(**gates)})
    record_heartbeat(sim.db, sim.one, heartbeat)
    assert json.loads(sim.db.get(HANode, sim.one.id).agent_automation_gates_json) == gates
    record_heartbeat(sim.db, sim.one, heartbeat_for(sim.sim_one))
    assert sim.db.get(HANode, sim.one.id).agent_automation_gates_json is None


def test_desired_state_advertises_gate_reporting():
    sim = hal_like_cluster(sqlite_session())
    assert desired_state(sim.one)["accepts_automation_gates"] is True


@pytest.mark.parametrize("advertised", [True, False, None])
def test_agent_reports_gates_only_to_a_server_that_accepts_them(tmp_path, monkeypatch, advertised):
    from ha_agent import failover_runtime, kaya_ha_agent as transport, keepalived_runtime

    state = State(tmp_path)
    state.config_path.write_text('{"agent_id":"fake-agent","kaya_url":"https://kaya.invalid"}', encoding="utf-8")
    monkeypatch.setattr(keepalived_runtime, "refresh_vip_state", lambda value: None)
    monkeypatch.setattr(failover_runtime, "refresh_dhcp_state", lambda value: None)
    monkeypatch.setattr(transport.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    desired = {"cluster_generation": 4, "desired_role": "STANDBY", "role_generation": 2, "automatic_failover": False,
               "maintenance_mode": True, "dhcp_managed": True, "keepalived": None, "lease_snapshot": None, "failover": None}
    if advertised is not None:
        desired["accepts_automation_gates"] = advertised
    heartbeats = []

    def signed_request(_state, method, path, payload=None):
        if path == "/api/ha/agent/v1/heartbeat":
            heartbeats.append(payload)
            return {"accepted": True, "desired": desired}
        return {"accepted": 1}

    monkeypatch.setattr(transport, "signed_request", signed_request)
    transport.run_once(state)  # first report learns what the server accepts
    transport.run_once(state)
    assert "automation_gates" not in heartbeats[0]
    if advertised is True:
        assert heartbeats[1]["automation_gates"] == {"automatic_failover": False, "maintenance_mode": True, "dhcp_managed": True}
        HAAgentHeartbeat(**heartbeats[1])  # what the agent sends passes server validation
    else:
        assert "automation_gates" not in heartbeats[1]
    state.db.close()
