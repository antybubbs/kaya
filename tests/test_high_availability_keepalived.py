import json
import subprocess
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import HAAgentCredential, HACluster, HAFailoverRun, HANode, User
from app.schemas.high_availability import HAAgentActionResult, HAAgentHeartbeat
from app.services.ha_agents import HAAgentError, desired_state, record_action_result, record_heartbeat
from app.services.ha_keepalived import HAKeepalivedError, deployment_blockers, desired_keepalived_action, prepare_deployment, render_keepalived_config, request_manual_vip_move, validate_network
from ha_agent.keepalived_runtime import KeepalivedRuntimeError, apply_desired_keepalived, validate_desired_configuration
from ha_agent.kaya_ha_agent import State


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def ready_cluster(db: Session) -> HACluster:
    admin = User(email="keepalived@example.test", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(name="DNS Pair", provider_key="pihole", status="VALIDATED", virtual_ip="192.168.50.53", prefix_length=24, vrrp_router_id=51, created_by=admin)
    db.add_all([admin, cluster]); db.flush()
    primary = HANode(cluster_id=cluster.id, display_name="Primary", management_host="192.168.50.2", api_base_url="https://192.168.50.2", network_interface="ens18", role="ACTIVE", desired_role="ACTIVE", last_heartbeat_at=datetime.utcnow(), dns_healthy=True, peer_reachable=True)
    standby = HANode(cluster_id=cluster.id, display_name="Standby", management_host="192.168.50.3", api_base_url="https://192.168.50.3", network_interface="ens18", role="STANDBY", desired_role="STANDBY", last_heartbeat_at=datetime.utcnow(), dns_healthy=True, peer_reachable=True)
    db.add_all([primary, standby]); db.flush()
    db.add_all([HAAgentCredential(node_id=primary.id, agent_id=primary.public_id, public_key="a" * 43, registered_at=datetime.utcnow()), HAAgentCredential(node_id=standby.id, agent_id=standby.public_id, public_key="b" * 43, registered_at=datetime.utcnow())])
    db.commit()
    return cluster


def test_keepalived_generator_is_deterministic_and_rejects_unsafe_network_input():
    with database() as db:
        cluster = ready_cluster(db)
        primary = next(node for node in cluster.nodes if node.role == "ACTIVE")
        primary.vrrp_priority = 150
        cluster.keepalived_generation = 4
        first = render_keepalived_config(cluster, primary)
        second = render_keepalived_config(cluster, primary)
        assert first == second
        assert "state BACKUP" in first.content
        assert "global_defs {" in first.content
        assert "script_user kaya-ha kaya-ha" in first.content
        assert "enable_script_security" in first.content
        assert "priority 150" in first.content
        assert "192.168.50.53/24" in first.content
        assert "DHCP" not in first.content
        assert first.checksum == __import__("hashlib").sha256(first.content.encode()).hexdigest()

        primary.network_interface = "ens18; touch /tmp/pwned"
        with pytest.raises(HAKeepalivedError, match="network interface"):
            validate_network(cluster)
        primary.network_interface = "ens18"
        cluster.virtual_ip = "192.168.50.255"
        with pytest.raises(HAKeepalivedError, match="broadcast"):
            validate_network(cluster)
        cluster.virtual_ip = "192.168.60.53"
        with pytest.raises(HAKeepalivedError, match="same IPv4 subnet"):
            validate_network(cluster)


def test_deployment_requires_agents_and_builds_node_bound_desired_actions():
    with database() as db:
        cluster = ready_cluster(db)
        assert deployment_blockers(cluster) == []
        prepared = prepare_deployment(db, cluster, 51, True)
        assert prepared.status == "DEPLOYING"
        assert prepared.keepalived_status == "PENDING_AGENT"
        assert prepared.keepalived_generation == 1
        assert {node.vrrp_priority for node in prepared.nodes} == {100, 150}
        actions = [desired_keepalived_action(prepared, node) for node in prepared.nodes]
        assert all(action and action["dhcp_transition"] == "DISABLED" for action in actions)
        assert actions[0]["action_id"] != actions[1]["action_id"]
        assert {action["checksum"] for action in actions} == {render_keepalived_config(prepared, node).checksum for node in prepared.nodes}
        assert desired_state(prepared.nodes[0])["allowed_actions"] == ["KEEPALIVED_APPLY"]


def test_controlled_move_temporarily_allows_only_the_destination_to_preempt():
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        source = next(node for node in cluster.nodes if node.desired_role == "ACTIVE")
        target = next(node for node in cluster.nodes if node.id != source.id)
        source.role = source.desired_role = "ACTIVE"
        target.role = target.desired_role = "STANDBY"
        source.vrrp_priority = 100
        target.vrrp_priority = 150
        run = HAFailoverRun(
            cluster_id=cluster.id,
            source_node_id=source.id,
            target_node_id=target.id,
            status="RUNNING",
            phase="MOVING_VIP",
            dhcp_managed=True,
            role_generation=2,
        )
        db.add(run)
        db.flush()
        for node in cluster.nodes:
            node.keepalived_status = "PENDING_AGENT"

        source_config = desired_keepalived_action(cluster, source)["configuration"]
        target_config = desired_keepalived_action(cluster, target)["configuration"]

        assert "nopreempt" in source_config
        assert "preempt_delay 3" not in source_config
        assert "nopreempt" not in target_config
        assert "preempt_delay 3" in target_config
        target_action = desired_keepalived_action(cluster, target)
        assert validate_desired_configuration(target_action) == target_config.encode()
        from ha_agent.kaya_ha_keepalived_helper import validate_managed_document
        assert validate_managed_document(target_config.encode())


def test_deployment_blockers_report_every_node_with_an_invalid_interface():
    with database() as db:
        cluster = ready_cluster(db)
        cluster.nodes[0].network_interface = ""
        cluster.nodes[1].network_interface = "not valid"
        blockers = deployment_blockers(cluster)
        assert "Enter a valid network interface for Primary." in blockers
        assert "Enter a valid network interface for Standby." in blockers


def test_action_results_are_generation_and_checksum_bound_then_reconcile_one_owner():
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        first, second = cluster.nodes
        first_action = desired_keepalived_action(cluster, first)
        with pytest.raises(HAAgentError, match="checksum"):
            record_action_result(db, first, HAAgentActionResult(action_id=first_action["action_id"], action_type="KEEPALIVED_APPLY", generation=1, status="APPLIED", checksum="0" * 64, message="wrong"))
        first_result = HAAgentActionResult(action_id=first_action["action_id"], action_type="KEEPALIVED_APPLY", generation=1, status="APPLIED", checksum=first_action["checksum"], backup_reference="backup-one", message="applied")
        record_action_result(db, first, first_result)
        second_action = desired_keepalived_action(cluster, second)
        record_action_result(db, second, HAAgentActionResult(action_id=second_action["action_id"], action_type="KEEPALIVED_APPLY", generation=1, status="APPLIED", checksum=second_action["checksum"], backup_reference="backup-two", message="applied"))
        assert cluster.keepalived_status == "DEPLOYED"
        assert cluster.status == "DEGRADED"

        record_heartbeat(db, first, HAAgentHeartbeat(observed_role="ACTIVE", observed_generation=cluster.cluster_generation, vip_owned=True, dhcp_running=False, dns_healthy=True, peer_reachable=True, config_generation=1, agent_version="0.1", keepalived_runtime_state="RUNNING"))
        assert cluster.status == "DEGRADED"
        assert cluster.current_active_node_id == first.id
        record_heartbeat(db, second, HAAgentHeartbeat(observed_role="STANDBY", observed_generation=cluster.cluster_generation, vip_owned=False, dhcp_running=False, dns_healthy=True, peer_reachable=True, config_generation=1, agent_version="0.1", keepalived_runtime_state="RUNNING"))
        assert cluster.status == "HEALTHY"
        assert cluster.current_active_node_id == first.id
        record_heartbeat(db, second, HAAgentHeartbeat(observed_role="STANDBY", observed_generation=cluster.cluster_generation, vip_owned=True, dhcp_running=False, dns_healthy=True, peer_reachable=True, config_generation=1, agent_version="0.1", keepalived_runtime_state="RUNNING"))
        assert cluster.status == "ERROR"
        assert cluster.current_active_node_id is None


def test_manual_vip_move_is_explicit_and_blocked_when_dhcp_is_reported():
    with database() as db:
        cluster = ready_cluster(db)
        cluster.keepalived_status = "DEPLOYED"; cluster.status = "HEALTHY"
        primary, standby = sorted(cluster.nodes, key=lambda node: 0 if node.role == "ACTIVE" else 1)
        for node in cluster.nodes: node.keepalived_status = "DEPLOYED"
        primary.vip_owned = True; primary.dhcp_running = True
        db.commit()
        with pytest.raises(HAKeepalivedError, match="DHCP running"):
            request_manual_vip_move(db, cluster, standby, True)
        primary.dhcp_running = False; db.commit()
        moved = request_manual_vip_move(db, cluster, standby, True)
        assert moved.status == "DEPLOYING"
        assert moved.role_generation == 2
        assert standby.desired_role == "ACTIVE" and standby.vrrp_priority == 150
        assert primary.desired_role == "STANDBY" and primary.vrrp_priority == 100


def test_agent_validates_and_applies_only_fixed_keepalived_action(tmp_path):
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        action = desired_keepalived_action(cluster, cluster.nodes[0])
    state = State(tmp_path)
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, json.dumps({"ok": True, "backup_reference": "keepalived-safe"}), "")

    result = apply_desired_keepalived(state, action, runner=runner)
    assert result["status"] == "APPLIED"
    assert calls == [["sudo", "-n", "/usr/lib/kaya-ha-agent/kaya_ha_keepalived_helper.py", "apply", str(tmp_path / "pending-keepalived.conf")]]
    assert state.get("config_generation") == action["generation"]
    tampered = {**action, "configuration": action["configuration"] + "include /tmp/evil.conf\n"}
    with pytest.raises(KeepalivedRuntimeError):
        validate_desired_configuration(tampered)
    state.db.close()

    failed_state = State(tmp_path / "failed")
    with pytest.raises(KeepalivedRuntimeError, match="sudo: helper denied"):
        apply_desired_keepalived(
            failed_state,
            action,
            runner=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, "not-json", "sudo: helper denied"),
        )
    failed_state.db.close()


def test_root_helper_rolls_back_invalid_config_and_preserves_unrelated_content(tmp_path, monkeypatch, capsys):
    import ha_agent.kaya_ha_keepalived_helper as helper

    source = tmp_path / "pending-keepalived.conf"; main = tmp_path / "keepalived.conf"; target = tmp_path / "conf.d" / "kaya-ha.conf"; backups = tmp_path / "backups"
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        generated = render_keepalived_config(cluster, cluster.nodes[0]).content
    source.write_text(generated, encoding="utf-8")
    main.write_text("global_defs { router_id EXISTING }\n", encoding="utf-8")
    target.parent.mkdir(); target.write_text("# previous Kaya include\n", encoding="utf-8")
    monkeypatch.setattr(helper, "SOURCE", source); monkeypatch.setattr(helper, "MAIN", main); monkeypatch.setattr(helper, "TARGET", target); monkeypatch.setattr(helper, "BACKUPS", backups)
    monkeypatch.setattr(helper, "command", lambda argv, timeout=15: subprocess.CompletedProcess(argv, 1, "", "invalid"))
    assert helper.apply(str(source)) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "Diagnostic: invalid" in result["message"]
    assert main.read_text(encoding="utf-8") == "global_defs { router_id EXISTING }\n"
    assert target.read_text(encoding="utf-8") == "# previous Kaya include\n"
    assert list(backups.glob("*.main")) and list(backups.glob("*.include"))


def test_root_helper_independently_allows_generated_config_and_rejects_injected_directives():
    import ha_agent.kaya_ha_keepalived_helper as helper

    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        generated = render_keepalived_config(cluster, cluster.nodes[0]).content.encode()
    assert helper.validate_managed_document(generated)
    assert b"nopreempt" in generated
    assert b"preempt_delay" not in generated
    assert b"weight -60" not in generated
    assert not helper.validate_managed_document(generated.replace(b"state BACKUP", b"state BACKUP\ninclude /tmp/evil.conf"))


def test_deployment_ui_and_agent_protocol_keep_dhcp_outside_keepalived_setup():
    template = Path("app/templates/high_availability_cluster_deployment.html").read_text(encoding="utf-8")
    router = Path("app/routers/high_availability.py").read_text(encoding="utf-8")
    agent_router = Path("app/routers/ha_agent_api.py").read_text(encoding="utf-8")
    helper = Path("ha_agent/kaya_ha_keepalived_helper.py").read_text(encoding="utf-8")
    transition = Path("ha_agent/kaya_ha_transition.py").read_text(encoding="utf-8")
    assert "DHCP is not changed here" in template
    assert "This setup deploys Keepalived only" in template
    assert "Move Virtual IP" in template
    assert "Deployment blocked" in template
    assert "Resolve blockers to deploy" in template
    assert "Edit node settings" in template
    assert "Deployment error reported by this node" in template
    assert "data-ha-deployment-live" in template
    assert "ha_deployment.js" in template
    live_script = Path("app/static/js/ha_deployment.js").read_text(encoding="utf-8")
    assert "setTimeout" in live_script
    assert "5000" in live_script
    assert "window.location.reload" not in live_script
    assert 'Depends(require_ha_admin)' in router
    assert '"dhcp_changed": False' in router
    assert '@router.post("/action-result")' in agent_router
    assert "shell=True" not in helper
    assert "--config-test" in helper
    assert "rollback" not in helper.lower() or "reload" in helper
    assert "automatic_failover" in transition
    assert "automatic-promote" in transition
    assert "split_brain_prevented" in transition
    assert "shell=True" not in transition
