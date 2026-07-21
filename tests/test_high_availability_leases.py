import json

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.core.security import decrypt_secret
from app.db.session import Base
from app.models.models import HACluster, HALeaseSnapshot, HANode, HAProviderConnection
from app.schemas.high_availability import HAAgentActionResult
from app.services.dns_providers import DNSProviderResult
from app.services.ha_agents import desired_state, record_action_result
from app.services.ha_leases import HALeaseError, reconcile_cluster_leases, snapshot_for_agent
from ha_agent.kaya_ha_agent import State, reconcile_desired


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def make_cluster(db: Session):
    cluster = HACluster(name="DHCP Pair", provider_key="pihole", status="HEALTHY", virtual_ip="192.168.50.53", prefix_length=24)
    first_connection = HAProviderConnection(provider_key="pihole", name="One", api_base_url="https://one.invalid")
    second_connection = HAProviderConnection(provider_key="pihole", name="Two", api_base_url="https://two.invalid")
    db.add_all([cluster, first_connection, second_connection])
    db.flush()
    primary = HANode(cluster_id=cluster.id, display_name="One", api_base_url=first_connection.api_base_url, ha_connection_id=first_connection.id, role="ACTIVE", desired_role="ACTIVE")
    standby = HANode(cluster_id=cluster.id, display_name="Two", api_base_url=second_connection.api_base_url, ha_connection_id=second_connection.id, role="STANDBY", desired_role="STANDBY")
    db.add_all([primary, standby])
    db.flush()
    cluster.authoritative_node_id = primary.id
    db.commit()
    return cluster, primary, standby


class LeasePiHole:
    active = True
    leases = []
    hosts = []

    def __init__(self, connection):
        self.connection = connection

    def get_ha_configuration(self):
        value = {"config": {"dhcp": {"active": self.active, "start": "192.168.50.100", "end": "192.168.50.200", "hosts": self.hosts}}}
        return DNSProviderResult(True, "loaded", {"configuration": {"dhcp": value}})

    def get_dhcp_leases(self):
        return DNSProviderResult(True, "loaded", {"leases": self.leases})


def test_validated_snapshot_is_encrypted_and_only_assigned_to_standby():
    with database() as db:
        cluster, primary, standby = make_cluster(db)
        LeasePiHole.active = True
        LeasePiHole.hosts = []
        LeasePiHole.leases = [{"expires": 2000000000, "name": "laptop", "hwaddr": "AA-BB-CC-DD-EE-FF", "ip": "192.168.50.120", "clientid": "client-one"}]

        state = reconcile_cluster_leases(db, cluster, client_factory=LeasePiHole)
        snapshot = db.query(HALeaseSnapshot).one()
        assert state.status == "PENDING"
        assert state.lease_count == 1
        assert "aa:bb:cc:dd:ee:ff" not in snapshot.encrypted_payload
        assert json.loads(decrypt_secret(snapshot.encrypted_payload))["leases"][0]["hwaddr"] == "aa:bb:cc:dd:ee:ff"
        assert desired_state(primary)["lease_snapshot"] is None
        action = desired_state(standby)["lease_snapshot"]
        assert action["action_type"] == "LEASE_SNAPSHOT_STAGE"
        assert snapshot_for_agent(standby, 1)["payload"]["leases"][0]["ip"] == "192.168.50.120"

        result = HAAgentActionResult(action_id=action["action_id"], action_type="LEASE_SNAPSHOT_STAGE", generation=1, status="APPLIED", checksum=action["checksum"], backup_reference="lease-generation-1", message="staged only")
        record_action_result(db, standby, result)
        assert state.status == "CURRENT"
        assert standby.lease_generation == 1
        assert snapshot.status == "STAGED"
        assert standby.dhcp_running is False


def test_external_dhcp_is_a_noop_and_preserves_existing_histories_by_separation():
    with database() as db:
        cluster, _, _ = make_cluster(db)
        LeasePiHole.active = False
        LeasePiHole.leases = []
        state = reconcile_cluster_leases(db, cluster, client_factory=LeasePiHole)
        assert state.status == "NOT_APPLICABLE"
        assert db.query(HALeaseSnapshot).count() == 0


def test_conflicting_and_out_of_range_leases_are_rejected_before_staging():
    with database() as db:
        cluster, _, _ = make_cluster(db)
        LeasePiHole.active = True
        LeasePiHole.hosts = []
        LeasePiHole.leases = [
            {"expires": 1, "hwaddr": "00:11:22:33:44:55", "ip": "192.168.50.120"},
            {"expires": 1, "hwaddr": "00:11:22:33:44:66", "ip": "192.168.50.120"},
        ]
        with pytest.raises(HALeaseError, match="Conflicting leases"):
            reconcile_cluster_leases(db, cluster, client_factory=LeasePiHole)
        assert cluster.lease_replication.status == "BLOCKED"
        assert db.query(HALeaseSnapshot).count() == 0

        LeasePiHole.leases = [{"expires": 1, "hwaddr": "00:11:22:33:44:55", "ip": "192.168.50.20"}]
        with pytest.raises(HALeaseError, match="outside the configured DHCP range"):
            reconcile_cluster_leases(db, cluster, client_factory=LeasePiHole)
        assert db.query(HALeaseSnapshot).count() == 0


def test_static_reservation_may_safely_be_outside_dynamic_range():
    with database() as db:
        cluster, _, _ = make_cluster(db)
        LeasePiHole.active = True
        LeasePiHole.hosts = ["00:11:22:33:44:55,192.168.50.20,printer"]
        LeasePiHole.leases = [{"expires": 1, "hwaddr": "00:11:22:33:44:55", "ip": "192.168.50.20"}]
        state = reconcile_cluster_leases(db, cluster, client_factory=LeasePiHole)
        assert state.status == "PENDING"
        assert db.query(HALeaseSnapshot).one().lease_count == 1


def test_dhcp_page_explains_network_independence_and_no_activation():
    template = open("app/templates/high_availability_cluster_dhcp.html", encoding="utf-8").read()
    assert "never the path your devices use" in template
    assert "never starts, stops, enables, or disables DHCP" in template
    assert "External DHCP" in template


def test_agent_checksum_verifies_and_stages_snapshot_without_touching_dhcp(tmp_path, monkeypatch):
    state = State(tmp_path)
    payload = {"version": 1, "cluster_id": "cluster", "source_node_id": "source", "created_at": "now", "leases": [{"expires": 1, "hwaddr": "00:11:22:33:44:55", "ip": "192.168.50.120", "name": "", "clientid": ""}]}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    checksum = __import__("hashlib").sha256(encoded).hexdigest()

    def fake_request(_state, method, path, body=None):
        assert method == "GET"
        return {"generation": 2, "checksum": checksum, "payload": payload}

    monkeypatch.setattr("ha_agent.kaya_ha_agent.signed_request", fake_request)
    reconcile_desired(state, {"cluster_generation": 1, "desired_role": "STANDBY", "lease_snapshot": {"action_id": "lease:test", "generation": 2, "checksum": checksum, "snapshot_path": "/snapshot"}})
    assert json.loads((tmp_path / "lease-snapshots" / "current.json").read_text())["payload"] == payload
    assert state.get("lease_generation") == 2
    assert state.get("pending_lease_action_result")["status"] == "APPLIED"
    assert state.get("dhcp_running", False) is False
    state.db.close()
