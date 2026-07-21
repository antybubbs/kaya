import json

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import DNSClientIPHistory, DNSProviderConfig, DNSRecognisedDevice, HACluster, HANode, HAProviderConnection, User
from app.services.dns_providers import DNSProviderResult, HAPiHoleProvider, PiHoleProvider, provider_for
from app.services.ha_sync import HASyncError, create_sync_plan, execute_sync, sync_plan


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def make_cluster(db: Session):
    user = User(email="ha-sync@example.com", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(name="Home DNS", provider_key="pihole", status="HEALTHY", virtual_ip="192.0.2.53", keepalived_status="DEPLOYED", created_by=user)
    first_connection = HAProviderConnection(provider_key="pihole", name="One", api_base_url="http://one.invalid", encrypted_secret="one", created_by=user)
    second_connection = HAProviderConnection(provider_key="pihole", name="Two", api_base_url="http://two.invalid", encrypted_secret="two", created_by=user)
    db.add_all([user, cluster, first_connection, second_connection]); db.flush()
    first = HANode(cluster_id=cluster.id, display_name="One", api_base_url=first_connection.api_base_url, ha_connection_id=first_connection.id, role="ACTIVE", desired_role="ACTIVE", vip_owned=True, dns_healthy=True, keepalived_runtime_state="RUNNING")
    second = HANode(cluster_id=cluster.id, display_name="Two", api_base_url=second_connection.api_base_url, ha_connection_id=second_connection.id, role="STANDBY", desired_role="STANDBY", vip_owned=False, dns_healthy=True, keepalived_runtime_state="RUNNING")
    db.add_all([first, second]); db.flush()
    cluster.authoritative_node_id = first.id
    cluster.current_active_node_id = first.id
    db.commit()
    return user, cluster, first, second


def test_standalone_provider_path_is_unchanged_and_linking_preserves_history():
    with database() as db:
        _, cluster, _, _ = make_cluster(db)
        provider = DNSProviderConfig(name="Existing", provider_type="pihole", base_url="http://one.invalid")
        db.add(provider); db.flush()
        client = DNSRecognisedDevice(provider_id=provider.id, identity_type="mac", identity_value="00:11:22:33:44:55")
        db.add(client); db.flush()
        history = DNSClientIPHistory(dns_client_id=client.id, provider_id=provider.id, ip_address="192.0.2.10")
        db.add(history); db.commit()
        provider_id, client_id, history_id = provider.id, client.id, history.id
        assert isinstance(provider_for(provider), PiHoleProvider)

        provider.ha_cluster_id = cluster.id
        db.commit()
        assert isinstance(provider_for(provider), HAPiHoleProvider)
        assert (provider.id, client.id, history.id) == (provider_id, client_id, history_id)


def test_ha_provider_refuses_ambiguous_vip_ownership():
    with database() as db:
        _, cluster, _, second = make_cluster(db)
        provider = DNSProviderConfig(name="HA", provider_type="pihole", base_url="http://192.0.2.53", ha_cluster_id=cluster.id)
        db.add(provider); db.commit()
        second.vip_owned = True
        cluster.current_active_node_id = None
        db.commit()
        result = provider_for(provider).test_connection()
        assert not result.ok
        assert "one current Pi-hole VIP owner" in result.message


class SyncPiHole:
    state = {}
    writes = []

    def __init__(self, connection):
        self.node = connection.id

    def get_ha_configuration(self):
        return DNSProviderResult(True, "loaded", {"configuration": self.state[self.node], "unavailable": {}})

    def apply_ha_configuration_group(self, key, value):
        self.writes.append((self.node, key))
        self.state[self.node][key] = value
        return DNSProviderResult(True, "applied", {})

    def reconcile_ha_collections(self, source, *, allow_deletions):
        self.writes.append((self.node, "collections"))
        for key in ("groups", "filtering", "clients"):
            if key in source:
                self.state[self.node][key] = source[key]
        return DNSProviderResult(True, "reconciled", {})


def test_sync_creates_encrypted_backup_before_write_and_verifies():
    with database() as db:
        user, cluster, source, target = make_cluster(db)
        source_value = {"config": {"dns": {"hosts": ["one.test,192.0.2.10"]}}}
        target_value = {"config": {"dns": {"hosts": []}}}
        source.configuration_snapshot_json = json.dumps({"local_dns": source_value})
        target.configuration_snapshot_json = json.dumps({"local_dns": target_value})
        db.commit()
        SyncPiHole.state = {f"ha-{source.ha_connection_id}": {"local_dns": source_value}, f"ha-{target.ha_connection_id}": {"local_dns": target_value}}
        SyncPiHole.writes = []
        run = create_sync_plan(db, cluster, user)
        execute_sync(db, cluster, run, client_factory=SyncPiHole)
        db.refresh(run)
        assert run.status == "SUCCEEDED"
        assert len(run.backups) == 1
        assert run.backups[0].encrypted_snapshot != json.dumps({"local_dns": target_value}, sort_keys=True, separators=(",", ":"))
        assert SyncPiHole.writes == [(f"ha-{target.ha_connection_id}", "local_dns")]
        assert target.last_sync_at is not None


def test_collection_deletions_require_explicit_confirmation_and_leases_are_excluded():
    with database() as db:
        user, cluster, source, target = make_cluster(db)
        source_value = {"groups": [{"id": 0, "name": "Default"}]}
        target_value = {"groups": [{"id": 0, "name": "Default"}, {"id": 1, "name": "Old"}]}
        source.configuration_snapshot_json = json.dumps({"groups": source_value})
        target.configuration_snapshot_json = json.dumps({"groups": target_value})
        db.commit()
        SyncPiHole.state = {f"ha-{source.ha_connection_id}": {"groups": source_value}, f"ha-{target.ha_connection_id}": {"groups": target_value}}
        SyncPiHole.writes = []
        run = create_sync_plan(db, cluster, user)
        plan = json.loads(run.plan_json)
        assert plan["blocked_groups"] == []
        assert plan["deletion_count"] == 1
        assert plan["lease_replication"] is False
        with pytest.raises(HASyncError, match="explicitly confirm"):
            execute_sync(db, cluster, run, client_factory=SyncPiHole)
        assert not run.backups


def test_dhcp_runtime_activation_is_not_a_sync_change():
    with database() as db:
        _, cluster, source, target = make_cluster(db)
        source.configuration_snapshot_json = json.dumps({"dhcp": {"config": {"dhcp": {"active": True, "start": "192.0.2.100"}}}})
        target.configuration_snapshot_json = json.dumps({"dhcp": {"config": {"dhcp": {"active": False, "start": "192.0.2.100"}}}})
        db.commit()
        plan = sync_plan(cluster)
        assert plan["groups"] == []
        assert plan["dhcp_mode"] == "PIHOLE_MANAGED"
        assert plan["lease_replication"] is False
