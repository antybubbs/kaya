import json
from pathlib import Path
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import DNSClientIPHistory, DNSProviderConfig, DNSRecognisedDevice, DNSStatisticsSnapshot, HACluster, HANode, HAProviderConnection, User
from app.services import dns_insights
from app.services.dns_insights import analyse_provider
from app.services.dns_providers import DNSProviderResult, HAPiHoleProvider, PiHoleProvider, provider_for
from app.services.ha_sync import HAStaleSyncPlanError, HASyncError, create_live_sync_plan, create_sync_plan, execute_sync, sync_plan
from app.routers.admin import DNSProviderSettingsError, save_dns_manager_settings


def test_dns_provider_actions_are_not_blocked_by_hidden_settings_panels():
    template = Path("app/templates/settings.html").read_text(encoding="utf-8")
    assert 'formaction="/system/site-administration/save-dns-provider" formmethod="post" formnovalidate' in template
    assert 'formaction="/system/site-administration/test-dns-provider" formmethod="post" formnovalidate' in template

    script = Path("app/static/js/settings_tabs.js").read_text(encoding="utf-8")
    assert "event.submitter?.formNoValidate" in script

    router = Path("app/routers/admin.py").read_text(encoding="utf-8")
    assert 'RedirectResponse("/system/site-administration?tab=module-dns-manager&provider_saved=1"' in router


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


def dns_settings(provider, cluster, **overrides):
    values = {
        "dns_manager_enabled": "1", "dns_collector_enabled": "1", "dns_default_provider_id": str(provider.id), "dns_refresh_interval_seconds": "300", "dns_cache_enabled": "1",
        "dns_vlan_integration_enabled": "1", "dns_match_suggestions_enabled": "1", "dns_auto_link_exact_mac": "", "dns_auto_update_dynamic_ip": "", "dns_stale_client_days": "30",
        "dns_retain_client_history": "1", "dns_client_history_days": "365", "dns_traffic_history_days": "30", "dns_vlan_enrichment_enabled": "1", "dns_update_empty_managed_hostname": "",
        "dns_provider_id": str(provider.id), "dns_provider_name": provider.name, "dns_provider_type": "pihole", "dns_provider_connection_mode": "ha_cluster", "dns_provider_ha_cluster_id": str(cluster.id),
        "dns_provider_base_url": provider.base_url, "dns_provider_auth_method": "password", "dns_provider_secret": "", "dns_provider_ssl_verify": "1", "dns_provider_timeout_seconds": "10", "dns_provider_enabled": "1", "dns_provider_description": "",
    }
    values.update(overrides)
    return values


def test_settings_can_convert_existing_provider_to_ha_without_losing_identity_or_history():
    with database() as db:
        _, cluster, _, _ = make_cluster(db)
        provider = DNSProviderConfig(name="Existing", provider_type="pihole", base_url="http://one.invalid")
        db.add(provider); db.flush()
        client = DNSRecognisedDevice(provider_id=provider.id, identity_type="mac", identity_value="00:11:22:33:44:55")
        db.add(client); db.flush()
        history = DNSClientIPHistory(dns_client_id=client.id, provider_id=provider.id, ip_address="192.0.2.10")
        db.add(history); db.commit()
        ids = provider.id, client.id, history.id

        saved = save_dns_manager_settings(db, **dns_settings(provider, cluster))
        db.commit()

        assert saved.id == ids[0]
        assert saved.ha_cluster_id == cluster.id
        assert saved.base_url == "http://192.0.2.53"
        assert (provider.id, client.id, history.id) == ids
        assert isinstance(provider_for(saved), HAPiHoleProvider)


def test_settings_reject_unready_ha_cluster_instead_of_silently_ignoring_selection():
    with database() as db:
        _, cluster, _, _ = make_cluster(db)
        provider = DNSProviderConfig(name="Existing", provider_type="pihole", base_url="http://one.invalid")
        db.add(provider); db.commit()
        cluster.status = "DEGRADED"; db.commit()

        with pytest.raises(DNSProviderSettingsError, match="not currently ready"):
            save_dns_manager_settings(db, **dns_settings(provider, cluster))
        assert provider.ha_cluster_id is None


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
        assert "one live Pi-hole VIP owner" in result.message


def test_ha_provider_routes_to_current_owner_and_ignores_offline_cached_owner():
    with database() as db:
        _, cluster, first, second = make_cluster(db)
        provider = DNSProviderConfig(name="HA", provider_type="pihole", base_url="http://192.0.2.53", ha_cluster_id=cluster.id)
        db.add(provider)
        first.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=6)
        first.vip_owned = True
        second.last_heartbeat_at = datetime.utcnow()
        second.vip_owned = True
        second.dns_healthy = True
        second.keepalived_runtime_state = "RUNNING"
        cluster.current_active_node_id = second.id
        db.commit()

        active = provider_for(provider)._active_provider()
        assert active.config.base_url == "http://two.invalid"


def test_ha_analysis_uses_active_node_and_updates_connection_snapshot(monkeypatch):
    with database() as db:
        _, cluster, active_node, _ = make_cluster(db)
        provider = DNSProviderConfig(name="HA", provider_type="pihole", base_url="http://192.0.2.53", ha_cluster_id=cluster.id)
        db.add(provider)
        active_node.last_heartbeat_at = datetime.utcnow()
        db.commit()

        def collect(active_provider):
            assert active_provider.config.base_url == "http://one.invalid"
            return {
                "status": DNSProviderResult(True, "connected", {"blocking": "enabled"}),
                "stats": DNSProviderResult(True, "loaded", {"queries": {"total": 10, "blocked": 2}, "clients": {"active": 1}}),
                "history": DNSProviderResult(True, "loaded", {}),
                "clients": DNSProviderResult(True, "loaded", {}),
                "queries": DNSProviderResult(True, "loaded", {"queries": []}),
                "dhcp": DNSProviderResult(True, "loaded", {}),
                "blocklists": DNSProviderResult(True, "loaded", {}),
            }

        monkeypatch.setattr(dns_insights, "_collect_provider_data", collect)
        result = analyse_provider(db, provider)

        db.refresh(provider)
        snapshot = db.query(DNSStatisticsSnapshot).filter_by(provider_id=provider.id).one()
        assert provider.last_status == "online"
        assert snapshot.provider_connected is True
        assert snapshot.period_end == result.generated_at


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


def test_live_plan_refreshes_both_snapshots_before_review():
    with database() as db:
        user, cluster, source, target = make_cluster(db)
        old_value = {"config": {"dns": {"hosts": []}}}
        source_value = {"config": {"dns": {"hosts": ["one.test,192.0.2.10"]}}}
        target_value = {"config": {"dns": {"hosts": ["two.test,192.0.2.11"]}}}
        source.configuration_snapshot_json = json.dumps({"local_dns": old_value})
        target.configuration_snapshot_json = json.dumps({"local_dns": old_value})
        db.commit()
        SyncPiHole.state = {
            f"ha-{source.ha_connection_id}": {"local_dns": source_value},
            f"ha-{target.ha_connection_id}": {"local_dns": target_value},
        }

        run = create_live_sync_plan(db, cluster, user, client_factory=SyncPiHole)

        assert run.status == "PLANNED"
        assert json.loads(source.configuration_snapshot_json)["local_dns"] == source_value
        assert json.loads(target.configuration_snapshot_json)["local_dns"] == target_value


def test_live_change_names_stale_configuration_group_and_writes_nothing():
    with database() as db:
        user, cluster, source, target = make_cluster(db)
        source_value = {"config": {"dns": {"hosts": ["one.test,192.0.2.10"]}}}
        target_value = {"config": {"dns": {"hosts": []}}}
        source.configuration_snapshot_json = json.dumps({"local_dns": source_value})
        target.configuration_snapshot_json = json.dumps({"local_dns": target_value})
        db.commit()
        SyncPiHole.state = {
            f"ha-{source.ha_connection_id}": {"local_dns": source_value},
            f"ha-{target.ha_connection_id}": {"local_dns": target_value},
        }
        SyncPiHole.writes = []
        run = create_sync_plan(db, cluster, user)
        SyncPiHole.state[f"ha-{source.ha_connection_id}"] = {"local_dns": {"config": {"dns": {"hosts": ["changed.test,192.0.2.12"]}}}}

        with pytest.raises(HAStaleSyncPlanError, match="Local DNS") as error:
            execute_sync(db, cluster, run, client_factory=SyncPiHole)

        assert error.value.changed_groups == ["local_dns"]
        assert SyncPiHole.writes == []


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
