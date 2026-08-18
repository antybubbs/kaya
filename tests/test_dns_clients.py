from datetime import datetime, timedelta
import inspect
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.db.session import Base
from app.models.models import DHCPLeaseHistory, DHCPRange, DNSClientEvent, DNSClientHostnameHistory, DNSClientIPHistory, DNSClientObservation, DNSClientTrafficEvent, DNSProviderConfig, DNSRecognisedDevice, HACluster, IPAddress, RemoteManagerSetting, VLAN
from app.services.dns_clients import cleanup_dns_history, client_status, consolidate_strong_identity_duplicates, dhcp_range_for_ip, list_clients, list_dhcp_leases, normalise_mac, observe_client, reconcile_managed_matches
from app.services.dns_client_repair import repair_dns_client_identities
from app.services.dns_insights import NormalisedClient, _persist_client_traffic, _persist_dhcp_leases
from app.routers import dns_manager
from app.routers import ip_addresses
from app.services import dns_collector


def factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def setup_provider(db):
    provider = DNSProviderConfig(name="Pi-hole", provider_type="pihole", base_url="http://example.invalid")
    db.add(provider)
    db.commit()
    return provider


def observation(*, hostname="client.home", ip="192.168.1.10", mac="e8-db-84-68-4c-b8", queries=12, blocked=2, provider_client_id=None):
    return SimpleNamespace(hostname=hostname, ip=ip, mac=mac, queries=queries, blocked_queries=blocked, provider_client_id=provider_client_id, first_seen=None, last_seen=None, source="test sync")


def setting(db, key, value):
    row = db.query(RemoteManagerSetting).filter_by(key=key).first() or RemoteManagerSetting(key=key)
    row.value = value
    db.add(row)
    db.commit()


def test_mac_normalisation_and_invalid_permanent_identities():
    expected = "e8:db:84:68:4c:b8"
    assert normalise_mac("E8-DB-84-68-4C-B8") == expected
    assert normalise_mac("e8:db:84:68:4c:b8") == expected
    assert normalise_mac("e8db84684cb8") == expected
    assert normalise_mac("") is None
    assert normalise_mac("00:00:00:00:00:00") is None
    assert normalise_mac("ff:ff:ff:ff:ff:ff") is None
    assert normalise_mac("not-a-mac") is None


def test_same_mac_retains_identity_and_idempotent_history_and_events():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        first = observe_client(db, provider, observation(), datetime.utcnow())
        db.commit()
        client_id = first.id

        unchanged = observe_client(db, provider, observation(), datetime.utcnow())
        db.commit()
        assert unchanged.id == client_id
        assert db.query(DNSRecognisedDevice).count() == 1
        assert db.query(DNSClientIPHistory).count() == 1
        assert db.query(DNSClientHostnameHistory).count() == 1
        assert db.query(DNSClientIPHistory).one().observation_count == 2
        assert db.query(DNSClientEvent).filter_by(event_type="client_discovered").count() == 1
        assert db.query(DNSClientEvent).filter_by(event_type="ip_changed").count() == 0

        changed = observe_client(db, provider, observation(hostname="renamed.home", ip="192.168.1.25"), datetime.utcnow())
        db.commit()
        assert changed.id == client_id
        assert db.query(DNSClientIPHistory).count() == 2
        assert db.query(DNSClientHostnameHistory).count() == 2
        assert db.query(DNSClientEvent).filter_by(event_type="ip_changed").count() == 1
        assert db.query(DNSClientEvent).filter_by(event_type="hostname_changed").count() == 1


def test_legacy_identity_row_is_reused_and_backfilled_without_losing_user_data():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        legacy = DNSRecognisedDevice(
            provider_id=provider.id,
            provider_type="pihole",
            identity_type="mac",
            identity_value="00:be:43:9a:d5:91",
            friendly_name="Alyssa's PC",
            notes="Retain this history",
            first_seen_at=datetime.utcnow() - timedelta(days=30),
            last_seen_at=datetime.utcnow() - timedelta(days=1),
        )
        db.add(legacy)
        db.commit()
        original_id = legacy.id

        refreshed = observe_client(db, provider, observation(hostname="HAL-AlyssaDesk", ip="192.168.1.200", mac="00:be:43:9a:d5:91"), datetime.utcnow())
        db.commit()
        assert refreshed.id == original_id
        assert refreshed.normalised_mac == "00:be:43:9a:d5:91"
        assert refreshed.friendly_name == "Alyssa's PC"
        assert refreshed.notes == "Retain this history"
        assert db.query(DNSRecognisedDevice).count() == 1


def test_same_mac_on_different_providers_keeps_separate_provider_history():
    make = factory()
    with make() as db:
        first_provider = setup_provider(db)
        second_provider = DNSProviderConfig(name="Pi-hole standby", provider_type="pihole", base_url="http://standby.invalid")
        db.add(second_provider)
        db.commit()
        first = observe_client(db, first_provider, observation(), datetime.utcnow())
        second = observe_client(db, second_provider, observation(), datetime.utcnow())
        db.commit()
        assert first.id != second.id
        assert first.provider_id == first_provider.id
        assert second.provider_id == second_provider.id


def test_same_mac_on_members_of_one_ha_cluster_is_one_logical_client():
    make = factory()
    with make() as db:
        cluster = HACluster(name="Fake HA DNS")
        db.add(cluster)
        db.flush()
        first_provider = DNSProviderConfig(name="Fake HA DNS", provider_type="pihole", base_url="http://one.invalid", ha_cluster_id=cluster.id)
        second_provider = DNSProviderConfig(name="Fake HA DNS", provider_type="pihole", base_url="http://two.invalid", ha_cluster_id=cluster.id)
        db.add_all([first_provider, second_provider])
        db.commit()
        first = observe_client(db, first_provider, observation(), datetime.utcnow())
        db.commit()
        second = observe_client(db, second_provider, observation(), datetime.utcnow())
        db.commit()
        assert first.id == second.id
        assert db.query(DNSRecognisedDevice).count() == 1
        assert db.query(DNSClientObservation).count() == 2
        assert second.logical_provider_key == f"ha-cluster:{cluster.id}"


def test_same_hostname_with_different_macs_does_not_merge_and_null_mac_does_not_false_match():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        observe_client(db, provider, observation(ip="192.168.1.10", mac="00:11:22:33:44:55"), datetime.utcnow())
        observe_client(db, provider, observation(ip="192.168.1.11", mac="66:77:88:99:aa:bb"), datetime.utcnow())
        observe_client(db, provider, observation(hostname="other.home", ip="192.168.1.12", mac=""), datetime.utcnow())
        db.commit()
        assert db.query(DNSRecognisedDevice).count() == 3


def test_configured_dhcp_range_requires_stable_identity_for_reuse():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        vlan = VLAN(name="Client VLAN")
        db.add(vlan)
        db.flush()
        db.add(DHCPRange(name="Clients", vlan_id=vlan.id, start_address="192.168.1.100", end_address="192.168.1.199"))
        db.commit()
        assert dhcp_range_for_ip(db, "192.168.1.150").name == "Clients"

        first = observe_client(db, provider, observation(hostname="first", ip="192.168.1.150", mac="00:11:22:33:44:55"), datetime.utcnow())
        second = observe_client(db, provider, observation(hostname="second", ip="192.168.1.150", mac="66:77:88:99:aa:bb"), datetime.utcnow())
        db.commit()
        assert first.id != second.id


def test_macless_dhcp_client_repeatedly_observed_does_not_grow_logical_rows():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        db.add(DHCPRange(name="Clients", start_address="192.168.1.100", end_address="192.168.1.199"))
        db.commit()
        now = datetime.utcnow()
        ids = []
        for poll in range(100):
            client = observe_client(db, provider, observation(hostname="printer", ip="192.168.1.150", mac=""), now + timedelta(minutes=poll))
            ids.append(client.id)
            db.commit()
        assert len(set(ids)) == 1
        assert db.query(DNSRecognisedDevice).count() == 1
        assert client.observation_count == 100
        assert db.query(DNSClientObservation).count() == 100


def test_macless_client_alternating_ha_members_keeps_status_and_enriches_with_mac():
    make = factory()
    with make() as db:
        cluster = HACluster(name="Fake HAL-DNS")
        db.add(cluster)
        db.flush()
        providers = [
            DNSProviderConfig(name="Fake Pi-hole 1", provider_type="pihole", base_url="http://one.invalid", ha_cluster_id=cluster.id),
            DNSProviderConfig(name="Fake Pi-hole 2", provider_type="pihole", base_url="http://two.invalid", ha_cluster_id=cluster.id),
        ]
        db.add_all(providers)
        db.commit()
        now = datetime.utcnow()
        first = observe_client(db, providers[0], observation(hostname="lamp.home", ip="192.168.1.194", mac=""), now)
        db.commit()
        first.is_known = True
        db.commit()
        second = observe_client(db, providers[1], observation(hostname="lamp.home", ip="192.168.1.194", mac=""), now + timedelta(minutes=1))
        db.commit()
        enriched = observe_client(db, providers[0], observation(hostname="lamp.home", ip="192.168.1.194", mac="02:00:00:00:01:94"), now + timedelta(minutes=2))
        db.commit()
        assert first.id == second.id == enriched.id
        assert db.query(DNSRecognisedDevice).count() == 1
        assert enriched.is_known is True
        assert enriched.normalised_mac == "02:00:00:00:01:94"
        assert enriched.identity_key == "mac:02:00:00:00:01:94"
        assert db.query(DNSClientObservation).count() == 3


def test_logical_identity_constraint_rejects_racing_duplicate_insert():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        values = dict(provider_id=provider.id, logical_provider_key=f"provider:{provider.id}", identity_key="weak:fake-race:2026-07-26", identity_type="ip", current_ip="192.0.2.194")
        db.add(DNSRecognisedDevice(identity_value="race-a", **values))
        db.commit()
        db.add(DNSRecognisedDevice(identity_value="race-b", **values))
        try:
            db.commit()
            assert False, "logical identity uniqueness must reject the racing insert"
        except IntegrityError:
            db.rollback()
        assert db.query(DNSRecognisedDevice).count() == 1


def test_existing_null_mac_duplicate_repair_preserves_status_and_relationships():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        now = datetime.utcnow()
        first = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key=f"provider:{provider.id}", identity_type="dhcp_observation", identity_value="poll-1", hostname="lamp.home", normalised_hostname="lamp.home", current_ip="192.168.1.194", is_known=False, first_seen_at=now, last_seen_at=now, observation_count=1)
        second = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key=f"provider:{provider.id}", identity_type="dhcp_observation", identity_value="poll-2", hostname="lamp.home", normalised_hostname="lamp.home", current_ip="192.168.1.194", is_known=True, first_seen_at=now + timedelta(minutes=1), last_seen_at=now + timedelta(minutes=1), observation_count=1)
        db.add_all([first, second])
        db.flush()
        db.add(DNSClientEvent(dns_client_id=second.id, event_type="marked_known", event_summary="Synthetic known action", provider_id=provider.id))
        db.add(DNSClientIPHistory(dns_client_id=second.id, ip_address="192.168.1.194", first_seen_at=now, last_seen_at=now, observation_count=2, provider_id=provider.id))
        db.commit()
        raw = db.get_bind().raw_connection()
        try:
            stats = repair_dns_client_identities(raw)
            raw.commit()
        finally:
            raw.close()
        db.expire_all()
        assert stats["before"] == 2 and stats["after"] == 1 and stats["merged"] == 1
        survivor = db.query(DNSRecognisedDevice).one()
        assert survivor.is_known is True
        assert survivor.first_seen_at == now
        assert survivor.last_seen_at == now + timedelta(minutes=1)
        assert survivor.observation_count == 2
        assert db.query(DNSClientObservation).filter_by(dns_client_id=survivor.id).count() == 2
        assert db.query(DNSClientEvent).filter_by(dns_client_id=survivor.id).count() == 1
        assert db.query(DNSClientIPHistory).filter_by(dns_client_id=survivor.id).count() == 1


def test_dhcp_address_reuse_creates_distinct_lease_intervals_and_traffic_attribution():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        vlan = VLAN(name="Client VLAN")
        db.add(vlan)
        db.flush()
        scope = DHCPRange(name="Clients", vlan_id=vlan.id, start_address="192.168.1.100", end_address="192.168.1.199")
        db.add(scope)
        db.flush()
        now = datetime.utcnow()
        first = observe_client(db, provider, observation(hostname="first", ip="192.168.1.150", mac="00:11:22:33:44:55"), now)
        db.flush()
        first_normalised = NormalisedClient("mac", first.normalised_mac, "first", first.current_ip, first.normalised_mac, device_id=first.id)
        _persist_dhcp_leases(db, provider, {"leases": [{"ip": first.current_ip, "mac": first.normalised_mac, "hostname": "first"}]}, [first_normalised], now)
        db.flush()
        first_lease = db.query(DHCPLeaseHistory).one()
        _persist_client_traffic(db, provider, [{"id": 1, "client": {"ip": first.current_ip, "name": "first"}, "domain": "example.com", "type": "A", "status": "CACHE", "timestamp": now.timestamp()}], [first_normalised], now)
        db.flush()
        event = db.query(DNSClientTrafficEvent).one()
        assert event.client_ip == "192.168.1.150"
        assert event.dhcp_lease_id == first_lease.id

        later = now + timedelta(minutes=5)
        second = observe_client(db, provider, observation(hostname="second", ip="192.168.1.150", mac="66:77:88:99:aa:bb"), later)
        db.flush()
        second_normalised = NormalisedClient("mac", second.normalised_mac, "second", second.current_ip, second.normalised_mac, device_id=second.id)
        _persist_dhcp_leases(db, provider, {"leases": [{"ip": second.current_ip, "mac": second.normalised_mac, "hostname": "second"}]}, [second_normalised], later)
        db.commit()
        leases = db.query(DHCPLeaseHistory).order_by(DHCPLeaseHistory.id).all()
        assert len(leases) == 2
        assert leases[0].is_active is False
        assert leases[0].ended_at == later
        assert leases[1].is_active is True
        assert leases[0].dns_client_id != leases[1].dns_client_id


def test_user_owned_fields_and_manual_link_survive_sync():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        vlan = VLAN(name="Servers")
        record = IPAddress(vlan=vlan, address="192.168.1.10", name="Managed PC", assignment_type="Static")
        db.add(record)
        db.flush()
        client = observe_client(db, provider, observation(), datetime.utcnow())
        client.is_known, client.is_ignored = True, True
        client.friendly_name, client.notes = "Anthony's PC", "Keep this note"
        client.linked_ip_record_id = record.id
        db.commit()

        refreshed = observe_client(db, provider, observation(hostname="new-provider-name", ip="192.168.1.20"), datetime.utcnow())
        db.commit()
        assert refreshed.is_known is True
        assert refreshed.is_ignored is True
        assert refreshed.friendly_name == "Anthony's PC"
        assert refreshed.notes == "Keep this note"
        assert refreshed.linked_ip_record_id == record.id
        assert record.address == "192.168.1.10"
        assert client_status(refreshed) == "Ignored"


def test_dynamic_auto_update_is_opt_in_and_static_is_never_automatic():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        setting(db, "dns_auto_update_dynamic_ip", "1")
        vlan = VLAN(name="LAN")
        dynamic = IPAddress(vlan=vlan, address="192.168.1.5", assignment_type="Dynamic")
        static = IPAddress(vlan=vlan, address="192.168.1.6", assignment_type="Static")
        db.add_all([dynamic, static])
        db.flush()
        dynamic_client = observe_client(db, provider, observation(ip="192.168.1.5", mac="00:11:22:33:44:55"), datetime.utcnow())
        static_client = observe_client(db, provider, observation(hostname="static.home", ip="192.168.1.6", mac="66:77:88:99:aa:bb"), datetime.utcnow())
        dynamic_client.linked_ip_record_id = dynamic.id
        static_client.linked_ip_record_id = static.id
        db.commit()

        observe_client(db, provider, observation(ip="192.168.1.15", mac="00:11:22:33:44:55"), datetime.utcnow())
        observe_client(db, provider, observation(hostname="static.home", ip="192.168.1.16", mac="66:77:88:99:aa:bb"), datetime.utcnow())
        db.commit()
        assert dynamic.address == "192.168.1.15"
        assert static.address == "192.168.1.6"


def test_exact_managed_matches_are_suggested_but_not_silently_linked():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        vlan = VLAN(name="LAN")
        record = IPAddress(vlan=vlan, address="192.168.1.10", name="Gaming PC", mac_address="e8:db:84:68:4c:b8")
        db.add(record)
        db.flush()
        client = observe_client(db, provider, observation(), datetime.utcnow())
        db.commit()
        assert client.suggested_ip_record_id == record.id
        assert client.match_method == "managed_mac"
        assert client.match_confidence == 100


def test_retained_clients_are_reconciled_after_managed_inventory_changes():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        client = observe_client(db, provider, observation(), datetime.utcnow())
        db.commit()
        assert client.suggested_ip_record_id is None
        vlan = VLAN(name="LAN")
        record = IPAddress(vlan=vlan, address=client.current_ip, name="Added later")
        db.add(record)
        db.commit()
        assert reconcile_managed_matches(db) == 1
        assert client.suggested_ip_record_id == record.id
        assert client.linked_ip_record_id is None


def test_deleting_managed_record_clears_link_and_historical_search_finds_client():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        vlan = VLAN(name="LAN")
        record = IPAddress(vlan=vlan, address="192.168.1.10")
        db.add(record)
        db.flush()
        client = observe_client(db, provider, observation(), datetime.utcnow() - timedelta(days=1))
        client.linked_ip_record_id = record.id
        db.commit()
        observe_client(db, provider, observation(ip="192.168.1.20"), datetime.utcnow())
        db.commit()

        rows, total = list_clients(db, search="192.168.1.10")
        assert total == 1 and rows[0].id == client.id
        db.delete(record)
        db.commit()
        db.expire_all()
        assert db.get(DNSRecognisedDevice, client.id).linked_ip_record_id is None


def test_client_routes_enforce_viewer_editor_and_admin_boundaries():
    routes = {(route.path, next(iter(route.methods or []), "")): route for route in dns_manager.router.routes}

    def dependencies(path, method):
        return {dependency.call.__name__ for dependency in routes[(path, method)].dependant.dependencies}

    assert "require_user" in dependencies("/networking/dns-manager/clients/{client_id}", "GET")
    assert "require_editor" in dependencies("/networking/dns-manager/clients/{client_id}/state", "POST")
    assert "require_editor" in dependencies("/networking/dns-manager/clients/{client_id}/link", "POST")
    assert "require_admin" in dependencies("/networking/dns-manager/clients/{client_id}/merge", "POST")
    assert "require_admin" in dependencies("/networking/dns-manager/clients/{client_id}/delete", "POST")

    ip_routes = {(route.path, next(iter(route.methods or []), "")): route for route in ip_addresses.router.routes}
    link_route = ip_routes[("/networking/vlan-ip-manager/{record_id}/link-dns-client", "POST")]
    assert "require_editor" in {dependency.call.__name__ for dependency in link_route.dependant.dependencies}


def test_vlan_ip_manager_exposes_reviewed_creation_for_unlinked_dns_clients():
    list_template = Path("app/templates/ip_addresses.html").read_text(encoding="utf-8")
    client_template = Path("app/templates/dns_client_detail.html").read_text(encoding="utf-8")
    form_template = Path("app/templates/ip_address_form.html").read_text(encoding="utf-8")
    assert "Observed DNS clients" in list_template
    assert "new?dns_client_id={{ client.id }}" in list_template
    assert "Create new VLAN/IP record" in client_template
    assert 'name="dns_client_id"' in form_template
    assert "dns_client_id" in inspect.signature(ip_addresses.create_ip_address).parameters


def test_empty_vlan_filter_means_all_vlans():
    assert ip_addresses.clean_vlan_filter("") is None
    assert ip_addresses.clean_vlan_filter("not-a-vlan") is None
    assert ip_addresses.clean_vlan_filter("12") == 12


def test_dns_client_category_uses_vlan_ip_manager_categories():
    manager_template = Path("app/templates/dns_manager.html").read_text(encoding="utf-8")
    detail_template = Path("app/templates/dns_client_detail.html").read_text(encoding="utf-8")
    assert '<th data-col="provider">Provider</th>' in manager_template
    assert '<th data-col="observations">Observations</th>' in manager_template
    assert "<dt>Category</dt>" in detail_template
    assert "linked_ip_record.category|urlencode" in detail_template
    assert "record.category" in detail_template
    assert "Possible Managed Match" in manager_template
    assert "<dt>VLAN</dt>" in detail_template
    assert "linked_ip_record.vlan" in detail_template


def test_dhcp_default_and_history_filters_are_database_paginated():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        now = datetime.utcnow()
        db.add_all([
            DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.10", lease_started_at=now, first_seen_at=now, last_seen_at=now, is_active=True),
            DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.11", lease_started_at=now - timedelta(days=1), first_seen_at=now - timedelta(days=1), last_seen_at=now, ended_at=now - timedelta(hours=2), is_active=False),
            DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.12", lease_started_at=now - timedelta(days=10), first_seen_at=now - timedelta(days=10), last_seen_at=now - timedelta(days=5), ended_at=now - timedelta(days=5), is_active=False),
        ])
        db.commit()
        current, current_total = list_dhcp_leases(db, provider_id=provider.id, status="current", now=now)
        history, history_total = list_dhcp_leases(db, provider_id=provider.id, status="history", now=now)
        assert current_total == 2 and {row.ip_address for row in current} == {"192.0.2.10", "192.0.2.11"}
        assert history_total == 1 and history[0].ip_address == "192.0.2.12"


def test_retention_cleanup_removes_only_expired_history():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        setting(db, "dns_observation_history_days", "30")
        setting(db, "dns_dhcp_history_days", "90")
        vlan = VLAN(name="Managed")
        record = IPAddress(vlan=vlan, address="192.0.2.20", name="Retained managed record")
        db.add(record)
        db.flush()
        old = datetime.utcnow() - timedelta(days=120)
        client = observe_client(db, provider, observation(ip="192.0.2.20"), old)
        client.linked_ip_record_id = record.id
        db.add_all([
            DHCPLeaseHistory(provider_id=provider.id, dns_client_id=client.id, ip_address="192.0.2.20", lease_started_at=old, first_seen_at=old, last_seen_at=old, ended_at=old, is_active=False),
            DHCPLeaseHistory(provider_id=provider.id, dns_client_id=client.id, ip_address="192.0.2.21", lease_started_at=old, first_seen_at=old, last_seen_at=old, is_active=True),
        ])
        db.commit()
        deleted = cleanup_dns_history(db, now=datetime.utcnow())
        assert deleted == {"observations": 1, "dhcp_leases": 1}
        assert db.get(DNSRecognisedDevice, client.id).linked_ip_record_id == record.id
        assert db.get(IPAddress, record.id) is not None
        assert db.query(DHCPLeaseHistory).one().is_active is True


def test_safe_duplicate_consolidation_preserves_managed_link_and_history():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        vlan = VLAN(name="Managed")
        record = IPAddress(vlan=vlan, address="192.0.2.30")
        db.add(record)
        db.flush()
        now = datetime.utcnow()
        first = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key=f"provider:{provider.id}", identity_type="ip", identity_value="192.0.2.30", current_ip="192.0.2.30", normalised_mac="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", linked_ip_record_id=record.id, first_seen_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=1), observation_count=2)
        duplicate = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key=f"provider:{provider.id}", identity_type="mac", identity_value="00:11:22:33:44:55", current_ip="192.0.2.31", normalised_mac="00:11:22:33:44:55", mac_address="00:11:22:33:44:55", first_seen_at=now - timedelta(days=1), last_seen_at=now, observation_count=3)
        db.add_all([first, duplicate])
        db.commit()
        assert consolidate_strong_identity_duplicates(db) == 1
        survivor = db.query(DNSRecognisedDevice).one()
        assert survivor.linked_ip_record_id == record.id
        assert survivor.current_ip == "192.0.2.31"
        assert survivor.observation_count == 5


def test_client_traffic_history_is_persisted_and_deduplicated():
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        client = observe_client(db, provider, observation(), datetime.utcnow())
        db.commit()
        normalised = NormalisedClient("ip", client.current_ip, client.hostname, client.current_ip, client.normalised_mac or "-", device_id=client.id)
        rows = [{
            "id": 1234,
            "time": 1784109600,
            "domain": "ads.example.test",
            "type": "A",
            "client": {"ip": client.current_ip, "name": client.hostname},
            "status": "GRAVITY",
            "reply": {"type": "NODATA", "time": 0.004},
            "upstream": "127.0.0.1#5335",
        }]
        assert _persist_client_traffic(db, provider, rows, [normalised], datetime.utcnow()) == 1
        db.commit()
        assert _persist_client_traffic(db, provider, rows, [normalised], datetime.utcnow()) == 0
        db.commit()
        event = db.query(DNSClientTrafficEvent).one()
        assert event.dns_client_id == client.id
        assert event.domain == "ads.example.test"
        assert event.is_blocked is True
        assert event.reply_time_ms == 4.0


def test_dns_collection_releases_read_transaction_before_slow_provider_work(
    monkeypatch, tmp_path
):
    database_path = tmp_path / "dns-collector.sqlite"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False, "timeout": 2},
    )
    Base.metadata.create_all(engine)
    make = sessionmaker(bind=engine)
    with make() as db:
        provider = setup_provider(db)
        provider_id = provider.id

    started = threading.Event()
    release = threading.Event()
    transaction_state = []

    def slow_analysis(db, provider, *, known_hostnames_raw):
        transaction_state.append(db.in_transaction())
        started.set()
        assert release.wait(5)

    monkeypatch.setattr(dns_collector, "analyse_provider", slow_analysis)
    worker = threading.Thread(
        target=dns_collector.collect_provider,
        args=(provider_id, "[]", make),
    )
    worker.start()
    assert started.wait(5)
    with make() as writer:
        writer.add(
            DNSProviderConfig(
                name="Concurrent writer", provider_type="pihole", base_url="http://example.invalid"
            )
        )
        started_at = time.monotonic()
        writer.commit()
        assert time.monotonic() - started_at < 1
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert transaction_state == [False]


def test_client_detail_exposes_traffic_summaries_and_history():
    template = Path("app/templates/dns_client_detail.html").read_text(encoding="utf-8")
    assert "Top requested domains" in template
    assert "Top blocked domains" in template
    assert 'data-table-key="dns-client-traffic-history"' in template
    assert "not complete browser URLs or page paths" in template
    assert 'id="dns-traffic-history"' in template
    assert "#dns-traffic-history" in template
    assert 'class="dns-domain-menu"' in template
    assert "WHOIS" in template and "DNS lookup" in template and "Reputation" in template
    assert 'name="return_to"' in template
    route_source = Path("app/routers/dns_manager.py").read_text(encoding="utf-8")
    assert "traffic_page_size = 8" in route_source
    assert ">Back</a>" in template and ">Next</a>" in template
    assert "dns_client_detail.js" in template
    detail_script = Path("app/static/js/dns_client_detail.js").read_text(encoding="utf-8")
    assert "--dns-popup-left" in detail_script and "getBoundingClientRect" in detail_script


def test_client_detail_does_not_load_large_observation_history(monkeypatch):
    make = factory()
    with make() as db:
        provider = setup_provider(db)
        now = datetime.utcnow()
        client = DNSRecognisedDevice(
            provider_id=provider.id,
            provider_type="pihole",
            identity_type="mac",
            identity_value="00:11:22:33:44:55",
            logical_provider_key=f"provider:{provider.id}",
            identity_key="mac:00:11:22:33:44:55",
            normalised_mac="00:11:22:33:44:55",
            mac_address="00:11:22:33:44:55",
            current_ip="192.0.2.10",
            first_seen_at=now,
            last_seen_at=now,
            observation_count=10000,
        )
        db.add(client)
        db.flush()
        db.bulk_insert_mappings(DNSClientObservation, [
            {
                "dns_client_id": client.id,
                "provider_id": provider.id,
                "observation_key": f"observation-{index}",
                "logical_provider_key": f"provider:{provider.id}",
                "observed_at": now,
            }
            for index in range(10000)
        ])
        db.commit()

        statements = []

        @event.listens_for(db.bind, "before_cursor_execute")
        def capture(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement.lower())

        rendered = {}
        monkeypatch.setattr(
            dns_manager,
            "provider_for",
            lambda provider: (_ for _ in ()).throw(TimeoutError("synthetic provider outage")),
        )
        monkeypatch.setattr(dns_manager.templates, "TemplateResponse", lambda request, template, context: rendered.update(context) or context)
        request = Request({
            "type": "http",
            "method": "GET",
            "path": f"/networking/dns-manager/clients/{client.id}",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("127.0.0.1", 8000),
            "scheme": "http",
            "session": {},
        })
        result = dns_manager.dns_client_detail(
            request,
            client.id,
            q="",
            traffic_q="",
            traffic_status="all",
            traffic_period="7d",
            traffic_page=1,
            db=db,
            user=SimpleNamespace(role="viewer"),
        )

        assert result["client"] is rendered["client"]
        assert rendered["client"].observation_count == 10000
        assert "dns_client_observations" not in " ".join(statements)


def test_exact_ip_or_mac_matches_can_be_confirmed_from_both_record_views():
    client_template = Path("app/templates/dns_client_detail.html").read_text(encoding="utf-8")
    ip_template = Path("app/templates/ip_address_detail.html").read_text(encoding="utf-8")
    assert "Confirm suggested link" in client_template
    assert "preferred_ip_record_id" in client_template
    assert "Exact matches awaiting confirmation" in ip_template
    assert "link-dns-client" in ip_template
    assert 'form="dns-link-{{ record.id }}-{{ dns.id }}"' in ip_template
    assert 'action="/networking/vlan-ip-manager/{{ record.id }}/link-dns-client"' in ip_template
    assert ip_template.index('id="dns-link-') > ip_template.index("</form>")
    client = DNSRecognisedDevice(current_ip="192.168.1.7", normalised_mac=None)
    record = IPAddress(address="192.168.1.7", mac_address=None)
    assert ip_addresses.dns_link_match(client, record) == (True, False)
    client.current_ip = "192.168.1.8"
    client.normalised_mac = "00:11:22:33:44:55"
    record.mac_address = "00-11-22-33-44-55"
    assert ip_addresses.dns_link_match(client, record) == (False, True)
