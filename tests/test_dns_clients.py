from datetime import datetime, timedelta
import inspect
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import DHCPLeaseHistory, DHCPRange, DNSClientEvent, DNSClientHostnameHistory, DNSClientIPHistory, DNSClientTrafficEvent, DNSProviderConfig, DNSRecognisedDevice, IPAddress, RemoteManagerSetting, VLAN
from app.services.dns_clients import client_status, dhcp_range_for_ip, list_clients, normalise_mac, observe_client, reconcile_managed_matches
from app.services.dns_insights import NormalisedClient, _persist_client_traffic, _persist_dhcp_leases
from app.routers import dns_manager
from app.routers import ip_addresses


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
    assert '<th data-col="category">Category</th>' in manager_template
    assert "linked_ip_record.category|urlencode" in manager_template
    assert "<dt>Category</dt>" in detail_template
    assert "linked_ip_record.category|urlencode" in detail_template
    assert "record.category" in detail_template
    assert '<th data-col="vlan">VLAN</th>' in manager_template
    assert "linked_ip_record.vlan" in manager_template
    assert "<dt>VLAN</dt>" in detail_template
    assert "linked_ip_record.vlan" in detail_template


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
