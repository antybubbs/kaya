"""Automatic DHCP identity continuity for adopted assets.

Leases enter through the real DNS Manager lease-ingestion path and devices
are adopted through the real Review / Adopt service; no assignment is inserted
directly. All data is synthetic (RFC 5737 addresses, locally administered or
documentation-style MACs, example.invalid accounts).
"""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.services.asset_identity as asset_identity
from app.db.session import Base
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    AuditLog,
    DHCPLeaseHistory,
    DHCPRange,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    NetworkMonitor,
    TrafficDeviceMonitoring,
    TrafficEndpointAggregate,
    TrafficLocalNetwork,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
    VLAN,
)
from app.services.asset_discovery import adopt_discovered_device, get_discovered_device
from app.services.asset_identity import reconcile_dhcp_assignment
from app.services.asset_profile_reporting import asset_reporting_context
from app.services import dns_insights
from app.services.dns_insights import _persist_dhcp_leases
from app.services.dns_providers import DNSProviderResult
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord
from app.services.modules import grant_all_registered_modules

NOW = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
T0, T1, T2, T3, T4 = (NOW - timedelta(hours=hours) for hours in (12, 11, 8, 5, 4))
OLD_IP, NEW_IP = "192.0.2.165", "192.0.2.178"


@pytest.fixture(params=["sqlite", "postgresql"])
def db(request):
    if request.param == "sqlite":
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine)()
        yield session
        session.close()
        return
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url)
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")()
    yield session
    session.close()
    transaction.rollback()
    connection.close()
    engine.dispose()


def _mac():
    """A unique, locally administered synthetic MAC."""
    raw = uuid.uuid4().hex[:10]
    return "02:" + ":".join(raw[i:i + 2] for i in range(0, 10, 2))


def _provider(db, name="Synthetic Pi-hole"):
    provider = DNSProviderConfig(name=f"{name} {uuid.uuid4().hex[:6]}", base_url="https://dns.example.invalid", provider_type="pihole")
    db.add(provider)
    db.commit()
    return provider


def _admin(db):
    user = User(email=f"synthetic-admin-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role="admin", is_active=True)
    db.add(user)
    db.flush()
    grant_all_registered_modules(db, user)
    db.commit()
    return user


def _item(ip, mac=None, clientid=None, name="synthetic-phone"):
    item = {"ip": ip, "name": name}
    if mac:
        item["hwaddr"] = mac
    if clientid:
        item["clientid"] = clientid
    return item


def _sync(db, provider, *items, at, authoritative=True):
    """One DNS Manager DHCP collection through the real ingestion function."""
    _persist_dhcp_leases(db, provider, {"leases": list(items)}, [], at, snapshot_authoritative=authoritative)
    db.commit()


def _lease(db, provider, ip, *, active=True):
    query = db.query(DHCPLeaseHistory).filter_by(provider_id=provider.id, ip_address=ip)
    if active:
        query = query.filter_by(is_active=True)
    return query.order_by(DHCPLeaseHistory.id.desc()).first()


def _adopt(db, admin, provider, ip, name=None):
    lease = _lease(db, provider, ip)
    candidate = get_discovered_device(db, f"dhcp:{lease.id}")
    assert candidate and candidate["asset_id"] is None
    return adopt_discovered_device(db, admin, candidate, new_name=name or f"Synthetic device {uuid.uuid4().hex[:6]}")


def _traffic_config(db, enabled):
    config = db.get(TrafficMonitoringConfiguration, 1)
    if config is None:
        db.add(TrafficMonitoringConfiguration(id=1, is_enabled=enabled))
    else:
        config.is_enabled = enabled
    db.commit()


def _counts(db):
    return {model.__name__: db.query(model).count() for model in (HardwareAsset, AssetNetworkAssignment, IPAddress, NetworkMonitor, TrafficDeviceMonitoring)}


def _rows(db, asset):
    return db.query(AssetNetworkAssignment).filter_by(asset_id=asset.id).order_by(AssetNetworkAssignment.started_at, AssetNetworkAssignment.id).all()


def _open(db, asset):
    return [row.address for row in _rows(db, asset) if row.ended_at is None]


def _reconciliation_audits(db, asset=None):
    rows = db.query(AuditLog).filter(AuditLog.entity == "asset_network_assignment", AuditLog.detail == "Reconciled confirmed DHCP network assignment").all()
    if asset is None:
        return rows
    ids = {str(row.id) for row in _rows(db, asset)}
    return [row for row in rows if row.entity_id in ids]


def _adopted_device(db, *, mac=None, clientid=None, ip=OLD_IP, provider=None, name="synthetic-phone"):
    """Lease → Review / Adopt → next collection links the DHCP-only address."""
    provider = provider or _provider(db)
    admin = _admin(db)
    _sync(db, provider, _item(ip, mac, clientid, name), at=T0)
    asset = _adopt(db, admin, provider, ip)
    _sync(db, provider, _item(ip, mac, clientid, name), at=T1)
    assert _open(db, asset) == [ip]
    return provider, admin, asset


# ------------------------------------------------------------ 1. confirmed MAC


def test_confirmed_mac_follows_new_dhcp_address(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    assets_before = db.query(HardwareAsset).count()
    _sync(db, provider, _item(NEW_IP, mac), at=T2)
    db.refresh(asset)
    rows = _rows(db, asset)
    # The old lease was last observed at T1; ownership after that is not attributed.
    assert [(row.address, row.ended_at) for row in rows] == [(OLD_IP, T1), (NEW_IP, None)]
    assert rows[0].started_at == T0  # supported by the first lease observation
    assert rows[1].started_at == T2 and rows[1].provenance == "dhcp_reconciliation"
    assert rows[1].source_id is None and rows[1].exporter_identity is None
    assert rows[1].dhcp_lease_id == _lease(db, provider, NEW_IP).id
    assert db.query(HardwareAsset).count() == assets_before
    assert get_discovered_device(db, f"dhcp:{_lease(db, provider, NEW_IP).id}")["asset_id"] == asset.id
    audits = _reconciliation_audits(db, asset)
    assert len(audits) == 2  # initial link and the address change, each audited


# ------------------------------------------------------------ 2. confirmed DHCP client identifier


def test_confirmed_client_id_follows_new_address_with_new_private_mac(db):
    clientid = f"ff:{uuid.uuid4().hex[:8]}"
    provider, _, asset = _adopted_device(db, mac=_mac(), clientid=clientid)
    _sync(db, provider, _item(NEW_IP, _mac(), clientid), at=T2)
    assert _open(db, asset) == [NEW_IP]


# ------------------------------------------------------------ 3. both agree


def test_mac_and_client_id_agreeing_reconcile(db):
    mac, clientid = _mac(), f"01:{uuid.uuid4().hex[:8]}"
    provider, _, asset = _adopted_device(db, mac=mac, clientid=clientid)
    _sync(db, provider, _item(NEW_IP, mac, clientid), at=T2)
    assert _open(db, asset) == [NEW_IP]


# ------------------------------------------------------------ 4. conflicting identifiers


def test_conflicting_mac_and_client_id_require_review(db):
    provider = _provider(db)
    mac_a, client_b = _mac(), f"01:{uuid.uuid4().hex[:8]}"
    _, _, asset_a = _adopted_device(db, mac=mac_a, provider=provider)
    _, _, asset_b = _adopted_device(db, mac=_mac(), clientid=client_b, ip="192.0.2.170", name="synthetic-tablet")
    _sync(db, provider, _item(OLD_IP, mac_a), _item("192.0.2.199", mac_a, client_b), at=T2)
    lease = _lease(db, provider, "192.0.2.199")
    assert reconcile_dhcp_assignment(db, lease, observed_at=T2) == "review_required"
    assert _open(db, asset_a) == [OLD_IP]
    assert "192.0.2.199" not in _open(db, asset_b)
    candidate = get_discovered_device(db, f"dhcp:{lease.id}")
    assert candidate["asset_id"] is None and candidate["identity_conflict"] is True  # flagged for review
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset_a.id, evidence_type="mac", status="confirmed").count() == 1


# ------------------------------------------------------------ 5. private MAC change without client id


def test_private_mac_change_without_client_id_requires_review(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _sync(db, provider, _item(OLD_IP, mac), _item(NEW_IP, _mac(), name="synthetic-phone"), at=T2)
    assert _open(db, asset) == [OLD_IP]
    assert db.query(AssetNetworkAssignment).filter_by(address=NEW_IP).count() == 0


# ------------------------------------------------------------ 6. hostname only


def test_matching_hostname_with_different_identifiers_is_never_enough(db):
    provider, _, asset = _adopted_device(db, mac=_mac(), clientid=f"01:{uuid.uuid4().hex[:8]}")
    _sync(db, provider, _item(OLD_IP, _mac(), f"01:{uuid.uuid4().hex[:8]}", name="synthetic-phone"), at=T2)
    _sync(db, provider, _item(NEW_IP, _mac(), f"01:{uuid.uuid4().hex[:8]}", name="synthetic-phone"), at=T3)
    assert db.query(AssetNetworkAssignment).filter_by(address=NEW_IP).count() == 0
    # The previous holder's assignment is never moved to the new identity.
    assert [row.asset_id for row in db.query(AssetNetworkAssignment).filter_by(address=OLD_IP).all()] == [asset.id]


# ------------------------------------------------------------ 7. repeated renewal


def test_repeated_lease_renewal_is_idempotent(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    audits = len(_reconciliation_audits(db, asset))
    for hours in (10, 9, 8, 7):
        _sync(db, provider, _item(OLD_IP, mac), at=NOW - timedelta(hours=hours))
    assert len(_rows(db, asset)) == 1 and _open(db, asset) == [OLD_IP]
    assert len(_reconciliation_audits(db, asset)) == audits


# ------------------------------------------------------------ 8. identical lease imported twice


def test_identical_lease_imported_twice_creates_one_assignment(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _sync(db, provider, _item(NEW_IP, mac), _item(NEW_IP, mac), at=T2)
    _sync(db, provider, _item(NEW_IP, mac), at=T2)
    assert _open(db, asset) == [NEW_IP]
    assert db.query(AssetNetworkAssignment).filter_by(asset_id=asset.id, address=NEW_IP).count() == 1


# ------------------------------------------------------------ 9. out-of-order leases


def test_out_of_order_leases_never_flap_back_to_the_older_address(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    # The provider still lists the unexpired old lease beside the new one, in either order.
    _sync(db, provider, _item(OLD_IP, mac), _item(NEW_IP, mac), at=T2)
    _sync(db, provider, _item(NEW_IP, mac), _item(OLD_IP, mac), at=T3)
    _sync(db, provider, _item(OLD_IP, mac), _item(NEW_IP, mac), at=T4)
    assert _open(db, asset) == [NEW_IP]
    assert len(_rows(db, asset)) == 2
    assert reconcile_dhcp_assignment(db, _lease(db, provider, OLD_IP), observed_at=T4) == "superseded"


# ------------------------------------------------------------ 10. address reused by a second asset


def test_address_reused_by_second_asset_is_bounded_and_never_shared(db):
    vlan = VLAN(name=f"Synthetic reuse {uuid.uuid4().hex[:6]}", subnet_cidr="192.0.2.0/24")
    db.add(vlan)
    db.flush()
    db.add(IPAddress(address=OLD_IP, vlan_id=vlan.id, name="synthetic-static-holder"))
    db.commit()
    provider, admin = _provider(db), _admin(db)
    mac_a, mac_b = _mac(), _mac()
    _sync(db, provider, _item(OLD_IP, mac_a), at=T0)
    asset_a = _adopt(db, admin, provider, OLD_IP)                  # static (managed IP) assignment
    _, _, asset_b = _adopted_device(db, mac=mac_b, ip="192.0.2.170", name="synthetic-other")
    # While A's static assignment holds the address, B's lease for it is never assigned to B.
    _sync(db, provider, _item(OLD_IP, mac_b, name="synthetic-other"), at=T2)
    assert reconcile_dhcp_assignment(db, _lease(db, provider, OLD_IP), observed_at=T2) == "review_required"
    assert _open(db, asset_a) == [OLD_IP] and OLD_IP not in _open(db, asset_b)
    # A moves by DHCP; its static interval is closed and B is then linked from its own lease.
    _sync(db, provider, _item(NEW_IP, mac_a), _item(OLD_IP, mac_b, name="synthetic-other"), at=T3)
    _sync(db, provider, _item(NEW_IP, mac_a), _item(OLD_IP, mac_b, name="synthetic-other"), at=T4)
    assert _open(db, asset_a) == [NEW_IP]
    assert _open(db, asset_b) == [OLD_IP]
    a_old = next(row for row in _rows(db, asset_a) if row.address == OLD_IP)
    b_old = next(row for row in _rows(db, asset_b) if row.address == OLD_IP)
    # Adoption stamps A's static interval with the wall clock, after this synthetic
    # timeline, so it closes empty; either way the two intervals never overlap.
    assert a_old.ended_at is not None
    assert a_old.ended_at <= b_old.started_at or a_old.ended_at == a_old.started_at


# ------------------------------------------------------------ 11. concurrent DHCP updates


def test_postgres_concurrent_evidence_reconciliation_is_idempotent():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    factory = sessionmaker(bind=engine)
    mac = _mac()
    try:
        with factory.begin() as db:
            provider = DNSProviderConfig(name=f"Concurrent fixture {uuid.uuid4().hex[:6]}", base_url="https://dns.example.invalid", provider_type="pihole")
            asset = HardwareAsset(name=f"Concurrent asset {uuid.uuid4().hex[:6]}")
            db.add_all([provider, asset])
            db.flush()
            db.add(AssetIdentityEvidence(asset_id=asset.id, evidence_type="mac", normalised_value=mac, source="discovery", source_scope="dhcp", status="confirmed", confirmed_at=T0))
            lease = DHCPLeaseHistory(provider_id=provider.id, ip_address=NEW_IP, mac_address=mac, lease_started_at=T2, first_seen_at=T2, last_seen_at=T2, is_active=True)
            db.add(lease)
            db.flush()
            lease_id, asset_id, provider_id = lease.id, asset.id, provider.id

        def reconcile_once(_):
            with factory() as session:
                result = reconcile_dhcp_assignment(session, session.get(DHCPLeaseHistory, lease_id), observed_at=T2)
                session.commit()
                return result

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(reconcile_once, range(4)))
        with factory() as db:
            rows = db.query(AssetNetworkAssignment).filter_by(asset_id=asset_id).all()
            assert sorted(results) == ["reassigned", "renewed", "renewed", "renewed"]
            assert [(row.address, row.ended_at) for row in rows] == [(NEW_IP, None)]
    finally:
        # This test commits for real; remove its synthetic rows so later tests stay isolated.
        with factory.begin() as db:
            ids = [str(row.id) for row in db.query(AssetNetworkAssignment.id).filter_by(asset_id=asset_id)]
            db.query(AuditLog).filter(AuditLog.entity == "asset_network_assignment", AuditLog.entity_id.in_(ids or ["-"])).delete(synchronize_session=False)
            db.query(AssetNetworkAssignment).filter_by(asset_id=asset_id).delete()
            db.query(AssetIdentityEvidence).filter_by(asset_id=asset_id).delete()
            db.query(DHCPLeaseHistory).filter_by(id=lease_id).delete()
            db.query(HardwareAsset).filter_by(id=asset_id).delete()
            db.query(DNSProviderConfig).filter_by(id=provider_id).delete()
        engine.dispose()


# ------------------------------------------------------------ 12. multiple DHCP providers


def test_confirmed_identity_follows_the_device_across_dhcp_providers(db):
    mac = _mac()
    _, _, asset = _adopted_device(db, mac=mac)
    second = _provider(db, "Synthetic secondary Pi-hole")
    _sync(db, second, _item(NEW_IP, mac), _item("192.0.2.180", _mac(), name="synthetic-unrelated"), at=T2)
    assert _open(db, asset) == [NEW_IP]
    assert db.query(AssetNetworkAssignment).filter_by(address="192.0.2.180").count() == 0


# ------------------------------------------------------------ 13. VLAN / source contexts


def test_vlan_context_comes_only_from_containing_subnets_and_no_exporter_is_invented(db):
    low = VLAN(name=f"Synthetic low {uuid.uuid4().hex[:6]}", subnet_cidr="192.0.2.0/25")
    high = VLAN(name=f"Synthetic high {uuid.uuid4().hex[:6]}", subnet_cidr="192.0.2.128/25")
    db.add_all([low, high])
    db.flush()
    db.add(DHCPRange(name="Synthetic high scope", start_address="192.0.2.150", end_address="192.0.2.199", vlan_id=high.id, is_enabled=True))
    db.add(TrafficSource(name=f"Synthetic NSEL {uuid.uuid4().hex[:6]}", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False))
    db.commit()
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    assert _rows(db, asset)[0].vlan_id == high.id
    _sync(db, provider, _item("192.0.2.20", mac), at=T2)  # outside the high VLAN and the scope
    current = next(row for row in _rows(db, asset) if row.ended_at is None)
    assert (current.address, current.vlan_id, current.network_cidr) == ("192.0.2.20", None, None)
    assert all(row.source_id is None and row.exporter_identity is None for row in _rows(db, asset))


# ------------------------------------------------------------ 14. DHCP-only device


def test_dhcp_only_device_needs_no_managed_ip(db):
    managed_before = db.query(IPAddress).count()
    provider, _, asset = _adopted_device(db, mac=_mac())
    assert db.query(IPAddress).count() == managed_before
    assert _rows(db, asset)[0].ip_address_id is None


# ------------------------------------------------------------ 15. existing managed IP record


def test_existing_managed_ip_assignment_is_closed_without_creating_ip_records(db):
    managed_before = db.query(IPAddress).count()
    vlan = VLAN(name=f"Synthetic managed {uuid.uuid4().hex[:6]}", subnet_cidr="192.0.2.0/24")
    db.add(vlan)
    db.flush()
    db.add(IPAddress(address=OLD_IP, vlan_id=vlan.id, name="synthetic-managed"))
    db.commit()
    mac = _mac()
    provider = _provider(db)
    admin = _admin(db)
    _sync(db, provider, _item(OLD_IP, mac), at=T0)
    asset = _adopt(db, admin, provider, OLD_IP)
    (adopted,) = _rows(db, asset)
    assert adopted.ip_address_id is not None and adopted.provenance == "discovered_device_adoption"
    _sync(db, provider, _item(NEW_IP, mac), at=T2)
    rows = _rows(db, asset)
    assert [(row.address, row.ended_at is None) for row in rows] == [(OLD_IP, False), (NEW_IP, True)]
    assert rows[1].ip_address_id is None and rows[1].vlan_id == vlan.id
    assert db.query(IPAddress).count() == managed_before + 1


# ------------------------------------------------------------ 16. Asset Manager disabled


def test_disabled_asset_manager_makes_no_automatic_change(db, monkeypatch):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    monkeypatch.setattr(asset_identity, "module_is_enabled", lambda _db, module: module.key != "asset_manager")
    _sync(db, provider, _item(NEW_IP, mac), at=T2)
    assert _open(db, asset) == [OLD_IP]


# ------------------------------------------------------------ 17. Network Traffic disabled


def test_disabled_network_traffic_does_not_block_identity_continuity(db):
    _traffic_config(db, False)
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _sync(db, provider, _item(NEW_IP, mac), at=T2)
    assert _open(db, asset) == [NEW_IP]
    assert db.query(TrafficDeviceMonitoring).filter_by(asset_id=asset.id).count() == 0


# ------------------------------------------------------------ 18. existing DNS Manager records


def test_dns_manager_records_and_lease_history_are_preserved(db):
    mac = _mac()
    provider = _provider(db)
    dns_client = DNSRecognisedDevice(
        provider_id=provider.id, logical_provider_key="synthetic", identity_type="mac", identity_value=mac,
        normalised_mac=mac, mac_address=mac, hostname="synthetic-phone", current_ip=OLD_IP,
    )
    db.add(dns_client)
    db.commit()
    provider, _, asset = _adopted_device(db, mac=mac, provider=provider)
    snapshot = (dns_client.hardware_asset_id, dns_client.current_ip, db.query(DNSRecognisedDevice).count())
    _sync(db, provider, _item(NEW_IP, mac), at=T2)
    db.refresh(dns_client)
    assert (dns_client.hardware_asset_id, dns_client.current_ip, db.query(DNSRecognisedDevice).count()) == snapshot
    old_lease = _lease(db, provider, OLD_IP, active=False)
    assert old_lease is not None and old_lease.is_active is False and old_lease.ended_at == T2
    assert _lease(db, provider, NEW_IP).is_active is True


# ------------------------------------------------------------ 19. no automatic asset creation


def test_unknown_device_never_creates_an_asset_or_assignment(db):
    before = _counts(db)
    provider = _provider(db)
    _sync(db, provider, _item("192.0.2.30", _mac(), f"01:{uuid.uuid4().hex[:8]}", name="synthetic-unknown"), at=T0)
    _sync(db, provider, _item("192.0.2.31", _mac(), name="synthetic-unknown"), at=T1)
    assert _counts(db) == before


# ------------------------------------------------------------ 20. historical traffic ownership


def _flow(source_id, address, at, sequence):
    return NormalizedFlowRecord(
        exporter_identity="192.0.2.1", source_id=source_id, sequence=sequence, record_index=0,
        observed_at=at, flow_start=None, flow_end=None, source_ip=address, destination_ip="198.51.100.20",
        source_port=50000 + sequence, destination_port=443, protocol=6, input_interface=None, output_interface=None,
        translated_source_ip=None, translated_destination_ip=None, translated_source_port=None, translated_destination_port=None,
        bytes_total=(sequence * 100) + 10, packets_total=2, direction="unknown", event_type=None, connection_id=None,
        cumulative_counters=False, data_quality="complete",
        forward_bytes=sequence * 100, reverse_bytes=10, forward_packets=1, reverse_packets=1,
    )


def test_historical_traffic_stays_with_the_owner_of_each_interval(db):
    _traffic_config(db, True)
    if not db.query(TrafficLocalNetwork).filter_by(network_cidr="192.0.2.0/24").first():
        db.add(TrafficLocalNetwork(name=f"Synthetic LAN {uuid.uuid4().hex[:6]}", network_cidr="192.0.2.0/24", is_enabled=True))
    source = TrafficSource(name=f"Synthetic NSEL {uuid.uuid4().hex[:6]}", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)
    db.add(source)
    db.commit()
    provider = _provider(db)
    mac_a, mac_b = _mac(), _mac()
    _, admin, asset_a = _adopted_device(db, mac=mac_a, provider=provider)
    # Within the interval DHCP confirmed (first seen T0, last seen T1).
    process_records(db, [_flow(source.id, OLD_IP, T0 + timedelta(minutes=30), 1)], source_id=source.id)
    db.commit()
    _sync(db, provider, _item(NEW_IP, mac_a), at=T2)
    process_records(db, [_flow(source.id, NEW_IP, T2 + timedelta(minutes=30), 2)], source_id=source.id)
    db.commit()
    _sync(db, provider, _item(NEW_IP, mac_a), _item(OLD_IP, mac_b, name="synthetic-other"), at=T3)
    asset_b = _adopt(db, admin, provider, OLD_IP)
    _sync(db, provider, _item(NEW_IP, mac_a), _item(OLD_IP, mac_b, name="synthetic-other"), at=T4)
    process_records(db, [_flow(source.id, OLD_IP, T4 + timedelta(minutes=30), 3)], source_id=source.id)
    db.commit()

    a = asset_reporting_context(db, admin, asset_a.id, period="24h")["traffic"]
    b = asset_reporting_context(db, admin, asset_b.id, period="24h")["traffic"]
    # A keeps its old-address traffic and gains new-address traffic; B gets only its own interval.
    assert a["upload_bytes"] == 100 + 200
    assert b["upload_bytes"] == 300
    assert a["excluded_buckets"] == 0 and b["excluded_buckets"] == 0



# ------------------------------------------------------------ lease end and address reuse


def _traffic_source(db):
    _traffic_config(db, True)
    if not db.query(TrafficLocalNetwork).filter_by(network_cidr="192.0.2.0/24").first():
        db.add(TrafficLocalNetwork(name=f"Synthetic LAN {uuid.uuid4().hex[:6]}", network_cidr="192.0.2.0/24", is_enabled=True))
    source = TrafficSource(name=f"Synthetic NSEL {uuid.uuid4().hex[:6]}", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)
    db.add(source)
    db.commit()
    return source


def _measure(db, source, address, at, sequence):
    process_records(db, [_flow(source.id, address, at, sequence)], source_id=source.id)
    db.commit()


def _raw_upload(db, source, address):
    return int(db.query(func.coalesce(func.sum(TrafficEndpointAggregate.bytes_total), 0)).filter(
        TrafficEndpointAggregate.endpoint_ip == address, TrafficEndpointAggregate.bucket_seconds == 300,
        TrafficEndpointAggregate.direction == "upload", TrafficEndpointAggregate.source_id == source.id,
    ).scalar())


def _collect(db, provider, monkeypatch, leases, *, at):
    """A full DNS Manager collection pass; ``leases=None`` simulates a DHCP provider outage."""

    class _Clock(datetime):
        @classmethod
        def utcnow(cls):
            return at

    monkeypatch.setattr(dns_insights, "datetime", _Clock)
    dhcp = DNSProviderResult(False, "Synthetic DHCP outage") if leases is None else DNSProviderResult(True, "Synthetic DHCP leases", {"leases": leases})
    payloads = {
        "status": DNSProviderResult(True, "ok", {"blocking": "enabled"}), "stats": DNSProviderResult(True, "ok", {}),
        "history": DNSProviderResult(False, "n/a"), "clients": DNSProviderResult(False, "n/a"),
        "queries": DNSProviderResult(True, "ok", {"queries": []}), "dhcp": dhcp, "blocklists": DNSProviderResult(False, "n/a"),
    }
    try:
        dns_insights.build_context(db, provider, payloads=payloads)
        db.commit()
    finally:
        monkeypatch.setattr(dns_insights, "datetime", datetime)


def _closure_audits(db, asset):
    ids = {str(row.id) for row in _rows(db, asset)}
    rows = db.query(AuditLog).filter(AuditLog.entity == "asset_network_assignment", AuditLog.detail == "Closed DHCP network assignment after its lease ended").all()
    return [row for row in rows if row.entity_id in ids]


def test_unadopted_replacement_device_never_inherits_the_previous_owners_traffic(db):
    source = _traffic_source(db)
    mac_a, mac_b = _mac(), _mac()
    provider, admin, asset_a = _adopted_device(db, mac=mac_a)
    assets_before = db.query(HardwareAsset).count()
    _measure(db, source, OLD_IP, T0 + timedelta(minutes=30), 11)        # A, inside its confirmed lease
    _sync(db, provider, at=T2)                                           # A's lease ends (released)
    _sync(db, provider, _item(OLD_IP, mac_b, name="synthetic-guest"), at=T3)  # unadopted B gets the address
    _measure(db, source, OLD_IP, T3 + timedelta(minutes=30), 12)        # B's traffic
    a = asset_reporting_context(db, admin, asset_a.id, period="24h")["traffic"]
    assert a["upload_bytes"] == 1100                                     # never B's 1200
    assert _raw_upload(db, source, OLD_IP) == 1100 + 1200               # raw usage is still measured
    (old,) = _rows(db, asset_a)
    assert old.ended_at == T1                                            # last DHCP observation, nothing invented
    assert db.query(HardwareAsset).count() == assets_before              # B is never adopted
    assert db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.address == OLD_IP, AssetNetworkAssignment.ended_at.is_(None)).count() == 0
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset_a.id, evidence_type="mac", status="confirmed").count() == 1
    assert len(_closure_audits(db, asset_a)) == 1
    # A later receives a new address and reconnects through its confirmed identity.
    _sync(db, provider, _item(NEW_IP, mac_a), _item(OLD_IP, mac_b, name="synthetic-guest"), at=T4)
    assert _open(db, asset_a) == [NEW_IP]
    assert db.query(HardwareAsset).count() == assets_before


def test_replacement_in_the_same_snapshot_closes_at_the_last_observation(db):
    source = _traffic_source(db)
    provider, admin, asset_a = _adopted_device(db, mac=_mac())
    _sync(db, provider, _item(OLD_IP, _mac(), name="synthetic-guest"), at=T2)
    _measure(db, source, OLD_IP, T1 + timedelta(minutes=30), 21)        # ownership uncertain: fails closed
    _measure(db, source, OLD_IP, T2 + timedelta(minutes=30), 22)
    assert _rows(db, asset_a)[0].ended_at == T1
    traffic = asset_reporting_context(db, admin, asset_a.id, period="24h")["traffic"]
    assert traffic["sources"] == [] and traffic["status"]["state"] == "none"


def test_address_reused_by_another_confirmed_asset_links_in_the_same_collection(db):
    provider = _provider(db)
    mac_a, mac_b = _mac(), _mac()
    _, _, asset_a = _adopted_device(db, mac=mac_a, provider=provider)
    _, _, asset_b = _adopted_device(db, mac=mac_b, ip="192.0.2.170", name="synthetic-tablet")
    _sync(db, provider, _item(OLD_IP, mac_b, name="synthetic-tablet"), at=T2)
    assert _open(db, asset_a) == []
    assert _open(db, asset_b) == [OLD_IP]
    a_old = _rows(db, asset_a)[0]
    b_new = next(row for row in _rows(db, asset_b) if row.address == OLD_IP)
    assert a_old.ended_at == T1 and b_new.started_at == T2


def test_static_assignment_is_not_closed_when_a_lease_disappears(db):
    vlan = VLAN(name=f"Synthetic static {uuid.uuid4().hex[:6]}", subnet_cidr="192.0.2.0/24")
    db.add(vlan)
    db.flush()
    db.add(IPAddress(address=OLD_IP, vlan_id=vlan.id, name="synthetic-static"))
    db.commit()
    mac = _mac()
    provider, admin = _provider(db), _admin(db)
    _sync(db, provider, _item(OLD_IP, mac), at=T0)
    asset = _adopt(db, admin, provider, OLD_IP)
    _sync(db, provider, _item(OLD_IP, mac), at=T1)
    _sync(db, provider, at=T2)
    (row,) = _rows(db, asset)
    assert row.provenance == "discovered_device_adoption" and row.dhcp_lease_id is None and row.ended_at is None


def test_temporary_provider_outage_never_closes_by_assumption(db, monkeypatch):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _collect(db, provider, monkeypatch, None, at=T2)                     # DHCP unavailable, no expiry known
    assert _open(db, asset) == [OLD_IP]
    _collect(db, provider, monkeypatch, [_item(OLD_IP, mac)], at=T3)     # recovered, same lease
    assert len(_rows(db, asset)) == 1 and _open(db, asset) == [OLD_IP]


def test_provider_confirmed_expiry_during_outage_fails_closed(db, monkeypatch):
    mac = _mac()
    expires = (T1 + timedelta(minutes=30) - datetime(1970, 1, 1)).total_seconds()
    provider, admin = _provider(db), _admin(db)
    _collect(db, provider, monkeypatch, [_item(OLD_IP, mac)], at=T0)
    asset = _adopt(db, admin, provider, OLD_IP)
    _collect(db, provider, monkeypatch, [{**_item(OLD_IP, mac), "expires": expires}], at=T1)
    _collect(db, provider, monkeypatch, None, at=T2)                     # outage after the provider's expiry
    assert _rows(db, asset)[0].ended_at == T1
    renewed = (T4 - datetime(1970, 1, 1)).total_seconds()
    _collect(db, provider, monkeypatch, [{**_item(OLD_IP, mac), "expires": renewed}], at=T3)
    rows = _rows(db, asset)
    # The outage window stays unattributed; the renewed lease is followed from its observation.
    assert [(row.started_at, row.ended_at) for row in rows] == [(T0, T1), (T3, None)]


def test_infinite_lease_is_never_treated_as_expired(db, monkeypatch):
    mac = _mac()
    provider, admin = _provider(db), _admin(db)
    _collect(db, provider, monkeypatch, [{**_item(OLD_IP, mac), "expires": 0}], at=T0)
    asset = _adopt(db, admin, provider, OLD_IP)
    _collect(db, provider, monkeypatch, [{**_item(OLD_IP, mac), "expires": 0}], at=T1)
    _collect(db, provider, monkeypatch, None, at=T2)
    assert _open(db, asset) == [OLD_IP]


def test_incomplete_snapshot_fails_closed_then_relinks_without_backfill(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _sync(db, provider, _item("192.0.2.190", _mac(), name="synthetic-other"), at=T2)  # snapshot omits A
    _sync(db, provider, _item(OLD_IP, mac), at=T3)
    rows = _rows(db, asset)
    assert [(row.address, row.started_at, row.ended_at) for row in rows] == [(OLD_IP, T0, T1), (OLD_IP, T3, None)]


def test_lease_end_on_another_provider_never_closes_this_providers_assignment(db):
    provider, _, asset = _adopted_device(db, mac=_mac())
    other = _provider(db, "Synthetic secondary")
    _sync(db, other, _item("192.0.2.150", _mac(), name="synthetic-elsewhere"), at=T2)
    _sync(db, other, at=T3)
    assert _open(db, asset) == [OLD_IP]


def test_repeated_collections_close_once_and_audit_once(db):
    provider, _, asset = _adopted_device(db, mac=_mac())
    for at in (T2, T3, T4):
        _sync(db, provider, at=at)
    assert _rows(db, asset)[0].ended_at == T1
    assert len(_closure_audits(db, asset)) == 1


def test_successful_unverified_empty_snapshot_retains_active_lease(db):
    provider, _, asset = _adopted_device(db, mac=_mac())
    _persist_dhcp_leases(db, provider, {"leases": []}, [], T2)
    db.commit()
    assert _open(db, asset) == [OLD_IP]
    lease = _lease(db, provider, OLD_IP, active=False)
    assert lease is not None and lease.is_active is True


def test_authoritative_empty_snapshot_closes_active_lease(db):
    provider, _, asset = _adopted_device(db, mac=_mac())
    _persist_dhcp_leases(db, provider, {"leases": []}, [], T2, snapshot_authoritative=True)
    db.commit()
    assert _open(db, asset) == []
    lease = _lease(db, provider, OLD_IP, active=False)
    assert lease is not None and lease.is_active is False


def test_closure_audit_failure_rolls_back_the_closure(db, monkeypatch):
    provider, _, asset = _adopted_device(db, mac=_mac())
    monkeypatch.setattr(asset_identity, "write_audit", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError):
        _persist_dhcp_leases(db, provider, {"leases": []}, [], T2, snapshot_authoritative=True)
    db.rollback()
    monkeypatch.undo()
    assert _open(db, asset) == [OLD_IP]


def test_postgres_concurrent_lease_end_closes_once():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    factory = sessionmaker(bind=engine)
    mac = _mac()
    with factory.begin() as db:
        provider = DNSProviderConfig(name=f"Concurrent closure {uuid.uuid4().hex[:6]}", base_url="https://dns.example.invalid", provider_type="pihole")
        asset = HardwareAsset(name=f"Concurrent closure asset {uuid.uuid4().hex[:6]}")
        db.add_all([provider, asset])
        db.flush()
        lease = DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.209", mac_address=mac, lease_started_at=T0, first_seen_at=T0, last_seen_at=T1, is_active=False, ended_at=T2)
        db.add(lease)
        db.flush()
        db.add(AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.209", address_family=4, dhcp_lease_id=lease.id, started_at=T0, provenance="dhcp_reconciliation", status="confirmed"))
        provider_id, asset_id, lease_id = provider.id, asset.id, lease.id
    try:
        def close_once(_):
            with factory() as session:
                closed = asset_identity.close_ended_dhcp_assignments(session, provider_id=provider_id, observed_at=T2)
                session.commit()
                return closed

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(close_once, range(4)))
        with factory() as db:
            rows = db.query(AssetNetworkAssignment).filter_by(asset_id=asset_id).all()
            ids = [str(row.id) for row in rows]
            audits = db.query(AuditLog).filter(AuditLog.entity == "asset_network_assignment", AuditLog.entity_id.in_(ids)).count()
            assert sorted(results) == [0, 0, 0, 1]
            assert [row.ended_at for row in rows] == [T1] and audits == 1
    finally:
        with factory.begin() as db:
            ids = [str(row.id) for row in db.query(AssetNetworkAssignment.id).filter_by(asset_id=asset_id)]
            db.query(AuditLog).filter(AuditLog.entity == "asset_network_assignment", AuditLog.entity_id.in_(ids or ["-"])).delete(synchronize_session=False)
            db.query(AssetNetworkAssignment).filter_by(asset_id=asset_id).delete()
            db.query(DHCPLeaseHistory).filter_by(id=lease_id).delete()
            db.query(HardwareAsset).filter_by(id=asset_id).delete()
            db.query(DNSProviderConfig).filter_by(id=provider_id).delete()
        engine.dispose()
