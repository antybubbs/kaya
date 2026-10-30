import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.models import (
    AssetNetworkAssignment,
    AssetIdentityEvidence,
    AuditLog,
    DHCPLeaseHistory,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    User,
    RemoteManagerSetting,
    IPAddress,
)
from app.services import asset_discovery
from app.services.asset_discovery import adopt_discovered_device
from app.services.asset_tags import allocate_asset_tag


@pytest.fixture
def postgres_factory():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=8, max_overflow=0, pool_pre_ping=True)
    yield sessionmaker(bind=engine)
    engine.dispose()


def _case(factory, *, second_provider=False):
    token = uuid4().hex[:12]
    with factory.begin() as db:
        actor = User(email=f"phase55-pg-{token}@example.invalid", role="admin", is_active=True)
        first = HardwareAsset(name=f"Phase55 PostgreSQL asset one {token}", status="In use")
        second = HardwareAsset(name=f"Phase55 PostgreSQL asset two {token}", status="In use")
        provider = DNSProviderConfig(name=f"Phase55 DNS one {token}", base_url="http://198.51.100.20")
        db.add_all([
            actor, first, second, provider,
            RemoteManagerSetting(key="asset_tags_auto_generate", value="1"),
            RemoteManagerSetting(key="asset_tags_prefix", value=f"P55{token[:4]}"),
            RemoteManagerSetting(key="asset_tags_separator", value="-"),
            RemoteManagerSetting(key="asset_tags_padding", value="4"),
            RemoteManagerSetting(key="asset_tags_start_number", value="1"),
        ])
        if second_provider:
            other_provider = DNSProviderConfig(name=f"Phase55 DNS two {token}", base_url="http://198.51.100.21")
            db.add(other_provider)
        db.flush()
        client = DNSRecognisedDevice(
            provider_id=provider.id,
            logical_provider_key=f"phase55-{token}",
            identity_key=f"mac:{token}",
            identity_type="mac",
            identity_value=f"00:11:22:33:44:{token[-2:]}",
            hostname=f"phase55-{token}.example.invalid",
            mac_address=f"00:11:22:33:44:{token[-2:]}",
            normalised_mac=f"00:11:22:33:44:{token[-2:]}",
            first_seen_at=datetime(2026, 1, 1),
            last_seen_at=datetime(2026, 1, 1),
        )
        db.add(client)
        other_client = None
        if second_provider:
            other_client = DNSRecognisedDevice(
                provider_id=other_provider.id,
                logical_provider_key=f"phase55-other-{token}",
                identity_key=f"mac:other-{token}",
                identity_type="mac",
                identity_value=client.identity_value,
                hostname=f"phase55-other-{token}.example.invalid",
                mac_address=client.mac_address,
                normalised_mac=client.normalised_mac,
                first_seen_at=datetime(2026, 1, 1),
                last_seen_at=datetime(2026, 1, 1),
            )
            db.add(other_client)
        db.flush()
        result = {
            "token": token,
            "actor_id": actor.id,
            "asset_ids": [first.id, second.id],
            "client_ids": [client.id] + ([other_client.id] if other_client else []),
            "provider_ids": [provider.id] + ([other_provider.id] if second_provider else []),
            "adopted_name": f"Sky Decoder {token}",
        }
    return result


def _candidate(db, client_id):
    client = db.get(DNSRecognisedDevice, client_id)
    return {
        "id": f"dns:{client.id}",
        "kind": "dns",
        "name": client.hostname,
        "ip_addresses": [],
        "mac_addresses": [client.normalised_mac],
        "dhcp_client_ids": [],
        "review_state": "review",
        "asset_id": None,
        "dns_client_id": client.id,
    }


def _cleanup(factory, case):
    with factory.begin() as db:
        cleanup_assets = db.query(HardwareAsset.id).filter(
            (HardwareAsset.id.in_(case["asset_ids"])) |
            (HardwareAsset.name.in_(["Concurrent synthetic asset", "Manual concurrent asset", case["adopted_name"]]))
        ).all()
        cleanup_asset_ids = [row[0] for row in cleanup_assets]
        db.query(AuditLog).filter(AuditLog.user_id == case["actor_id"]).delete(synchronize_session=False)
        db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id.in_(cleanup_asset_ids or [-1])).delete(synchronize_session=False)
        db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.id.in_(case["client_ids"])).delete(synchronize_session=False)
        db.query(DNSProviderConfig).filter(DNSProviderConfig.id.in_(case["provider_ids"])).delete(synchronize_session=False)
        db.query(HardwareAsset).filter(
            (HardwareAsset.id.in_(case["asset_ids"])) |
            (HardwareAsset.name.in_(["Concurrent synthetic asset", "Manual concurrent asset", case["adopted_name"]]))
        ).delete(synchronize_session=False)
        db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key.like("asset_tags_%")).delete(synchronize_session=False)
        db.query(User).filter(User.id == case["actor_id"]).delete(synchronize_session=False)


def _adopt_concurrently(factory, actor_id, candidates, asset_ids):
    barrier = __import__("threading").Barrier(len(asset_ids))

    def worker(index):
        with factory() as db:
            actor = db.get(User, actor_id)
            barrier.wait()
            try:
                row = adopt_discovered_device(db, actor, candidates[index], asset_id=asset_ids[index])
                return ("ok", row.id)
            except Exception as exc:  # assertions below inspect the final database state
                db.rollback()
                return (type(exc).__name__, str(exc))

    with ThreadPoolExecutor(max_workers=len(asset_ids)) as pool:
        return list(pool.map(worker, range(len(asset_ids))))


def test_postgres_same_candidate_can_be_adopted_by_only_one_existing_asset(postgres_factory):
    case = _case(postgres_factory)
    try:
        with postgres_factory() as db:
            candidate = _candidate(db, case["client_ids"][0])
        results = _adopt_concurrently(postgres_factory, case["actor_id"], [candidate, candidate], case["asset_ids"])
        assert sorted(result[0] for result in results) == ["ValueError", "ok"]
        with postgres_factory() as db:
            client = db.get(DNSRecognisedDevice, case["client_ids"][0])
            assert client.hardware_asset_id in case["asset_ids"]
            assert db.query(AssetIdentityEvidence).filter_by(normalised_value=client.normalised_mac).count() == 1
            assert db.query(AuditLog).filter_by(action="adopt", entity="discovered_device").count() == 1
    finally:
        _cleanup(postgres_factory, case)


def test_postgres_real_adoption_route_allows_new_mac_with_legacy_unscoped_dhcp_id(postgres_factory, monkeypatch):
    case = _case(postgres_factory)
    route_db = None
    try:
        from app.routers import hardware_assets

        with postgres_factory() as db:
            actor = db.get(User, case["actor_id"])
            client = db.get(DNSRecognisedDevice, case["client_ids"][0])
            client.provider_client_id = "73"
            db.add(AssetIdentityEvidence(
                asset_id=case["asset_ids"][0], evidence_type="dhcp_client_id", normalised_value="73",
                source="dhcp", source_scope=None, status="confirmed",
                first_observed_at=datetime(2026, 1, 1), last_observed_at=datetime(2026, 1, 1),
                confirmed_by=actor.id, confirmed_at=datetime(2026, 1, 1),
            ))
            db.commit()

        monkeypatch.setattr(hardware_assets, "validate_csrf_token", lambda *_args: None)
        monkeypatch.setattr(hardware_assets, "csrf_context", lambda *_args: {"csrf_token": "synthetic-csrf"})
        route_db = postgres_factory()
        actor = route_db.get(User, case["actor_id"])
        result = hardware_assets.adopt_discovered_device_route(
            SimpleNamespace(),
            candidate_id=f"dns:{case['client_ids'][0]}",
            asset_id=None,
            new_name=case["adopted_name"],
            category="",
            csrf_token="synthetic-csrf",
            db=route_db,
            user=actor,
        )

        assert result.status_code == 303
        with postgres_factory() as db:
            client = db.get(DNSRecognisedDevice, case["client_ids"][0])
            new_asset = db.query(HardwareAsset).filter(HardwareAsset.name == case["adopted_name"]).one()
            assert client.hardware_asset_id == new_asset.id
            assert client.hardware_asset_id not in case["asset_ids"]
            assert db.query(AssetIdentityEvidence).filter_by(asset_id=case["asset_ids"][0], evidence_type="dhcp_client_id").one().status == "confirmed"
            assert db.query(AssetIdentityEvidence).filter_by(asset_id=new_asset.id, evidence_type="mac", status="confirmed").count() == 1
            assert db.query(AssetIdentityEvidence).filter_by(asset_id=new_asset.id, evidence_type="dhcp_client_id", source_scope=f"provider:{client.provider_id}:range:unscoped", status="confirmed").count() == 1
    finally:
        if route_db is not None:
            route_db.close()
        _cleanup(postgres_factory, case)


def test_postgres_dhcp_adoption_uses_mac_not_lease_freshness_or_historical_ip(postgres_factory, monkeypatch):
    """Exercise the administrator adoption route for stale and current DHCP evidence."""
    case = _case(postgres_factory)
    route_db = None
    try:
        from app.routers import hardware_assets

        monkeypatch.setattr(hardware_assets, "validate_csrf_token", lambda *_args: None)
        monkeypatch.setattr(hardware_assets, "csrf_context", lambda *_args: {"csrf_token": "synthetic-csrf"})
        now = datetime.utcnow()
        old_mac = "02:00:00:00:71:01"
        expired_mac = "02:00:00:00:71:02"
        active_mac = "02:00:00:00:71:03"
        duplicate_mac = old_mac
        with postgres_factory.begin() as db:
            old_asset = db.get(HardwareAsset, case["asset_ids"][0])
            db.add(AssetIdentityEvidence(asset_id=old_asset.id, evidence_type="mac", normalised_value=old_mac, source="discovery", source_scope="dhcp", status="confirmed", first_observed_at=now, last_observed_at=now, confirmed_by=case["actor_id"], confirmed_at=now))
            old_ip = IPAddress(address="192.0.2.171")
            expired_ip = IPAddress(address="192.0.2.172")
            active_ip = IPAddress(address="192.0.2.173")
            db.add_all([old_ip, expired_ip, active_ip])
            db.flush()
            db.add(AssetNetworkAssignment(asset_id=old_asset.id, address=old_ip.address, address_family=4, ip_address_id=old_ip.id, started_at=now - timedelta(days=2), ended_at=now - timedelta(days=1), provenance="dhcp_reconciliation", status="confirmed"))
            expired = DHCPLeaseHistory(provider_id=case["provider_ids"][0], ip_address=expired_ip.address, mac_address=expired_mac, hostname="expired-new-device", lease_started_at=now - timedelta(days=2), first_seen_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=1), expires_at=now - timedelta(days=1), is_active=False)
            active = DHCPLeaseHistory(provider_id=case["provider_ids"][0], ip_address=active_ip.address, mac_address=active_mac, hostname="active-new-device", lease_started_at=now, first_seen_at=now, last_seen_at=now, expires_at=now + timedelta(days=1), is_active=True)
            duplicate = DHCPLeaseHistory(provider_id=case["provider_ids"][0], ip_address=old_ip.address, mac_address=duplicate_mac, hostname="duplicate-device", lease_started_at=now - timedelta(days=2), first_seen_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=1), is_active=False)
            db.add_all([expired, active, duplicate])
            db.flush()
            expired_id, active_id, duplicate_id = expired.id, active.id, duplicate.id

        def adopt(lease_id, name):
            nonlocal route_db
            route_db = postgres_factory()
            actor = route_db.get(User, case["actor_id"])
            result = hardware_assets.adopt_discovered_device_route(
                SimpleNamespace(), candidate_id=f"dhcp:{lease_id}", asset_id=None,
                new_name=name, category="", csrf_token="synthetic-csrf", db=route_db, user=actor,
            )
            route_db.close()
            route_db = None
            return result

        assert adopt(expired_id, "Expired new device").status_code == 303
        assert adopt(active_id, "Active new device").status_code == 303
        with postgres_factory() as db:
            actor = db.get(User, case["actor_id"])
            with pytest.raises(ValueError, match="already confirmed"):
                adopt_discovered_device(db, actor, asset_discovery.get_discovered_device(db, f"dhcp:{duplicate_id}"), new_name="Duplicate device")

        with postgres_factory() as db:
            assert db.query(HardwareAsset).filter(HardwareAsset.name == "Expired new device").count() == 1
            assert db.query(HardwareAsset).filter(HardwareAsset.name == "Active new device").count() == 1
            expired_asset = db.query(HardwareAsset).filter(HardwareAsset.name == "Expired new device").one()
            active_asset = db.query(HardwareAsset).filter(HardwareAsset.name == "Active new device").one()
            assert db.query(AssetNetworkAssignment).filter_by(asset_id=expired_asset.id).count() == 0
            assert db.query(AssetNetworkAssignment).filter_by(asset_id=active_asset.id, address="192.0.2.173", ended_at=None).count() == 1
            assert db.query(AssetNetworkAssignment).filter_by(asset_id=case["asset_ids"][0], address="192.0.2.171").one().ended_at is not None
            assert db.query(HardwareAsset).filter(HardwareAsset.name == "Duplicate device").count() == 0
    finally:
        if route_db is not None:
            route_db.close()
        with postgres_factory.begin() as db:
            adopted_ids = [row[0] for row in db.query(HardwareAsset.id).filter(HardwareAsset.name.in_(["Expired new device", "Active new device", "Duplicate device"])).all()]
            db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id.in_(adopted_ids or [-1])).delete(synchronize_session=False)
            db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id.in_(adopted_ids or [-1])).delete(synchronize_session=False)
            db.query(HardwareAsset).filter(HardwareAsset.id.in_(adopted_ids or [-1])).delete(synchronize_session=False)
            db.query(DHCPLeaseHistory).filter(DHCPLeaseHistory.ip_address.in_(["192.0.2.171", "192.0.2.172", "192.0.2.173"])).delete(synchronize_session=False)
            db.query(IPAddress).filter(IPAddress.address.in_(["192.0.2.171", "192.0.2.172", "192.0.2.173"])).delete(synchronize_session=False)
        _cleanup(postgres_factory, case)


def test_postgres_same_candidate_create_and_adopt_has_one_new_asset(postgres_factory):
    case = _case(postgres_factory)
    try:
        with postgres_factory() as db:
            candidate = _candidate(db, case["client_ids"][0])

        barrier = __import__("threading").Barrier(2)

        def worker():
            with postgres_factory() as db:
                actor = db.get(User, case["actor_id"])
                barrier.wait()
                try:
                    row = adopt_discovered_device(db, actor, candidate, new_name="Concurrent synthetic asset")
                    return ("ok", row.id)
                except Exception as exc:
                    db.rollback()
                    return (type(exc).__name__, str(exc))

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: worker(), range(2)))
        assert sorted(result[0] for result in results) == ["ValueError", "ok"]
        with postgres_factory() as db:
            assert db.query(HardwareAsset).filter(HardwareAsset.name == "Concurrent synthetic asset").count() == 1
    finally:
        _cleanup(postgres_factory, case)


def test_postgres_audit_failure_rolls_back_asset_evidence_and_source_link(postgres_factory, monkeypatch):
    case = _case(postgres_factory)
    try:
        monkeypatch.setattr(asset_discovery, "write_audit", lambda *args, **kwargs: None)
        with postgres_factory() as db:
            actor = db.get(User, case["actor_id"])
            candidate = _candidate(db, case["client_ids"][0])
            with pytest.raises(RuntimeError, match="audited"):
                adopt_discovered_device(db, actor, candidate, new_name="Rolled back synthetic asset")
        with postgres_factory() as db:
            client = db.get(DNSRecognisedDevice, case["client_ids"][0])
            assert client.hardware_asset_id is None
            assert db.query(HardwareAsset).filter(HardwareAsset.name == "Rolled back synthetic asset").count() == 0
            assert db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id.in_(case["asset_ids"])).count() == 0
    finally:
        _cleanup(postgres_factory, case)


def test_postgres_competing_source_records_cannot_confirm_same_mac(postgres_factory):
    case = _case(postgres_factory, second_provider=True)
    try:
        with postgres_factory() as db:
            candidates = [_candidate(db, client_id) for client_id in case["client_ids"]]
        results = _adopt_concurrently(postgres_factory, case["actor_id"], candidates, case["asset_ids"])
        assert sorted(result[0] for result in results) == ["ValueError", "ok"]
        with postgres_factory() as db:
            assert db.query(AssetIdentityEvidence).filter_by(evidence_type="mac", normalised_value=candidates[0]["mac_addresses"][0]).count() == 1
    finally:
        _cleanup(postgres_factory, case)


def test_postgres_manual_creation_and_discovery_adoption_allocate_distinct_tags(postgres_factory):
    case = _case(postgres_factory)
    try:
        with postgres_factory() as db:
            candidate = _candidate(db, case["client_ids"][0])
        barrier = __import__("threading").Barrier(2)

        def manual_worker():
            with postgres_factory() as db:
                barrier.wait()
                tag = allocate_asset_tag(db, None)
                db.add(HardwareAsset(asset_tag=tag, name="Manual concurrent asset", status="In use"))
                db.commit()
                return tag

        def adoption_worker():
            with postgres_factory() as db:
                actor = db.get(User, case["actor_id"])
                barrier.wait()
                row = adopt_discovered_device(db, actor, candidate, new_name="Concurrent synthetic asset")
                return row.asset_tag

        with ThreadPoolExecutor(max_workers=2) as pool:
            manual_future = pool.submit(manual_worker)
            adoption_future = pool.submit(adoption_worker)
            tags = {manual_future.result(), adoption_future.result()}

        assert len(tags) == 2
        with postgres_factory() as db:
            assert db.query(HardwareAsset).filter(HardwareAsset.name.in_(["Manual concurrent asset", "Concurrent synthetic asset"])).count() == 2
    finally:
        _cleanup(postgres_factory, case)
