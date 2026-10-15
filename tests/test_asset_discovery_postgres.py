import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.models import (
    AssetIdentityEvidence,
    AuditLog,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    User,
)
from app.services import asset_discovery
from app.services.asset_discovery import adopt_discovered_device


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
        db.add_all([actor, first, second, provider])
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
        db.query(AuditLog).filter(AuditLog.user_id == case["actor_id"]).delete(synchronize_session=False)
        db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id.in_(case["asset_ids"])).delete(synchronize_session=False)
        db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.id.in_(case["client_ids"])).delete(synchronize_session=False)
        db.query(DNSProviderConfig).filter(DNSProviderConfig.id.in_(case["provider_ids"])).delete(synchronize_session=False)
        db.query(HardwareAsset).filter(HardwareAsset.id.in_(case["asset_ids"])).delete(synchronize_session=False)
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
