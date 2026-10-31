"""Seed retrospective DHCP closure findings into a verified disposable database.

Run after ``stage2b_acceptance_seed.py`` (which creates the synthetic accounts).
Adds one lease-less adoption row and one lease-linked row whose lease evidence
predates the recorded reconciliation baseline, then runs a Data Integrity audit
so both appear as findings awaiting retrospective review. All data is synthetic
(RFC 5737 addresses, locally administered MACs, example.invalid names).
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSProviderConfig,
    HardwareAsset,
    IPAddress,
    RemoteManagerSetting,
    User,
    VLAN,
)
from app.models.models import DataIntegrityFinding, DNSClientEvent, DNSRecognisedDevice, UserModulePermission
from app.services import data_integrity
from app.services.asset_identity import RECONCILIATION_BASELINE_KEY
from app.services.data_integrity_checks import AUTO_FILL_SOURCE, Detection
from app.services.modules import grant_all_registered_modules
from tests.fixtures.stage2b_acceptance import FIXTURE_PASSWORD, hash_password
from scripts.kaya_test_migrations import _verify_connected_target, verify_disposable_url

ADMIN_ID = 9001
# Unique per run, so the seed can be repeated against the same disposable
# database without earlier runs' confirmed MACs making ownership ambiguous.
TOKEN = secrets.token_hex(3)
OCTET = 100 + secrets.randbelow(150)
REVIEW_ONLY_EMAIL = f"retro-review-only-{TOKEN}@example.invalid"
LEGACY_IP, EXPIRED_IP = f"198.51.100.{OCTET}", f"198.51.100.{OCTET + 1}"
LEGACY_MAC = "02:00:5e:" + ":".join(TOKEN[i:i + 2] for i in range(0, 6, 2))
EXPIRED_MAC = "02:00:5f:" + ":".join(TOKEN[i:i + 2] for i in range(0, 6, 2))
CAMERA_MAC = "02:00:60:" + ":".join(TOKEN[i:i + 2] for i in range(0, 6, 2))
CAMERA_IP = f"198.51.100.{OCTET + 2}"


def seed(db) -> dict:
    now = datetime.utcnow().replace(second=0, microsecond=0)
    t0, t1, t2, t3 = (now - timedelta(hours=hours) for hours in (12, 11, 8, 5))
    admin = db.get(User, ADMIN_ID)
    if admin is None:
        raise SystemExit("Run stage2b_acceptance_seed.py first: the synthetic administrator is missing.")
    grant_all_registered_modules(db, admin)
    # An administrator who may review Data Integrity but not apply repairs.
    review_only = User(email=REVIEW_ONLY_EMAIL, password_hash=hash_password(FIXTURE_PASSWORD), role="admin", is_active=True)
    db.add(review_only)
    db.flush()
    grant_all_registered_modules(db, review_only)
    db.flush()
    db.query(UserModulePermission).filter_by(user_id=review_only.id, module_key="data_integrity.repair").delete()
    vlan = VLAN(name=f"Retrospective acceptance LAN {TOKEN}", subnet_cidr="198.51.100.0/24")
    provider = DNSProviderConfig(name=f"Retrospective acceptance Pi-hole {TOKEN}", base_url="https://dns.example.invalid", provider_type="pihole")
    legacy_asset = HardwareAsset(name="Retrospective legacy phone", asset_tag=f"SYN-RETRO-{TOKEN}-1", status="In use")
    expired_asset = HardwareAsset(name="Retrospective expired tablet", asset_tag=f"SYN-RETRO-{TOKEN}-2", status="In use")
    db.add_all([vlan, provider, legacy_asset, expired_asset])
    db.flush()
    record = IPAddress(address=LEGACY_IP, vlan_id=vlan.id, assignment_type="Dynamic", name="retro-legacy.example.invalid")
    db.add(record)
    for asset, mac in ((legacy_asset, LEGACY_MAC), (expired_asset, EXPIRED_MAC)):
        db.add(AssetIdentityEvidence(asset_id=asset.id, evidence_type="mac", normalised_value=mac, source="discovery", source_scope="dhcp",
                                     status="confirmed", first_observed_at=t0, last_observed_at=t0, confirmed_by=admin.id, confirmed_at=t0))
    legacy_lease = DHCPLeaseHistory(provider_id=provider.id, ip_address=LEGACY_IP, mac_address=LEGACY_MAC, hostname="retro-legacy",
                                    lease_started_at=t0, first_seen_at=t0, last_seen_at=t1, is_active=False, ended_at=t2, source="Pi-hole DHCP lease")
    expired_lease = DHCPLeaseHistory(provider_id=provider.id, ip_address=EXPIRED_IP, mac_address=EXPIRED_MAC, hostname="retro-expired",
                                     lease_started_at=t0, first_seen_at=t0, last_seen_at=t2, expires_at=t2 + timedelta(minutes=30), is_active=True, source="Pi-hole DHCP lease")
    db.add_all([legacy_lease, expired_lease])
    db.flush()
    legacy_row = AssetNetworkAssignment(asset_id=legacy_asset.id, address=LEGACY_IP, address_family=4, vlan_id=vlan.id, ip_address_id=record.id,
                                        started_at=t0 + timedelta(minutes=1), provenance="discovered_device_adoption", status="confirmed",
                                        confirmed_by=admin.id, confirmed_at=t0)
    expired_row = AssetNetworkAssignment(asset_id=expired_asset.id, address=EXPIRED_IP, address_family=4, dhcp_lease_id=expired_lease.id,
                                         started_at=t0, provenance="dhcp_reconciliation", status="confirmed", confirmed_at=t0)
    db.add_all([legacy_row, expired_row])
    # A Static record whose name was copied from a DNS observation, for the
    # "Set asset hostname" repair: its MAC is confirmed for exactly one asset.
    camera_asset = HardwareAsset(name="Hostname repair camera", asset_tag=f"SYN-RETRO-{TOKEN}-3", status="In use")
    camera_record = IPAddress(address=CAMERA_IP, vlan_id=vlan.id, assignment_type="Static", mac_address=CAMERA_MAC, name="old-camera.example.invalid")
    db.add_all([camera_asset, camera_record])
    db.flush()
    db.add(AssetIdentityEvidence(asset_id=camera_asset.id, evidence_type="mac", normalised_value=CAMERA_MAC, source="manual",
                                 status="confirmed", first_observed_at=t0, last_observed_at=t0, confirmed_by=admin.id, confirmed_at=t0))
    camera_client = DNSRecognisedDevice(
        provider_id=provider.id, logical_provider_key=f"retro-{TOKEN}", identity_key=f"mac:{CAMERA_MAC}", identity_type="mac",
        identity_value=CAMERA_MAC, hostname="new-camera.example.invalid", mac_address=CAMERA_MAC, normalised_mac=CAMERA_MAC,
        linked_ip_record_id=camera_record.id, first_seen_at=t0, last_seen_at=t2,
    )
    db.add(camera_client)
    db.flush()
    db.add(DNSClientEvent(dns_client_id=camera_client.id, event_type="managed_record_updated", event_summary="Empty managed hostname populated from observation",
                          new_value="old-camera.example.invalid", source=AUTO_FILL_SOURCE))
    existing = db.query(RemoteManagerSetting).filter_by(key=RECONCILIATION_BASELINE_KEY).first()
    if existing is None:
        db.add(RemoteManagerSetting(key=RECONCILIATION_BASELINE_KEY, value=t3.isoformat()))
    else:
        existing.value = t3.isoformat()
    db.commit()
    run = data_integrity.queue_audit(db, admin)
    run_id = data_integrity.claim_queued_run(db)
    if run_id != run.id:
        raise SystemExit("Another Data Integrity run was queued; refusing to continue.")
    status = data_integrity.execute_run(run_id, sessionmaker(bind=db.get_bind(), autoflush=False, expire_on_commit=False))
    db.expire_all()
    findings = {}
    for name, row in (("legacy", legacy_row), ("expired", expired_row)):
        key = Detection("obsolete_dhcp_assignment", str(row.id), "", "", {}, None).key
        finding = db.query(DataIntegrityFinding).filter_by(finding_key=key).one()
        findings[name] = {"finding_id": finding.id, "assignment_id": row.id, "asset_tag": f"SYN-RETRO-{TOKEN}-{1 if name == 'legacy' else 2}"}
    hostname_key = Detection("static_hostname_auto_filled", str(camera_record.id), "", "", {}, None).key
    hostname_finding = db.query(DataIntegrityFinding).filter_by(finding_key=hostname_key).one()
    findings["hostname"] = {"finding_id": hostname_finding.id, "asset_id": camera_asset.id, "asset_tag": f"SYN-RETRO-{TOKEN}-3", "ip_address_id": camera_record.id}
    return {
        "audit_status": status, "baseline_at": t3.isoformat(), "findings": findings,
        "expected_end": {"legacy": t1.isoformat(), "expired": t2.isoformat()},
        "addresses": {"legacy": LEGACY_IP, "expired": EXPIRED_IP},
        "macs": {"legacy": LEGACY_MAC, "expired": EXPIRED_MAC},
        "review_only_email": REVIEW_ONLY_EMAIL,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("KAYA_TEST_POSTGRES_URL"))
    parser.add_argument("--fixture-file", required=True)
    args = parser.parse_args()
    if os.environ.get("KAYA_STAGE2B_TEST_MARKER") != "I_UNDERSTAND_DISPOSABLE_STAGE2B":
        raise SystemExit("Refusing to seed without KAYA_STAGE2B_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGE2B")
    if not args.url:
        raise SystemExit("--url or KAYA_TEST_POSTGRES_URL is required")
    verify_disposable_url(args.url)
    fixture_path = Path(args.fixture_file).resolve()
    try:
        fixture_path.relative_to(Path(tempfile.gettempdir()).resolve())
    except ValueError as exc:
        raise SystemExit("--fixture-file must be inside the system temporary directory") from exc
    engine = create_engine(args.url, future=True)
    try:
        _verify_connected_target(engine, args.url)
        with sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)() as db:
            result = seed(db)
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result, sort_keys=True))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
