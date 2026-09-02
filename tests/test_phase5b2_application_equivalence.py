"""Docker-only application equivalence validation for Phase 5B-2."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, func
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.core.security import decrypt_secret, verify_password
from app.db.sqlite_to_postgres import migrate
from app.models.models import (
    AppSession,
    AuditLog,
    ComputeHost,
    ComputeMetric,
    ComputeWorkload,
    DNSProviderConfig,
    DNSClientTrafficEvent,
    DNSRecognisedDevice,
    HardwareAsset,
    HardwareAssetPhoto,
    HACluster,
    HANode,
    NotificationEvent,
    User,
    UserNotification,
)
from app.services.compute_monitor import compute_summary
from app.services.dns_clients import list_clients, observe_client
from app.services.dashboard import snapshot as dashboard_snapshot
from app.services.modules import accessible_module_keys
from scripts.generate_sqlite_migration_fixture import generate_functional


pytestmark = pytest.mark.skipif(
    not os.environ.get("KAYA_PHASE5B2_EQUIVALENCE"),
    reason="run explicitly against disposable SQLite and PostgreSQL databases",
)


def _stable_snapshot(engine) -> dict:
    with Session(engine) as db:
        viewer = db.get(User, 2)
        clients, total = list_clients(db)
        compute = compute_summary(db)
        dashboard = dashboard_snapshot(db, viewer)
        dashboard.pop("generated_at", None)
        for widget in dashboard.get("widgets", {}).values():
            widget.pop("last_successful_update", None)
        return {
            "users": [
                (row.id, row.email, row.password_hash, row.role, row.is_active)
                for row in db.query(User).order_by(User.id)
            ],
            "sessions": [
                (row.session_id, row.user_id, row.ended_at is not None)
                for row in db.query(AppSession).order_by(AppSession.id)
            ],
            "dns_clients": [
                (row.id, row.hostname, row.current_ip, row.mac_address, row.provider_id, row.hardware_asset_id)
                for row in clients
            ],
            "dns_total": total,
            "dns_traffic": db.query(DNSClientTrafficEvent).count(),
            "compute": {
                "summary": {key: value for key, value in compute.items() if key != "updated_at"},
                "hosts": [(row.id, row.name, row.status, row.memory_used, row.storage_used) for row in db.query(ComputeHost).order_by(ComputeHost.id)],
                "workloads": [(row.id, row.name, row.kind, row.status, row.memory_used, row.storage_used, row.tags) for row in db.query(ComputeWorkload).order_by(ComputeWorkload.id)],
            },
            "ha": {
                "clusters": [(row.public_id, row.name, row.status, row.role_generation, row.current_active_node_id) for row in db.query(HACluster).order_by(HACluster.id)],
                "nodes": [(row.public_id, row.role, row.desired_role, row.status, row.lease_generation) for row in db.query(HANode).order_by(HANode.id)],
            },
            "assets": {
                "assets": [(row.id, row.asset_tag, row.name, row.status) for row in db.query(HardwareAsset).order_by(HardwareAsset.id)],
                "photos": [(row.id, row.asset_id, row.storage_filename, row.is_primary) for row in db.query(HardwareAssetPhoto).order_by(HardwareAssetPhoto.id)],
            },
            "notifications": [
                (row.id, row.event_type, row.severity, row.resolved_at is not None)
                for row in db.query(NotificationEvent).order_by(NotificationEvent.id)
            ] + [
                (row.id, row.notification_event_id, row.user_id, row.read_at is not None)
                for row in db.query(UserNotification).order_by(UserNotification.id)
            ],
            "audit": [
                (row.id, row.user_id, row.action, row.entity, row.category, row.severity)
                for row in db.query(AuditLog).order_by(AuditLog.id)
            ],
            "dashboard": dashboard,
            "encrypted_value": decrypt_secret(db.query(DNSProviderConfig).filter_by(id=1).one().encrypted_secret),
        }


def test_functional_sqlite_postgresql_equivalence_and_writes(tmp_path: Path) -> None:
    target_url = os.environ["KAYA_PHASE5B2_TARGET_URL"]
    source = tmp_path / "functional.sqlite3"
    generate_functional(source)
    sqlite_engine = create_engine(f"sqlite:///{source}")
    before = _stable_snapshot(sqlite_engine)
    assert verify_password("synthetic-password", before["users"][1][2])
    assert not verify_password("wrong-password", before["users"][1][2])

    report = migrate(source, target_url, tmp_path / "backups", batch_size=100)
    assert report["result"] == "COMPLETED"
    postgres_engine = create_engine(target_url)
    after = _stable_snapshot(postgres_engine)
    assert before == after
    assert after["encrypted_value"] == "synthetic-provider-secret"

    with Session(postgres_engine) as db:
        viewer = db.get(User, 2)
        client = db.get(DNSRecognisedDevice, 1)
        observe_client(
            db,
            db.get(DNSProviderConfig, 1),
            SimpleNamespace(
                client_id="synthetic-client",
                mac="AA:BB:CC:DD:EE:FF",
                ip="192.0.2.10",
                hostname="post-migration.example.invalid",
                queries=1,
                blocked_queries=0,
                source_member=None,
                last_seen=datetime(2026, 1, 3, 12, 0, 0),
                first_seen=datetime(2026, 1, 3, 12, 0, 0),
                source="synthetic-post-migration",
            ),
            datetime(2026, 1, 3, 12, 0, 0),
        )
        max_traffic_id = db.query(func.max(DNSClientTrafficEvent.id)).scalar() or 0
        db.add(DNSClientTrafficEvent(id=max_traffic_id + 1, dns_client_id=client.id, provider_id=1, event_key="post-migration-event", client_ip="192.0.2.10", domain="post-migration.example.invalid", query_type="A", status="NOERROR", reply_type="A", reply_time_ms=1.0, upstream="10.0.0.1", is_blocked=False, observed_at=datetime(2026, 1, 3, 12, 0, 0), created_at=datetime(2026, 1, 3, 12, 0, 0)))
        host = db.get(ComputeHost, 1)
        max_metric_id = db.query(func.max(ComputeMetric.id)).scalar() or 0
        db.add(ComputeMetric(id=max_metric_id + 1, host_id=host.id, workload_id=1, cpu_percent=0, memory_used=0, memory_total=4096, storage_used=0, storage_total=2000000000000, recorded_at=datetime(2026, 1, 3, 12, 0, 0)))
        max_audit_id = db.query(func.max(AuditLog.id)).scalar() or 0
        db.add(AuditLog(id=max_audit_id + 1, user_id=viewer.id, action="synthetic.post_migration_write", entity="dns_client", entity_id="1", category="activity", severity="info", status_code=200, created_at=datetime(2026, 1, 3, 12, 0, 0)))
        db.commit()
        assert db.query(DNSClientTrafficEvent).filter_by(event_key="post-migration-event").one().id > max_traffic_id
        assert db.query(ComputeMetric).filter_by(id=max_metric_id + 1).one().cpu_percent == 0
        assert db.query(AuditLog).filter_by(action="synthetic.post_migration_write").one().user_id == viewer.id
        assert "dns_manager" in accessible_module_keys(db, viewer)
        assert "compute_manager" not in accessible_module_keys(db, viewer)

        asset_max = db.query(func.max(HardwareAsset.id)).scalar() or 0
        new_asset = HardwareAsset(id=asset_max + 1, asset_tag="SYN-0002", name="Post-migration asset", status="In use")
        db.add(new_asset)
        db.flush()
        for index in range(1, 6):
            db.add(HardwareAssetPhoto(asset_id=new_asset.id, storage_filename=f"post-{index}.webp", content_type="image/webp", is_primary=index == 1, sort_order=index))
        db.commit()
        with pytest.raises((IntegrityError, DBAPIError), match="photo limit exceeded"):
            db.add(HardwareAssetPhoto(asset_id=new_asset.id, storage_filename="post-sixth.webp", content_type="image/webp", sort_order=6))
            db.commit()
        db.rollback()
        duplicate = HardwareAsset(asset_tag="SYN-0001", name="Duplicate tag", status="In use")
        db.add(duplicate)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        node = db.query(HANode).filter_by(role="STANDBY").one()
        node.last_report_sequence = node.last_report_sequence + 1
        node.last_heartbeat_at = datetime(2026, 1, 3, 12, 0, 0)
        cluster = db.get(HACluster, 1)
        cluster.role_generation = cluster.role_generation + 1
        notification = NotificationEvent(event_type="synthetic.post_migration", module="dns_manager", category="dns", severity="info", title="Post-migration notification", message="Synthetic notification", correlation_id="synthetic-post-migration", created_by_user_id=viewer.id)
        db.add(notification)
        db.flush()
        db.add(UserNotification(notification_event_id=notification.id, user_id=viewer.id))
        db.commit()
        assert db.get(HANode, node.id).last_report_sequence == 1
        assert db.get(HACluster, 1).role_generation == 8
        assert db.query(UserNotification).filter_by(notification_event_id=notification.id, user_id=viewer.id).one()

        invalid_traffic = DNSClientTrafficEvent(dns_client_id=999999, provider_id=1, event_key="invalid-fk", domain="invalid.example.invalid")
        db.add(invalid_traffic)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
