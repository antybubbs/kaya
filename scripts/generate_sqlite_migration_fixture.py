"""Create a synthetic, current-head SQLite source for Phase 5 tests."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path

from alembic import command
from sqlalchemy import create_engine, text

from app.db.migrations import _alembic_config
from app.core.security import encrypt_secret, hash_password
from app.models.models import Base


def generate(
    path: Path,
    traffic_rows: int,
    metric_rows: int,
    audit_rows: int,
    audit_payload_bytes: int = 0,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{path.as_posix()}"
    command.upgrade(_alembic_config(url), "head")
    engine = create_engine(url)
    audit_detail = (
        "synthetic audit event " + ("audit-payload-" * ((audit_payload_bytes // 14) + 1))
    )[: max(audit_payload_bytes, len("synthetic audit event "))]
    with engine.begin() as connection:
        connection.execute(text("""
            INSERT INTO users (email, password_hash, role, is_active, totp_enabled, authentication_type, is_break_glass, role_source, created_at, updated_at)
            VALUES ('synthetic@example.invalid', :password_hash, 'admin', 1, 0, 'local', 0, 'local', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """), {"password_hash": hash_password("synthetic-admin-password")})
        connection.execute(text("""
            INSERT INTO dns_providers (name, provider_type, base_url, auth_method, ssl_verify, timeout_seconds, is_enabled, created_at, updated_at)
            VALUES ('Synthetic DNS', 'pihole', 'https://dns.invalid', 'password', 1, 10, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """))
        connection.execute(text("""
            INSERT INTO dns_recognised_devices (provider_id, logical_provider_key, identity_type, identity_value, hostname, current_ip, provider_type, is_known, is_ignored, is_suppressed, query_count, blocked_query_count, observation_count, first_seen_at, last_seen_at, created_at, updated_at)
            VALUES (1, 'synthetic', 'mac', 'aa:bb', 'synthetic.example.invalid', '192.0.2.10', 'pihole', 1, 0, 0, 10, 2, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """))
        connection.execute(text("""
            INSERT INTO compute_hosts (name, platform, base_url, verify_tls, is_enabled, poll_interval_seconds, status, created_at, updated_at)
            VALUES ('synthetic-compute', 'linux', 'https://compute.invalid', 1, 1, 30, 'online', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """))
        connection.execute(text("""
            INSERT INTO dns_client_traffic_events (dns_client_id, provider_id, event_key, client_ip, domain, query_type, status, reply_type, reply_time_ms, upstream, is_blocked, observed_at, created_at)
            SELECT 1, 1, 'event-' || n, '192.0.2.10', 'www-' || (n % 1000) || '.example.invalid', 'A', 'NOERROR', 'A', 1.25, '10.0.0.1', n % 10 = 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            FROM (WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < :rows) SELECT n FROM numbers)"""), {"rows": traffic_rows})
        connection.execute(text("""
            INSERT INTO compute_metrics (host_id, cpu_percent, memory_used, memory_total, storage_used, storage_total, recorded_at)
            SELECT 1, n % 100, 1000000000 + n, 16000000000, 50000000000 + n, 100000000000, CURRENT_TIMESTAMP
            FROM (WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < :rows) SELECT n FROM numbers)"""), {"rows": metric_rows})
        connection.execute(text("""
            INSERT INTO audit_logs (user_id, action, entity, entity_id, detail, category, severity, status_code, capture_tier, created_at)
            SELECT 1, 'synthetic.migration', 'dns_client', '1', :detail, 'activity', 'info', 200, 'standard', CURRENT_TIMESTAMP
            FROM (WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < :rows) SELECT n FROM numbers)"""), {"rows": audit_rows, "detail": audit_detail})
        connection.execute(text("""
            INSERT INTO remote_manager_settings (key, value, updated_at)
            VALUES ('synthetic-json', :json_value, CURRENT_TIMESTAMP)
        """), {"json_value": '{"unicode":"café","nested":{"ok":true}}'})
        connection.execute(text("""
            INSERT INTO runbook_images (original_filename, content_type, size_bytes, data, created_at)
            VALUES ('synthetic.bin', 'application/octet-stream', 8, X'0001020304050607', CURRENT_TIMESTAMP)
        """))


def generate_functional(path: Path) -> None:
    """Build a small, deterministic application-state fixture for equivalence tests."""
    generate(path, traffic_rows=12, metric_rows=8, audit_rows=4)
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    tables = Base.metadata.tables
    now = datetime(2026, 1, 2, 12, 0, 0)

    def insert(connection, table_name: str, **values):
        connection.execute(tables[table_name].insert().values(**values))

    with engine.begin() as connection:
        insert(connection, "users", id=2, email="viewer@example.invalid", password_hash=hash_password("synthetic-password"), first_name="NFC café", last_name="Viewer", role="viewer", is_active=True, authentication_type="local", role_source="local", created_at=now, updated_at=now)
        insert(connection, "users", id=3, email="disabled@example.invalid", password_hash=hash_password("synthetic-password"), role="viewer", is_active=False, authentication_type="local", role_source="local", created_at=now, updated_at=now)
        for index, (user_id, module_key, allowed) in enumerate(((1, "dns_manager", True), (1, "compute_manager", True), (2, "dns_manager", True), (2, "compute_manager", False)), 1):
            insert(connection, "user_module_permissions", id=index, user_id=user_id, module_key=module_key, allowed=allowed, created_by=1, created_at=now, updated_at=now)
        insert(connection, "app_sessions", id=1, session_id="synthetic-active-session", user_id=2, ip_address="192.0.2.20", user_agent="synthetic-test", created_at=now, last_seen_at=now)
        insert(connection, "app_sessions", id=2, session_id="synthetic-revoked-session", user_id=2, ip_address="192.0.2.21", user_agent="synthetic-test", created_at=now, last_seen_at=now, ended_at=now)
        insert(connection, "app_sessions", id=3, session_id="synthetic-expired-session", user_id=2, ip_address="192.0.2.22", user_agent="synthetic-test", created_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=2), ended_at=now - timedelta(days=1))
        insert(connection, "hardware_assets", id=1, asset_tag="SYN-0001", name="Synthetic appliance", category="Network", status="In use", manufacturer="Synthetic", model="Test-1", location="Lab", created_at=now, updated_at=now)
        insert(connection, "hardware_asset_photos", id=1, asset_id=1, original_filename="one.png", storage_filename="one.webp", thumbnail_filename="one-thumb.webp", content_type="image/webp", is_primary=True, sort_order=0, uploaded_at=now)
        insert(connection, "hardware_asset_photos", id=2, asset_id=1, original_filename="two.png", storage_filename="two.webp", thumbnail_filename="two-thumb.webp", content_type="image/webp", is_primary=False, sort_order=1, uploaded_at=now)
        insert(connection, "hardware_asset_attachments", id=1, asset_id=1, original_filename="notes.txt", stored_filename="notes.txt", content_type="text/plain", uploaded_at=now)
        insert(connection, "ip_addresses", id=1, address="192.0.2.10", name="Synthetic appliance", mac_address="AA:BB:CC:DD:EE:FF", assignment_type="Static", created_at=now, updated_at=now)
        connection.execute(text("UPDATE dns_providers SET encrypted_secret=:secret WHERE id=1"), {"secret": encrypt_secret("synthetic-provider-secret")})
        connection.execute(text("UPDATE dns_recognised_devices SET linked_ip_record_id=1, hardware_asset_id=1, mac_address='AA:BB:CC:DD:EE:FF', normalised_mac='aa:bb:cc:dd:ee:ff', friendly_name='Synthetic appliance' WHERE id=1"))
        insert(connection, "dns_client_observations", id=1, dns_client_id=1, provider_id=1, observation_key="synthetic-observation", ip_address="192.0.2.10", mac_address="AA:BB:CC:DD:EE:FF", hostname="café-🧪.example.invalid", logical_provider_key="synthetic", source="fixture", observed_at=now, created_at=now)
        insert(connection, "dns_client_ip_history", id=1, dns_client_id=1, ip_address="192.0.2.10", first_seen_at=now - timedelta(days=1), last_seen_at=now, observation_count=2, provider_id=1, source="fixture", created_at=now, updated_at=now)
        insert(connection, "dns_client_hostname_history", id=1, dns_client_id=1, hostname="café-🧪.example.invalid", normalised_hostname="café-🧪.example.invalid", first_seen_at=now - timedelta(days=1), last_seen_at=now, observation_count=2, provider_id=1, source="fixture", created_at=now, updated_at=now)
        insert(connection, "dns_client_events", id=1, dns_client_id=1, event_type="fixture", event_summary="Unicode and NULL fixture", old_value=None, new_value="café-🧪", source="fixture", provider_id=1, created_at=now)
        insert(connection, "compute_workloads", id=1, host_id=1, external_id="synthetic-workload", name="Synthetic workload", kind="container", node="node-a", status="running", cpu_percent=12.5, cpu_total=100, memory_used=2048, memory_total=4096, storage_used=1000000000000, storage_total=2000000000000, uptime_seconds=3600, owner="synthetic", tags="alpha,🧪", metadata_json=json.dumps({"unicode": "café", "nullable": None}), last_seen_at=now, created_at=now, updated_at=now)
        insert(connection, "dhcp_lease_history", id=1, provider_id=1, dns_client_id=1, ip_address="192.0.2.10", hostname="synthetic.example.invalid", source="fixture", created_at=now, updated_at=now)
        insert(connection, "dns_insights", id=1, provider_id=1, insight_key="synthetic-insight", rule_key="synthetic-rule", category="dns", severity="info", title="Synthetic insight", summary="Synthetic summary", created_at=now, updated_at=now)
        insert(connection, "dns_investigations", id=1, provider_id=1, domain="example.invalid", status="open", created_at=now, updated_at=now)
        insert(connection, "ha_clusters", id=1, public_id="00000000-0000-0000-0000-000000000001", name="Synthetic HA", provider_key="pihole", status="ACTIVE", virtual_ip="192.0.2.50", prefix_length=24, automatic_failover_enabled=True, cluster_generation=3, role_generation=7, created_by_user_id=1, created_at=now, updated_at=now)
        insert(connection, "ha_nodes", id=1, cluster_id=1, public_id="00000000-0000-0000-0000-000000000011", display_name="Synthetic active", api_base_url="https://ha-active.invalid", role="ACTIVE", desired_role="ACTIVE", status="HEALTHY", agent_id="synthetic-agent-a", observed_generation=7, vip_owned=True, dns_healthy=True, peer_reachable=True, lease_generation=7, config_generation=2, last_heartbeat_at=now, created_at=now, updated_at=now)
        insert(connection, "ha_nodes", id=2, cluster_id=1, public_id="00000000-0000-0000-0000-000000000012", display_name="Synthetic standby", api_base_url="https://ha-standby.invalid", role="STANDBY", desired_role="STANDBY", status="HEALTHY", agent_id="synthetic-agent-b", observed_generation=7, vip_owned=False, dns_healthy=True, peer_reachable=True, lease_generation=7, config_generation=2, last_heartbeat_at=now, created_at=now, updated_at=now)
        connection.execute(text("UPDATE ha_clusters SET authoritative_node_id=1, current_active_node_id=1, preferred_node_id=1 WHERE id=1"))
        insert(connection, "ha_sync_runs", id=1, cluster_id=1, source_node_id=1, target_node_id=2, plan_json="{}", created_at=now)
        insert(connection, "ha_agent_action_results", id=1, action_id="synthetic-action", cluster_id=1, node_id=1, action_type="sync", generation=7, status="completed", message_redacted="Synthetic action", received_at=now)
        insert(connection, "ha_agent_credentials", id=1, node_id=1, agent_id="synthetic-agent-a", created_at=now, updated_at=now)
        insert(connection, "ha_backups", id=1, sync_run_id=1, node_id=1, encrypted_snapshot=b"synthetic-snapshot", checksum="synthetic-checksum", created_at=now)
        insert(connection, "ha_drift_items", id=1, sync_run_id=1, group_key="synthetic-group", risk="low", status="resolved", source_checksum="source", target_checksum="target", message="Synthetic drift")
        insert(connection, "ha_events", id=1, cluster_id=1, node_id=1, event_type="sync", severity="info", source="fixture", message="Synthetic HA event", occurred_at=now)
        insert(connection, "ha_failover_runs", id=1, cluster_id=1, source_node_id=1, target_node_id=2, preferred_node_id=1, role_generation=7, created_at=now)
        insert(connection, "ha_health_checks", id=1, cluster_id=1, node_id=1, check_key="synthetic", status="healthy", severity="info", summary="Synthetic health", observed_at=now)
        insert(connection, "ha_lease_replication_states", id=1, cluster_id=1, source_node_id=1, target_node_id=2, status="CURRENT", desired_generation=7, applied_generation=7, lease_count=4, last_event_at=now, last_full_reconciliation_at=now, created_at=now, updated_at=now)
        insert(connection, "ha_lease_snapshots", id=1, cluster_id=1, source_node_id=1, target_node_id=2, generation=7, checksum="synthetic-snapshot-checksum", encrypted_payload=b"synthetic-payload", created_at=now)
        insert(connection, "notification_events", id=1, event_type="synthetic.read", module="dashboard", category="system", severity="info", title="Read notification", message="Synthetic read notification", metadata_json='{"unicode":"café"}', target_route="/dashboard", correlation_id="synthetic-correlation-read", created_by_user_id=1, created_at=now, resolved_at=now)
        insert(connection, "notification_events", id=2, event_type="synthetic.unread", module="dns_manager", category="dns", severity="warning", title="Unread notification", message="Synthetic unread notification", metadata_json='{"nullable":null}', target_route="/networking/dns-manager", correlation_id="synthetic-correlation-unread", created_by_user_id=1, created_at=now)
        insert(connection, "user_notifications", id=1, notification_event_id=1, user_id=2, read_at=now, created_at=now, updated_at=now)
        insert(connection, "user_notifications", id=2, notification_event_id=2, user_id=2, created_at=now, updated_at=now)
        insert(connection, "notification_preferences", id=1, user_id=2, event_type="synthetic.unread", in_app_enabled=True, push_enabled=False, email_enabled=False, minimum_severity="info", recovery_enabled=True, timezone="UTC", created_at=now, updated_at=now)
        insert(connection, "push_subscriptions", id=1, user_id=2, endpoint_hash="synthetic-endpoint-hash", encrypted_subscription=encrypt_secret("synthetic-push-subscription"), device_label="Synthetic browser", browser_family="Test", operating_system="Linux", status="active", created_at=now)
        insert(connection, "audit_logs", id=100, user_id=2, action="synthetic.read", entity="dns_client", entity_id="1", ip_address="192.0.2.20", detail="Synthetic audit detail", category="activity", severity="info", status_code=200, request_id="synthetic-audit-request", capture_tier="standard", created_at=now)
        for module_key in (
            "asset_manager", "backup_manager", "compute_manager", "dashboard",
            "dns_manager", "domain_manager", "high_availability", "licence_manager",
            "network_monitor", "rack_manager", "remote_manager", "runbooks",
            "secret_vault", "secure_send", "vlan_ip_manager",
        ):
            connection.execute(text("""
                INSERT INTO user_module_permissions (user_id, module_key, allowed, created_by, created_at, updated_at)
                SELECT id, :module_key, 1, id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                FROM users WHERE email = 'synthetic@example.invalid'
                AND NOT EXISTS (
                    SELECT 1 FROM user_module_permissions
                    WHERE user_id = users.id AND module_key = :module_key
                )
            """), {"module_key": module_key})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--traffic-rows", type=int, default=10)
    parser.add_argument("--metric-rows", type=int, default=10)
    parser.add_argument("--audit-rows", type=int, default=10)
    parser.add_argument("--audit-payload-bytes", type=int, default=0)
    parser.add_argument("--functional", action="store_true")
    parser.add_argument(
        "--historical-revision",
        choices=("20260813_01",),
        help="Downgrade the generated functional fixture to a supported historical revision.",
    )
    arguments = parser.parse_args()
    if arguments.functional:
        generate_functional(arguments.path)
    else:
        generate(
            arguments.path,
            arguments.traffic_rows,
            arguments.metric_rows,
            arguments.audit_rows,
            arguments.audit_payload_bytes,
        )
    if arguments.historical_revision:
        command.downgrade(
            _alembic_config(f"sqlite:///{arguments.path.resolve().as_posix()}"),
            arguments.historical_revision,
        )
    print(f"synthetic SQLite source created: rows={arguments.traffic_rows}/{arguments.metric_rows}/{arguments.audit_rows}")


if __name__ == "__main__":
    main()
