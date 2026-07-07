import argparse
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.demo import DEMO_ACCOUNTS
from app.core.security import encrypt_secret, hash_password
from app.db.session import Base
from app.models.models import (
    AuditLog,
    BackupJob,
    BackupRecord,
    ComputeEvent,
    ComputeHost,
    ComputeInventoryItem,
    ComputeMetric,
    ComputeWorkload,
    DNSInvestigation,
    DNSProviderConfig,
    DomainRecord,
    HardwareAsset,
    IPAddress,
    Licence,
    ManagedListItem,
    NetworkMonitor,
    RemoteAccess,
    RemoteManagerSetting,
    RunbookPage,
    RunbookSpace,
    User,
    VLAN,
)


def seed_database(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    database_path.unlink(missing_ok=True)
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)

    with Session(engine) as db:
        users = {}
        for name, account in DEMO_ACCOUNTS.items():
            user = User(
                email=account["email"],
                first_name=name.title(),
                last_name="Demo",
                password_hash=hash_password(account["password"]),
                role=account["role"],
                is_active=True,
            )
            db.add(user)
            users[name] = user
        db.flush()

        vlans = [
            VLAN(name="VLAN 1", description="Default management network"),
            VLAN(name="Servers", description="Application and virtualisation hosts"),
            VLAN(name="IoT", description="Isolated smart-home devices"),
            VLAN(name="Guests", description="Guest wireless clients"),
        ]
        db.add_all(vlans)
        db.flush()

        addresses = [
            IPAddress(vlan_id=vlans[0].id, address="10.20.1.1", category="Network", name="core-router", description="Primary lab gateway", assignment_type="Static", notes="Demo address only"),
            IPAddress(vlan_id=vlans[1].id, address="10.20.10.11", category="Compute", name="pve-01", description="Primary Proxmox node", assignment_type="Static"),
            IPAddress(vlan_id=vlans[1].id, address="10.20.10.21", category="Storage", name="nas-01", description="Shared storage appliance", assignment_type="Static"),
            IPAddress(vlan_id=vlans[1].id, address="10.20.10.31", category="Services", name="docker-01", description="Container services host", assignment_type="Static"),
            IPAddress(vlan_id=vlans[2].id, address="10.20.30.42", category="IoT", name="living-room-display", description="Dashboard display", assignment_type="Dynamic"),
        ]
        db.add_all(addresses)
        db.flush()
        db.add_all([
            NetworkMonitor(ip_address_id=row.id, display_name=row.name, is_enabled=False, interval_seconds=300, timeout_ms=1500, last_status="up", last_latency_ms=4, last_checked_at=now - timedelta(minutes=3))
            for row in addresses[:4]
        ])
        db.add_all([
            RemoteAccess(ip_address_id=addresses[1].id, display_name="Proxmox console", is_enabled=True, protocol="ssh", port=22, username="demo", notes="Live connections are disabled in the public demo."),
            RemoteAccess(ip_address_id=addresses[3].id, display_name="Docker host", is_enabled=True, protocol="ssh", port=22, username="demo", notes="Live connections are disabled in the public demo."),
        ])
        db.add_all([
            RemoteManagerSetting(key="guacamole_enabled", value="0"),
            RemoteManagerSetting(key="guacd_host", value=""),
            RemoteManagerSetting(key="guacd_port", value="4822"),
            RemoteManagerSetting(key="dns_manager_enabled", value="1"),
            RemoteManagerSetting(key="dns_cache_enabled", value="1"),
            RemoteManagerSetting(key="dns_refresh_interval_seconds", value="300"),
            RemoteManagerSetting(key="backup_targets_json", value=json.dumps([
                {
                    "name": "Demo NAS",
                    "type": "smb",
                    "path": "/mnt/backups/demo-nas",
                    "remote_host": "nas-01.lab.home.arpa",
                    "remote_share": "KayaBackups/Demo",
                    "remote_username": "kaya-demo",
                    "remote_password_enc": encrypt_secret("demo-password-only"),
                },
                {
                    "name": "Offsite Vault",
                    "type": "sftp",
                    "path": "/mnt/backups/offsite",
                    "remote_host": "backup-vault.example.invalid",
                    "remote_share": "/kaya/demo",
                    "remote_username": "kaya-offsite",
                    "remote_password_enc": encrypt_secret("demo-password-only"),
                },
            ], separators=(",", ":"))),
            RemoteManagerSetting(key="backup_default_target_name", value="Demo NAS"),
        ])

        db.add_all([
            HardwareAsset(asset_tag="SRV-001", name="Virtualisation Server", category="Server", status="In use", manufacturer="Dell", model="PowerEdge R730", serial_number="DEMO-SRV-001", location="Lab Rack U10", assigned_to="Infrastructure", purchase_date=date(2023, 4, 12), purchase_cost="GBP 850", warranty_expires=date(2027, 4, 12), supplier="Demo Hardware Ltd", notes="Synthetic public demo record."),
            HardwareAsset(asset_tag="NET-001", name="Core Switch", category="Network", status="In use", manufacturer="Ubiquiti", model="USW-Pro-24", serial_number="DEMO-NET-001", location="Lab Rack U18", assigned_to="Infrastructure", purchase_date=date(2024, 2, 8), purchase_cost="GBP 620", notes="Synthetic public demo record."),
            HardwareAsset(asset_tag="STO-001", name="NAS Appliance", category="Storage", status="In use", manufacturer="Synology", model="DS1821+", serial_number="DEMO-STO-001", location="Lab Rack U6", assigned_to="Infrastructure", purchase_date=date(2023, 9, 18), purchase_cost="GBP 1,100", notes="Synthetic public demo record."),
            HardwareAsset(asset_tag="LAP-014", name="Admin Laptop", category="Laptop", status="Spare", manufacturer="Lenovo", model="ThinkPad T14", serial_number="DEMO-LAP-014", location="Office", assigned_to="Lab Admin", purchase_date=date(2024, 6, 3), purchase_cost="GBP 780", notes="Synthetic public demo record."),
        ])

        db.add_all([
            Licence(licence_id="LIC-001", organisation="Kaya Demo", product="Windows Server 2025", vendor="Microsoft", encrypted_product_key=encrypt_secret("DEMO-ONLY-AAAAA-BBBBB-CCCCC"), licence_type="Volume", activations="2", seats=4, osa_status="Active", expiry_date=date.today() + timedelta(days=210), is_favourite=True, notes="Not a real product key."),
            Licence(licence_id="LIC-002", organisation="Kaya Demo", product="Backup Suite", vendor="Example Software", encrypted_product_key=encrypt_secret("DEMO-ONLY-DDDDD-EEEEE-FFFFF"), licence_type="Subscription", activations="1", seats=10, osa_status="Active", expiry_date=date.today() + timedelta(days=95), notes="Not a real product key."),
        ])

        db.add_all([
            DomainRecord(name="kaya-demo.example", registrar="Example Registrar", dns_provider="Example DNS", status="active", expires_at=now + timedelta(days=240), auto_renew=True, nameservers="ns1.example.invalid\nns2.example.invalid", dns_records=json.dumps([{"type": "A", "name": "demo", "value": "192.0.2.10"}]), notes="Reserved example domain; no live lookup is performed."),
            DomainRecord(name="lab-services.example", registrar="Example Registrar", dns_provider="Example DNS", status="active", expires_at=now + timedelta(days=120), auto_renew=False, nameservers="ns1.example.invalid", notes="Reserved example domain; no live lookup is performed."),
        ])
        dns_provider = DNSProviderConfig(
            name="Demo Pi-hole",
            provider_type="pihole",
            base_url="https://pihole.demo.invalid",
            auth_method="password",
            encrypted_secret=encrypt_secret("demo-password-only"),
            ssl_verify=True,
            timeout_seconds=5,
            is_enabled=True,
            description="Synthetic provider used by the public demo. No live DNS service is contacted.",
            last_status="online",
            last_checked_at=now - timedelta(minutes=2),
        )
        db.add(dns_provider)
        db.flush()
        db.add(RemoteManagerSetting(key="dns_default_provider_id", value=str(dns_provider.id)))
        db.add_all([
            DNSInvestigation(
                provider_id=dns_provider.id,
                domain="phish-demo.example.invalid",
                client_name="unknown-android",
                client_ip="10.20.30.88",
                query_type="A",
                status="open",
                reply_type="gravity",
                reply_time="0.3 ms",
                upstream="-",
                observed_at=(now - timedelta(minutes=18)).strftime("%Y-%m-%d %H:%M:%S"),
                notes="Demo investigation showing how a suspicious blocked query is tracked.",
                created_by_id=users["editor"].id,
            ),
            DNSInvestigation(
                provider_id=dns_provider.id,
                domain="casino-demo.example.invalid",
                client_name="guest-tablet",
                client_ip="10.20.40.23",
                query_type="A",
                status="open",
                reply_type="regex",
                reply_time="0.5 ms",
                upstream="-",
                observed_at=(now - timedelta(minutes=42)).strftime("%Y-%m-%d %H:%M:%S"),
                notes="Synthetic policy hit for the reports view.",
                created_by_id=users["admin"].id,
            ),
        ])

        space = RunbookSpace(name="Lab Operations", description="Common operating procedures for the demo lab", sort_order=10)
        db.add(space)
        db.flush()
        db.add_all([
            RunbookPage(space_id=space.id, title="Welcome to Kaya", slug="welcome-to-kaya", summary="A quick tour of this public demo.", body="# Welcome\n\nTry creating and editing inventory. Everything resets during the daily refresh.\n\n> All records and credentials in this demo are synthetic.", tags="welcome,demo", is_pinned=True, created_by_id=users["admin"].id, updated_by_id=users["admin"].id),
            RunbookPage(space_id=space.id, title="Patch night checklist", slug="patch-night-checklist", summary="Example monthly maintenance workflow.", body="## Before maintenance\n\n- Confirm backups\n- Review monitoring\n- Notify users\n\n## After maintenance\n\n- Validate services\n- Record changes", tags="maintenance,checklist", is_pinned=True, created_by_id=users["editor"].id, updated_by_id=users["editor"].id),
            RunbookPage(space_id=space.id, title="Restore a container", slug="restore-a-container", summary="Example recovery procedure.", body="1. Select the latest verified backup.\n2. Restore into an isolated network.\n3. Validate data and configuration.\n4. Promote the restored workload.", tags="backup,recovery", created_by_id=users["editor"].id, updated_by_id=users["editor"].id),
        ])

        host = ComputeHost(name="pve-01", platform="proxmox", base_url="https://10.20.10.11:8006", verify_tls=True, is_enabled=False, poll_interval_seconds=60, owner="Infrastructure", notes="Synthetic demo host; polling is disabled.", status="online", version="8.4", cpu_percent=18.6, memory_used=38_654_705_664, memory_total=68_719_476_736, storage_used=1_099_511_627_776, storage_total=2_199_023_255_552, last_synced_at=now - timedelta(minutes=4))
        db.add(host)
        db.flush()
        workloads = [
            ComputeWorkload(host_id=host.id, external_id="100", name="reverse-proxy", kind="lxc", node="pve-01", status="running", cpu_percent=3.2, cpu_total=2, memory_used=536_870_912, memory_total=2_147_483_648, storage_used=8_589_934_592, storage_total=21_474_836_480, uptime_seconds=1_296_000, owner="Infrastructure", backup_policy="Daily", tags="proxy,production", metadata_json=json.dumps({"addresses": ["10.20.10.40"]}), last_seen_at=now),
            ComputeWorkload(host_id=host.id, external_id="101", name="home-automation", kind="vm", node="pve-01", status="running", cpu_percent=7.8, cpu_total=4, memory_used=4_294_967_296, memory_total=8_589_934_592, storage_used=42_949_672_960, storage_total=85_899_345_920, uptime_seconds=604_800, owner="Home", backup_policy="Nightly", tags="automation,critical", metadata_json=json.dumps({"addresses": ["10.20.30.10"]}), last_seen_at=now),
            ComputeWorkload(host_id=host.id, external_id="102", name="test-runner", kind="lxc", node="pve-01", status="stopped", cpu_percent=0, cpu_total=2, memory_used=0, memory_total=2_147_483_648, storage_used=5_368_709_120, storage_total=21_474_836_480, uptime_seconds=0, owner="Development", backup_policy="Weekly", tags="test", metadata_json=json.dumps({"addresses": ["10.20.10.52"]}), last_seen_at=now),
        ]
        db.add_all(workloads)
        db.flush()
        db.add_all([
            ComputeInventoryItem(host_id=host.id, external_id="local-lvm", name="local-lvm", kind="storage", status="available", size_bytes=2_199_023_255_552, metadata_json=json.dumps({"type": "lvmthin"}), last_seen_at=now),
            ComputeInventoryItem(host_id=host.id, external_id="iso/debian-12.iso", name="debian-12.iso", kind="iso", status="available", size_bytes=671_088_640, last_seen_at=now),
            ComputeInventoryItem(host_id=host.id, external_id="backup-vzdump-nightly", name="Nightly VM backup", kind="backup", status="enabled", metadata_json=json.dumps({"last_status": "successful", "last_task": {"starttime": int((now - timedelta(hours=7)).timestamp())}, "schedule": "daily 02:15", "storage": "Demo NAS", "vmid": "100,101"}), last_seen_at=now - timedelta(minutes=4)),
            ComputeInventoryItem(host_id=host.id, external_id="backup-dev-weekly", name="Weekly development backup", kind="backup", status="enabled", metadata_json=json.dumps({"last_status": "warning", "last_task": {"starttime": int((now - timedelta(days=2)).timestamp())}, "schedule": "sun 03:00", "storage": "Offsite Vault", "vmid": "102"}), last_seen_at=now - timedelta(minutes=4)),
            ComputeMetric(host_id=host.id, cpu_percent=18.6, memory_used=38_654_705_664, memory_total=68_719_476_736, storage_used=1_099_511_627_776, storage_total=2_199_023_255_552, recorded_at=now - timedelta(minutes=4)),
            ComputeEvent(host_id=host.id, workload_id=workloads[0].id, event_type="started", detail="Workload started successfully", created_at=now - timedelta(hours=3)),
        ])

        docker_host = ComputeHost(
            name="docker-01",
            platform="docker_agent",
            base_url="http://10.20.10.31:8088",
            agent_token_hash="0" * 64,
            verify_tls=True,
            is_enabled=False,
            poll_interval_seconds=60,
            owner="Infrastructure",
            notes="Synthetic Docker Agent host; agent polling is disabled in the public demo.",
            status="online",
            version="Docker 27.5 / Kaya Agent demo",
            cpu_percent=22.4,
            memory_used=6_442_450_944,
            memory_total=17_179_869_184,
            storage_used=188_978_561_024,
            storage_total=536_870_912_000,
            metadata_json=json.dumps({"agent_capabilities": {"docker_backups": True}}),
            last_synced_at=now - timedelta(minutes=6),
            agent_last_seen_at=now - timedelta(minutes=6),
        )
        db.add(docker_host)
        db.flush()
        docker_workloads = [
            ComputeWorkload(host_id=docker_host.id, external_id="demo-grafana", name="grafana", kind="container", node="docker-01", status="running", cpu_percent=2.4, cpu_total=2, memory_used=412_090_368, memory_total=1_073_741_824, storage_used=2_147_483_648, storage_total=10_737_418_240, uptime_seconds=864_000, owner="Observability", backup_policy="auto", tags="monitoring,dashboard", metadata_json=json.dumps({"mounts": [{"Type": "bind", "Destination": "/var/lib/grafana"}, {"Type": "volume", "Destination": "/etc/grafana"}]}), last_seen_at=now),
            ComputeWorkload(host_id=docker_host.id, external_id="demo-vaultwarden", name="vaultwarden", kind="container", node="docker-01", status="running", cpu_percent=1.1, cpu_total=1, memory_used=268_435_456, memory_total=536_870_912, storage_used=1_610_612_736, storage_total=8_589_934_592, uptime_seconds=432_000, owner="Home", backup_policy="paths=/data", tags="passwords,critical", metadata_json=json.dumps({"mounts": [{"Type": "bind", "Destination": "/data"}]}), last_seen_at=now),
            ComputeWorkload(host_id=docker_host.id, external_id="demo-paperless", name="paperless-ngx", kind="container", node="docker-01", status="running", cpu_percent=4.8, cpu_total=2, memory_used=805_306_368, memory_total=2_147_483_648, storage_used=16_106_127_360, storage_total=53_687_091_200, uptime_seconds=259_200, owner="Admin", backup_policy="volumes-only", tags="documents", metadata_json=json.dumps({"mounts": [{"Type": "volume", "Destination": "/usr/src/paperless/data"}, {"Type": "bind", "Destination": "/usr/src/paperless/media"}]}), last_seen_at=now),
        ]
        db.add_all(docker_workloads)
        db.flush()
        db.add_all([
            BackupRecord(name="NAS configuration export", source_type="manual", target="Demo NAS / appliance-configs", schedule="Every Friday 22:00", owner="Infrastructure", last_status="successful", last_run_at=now - timedelta(days=1, hours=3), notes="Synthetic manual record for network device configuration backups.", is_enabled=True),
            BackupRecord(name="Domain registrar CSV export", source_type="manual", target="Offsite Vault / domain-exports", schedule="Monthly", owner="Admin", last_status="successful", last_run_at=now - timedelta(days=9), notes="Example governance backup outside the Docker/Proxmox agents.", is_enabled=True),
            BackupRecord(name="Laptop recovery image", source_type="manual", target="Demo NAS / endpoints", schedule="Ad hoc", owner="Support", last_status="failed", last_run_at=now - timedelta(days=3, hours=4), notes="Failure shown intentionally so the demo has something to triage.", is_enabled=True),
        ])
        db.add_all([
            BackupJob(host_id=docker_host.id, workload_id=docker_workloads[0].id, operation="backup", status="successful", encryption_enabled=True, encrypted_backup_key=encrypt_secret("demo-backup-key-grafana"), artifact_path="/mnt/backups/demo-nas/docker-01/grafana-20260707-0215.tar.zst.enc", size_bytes=734_003_200, metadata_json=json.dumps({"target_name": "Demo NAS", "path_count": 2, "paths": ["/var/lib/grafana", "/etc/grafana"]}), requested_by_id=users["admin"].id, created_at=now - timedelta(hours=8), dispatched_at=now - timedelta(hours=8, minutes=-1), started_at=now - timedelta(hours=7, minutes=58), finished_at=now - timedelta(hours=7, minutes=51)),
            BackupJob(host_id=docker_host.id, workload_id=docker_workloads[1].id, operation="backup", status="successful", encryption_enabled=True, encrypted_backup_key=encrypt_secret("demo-backup-key-vaultwarden"), artifact_path="/mnt/backups/demo-nas/docker-01/vaultwarden-20260707-0217.tar.zst.enc", size_bytes=86_507_520, metadata_json=json.dumps({"target_name": "Demo NAS", "path_count": 1, "paths": ["/data"]}), requested_by_id=users["editor"].id, created_at=now - timedelta(hours=8), dispatched_at=now - timedelta(hours=7, minutes=59), started_at=now - timedelta(hours=7, minutes=57), finished_at=now - timedelta(hours=7, minutes=54)),
            BackupJob(host_id=docker_host.id, workload_id=docker_workloads[2].id, operation="backup", status="failed", encryption_enabled=True, encrypted_backup_key=encrypt_secret("demo-backup-key-paperless"), artifact_path=None, size_bytes=None, error="Demo failure: media path was unavailable during scan.", metadata_json=json.dumps({"target_name": "Offsite Vault", "path_count": 0}), requested_by_id=users["admin"].id, created_at=now - timedelta(hours=2), dispatched_at=now - timedelta(hours=2, minutes=-1), started_at=now - timedelta(hours=1, minutes=58), finished_at=now - timedelta(hours=1, minutes=55)),
        ])

        list_values = {
            ("hardware_assets", "category"): ["Server", "Network", "Storage", "Laptop"],
            ("ip_addresses", "category"): ["Network", "Compute", "Storage", "Services", "IoT"],
            ("licences", "licence_type"): ["Volume", "Subscription", "Perpetual"],
        }
        for (module, list_key), values in list_values.items():
            db.add_all(ManagedListItem(module=module, list_key=list_key, value=value, sort_order=index) for index, value in enumerate(values))

        db.add_all([
            AuditLog(user_id=users["admin"].id, action="create", entity="demo", detail="Created the public demo baseline", category="system", severity="info", created_at=now - timedelta(days=1)),
            AuditLog(user_id=users["editor"].id, action="update", entity="runbook_page", entity_id="2", detail="Updated patch night checklist", category="activity", severity="info", created_at=now - timedelta(hours=6)),
        ])
        db.commit()

    engine.dispose()
    print(f"Demo database created at {database_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a deterministic Kaya public-demo database.")
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    seed_database(args.database.resolve())
