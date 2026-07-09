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
    CustomField,
    CustomFieldValue,
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
    NetworkMonitorCheck,
    Rack,
    RackItem,
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
            VLAN(name="Security", description="Cameras, NVRs and restricted physical-security systems"),
            VLAN(name="Lab DMZ", description="Reverse proxies, tunnels and public-facing demo services"),
        ]
        db.add_all(vlans)
        db.flush()

        addresses = [
            IPAddress(vlan_id=vlans[0].id, address="10.20.1.1", category="Network", name="core-router", description="Primary lab gateway", assignment_type="Static", notes="Demo address only"),
            IPAddress(vlan_id=vlans[0].id, address="10.20.1.2", category="Network", name="core-switch", description="Main managed switch", assignment_type="Static", notes="Synthetic switch management address."),
            IPAddress(vlan_id=vlans[1].id, address="10.20.10.11", category="Compute", name="pve-01", description="Primary Proxmox node", assignment_type="Static"),
            IPAddress(vlan_id=vlans[1].id, address="10.20.10.12", category="Compute", name="pve-02", description="Secondary Proxmox node used for failover demos", assignment_type="Static"),
            IPAddress(vlan_id=vlans[1].id, address="10.20.10.21", category="Storage", name="nas-01", description="Shared storage appliance", assignment_type="Static"),
            IPAddress(vlan_id=vlans[1].id, address="10.20.10.31", category="Services", name="docker-01", description="Container services host", assignment_type="Static"),
            IPAddress(vlan_id=vlans[5].id, address="10.20.20.10", category="Services", name="reverse-proxy", description="Public entry point for demo services", assignment_type="Static", notes="Represents Nginx Proxy Manager, Traefik or Caddy."),
            IPAddress(vlan_id=vlans[2].id, address="10.20.30.42", category="IoT", name="living-room-display", description="Dashboard display", assignment_type="Dynamic"),
            IPAddress(vlan_id=vlans[2].id, address="10.20.30.55", category="IoT", name="garage-sensor", description="Environmental sensor", assignment_type="Dynamic"),
            IPAddress(vlan_id=vlans[3].id, address="10.20.40.23", category="Guest", name="guest-tablet", description="Example guest client seen in DNS investigations", assignment_type="Dynamic"),
            IPAddress(vlan_id=vlans[4].id, address="10.20.50.15", category="Security", name="front-door-camera", description="PoE camera at the front door", assignment_type="Static"),
            IPAddress(vlan_id=vlans[4].id, address="10.20.50.20", category="Security", name="nvr-01", description="Network video recorder", assignment_type="Static"),
        ]
        db.add_all(addresses)
        db.flush()
        monitors = []
        monitor_samples = [
            (addresses[0], "up", 3, None),
            (addresses[1], "up", 2, None),
            (addresses[2], "up", 4, None),
            (addresses[3], "warning", 18, "High packet jitter during the last check."),
            (addresses[4], "up", 5, None),
            (addresses[5], "up", 6, None),
            (addresses[6], "up", 7, None),
            (addresses[10], "down", None, "Demo outage: camera stopped responding to ICMP."),
            (addresses[11], "up", 5, None),
        ]
        for index, (row, last_status, latency, error) in enumerate(monitor_samples):
            monitor = NetworkMonitor(
                ip_address_id=row.id,
                display_name=row.name,
                is_enabled=False,
                interval_seconds=300,
                timeout_ms=1500,
                notify_enabled=index in {3, 7},
                last_status=last_status,
                last_latency_ms=latency,
                last_error=error,
                last_checked_at=now - timedelta(minutes=3 + index),
            )
            monitors.append(monitor)
        db.add_all(monitors)
        db.flush()
        for monitor in monitors:
            db.add_all([
                NetworkMonitorCheck(monitor_id=monitor.id, status="up", latency_ms=monitor.last_latency_ms or 5, checked_at=now - timedelta(minutes=33)),
                NetworkMonitorCheck(monitor_id=monitor.id, status=monitor.last_status or "up", latency_ms=monitor.last_latency_ms, error=monitor.last_error, checked_at=monitor.last_checked_at or now),
            ])
        db.add_all([
            RemoteAccess(ip_address_id=addresses[2].id, display_name="Proxmox console", is_enabled=True, protocol="ssh", port=22, username="demo", host_key_fingerprint="SHA256:demo-proxmox-host-key", notes="Live connections are disabled in the public demo."),
            RemoteAccess(ip_address_id=addresses[4].id, display_name="NAS shell", is_enabled=True, protocol="ssh", port=22, username="demo", host_key_fingerprint="SHA256:demo-nas-host-key", notes="Synthetic SSH target for browsing Remote Manager layout."),
            RemoteAccess(ip_address_id=addresses[5].id, display_name="Docker host", is_enabled=True, protocol="ssh", port=22, username="demo", host_key_fingerprint="SHA256:demo-docker-host-key", notes="Live connections are disabled in the public demo."),
            RemoteAccess(ip_address_id=addresses[11].id, display_name="NVR desktop", is_enabled=True, protocol="rdp", port=3389, username="demo-admin", notes="Synthetic RDP target. The public demo shows a still preview instead of opening a live session."),
        ])
        db.add_all([
            RemoteManagerSetting(key="guacamole_enabled", value="0"),
            RemoteManagerSetting(key="guacd_host", value=""),
            RemoteManagerSetting(key="guacd_port", value="4822"),
            RemoteManagerSetting(key="split_screen_enabled", value="1"),
            RemoteManagerSetting(key="recording_enabled", value="1"),
            RemoteManagerSetting(key="recording_auto_enabled", value="0"),
            RemoteManagerSetting(key="recording_max_upload_mb", value="512"),
            RemoteManagerSetting(key="ssh_font_size", value="14"),
            RemoteManagerSetting(key="ssh_theme", value="kaya-dark"),
            RemoteManagerSetting(key="rdp_resize_method", value="display-update"),
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

        assets = [
            HardwareAsset(asset_tag="SRV-001", name="Virtualisation Server", category="Server", status="In use", manufacturer="Dell", model="PowerEdge R730", serial_number="DEMO-SRV-001", location="Lab Rack U10", assigned_to="Infrastructure", purchase_date=date(2023, 4, 12), purchase_cost="GBP 850", warranty_expires=date(2027, 4, 12), supplier="Demo Hardware Ltd", notes="Synthetic public demo record. Runs Proxmox workloads shown in VM/Docker Manager."),
            HardwareAsset(asset_tag="SRV-002", name="Secondary Proxmox Node", category="Server", status="Maintenance", manufacturer="HP", model="ProLiant DL380 Gen9", serial_number="DEMO-SRV-002", location="Lab Rack U14", assigned_to="Infrastructure", purchase_date=date(2022, 11, 3), purchase_cost="GBP 760", warranty_expires=date(2026, 11, 3), supplier="Demo Hardware Ltd", notes="Shown in maintenance to demonstrate asset status filtering."),
            HardwareAsset(asset_tag="NET-001", name="Core Switch", category="Network", status="In use", manufacturer="Ubiquiti", model="USW-Pro-24", serial_number="DEMO-NET-001", location="Lab Rack U18", assigned_to="Infrastructure", purchase_date=date(2024, 2, 8), purchase_cost="GBP 620", notes="Synthetic public demo record."),
            HardwareAsset(asset_tag="NET-002", name="PoE Access Switch", category="Network", status="In use", manufacturer="TP-Link", model="TL-SG2210MP", serial_number="DEMO-NET-002", location="Lab Rack U21", assigned_to="Security", purchase_date=date(2024, 5, 21), purchase_cost="GBP 210", notes="Feeds demo camera and IoT endpoints."),
            HardwareAsset(asset_tag="STO-001", name="NAS Appliance", category="Storage", status="In use", manufacturer="Synology", model="DS1821+", serial_number="DEMO-STO-001", location="Lab Rack U6", assigned_to="Infrastructure", purchase_date=date(2023, 9, 18), purchase_cost="GBP 1,100", notes="Synthetic public demo record."),
            HardwareAsset(asset_tag="PWR-001", name="Rack UPS", category="Power", status="In use", manufacturer="APC", model="Smart-UPS 1500", serial_number="DEMO-PWR-001", location="Lab Rack U1", assigned_to="Infrastructure", purchase_date=date(2023, 1, 11), purchase_cost="GBP 420", notes="Used to demonstrate rack power equipment."),
            HardwareAsset(asset_tag="CAM-001", name="Front Door Camera", category="Security", status="In use", manufacturer="Reolink", model="RLC-811A", serial_number="DEMO-CAM-001", location="Front Door", assigned_to="Security", purchase_date=date(2024, 7, 14), purchase_cost="GBP 92", notes="Synthetic endpoint shown as down in Network Monitor."),
            HardwareAsset(asset_tag="LAP-014", name="Admin Laptop", category="Laptop", status="Spare", manufacturer="Lenovo", model="ThinkPad T14", serial_number="DEMO-LAP-014", location="Office", assigned_to="Lab Admin", purchase_date=date(2024, 6, 3), purchase_cost="GBP 780", notes="Synthetic public demo record."),
        ]
        db.add_all(assets)
        db.flush()
        rack = Rack(name="Demo Lab Rack", location="Garage lab", height_u=24, description="Synthetic rack layout used to show rack elevation, occupancy and linked hardware assets.", sort_order=10)
        db.add(rack)
        db.flush()
        db.add_all([
            RackItem(rack_id=rack.id, hardware_asset_id=assets[5].id, name="Rack UPS", start_u=1, height_u=2, mount_side="both", category="Power", color="#dc2626", notes="Power base for the demo rack."),
            RackItem(rack_id=rack.id, hardware_asset_id=assets[4].id, name="NAS Appliance", start_u=5, height_u=2, mount_side="front", category="Storage", color="#7c3aed", notes="Shared storage and backup target."),
            RackItem(rack_id=rack.id, hardware_asset_id=assets[0].id, name="Virtualisation Server", start_u=10, height_u=2, mount_side="front", category="Server", color="#2563eb", notes="Runs the Proxmox demo workloads."),
            RackItem(rack_id=rack.id, hardware_asset_id=assets[1].id, name="Secondary Proxmox Node", start_u=13, height_u=2, mount_side="front", category="Server", color="#2563eb", notes="Maintenance-state server for rack filtering."),
            RackItem(rack_id=rack.id, hardware_asset_id=assets[2].id, name="Core Switch", start_u=18, height_u=1, mount_side="front", category="Switch", color="#059669", notes="Network core."),
            RackItem(rack_id=rack.id, hardware_asset_id=assets[3].id, name="PoE Access Switch", start_u=20, height_u=1, mount_side="front", category="Switch", color="#059669", notes="PoE edge switch."),
            RackItem(rack_id=rack.id, name="Patch Panel A", start_u=22, height_u=1, mount_side="front", category="Patch", color="#d97706", notes="Synthetic patch panel."),
        ])

        db.add_all([
            Licence(licence_id="LIC-001", organisation="Kaya Demo", product="Windows Server 2025", vendor="Microsoft", encrypted_product_key=encrypt_secret("DEMO-ONLY-AAAAA-BBBBB-CCCCC"), licence_type="Volume", activations="2", seats=4, osa_status="Active", expiry_date=date.today() + timedelta(days=210), is_favourite=True, notes="Not a real product key."),
            Licence(licence_id="LIC-002", organisation="Kaya Demo", product="Backup Suite", vendor="Example Software", encrypted_product_key=encrypt_secret("DEMO-ONLY-DDDDD-EEEEE-FFFFF"), licence_type="Subscription", activations="1", seats=10, osa_status="Active", expiry_date=date.today() + timedelta(days=95), notes="Not a real product key."),
            Licence(licence_id="LIC-003", organisation="Kaya Demo", product="Remote Support Tool", vendor="ExampleOps", encrypted_product_key=encrypt_secret("DEMO-ONLY-GGGGG-HHHHH-IIIII"), licence_type="Per technician", activations="5", seats=5, osa_status="Renewal due", expiry_date=date.today() + timedelta(days=28), is_favourite=True, notes="Short-dated licence to make renewal views interesting."),
            Licence(licence_id="LIC-004", organisation="Kaya Demo", product="Design Suite", vendor="Example Creative", encrypted_product_key=encrypt_secret("DEMO-ONLY-JJJJJ-KKKKK-LLLLL"), licence_type="Subscription", activations="3", seats=3, osa_status="Active", expiry_date=date.today() + timedelta(days=310), notes="Synthetic workstation application licence."),
        ])

        db.add_all([
            DomainRecord(name="kaya-demo.example", registrar="Example Registrar", dns_provider="Example DNS", status="active", expires_at=now + timedelta(days=240), auto_renew=True, nameservers="ns1.example.invalid\nns2.example.invalid", dns_records=json.dumps([{"type": "A", "name": "demo", "value": "192.0.2.10"}]), notes="Reserved example domain; no live lookup is performed."),
            DomainRecord(name="lab-services.example", registrar="Example Registrar", dns_provider="Example DNS", status="active", expires_at=now + timedelta(days=120), auto_renew=False, nameservers="ns1.example.invalid", notes="Reserved example domain; no live lookup is performed."),
            DomainRecord(name="vpn-lab.example", registrar="Example Registrar", dns_provider="Cloudflare Demo", status="active", expires_at=now + timedelta(days=35), auto_renew=True, nameservers="arya.ns.cloudflare.invalid\nwest.ns.cloudflare.invalid", dns_records=json.dumps([{"type": "CNAME", "name": "tunnel", "value": "demo-tunnel.example.invalid"}, {"type": "TXT", "name": "_acme-challenge", "value": "demo-token"}]), notes="Synthetic tunnel/domain record for reverse-proxy demos."),
            DomainRecord(name="expired-lab.example", registrar="Example Registrar", dns_provider="Example DNS", status="attention", expires_at=now - timedelta(days=2), auto_renew=False, nameservers="ns1.example.invalid", lookup_error="Demo warning: renewal check found the domain past its expected date.", notes="Intentionally expired demo domain so status badges are visible."),
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
        security_space = RunbookSpace(name="Security & Access", description="Example security operations and access workflows", sort_order=20)
        db.add_all([space, security_space])
        db.flush()
        db.add_all([
            RunbookPage(space_id=space.id, title="Welcome to Kaya", slug="welcome-to-kaya", summary="A quick tour of this public demo.", body="# Welcome\n\nTry creating and editing inventory. Everything resets during the daily refresh.\n\n> All records and credentials in this demo are synthetic.", tags="welcome,demo", is_pinned=True, created_by_id=users["admin"].id, updated_by_id=users["admin"].id),
            RunbookPage(space_id=space.id, title="Patch night checklist", slug="patch-night-checklist", summary="Example monthly maintenance workflow.", body="## Before maintenance\n\n- Confirm backups\n- Review monitoring\n- Notify users\n\n```bash\n# Demo-only example\ndocker compose pull && docker compose up -d\n```\n\n## After maintenance\n\n- Validate services\n- Record changes\n- Watch DNS and network monitor alerts for 30 minutes", tags="maintenance,checklist", is_pinned=True, created_by_id=users["editor"].id, updated_by_id=users["editor"].id),
            RunbookPage(space_id=space.id, title="Restore a container", slug="restore-a-container", summary="Example recovery procedure.", body="1. Select the latest verified backup.\n2. Restore into an isolated network.\n3. Validate data and configuration.\n4. Promote the restored workload.\n\n```yaml\nservice: vaultwarden\nrestore_target: docker-01\nvalidation: login-page-healthcheck\n```", tags="backup,recovery", created_by_id=users["editor"].id, updated_by_id=users["editor"].id),
            RunbookPage(space_id=space.id, title="New service onboarding", slug="new-service-onboarding", summary="Template for adding a service to Kaya.", body="## Capture the basics\n\n- Add the IP address and VLAN\n- Add the hardware or compute workload owner\n- Add a backup record\n- Add Remote Manager notes if access is required\n\n## Before go-live\n\n- Add DNS records\n- Add monitoring\n- Document rollback steps", tags="template,onboarding", created_by_id=users["admin"].id, updated_by_id=users["admin"].id),
            RunbookPage(space_id=security_space.id, title="Investigate blocked DNS query", slug="investigate-blocked-dns-query", summary="Example DNS Manager triage workflow.", body="## Triage\n\n1. Open DNS Manager and review open investigations.\n2. Match the client IP to IP Address Manager.\n3. Check whether the device belongs on its VLAN.\n4. Close or escalate the investigation.\n\n> Demo investigations are synthetic and safe.", tags="dns,security,triage", is_pinned=True, created_by_id=users["editor"].id, updated_by_id=users["editor"].id),
            RunbookPage(space_id=security_space.id, title="Remote access policy", slug="remote-access-policy", summary="How Remote Manager is used in the demo environment.", body="## Public demo behaviour\n\nRemote Manager is locked on the public demo. Kaya still shows the layout and settings, but it does not open live SSH or RDP sessions.\n\n## Real deployment guidance\n\n- Use named accounts\n- Record sensitive sessions only when policy allows\n- Keep trusted proxy settings accurate\n- Review audit logs after administrative access", tags="remote-access,policy", created_by_id=users["admin"].id, updated_by_id=users["admin"].id),
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
            ("hardware_assets", "category"): ["Server", "Network", "Storage", "Power", "Security", "Laptop"],
            ("hardware_assets", "status"): ["In use", "Spare", "Maintenance", "Retired"],
            ("hardware_assets", "location"): ["Garage lab", "Office", "Front Door", "Lab Rack U10", "Lab Rack U18"],
            ("ip_addresses", "category"): ["Network", "Compute", "Storage", "Services", "IoT", "Guest", "Security"],
            ("licences", "licence_type"): ["Volume", "Subscription", "Perpetual", "Per technician"],
        }
        for (module, list_key), values in list_values.items():
            db.add_all(ManagedListItem(module=module, list_key=list_key, value=value, sort_order=index) for index, value in enumerate(values))

        custom_fields = [
            CustomField(module="hardware_assets", label="Support contract", field_key="support_contract", field_type="text", is_active=True, sort_order=10),
            CustomField(module="hardware_assets", label="Criticality", field_key="criticality", field_type="select", options="Low\nMedium\nHigh\nCritical", is_active=True, sort_order=20),
            CustomField(module="ip_addresses", label="Owner team", field_key="owner_team", field_type="text", is_active=True, sort_order=10),
        ]
        db.add_all(custom_fields)
        db.flush()
        db.add_all([
            CustomFieldValue(field_id=custom_fields[0].id, entity_type="hardware_asset", entity_id=assets[0].id, value="DemoCare 24x7"),
            CustomFieldValue(field_id=custom_fields[1].id, entity_type="hardware_asset", entity_id=assets[0].id, value="Critical"),
            CustomFieldValue(field_id=custom_fields[1].id, entity_type="hardware_asset", entity_id=assets[4].id, value="High"),
            CustomFieldValue(field_id=custom_fields[2].id, entity_type="ip_address", entity_id=addresses[6].id, value="Platform"),
            CustomFieldValue(field_id=custom_fields[2].id, entity_type="ip_address", entity_id=addresses[10].id, value="Security"),
        ])

        db.add_all([
            AuditLog(user_id=users["admin"].id, action="create", entity="demo", detail="Created the public demo baseline", category="system", severity="info", created_at=now - timedelta(days=1)),
            AuditLog(user_id=users["editor"].id, action="update", entity="runbook_page", entity_id="2", detail="Updated patch night checklist", category="activity", severity="info", created_at=now - timedelta(hours=6)),
            AuditLog(user_id=users["admin"].id, action="backup", entity="compute_workload", entity_id=str(docker_workloads[0].id), detail="Demo backup completed for grafana", category="activity", severity="info", created_at=now - timedelta(hours=7, minutes=51)),
            AuditLog(user_id=users["editor"].id, action="investigate", entity="dns_investigation", entity_id="1", detail="Opened DNS investigation for phish-demo.example.invalid", category="security", severity="warning", created_at=now - timedelta(minutes=18)),
            AuditLog(user_id=users["admin"].id, action="alert", entity="network_monitor", entity_id=str(monitors[7].id), detail="Front door camera monitor is down in demo data", category="security", severity="warning", created_at=now - timedelta(minutes=9)),
        ])
        db.commit()

    engine.dispose()
    print(f"Demo database created at {database_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a deterministic Kaya public-demo database.")
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    seed_database(args.database.resolve())
