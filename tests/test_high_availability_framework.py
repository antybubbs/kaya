import asyncio
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.security import decrypt_secret, hash_password
from app.db.session import Base
from app.main import app
from app.models.models import (
    AuditLog,
    DNSClientEvent,
    DNSClientIPHistory,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HACluster,
    HAHealthCheck,
    HANode,
    HAProviderConnection,
    IPAddress,
    RemoteManagerSetting,
    User,
)
from app.routers.admin import set_high_availability_feature
from app.routers.high_availability import active_clusters, cluster_or_404, require_ha_admin, require_high_availability, test_cluster_connection as connection_route, update_cluster_topology
from app.schemas.high_availability import HAClusterDraftCreate, HAClusterRead
from app.services.ha_clusters import HADraftError, create_cluster_draft, soft_delete_cluster, validate_cluster_draft
from app.services.ha_registry import SUPPORTED_HA_PROVIDERS
from app.services.dns_providers import DNSProviderResult
from app.services.site_settings import get_site_setting


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def form_request(path: str, values: dict[str, str]):
    body = urlencode(values).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", str(len(body)).encode()),
            ],
            "client": ("198.51.100.2", 1234),
            "server": ("kaya.example.com", 443),
            "session": {"csrf_token": "csrf"},
            "app": app,
        },
        receive,
    )


def test_high_availability_is_disabled_by_default_and_registry_is_pihole_only():
    with database() as db:
        assert get_site_setting(db, "high_availability_enabled") == ""
        with pytest.raises(HTTPException) as rejected:
            require_high_availability(form_request("/high-availability", {}), db=db, user=object())
        assert rejected.value.status_code == 404
    assert [provider.key for provider in SUPPORTED_HA_PROVIDERS] == ["pihole"]


def test_admin_toggle_is_audited_and_preserves_dns_links_and_history():
    with database() as db:
        admin = User(email="admin@example.com", password_hash=hash_password("correct horse battery staple"), role="admin", is_active=True)
        provider = DNSProviderConfig(name="Existing Pi-hole", provider_type="pihole", base_url="http://pihole.invalid")
        linked_ip = IPAddress(address="192.0.2.25", assignment_type="Static")
        db.add_all([admin, provider, linked_ip])
        db.flush()
        client = DNSRecognisedDevice(
            provider_id=provider.id,
            identity_type="mac",
            identity_value="00:11:22:33:44:55",
            current_ip="192.0.2.25",
            linked_ip_record_id=linked_ip.id,
        )
        db.add(client)
        db.flush()
        history = DNSClientIPHistory(dns_client_id=client.id, ip_address="192.0.2.25", provider_id=provider.id)
        event_row = DNSClientEvent(dns_client_id=client.id, event_type="client_discovered", event_summary="First observed", provider_id=provider.id)
        db.add_all([history, event_row])
        db.commit()
        original_ids = (provider.id, linked_ip.id, client.id, history.id, event_row.id)

        response = asyncio.run(
            set_high_availability_feature(
                form_request(
                    "/system/site-administration/experimental-features/high-availability",
                    {"csrf_token": "csrf", "enabled": "1"},
                ),
                db=db,
                user=admin,
            )
        )

        assert response.status_code == 303
        assert get_site_setting(db, "high_availability_enabled") == "1"
        assert db.get(DNSProviderConfig, original_ids[0]).name == "Existing Pi-hole"
        assert db.get(IPAddress, original_ids[1]).address == "192.0.2.25"
        preserved_client = db.get(DNSRecognisedDevice, original_ids[2])
        assert preserved_client.linked_ip_record_id == original_ids[1]
        assert db.get(DNSClientIPHistory, original_ids[3]).dns_client_id == original_ids[2]
        assert db.get(DNSClientEvent, original_ids[4]).dns_client_id == original_ids[2]
        audit = db.query(AuditLog).filter_by(entity="experimental_feature", entity_id="high_availability").one()
        assert audit.action == "feature_enabled"


def test_feature_ui_is_gated_operational_and_uses_reusable_maturity_badges():
    base = Path("app/templates/base.html").read_text(encoding="utf-8")
    settings = Path("app/templates/settings.html").read_text(encoding="utf-8")
    overview = Path("app/templates/high_availability.html").read_text(encoding="utf-8")
    services = Path("app/templates/high_availability_services.html").read_text(encoding="utf-8")
    badge = Path("app/templates/components/maturity_badge.html").read_text(encoding="utf-8")
    assert "high_availability_enabled|default(false)" in base
    assert "Experimental Features" in settings
    assert "feature_status" in settings
    assert "manage controlled failover" in overview
    assert "Milestone" not in overview
    assert "managed within High Availability" in services
    assert "maturity-badge--" in badge
    assert "tabindex=\"0\"" in badge


def test_draft_reuses_two_unique_pihole_integrations_without_copying_secrets(monkeypatch):
    with database() as db:
        admin = User(email="draft-admin@example.com", password_hash="x", role="admin", is_active=True)
        first = DNSProviderConfig(name="Primary", provider_type="pihole", base_url="https://pi-one.invalid", encrypted_secret="encrypted-one")
        second = DNSProviderConfig(name="Standby", provider_type="pihole", base_url="https://pi-two.invalid", encrypted_secret="encrypted-two")
        db.add_all([admin, first, second]); db.commit()
        cluster = create_cluster_draft(
            db,
            HAClusterDraftCreate(
                name="Home DNS",
                description="Draft only",
                primary={"name": "Primary", "api_base_url": "https://pi-one.invalid"},
                secondary={"name": "Standby", "api_base_url": "https://pi-two.invalid"},
                virtual_ip="192.0.2.53",
                prefix_length=24,
            ),
            admin,
        )
        assert cluster.status == "DRAFT"
        assert cluster.virtual_ip == "192.0.2.53"
        assert len(cluster.nodes) == 2
        assert {node.integration_reference_id for node in cluster.nodes} == {first.id, second.id}
        assert {node.ha_connection_id for node in cluster.nodes} == {None}
        assert db.query(HAProviderConnection).count() == 0
        assert {node.role for node in cluster.nodes} == {"ACTIVE", "STANDBY"}
        assert not any(hasattr(node, "encrypted_secret") for node in cluster.nodes)
        assert db.get(DNSProviderConfig, first.id).encrypted_secret == "encrypted-one"
        assert db.get(DNSProviderConfig, second.id).encrypted_secret == "encrypted-two"

        import app.services.dns_providers as provider_module
        monkeypatch.setattr(provider_module, "provider_for", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("provider contacted")))
        checks = validate_cluster_draft(db, cluster)
        assert len(checks) == 4
        assert db.query(HAHealthCheck).filter_by(cluster_id=cluster.id).count() == 4
        assert all("no provider request" in row.technical_detail_redacted.lower() for row in checks)
        assert HAClusterRead.model_validate(cluster).nodes[0].integration_reference_id in {first.id, second.id}


def test_new_ha_connections_are_encrypted_and_do_not_create_dns_manager_providers():
    with database() as db:
        admin = User(email="admin-two@example.com", password_hash="x", role="admin", is_active=True)
        db.add(admin); db.commit()
        cluster = create_cluster_draft(
            db,
            HAClusterDraftCreate(
                name="HA owned",
                primary={"name": "Primary", "api_base_url": "https://new-one.invalid", "secret": "secret-one"},
                secondary={"name": "Standby", "api_base_url": "https://new-two.invalid", "secret": "secret-two"},
            ),
            admin,
        )
        connections = db.query(HAProviderConnection).order_by(HAProviderConnection.name).all()
        assert len(connections) == 2
        assert db.query(DNSProviderConfig).count() == 0
        assert {node.integration_reference_id for node in cluster.nodes} == {None}
        assert all(node.ha_connection_id for node in cluster.nodes)
        assert {decrypt_secret(connection.encrypted_secret) for connection in connections} == {"secret-one", "secret-two"}
        assert all(connection.encrypted_secret not in {"secret-one", "secret-two"} for connection in connections)


def test_draft_requires_two_different_nodes_and_admin_creation_permission():
    with database() as db:
        admin = User(email="admin-three@example.com", password_hash="x", role="admin", is_active=True)
        viewer = User(email="viewer@example.com", password_hash="x", role="viewer", is_active=True)
        provider = DNSProviderConfig(name="Only Pi-hole", provider_type="pihole", base_url="https://only.invalid")
        db.add_all([admin, viewer, provider]); db.commit()
        with pytest.raises(HADraftError, match="two different"):
            create_cluster_draft(
                db,
                HAClusterDraftCreate(
                    name="Invalid",
                    primary={"name": "Primary", "api_base_url": provider.base_url},
                    secondary={"name": "Standby", "api_base_url": provider.base_url},
                ),
                admin,
            )
        with pytest.raises(HADraftError, match="supported provider"):
            create_cluster_draft(
                db,
                HAClusterDraftCreate(
                    name="Unsupported",
                    provider_key="future-app",
                    primary={"name": "First", "api_base_url": "https://first.invalid", "secret": "one"},
                    secondary={"name": "Second", "api_base_url": "https://second.invalid", "secret": "two"},
                ),
                admin,
            )
        with pytest.raises(PermissionError):
            require_ha_admin(viewer)
        assert db.query(HACluster).count() == 0
        assert db.query(HANode).count() == 0


def test_cluster_creation_explains_safe_setup_boundary():
    wizard = Path("app/templates/high_availability_cluster_form.html").read_text(encoding="utf-8")
    picker = Path("app/templates/high_availability_provider_picker.html").read_text(encoding="utf-8")
    nodes_page = Path("app/templates/high_availability_cluster_nodes.html").read_text(encoding="utf-8")
    routes = Path("app/routers/high_availability.py").read_text(encoding="utf-8")
    assert "Nothing is deployed or moved until" in wizard
    assert "Create Cluster" in wizard
    assert "Choose the provider or application" in picker
    assert "/high-availability/clusters/new/{{ provider.key }}" in picker
    assert "managed from High Availability" in wizard
    assert 'type="password"' in wizard
    assert "primary_secret\", \"secondary_secret" in routes
    assert "credentials are not duplicated" in nodes_page
    assert "Depends(require_ha_admin)" in routes
    assert "response_model=list[HAClusterRead]" in routes


def test_setup_menu_is_not_clipped_or_forced_open():
    header = Path("app/templates/_high_availability_cluster_header.html").read_text(encoding="utf-8")
    styles = Path("app/static/css/kaya.css").read_text(encoding="utf-8")
    assert '<details class="ha-setup-menu {{' in header
    assert "{% if cluster_section in ['validation', 'agents', 'deployment'] %}open{% endif %}" not in header
    assert ".ha-detail-tabs{flex-wrap:wrap;overflow:visible}" in styles


def test_draft_connection_route_returns_inline_result_and_audits_without_secret(monkeypatch):
    with database() as db:
        admin = User(email="connection-test-admin@example.com", password_hash="x", role="admin", is_active=True)
        db.add(admin); db.commit()
        monkeypatch.setattr("app.routers.high_availability.test_draft_node_connection", lambda *args, **kwargs: DNSProviderResult(True, "Pi-hole connection test passed."))
        response = asyncio.run(
            connection_route(
                form_request(
                    "/high-availability/clusters/test-connection",
                    {"csrf_token": "csrf", "provider_key": "pihole", "node": "primary", "primary_name": "Primary", "primary_api_base_url": "https://primary.invalid", "primary_secret": "never-log-this", "primary_ssl_verify": "1"},
                ),
                db=db,
                user=admin,
            )
        )
        assert response.status_code == 200
        assert b'"ok":true' in response.body
        assert b"Pi-hole connection test passed" in response.body
        audit = db.query(AuditLog).filter_by(entity="ha_draft_node", action="connection_tested").one()
        assert "never-log-this" not in (audit.detail or "")
        assert "never-log-this" not in (audit.metadata_json or "")


def test_high_availability_uses_expandable_sidebar_hierarchy():
    base = Path("app/templates/base.html").read_text(encoding="utf-8")
    module_nav = Path("app/templates/_high_availability_nav.html").read_text(encoding="utf-8")
    assert 'data-sidebar-menu="high-availability"' in base
    assert '<span class="nav-label">High Availability</span>' in base
    assert '<span class="nav-label">Overview</span>' in base
    assert '<span class="nav-label">Clusters</span>' in base
    assert '<span class="nav-label">Providers/Apps</span>' in base
    assert "Providers/Apps" in module_nav


def test_high_availability_header_actions_do_not_stretch():
    stylesheet = Path("app/static/css/kaya.css").read_text(encoding="utf-8")
    assert ".ha-header{align-items:center;grid-template-columns:minmax(0,1fr) max-content" in stylesheet
    assert ".ha-header>.button{align-self:center;grid-column:2;justify-self:end;min-height:34px;width:auto}" in stylesheet
    assert ".ha-header>.button{justify-self:start}" in stylesheet


def test_disabling_with_a_cluster_requires_acknowledgement_and_preserves_draft():
    with database() as db:
        admin = User(email="disable-admin@example.com", password_hash="x", role="admin", is_active=True)
        cluster = HACluster(name="Preserve me", provider_key="pihole", status="DRAFT", created_by=admin)
        db.add_all([admin, cluster, RemoteManagerSetting(key="high_availability_enabled", value="1")]); db.commit()
        cluster_id = cluster.id

        rejected = asyncio.run(
            set_high_availability_feature(
                form_request(
                    "/system/site-administration/experimental-features/high-availability",
                    {"csrf_token": "csrf", "enabled": "0"},
                ),
                db=db,
                user=admin,
            )
        )
        assert "feature_error=acknowledgement-required" in rejected.headers["location"]
        assert get_site_setting(db, "high_availability_enabled") == "1"
        assert db.get(HACluster, cluster_id).name == "Preserve me"

        accepted = asyncio.run(
            set_high_availability_feature(
                form_request(
                    "/system/site-administration/experimental-features/high-availability",
                    {"csrf_token": "csrf", "enabled": "0", "acknowledge_ha_disable": "1"},
                ),
                db=db,
                user=admin,
            )
        )
        assert "feature_status=disabled" in accepted.headers["location"]
        assert get_site_setting(db, "high_availability_enabled") == ""
        assert db.get(HACluster, cluster_id).name == "Preserve me"


def test_cluster_danger_zone_requires_exact_confirmation_and_soft_deletes_without_data_loss():
    with database() as db:
        admin = User(email="delete-admin@example.com", password_hash="x", role="admin", is_active=True)
        provider = DNSProviderConfig(name="Preserved DNS", provider_type="pihole", base_url="https://preserved.invalid", encrypted_secret="encrypted")
        linked_ip = IPAddress(address="192.0.2.88", assignment_type="Static")
        cluster = HACluster(name="Critical DNS Pair", provider_key="pihole", status="VALIDATED", created_by=admin)
        db.add_all([admin, provider, linked_ip, cluster]); db.flush()
        client = DNSRecognisedDevice(provider_id=provider.id, identity_type="mac", identity_value="00:aa:bb:cc:dd:ee", current_ip=linked_ip.address, linked_ip_record_id=linked_ip.id)
        db.add(client); db.flush()
        history = DNSClientIPHistory(dns_client_id=client.id, ip_address=linked_ip.address, provider_id=provider.id)
        node = HANode(cluster_id=cluster.id, display_name="Primary", management_host="preserved.invalid", api_base_url=provider.base_url, integration_reference_id=provider.id, role="ACTIVE", desired_role="ACTIVE", status="VALIDATED")
        db.add_all([history, node]); db.flush()
        check = HAHealthCheck(cluster_id=cluster.id, node_id=node.id, check_key="api_authentication", status="PASS", severity="info", summary="Preserve this result")
        db.add(check); db.commit()
        ids = {"cluster": cluster.id, "provider": provider.id, "ip": linked_ip.id, "client": client.id, "history": history.id, "node": node.id, "check": check.id}

        with pytest.raises(HADraftError, match="exact cluster name"):
            soft_delete_cluster(db, cluster, "wrong name", True)
        with pytest.raises(HADraftError, match="acknowledge"):
            soft_delete_cluster(db, cluster, cluster.name, False)
        assert db.get(HACluster, cluster.id).deleted_at is None

        deleted = soft_delete_cluster(db, cluster, cluster.name, True)
        assert deleted.status == "DELETED"
        assert deleted.deleted_at is not None
        assert deleted.maintenance_mode is True
        assert active_clusters(db) == []
        with pytest.raises(HTTPException) as missing:
            cluster_or_404(db, deleted.public_id)
        assert missing.value.status_code == 404
        assert db.get(HANode, ids["node"]).display_name == "Primary"
        assert db.get(HAHealthCheck, ids["check"]).summary == "Preserve this result"
        assert db.get(DNSProviderConfig, ids["provider"]).encrypted_secret == "encrypted"
        assert db.get(IPAddress, ids["ip"]).address == "192.0.2.88"
        assert db.get(DNSRecognisedDevice, ids["client"]).linked_ip_record_id == ids["ip"]
        assert db.get(DNSClientIPHistory, ids["history"]).dns_client_id == ids["client"]


def test_cluster_danger_zone_is_admin_only_audited_and_explains_preservation():
    detail = Path("app/templates/high_availability_cluster_detail.html").read_text(encoding="utf-8")
    clusters = Path("app/templates/high_availability_clusters.html").read_text(encoding="utf-8")
    routes = Path("app/routers/high_availability.py").read_text(encoding="utf-8")
    assert "Danger zone" in detail
    assert "Type <span class=\"mono\">{{ cluster.name }}</span> to confirm" in detail
    assert 'name="acknowledge_preservation"' in detail
    assert "stored nodes, connections, validation records, DNS links, and history remain preserved" in detail
    assert "Depends(require_ha_admin)" in routes
    assert '"soft_delete": True' in routes
    assert '"provider_contacted": False' in routes
    assert "connections, validation records, DNS links, and history were preserved" in clusters


def test_service_responsibilities_can_correct_managed_dhcp_without_controlling_nodes():
    with database() as db:
        admin = User(email="topology-admin@example.invalid", password_hash="x", role="admin", is_active=True)
        cluster = HACluster(
            name="Managed DHCP",
            provider_key="pihole",
            deployment_mode="DNS_ONLY",
            external_dhcp_provider="router",
            status="HEALTHY",
            virtual_ip="192.0.2.53",
            prefix_length=24,
            automatic_failover_enabled=True,
            created_by=admin,
        )
        db.add_all([admin, cluster])
        db.flush()
        db.add_all([
            HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="https://primary.invalid", role="ACTIVE", desired_role="ACTIVE", dhcp_running=True),
            HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="https://standby.invalid", role="STANDBY", desired_role="STANDBY", dhcp_running=False),
        ])
        db.commit()

        response = asyncio.run(update_cluster_topology(
            cluster.public_id,
            form_request(
                f"/high-availability/clusters/{cluster.public_id}/topology",
                {
                    "csrf_token": "csrf",
                    "deployment_mode": "DNS_DHCP",
                    "acknowledge_managed_dhcp": "1",
                    "cluster_name": cluster.name,
                },
            ),
            db=db,
            user=admin,
        ))

        db.refresh(cluster)
        assert response.status_code == 303
        assert cluster.deployment_mode == "DNS_DHCP"
        assert cluster.external_dhcp_provider is None
        assert cluster.automatic_failover_enabled is False
        assert [node.dhcp_running for node in cluster.nodes] == [True, False]
        audit = db.query(AuditLog).filter_by(entity="ha_service_responsibilities", entity_id=cluster.public_id).one()
        assert audit.metadata_json is not None


def test_service_responsibilities_refuse_external_mode_while_pihole_dhcp_is_live():
    with database() as db:
        admin = User(email="topology-block@example.invalid", password_hash="x", role="admin", is_active=True)
        cluster = HACluster(name="Managed DHCP", provider_key="pihole", deployment_mode="DNS_DHCP", status="HEALTHY", created_by=admin)
        db.add_all([admin, cluster])
        db.flush()
        db.add(HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="https://primary.invalid", role="ACTIVE", desired_role="ACTIVE", dhcp_running=True))
        db.commit()

        response = asyncio.run(update_cluster_topology(
            cluster.public_id,
            form_request(
                f"/high-availability/clusters/{cluster.public_id}/topology",
                {
                    "csrf_token": "csrf",
                    "deployment_mode": "DNS_ONLY",
                    "external_dhcp_provider": "router",
                    "cluster_name": cluster.name,
                },
            ),
            db=db,
            user=admin,
        ))

        db.refresh(cluster)
        assert response.status_code == 409
        assert cluster.deployment_mode == "DNS_DHCP"
