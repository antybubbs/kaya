import asyncio
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.security import hash_password
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
    IPAddress,
    RemoteManagerSetting,
    User,
)
from app.routers.admin import set_high_availability_feature
from app.routers.high_availability import require_ha_admin, require_high_availability
from app.schemas.high_availability import HAClusterDraftCreate, HAClusterRead
from app.services.ha_clusters import HADraftError, create_cluster_draft, validate_cluster_draft
from app.services.ha_registry import SUPPORTED_HA_PROVIDERS
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


def test_feature_ui_is_gated_read_only_and_uses_reusable_maturity_badges():
    base = Path("app/templates/base.html").read_text(encoding="utf-8")
    settings = Path("app/templates/settings.html").read_text(encoding="utf-8")
    overview = Path("app/templates/high_availability.html").read_text(encoding="utf-8")
    services = Path("app/templates/high_availability_services.html").read_text(encoding="utf-8")
    badge = Path("app/templates/components/maturity_badge.html").read_text(encoding="utf-8")
    assert "high_availability_enabled|default(false)" in base
    assert "Experimental Features" in settings
    assert "feature_status" in settings
    assert "read-only" in overview
    assert "Provider connections and writes are not available" in services
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
                primary_integration_id=first.id,
                secondary_integration_id=second.id,
                virtual_ip="192.0.2.53",
                prefix_length=24,
            ),
            admin,
        )
        assert cluster.status == "DRAFT"
        assert cluster.virtual_ip == "192.0.2.53"
        assert len(cluster.nodes) == 2
        assert {node.integration_reference_id for node in cluster.nodes} == {first.id, second.id}
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


def test_draft_requires_two_different_nodes_and_admin_creation_permission():
    with database() as db:
        admin = User(email="admin-two@example.com", password_hash="x", role="admin", is_active=True)
        viewer = User(email="viewer@example.com", password_hash="x", role="viewer", is_active=True)
        provider = DNSProviderConfig(name="Only Pi-hole", provider_type="pihole", base_url="https://only.invalid")
        db.add_all([admin, viewer, provider]); db.commit()
        with pytest.raises(HADraftError, match="two different"):
            create_cluster_draft(
                db,
                HAClusterDraftCreate(name="Invalid", primary_integration_id=provider.id, secondary_integration_id=provider.id),
                admin,
            )
        with pytest.raises(PermissionError):
            require_ha_admin(viewer)
        assert db.query(HACluster).count() == 0
        assert db.query(HANode).count() == 0


def test_milestone_two_templates_explain_draft_safety_boundary():
    wizard = Path("app/templates/high_availability_cluster_form.html").read_text(encoding="utf-8")
    detail = Path("app/templates/high_availability_cluster_detail.html").read_text(encoding="utf-8")
    routes = Path("app/routers/high_availability.py").read_text(encoding="utf-8")
    assert "does not connect to, configure, restart, synchronise, or fail over" in wizard
    assert "credentials are not duplicated" in detail
    assert "Depends(require_ha_admin)" in routes
    assert "response_model=list[HAClusterRead]" in routes


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
