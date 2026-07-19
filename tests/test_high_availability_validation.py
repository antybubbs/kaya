import json
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
import pytest

from app.core.security import decrypt_secret, encrypt_secret
from app.models.models import DNSProviderConfig, HACluster, HAHealthCheck, HANode, HAProviderConnection, User
from app.schemas.high_availability import HANodeDraftCreate, HANodeUpdate
from app.services.ha_clusters import HADraftError, test_draft_node_connection as probe_draft_connection, update_cluster_node
from app.services.dns_providers import DNSProviderResult, PiHoleProvider
from app.services.ha_validation import configuration_differences, run_live_validation


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def cluster_with_connections(db: Session) -> HACluster:
    admin = User(email="ha-validation@example.com", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(name="Validated DNS", provider_key="pihole", status="DRAFT", created_by=admin)
    primary = HAProviderConnection(provider_key="pihole", name="Primary connection", api_base_url="https://primary.invalid", encrypted_secret="encrypted-one", created_by=admin)
    secondary = HAProviderConnection(provider_key="pihole", name="Secondary connection", api_base_url="https://secondary.invalid", encrypted_secret="encrypted-two", created_by=admin)
    db.add_all([admin, cluster, primary, secondary]); db.flush()
    db.add_all(
        [
            HANode(cluster_id=cluster.id, display_name="Primary", management_host="primary.invalid", api_base_url=primary.api_base_url, ha_connection_id=primary.id, role="ACTIVE", desired_role="ACTIVE"),
            HANode(cluster_id=cluster.id, display_name="Standby", management_host="secondary.invalid", api_base_url=secondary.api_base_url, ha_connection_id=secondary.id, role="STANDBY", desired_role="STANDBY"),
        ]
    )
    db.commit()
    return cluster


class ReadOnlyFakePiHole:
    calls: list[tuple[str, str]] = []

    def __init__(self, connection):
        self.connection = connection

    def _result(self, method, data=None):
        self.calls.append((self.connection.id, method))
        return DNSProviderResult(True, f"{method} loaded", data or {})

    def test_connection(self):
        return self._result("test_connection", {"queries": 1})

    def get_version(self):
        return self._result("get_version", {"version": {"core": {"local": {"version": "v6.1"}}}})

    def get_status(self):
        return self._result("get_status", {"status": "enabled"})

    def get_ha_configuration(self):
        marker = "primary" if self.connection.id.endswith("1") else "standby"
        filtering = [{"address": f"https://{marker}.list.invalid", "password": "must-not-persist"}]
        configuration = {
            "filtering": filtering,
            "groups": [{"name": "Default"}],
            "clients": [{"client": "192.0.2.10"}],
            "local_dns": {"hosts": ["192.0.2.53 dns.home"]},
            "cname": {"records": []},
            "upstream_dns": {"servers": ["1.1.1.1"], "api_token": "must-not-persist"},
            "dhcp": {"enabled": False, "hostname": marker},
        }
        return self._result("get_ha_configuration", {"configuration": configuration, "unavailable": {}})

    def get_dhcp_leases(self):
        return self._result("get_dhcp_leases", {"leases": []})


def test_live_validation_is_read_only_redacted_and_builds_difference_report():
    ReadOnlyFakePiHole.calls = []
    with database() as db:
        cluster = cluster_with_connections(db)
        rows = run_live_validation(
            db,
            cluster,
            client_factory=ReadOnlyFakePiHole,
            dns_probe=lambda host: (True, f"DNS answered on {host}"),
        )
        refreshed = db.get(HACluster, cluster.id)
        assert refreshed.status == "VALIDATED"
        assert len(rows) == 14
        assert all(row.status == "PASS" for row in rows)
        assert {method for _, method in ReadOnlyFakePiHole.calls} == {
            "test_connection",
            "get_version",
            "get_status",
            "get_ha_configuration",
            "get_dhcp_leases",
        }
        snapshots = [node.configuration_snapshot_json for node in refreshed.nodes]
        assert all("must-not-persist" not in snapshot for snapshot in snapshots)
        assert all('"hostname"' not in snapshot for snapshot in snapshots)
        assert all(node.provider_version == "6.1" for node in refreshed.nodes)
        assert all(node.configuration_checksum for node in refreshed.nodes)
        differences = configuration_differences(refreshed)
        assert [difference.group_key for difference in differences] == ["filtering"]
        assert differences[0].source_of_truth == "Primary"
        assert "primary.list.invalid" in differences[0].proposed_value


class IncompletePiHole(ReadOnlyFakePiHole):
    def get_version(self):
        self.calls.append((self.connection.id, "get_version"))
        return DNSProviderResult(False, "Version endpoint unavailable", None)

    def get_ha_configuration(self):
        return self._result(
            "get_ha_configuration",
            {"configuration": {"filtering": {"lists": []}}, "unavailable": {"dhcp": "DHCP endpoint unavailable"}},
        )


def test_unknown_version_and_dhcp_capability_are_deployment_blocking():
    IncompletePiHole.calls = []
    with database() as db:
        cluster = cluster_with_connections(db)
        rows = run_live_validation(db, cluster, client_factory=IncompletePiHole, dns_probe=lambda host: (True, "DNS answered"))
        refreshed = db.get(HACluster, cluster.id)
        assert refreshed.status == "VALIDATION_FAILED"
        assert all(node.status == "VALIDATION_FAILED" for node in refreshed.nodes)
        blocking = {(row.check_key, row.status) for row in rows if row.severity == "blocking" and row.status != "PASS"}
        assert ("provider_version", "UNKNOWN") in blocking
        assert ("dhcp_configuration", "UNKNOWN") in blocking
        assert all(row.remediation for row in rows if row.severity == "blocking" and row.status != "PASS")


def test_pihole_ha_configuration_uses_get_only_configuration_surfaces(monkeypatch):
    paths = []
    client = object.__new__(PiHoleProvider)

    def fake_get(path):
        paths.append(path)
        return {"value": path}

    monkeypatch.setattr(client, "_v6_request_json", fake_get)
    result = client.get_ha_configuration()
    assert result.ok
    assert paths == [
        "/api/lists",
        "/api/groups",
        "/api/clients",
        "/api/config/dns/hosts",
        "/api/config/dns/cnameRecords",
        "/api/config/dns",
        "/api/config/dhcp",
    ]


def test_validation_report_ui_explains_safety_and_exclusions():
    template = Path("app/templates/high_availability_cluster_validation.html").read_text(encoding="utf-8")
    assert "Run Read-only Validation" in template
    assert "does not write configuration" in template
    assert "Unknown or failed high-risk checks remain deployment-blocking" in template
    assert "Hostnames, interfaces, paths, credentials, certificates, and runtime state are excluded" in template
    assert "Proposed result" in template


def test_editing_ha_owned_node_rotates_credential_and_invalidates_stale_validation():
    with database() as db:
        cluster = cluster_with_connections(db)
        node = next(item for item in cluster.nodes if item.role == "STANDBY")
        node.configuration_snapshot_json = '{"dhcp":{"enabled":false}}'
        node.configuration_checksum = "old-checksum"
        node.provider_version = "6.4.2"
        node.status = "VALIDATED"
        cluster.status = "VALIDATED"
        db.add(HAHealthCheck(cluster_id=cluster.id, node_id=node.id, check_key="api_authentication", status="PASS", severity="info", summary="Old result"))
        db.commit()

        updated, credential_changed = update_cluster_node(
            db,
            cluster,
            node,
            HANodeUpdate(
                name="Standby edited",
                api_base_url=node.api_base_url,
                secret="new-application-password",
                ssl_verify=False,
                timeout_seconds=25,
                network_interface="ens18",
            ),
            cluster.created_by,
        )

        assert credential_changed
        assert updated.display_name == "Standby edited"
        assert updated.network_interface == "ens18"
        assert updated.status == "UNVALIDATED"
        assert updated.provider_version is None
        assert updated.configuration_snapshot_json is None
        assert decrypt_secret(updated.ha_connection.encrypted_secret) == "new-application-password"
        assert updated.ha_connection.ssl_verify is False
        assert updated.ha_connection.timeout_seconds == 25
        assert db.get(HACluster, cluster.id).status == "DRAFT"
        assert db.query(HAHealthCheck).filter_by(cluster_id=cluster.id).count() == 0
        assert configuration_differences(db.get(HACluster, cluster.id)) == []


def test_rotating_reused_dns_credential_creates_ha_connection_without_changing_dns_manager():
    with database() as db:
        admin = User(email="ha-dns-separation@example.com", password_hash="x", role="admin", is_active=True)
        provider = DNSProviderConfig(
            name="DNS Manager Pi-hole",
            provider_type="pihole",
            base_url="https://shared.invalid",
            encrypted_secret=encrypt_secret("dns-manager-secret"),
            ssl_verify=True,
            timeout_seconds=10,
        )
        cluster = HACluster(name="Separated", provider_key="pihole", status="DRAFT", created_by=admin)
        peer_connection = HAProviderConnection(provider_key="pihole", name="Peer", api_base_url="https://peer.invalid", encrypted_secret=encrypt_secret("peer-secret"), created_by=admin)
        db.add_all([admin, provider, cluster, peer_connection]); db.flush()
        node = HANode(cluster_id=cluster.id, display_name="Shared", management_host="shared.invalid", api_base_url=provider.base_url, integration_reference_id=provider.id, role="ACTIVE", desired_role="ACTIVE")
        peer = HANode(cluster_id=cluster.id, display_name="Peer", management_host="peer.invalid", api_base_url=peer_connection.api_base_url, ha_connection_id=peer_connection.id, role="STANDBY", desired_role="STANDBY")
        db.add_all([node, peer]); db.commit()
        provider_secret = provider.encrypted_secret

        updated, credential_changed = update_cluster_node(
            db,
            cluster,
            node,
            HANodeUpdate(name="Shared", api_base_url=provider.base_url, secret="ha-only-secret", ssl_verify=True, timeout_seconds=10),
            admin,
        )

        assert credential_changed
        assert updated.integration_reference_id is None
        assert updated.ha_connection_id is not None
        assert decrypt_secret(updated.ha_connection.encrypted_secret) == "ha-only-secret"
        assert db.get(DNSProviderConfig, provider.id).encrypted_secret == provider_secret
        assert decrypt_secret(db.get(DNSProviderConfig, provider.id).encrypted_secret) == "dns-manager-secret"


def test_changing_to_new_address_requires_new_credential_and_preserves_current_connection():
    with database() as db:
        cluster = cluster_with_connections(db)
        node = next(item for item in cluster.nodes if item.role == "ACTIVE")
        connection_id = node.ha_connection_id
        with pytest.raises(HADraftError, match="application password"):
            update_cluster_node(
                db,
                cluster,
                node,
                HANodeUpdate(name=node.display_name, api_base_url="https://replacement.invalid", ssl_verify=True, timeout_seconds=10),
                cluster.created_by,
            )
        db.rollback()
        unchanged = db.get(HANode, node.id)
        assert unchanged.ha_connection_id == connection_id
        assert unchanged.api_base_url == "https://primary.invalid"


def test_node_edit_ui_is_admin_only_and_never_repopulates_credentials():
    template = Path("app/templates/high_availability_node_form.html").read_text(encoding="utf-8")
    detail = Path("app/templates/high_availability_cluster_nodes.html").read_text(encoding="utf-8")
    validation = Path("app/templates/high_availability_cluster_validation.html").read_text(encoding="utf-8")
    routes = Path("app/routers/high_availability.py").read_text(encoding="utf-8")
    assert "Edit Node" in detail
    assert "check.node.display_name" in validation
    assert "Changes made here do not modify DNS Manager" in template
    assert 'name="secret" type="password"' in template
    assert "form_values.get('secret'" not in template
    assert 'if key != "secret"' in routes
    assert "Depends(require_ha_admin)" in routes
    assert '"credential_changed": credential_changed' in routes


def test_draft_connection_test_is_read_only_and_uses_supplied_secret():
    captured = {}

    class DraftClient:
        def __init__(self, config):
            captured["config"] = config

        def test_connection(self):
            return DNSProviderResult(True, "Pi-hole connection test passed.", {"queries": 1})

    with database() as db:
        result = probe_draft_connection(
            db,
            HANodeDraftCreate(name="Draft Pi-hole", api_base_url="https://draft.invalid", secret="temporary-application-password", ssl_verify=True),
            "pihole",
            client_factory=DraftClient,
        )
        assert result.ok
        assert decrypt_secret(captured["config"].encrypted_secret) == "temporary-application-password"
        assert db.query(DNSProviderConfig).count() == 0
        assert db.query(HAProviderConnection).count() == 0
        assert db.query(HACluster).count() == 0


def test_cluster_tabs_are_routed_pages_and_connection_test_preserves_form_state():
    tabs = Path("app/templates/_high_availability_cluster_header.html").read_text(encoding="utf-8")
    wizard = Path("app/templates/high_availability_cluster_form.html").read_text(encoding="utf-8")
    javascript = Path("app/static/js/ha_cluster_form.js").read_text(encoding="utf-8")
    routes = Path("app/routers/high_availability.py").read_text(encoding="utf-8")
    for section in ("nodes", "validation", "agents", "events"):
        assert f'/clusters/{{{{ cluster.public_id }}}}/{section}' in tabs
        assert f'@router.get("/clusters/{{public_id}}/{section}")' in routes
    assert 'aria-current="page"' in tabs
    assert 'data-ha-test-node="primary"' in wizard
    assert 'data-ha-test-node="secondary"' in wizard
    assert 'type="button"' in wizard
    assert 'fetch("/high-availability/clusters/test-connection"' in javascript
    assert "window.location" not in javascript
    assert ".reset(" not in javascript
    assert 'return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/validation?validated=1"' in routes
    assert 'return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/nodes?node_updated=1"' in routes
