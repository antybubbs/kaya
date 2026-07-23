from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address
from urllib.parse import urlsplit
from types import SimpleNamespace
from typing import Callable

from sqlalchemy.orm import Session

from app.core.security import encrypt_secret
from app.models.models import DNSProviderConfig, HACluster, HAHealthCheck, HANode, HAProviderConnection, User
from app.schemas.high_availability import HAClusterDraftCreate, HANodeDraftCreate, HANodeUpdate
from app.services.ha_registry import provider_for_key
from app.services.dns_providers import DNSProviderResult, PiHoleProvider


class HADraftError(ValueError):
    pass


def _normalise_api_url(value: str) -> str:
    clean = value.strip().rstrip("/")
    parts = urlsplit(clean)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise HADraftError("Each node URL must be a valid HTTP or HTTPS address without embedded credentials.")
    if parts.query or parts.fragment:
        raise HADraftError("Node URLs cannot include a query string or fragment.")
    return clean


@dataclass(frozen=True)
class ResolvedNode:
    name: str
    api_base_url: str
    management_host: str
    ssl_verify: bool
    secret: str | None
    integration: DNSProviderConfig | None


def _resolve_node(db: Session, node: HANodeDraftCreate, provider_key: str) -> ResolvedNode:
    name = " ".join(node.name.split())
    if not name:
        raise HADraftError("Enter a name for each provider node.")
    api_base_url = _normalise_api_url(node.api_base_url)
    integration = next(
        (
            item
            for item in db.query(DNSProviderConfig)
            .filter(DNSProviderConfig.provider_type == provider_key, DNSProviderConfig.is_enabled == True)  # noqa: E712
            .all()
            if _normalise_api_url(item.base_url).casefold() == api_base_url.casefold()
        ),
        None,
    )
    secret = node.secret if node.secret and node.secret.strip() else None
    if secret is not None:
        integration = None  # An explicitly supplied credential creates an HA-owned connection.
    if integration is None and secret is None:
        raise HADraftError("Enter an application password for each new provider connection.")
    return ResolvedNode(name, api_base_url, urlsplit(api_base_url).hostname or "", node.ssl_verify, secret, integration)


def _matching_integration(db: Session, provider_key: str, api_base_url: str) -> DNSProviderConfig | None:
    return next(
        (
            item
            for item in db.query(DNSProviderConfig)
            .filter(DNSProviderConfig.provider_type == provider_key, DNSProviderConfig.is_enabled == True)  # noqa: E712
            .all()
            if _normalise_api_url(item.base_url).casefold() == api_base_url.casefold()
        ),
        None,
    )


def test_draft_node_connection(
    db: Session,
    node: HANodeDraftCreate,
    provider_key: str,
    *,
    client_factory: Callable[[object], PiHoleProvider] = PiHoleProvider,
) -> DNSProviderResult:
    provider = provider_for_key(provider_key)
    if not provider or not provider.selectable or provider_key != "pihole":
        raise HADraftError("Choose a supported provider before testing the connection.")
    resolved = _resolve_node(db, node, provider_key)
    source = resolved.integration
    config = SimpleNamespace(
        id=f"draft-{source.id}" if source else f"draft-{hash(resolved.api_base_url)}",
        base_url=source.base_url if source else resolved.api_base_url,
        auth_method=source.auth_method if source else "password",
        encrypted_secret=source.encrypted_secret if source else encrypt_secret(resolved.secret),
        ssl_verify=source.ssl_verify if source else resolved.ssl_verify,
        timeout_seconds=source.timeout_seconds if source else 10,
    )
    db.rollback()
    return client_factory(config).test_connection()


def update_cluster_node(db: Session, cluster: HACluster, node: HANode, update: HANodeUpdate, user: User) -> tuple[HANode, bool]:
    if node.cluster_id != cluster.id:
        raise HADraftError("That node does not belong to this cluster.")
    name = " ".join(update.name.split())
    if not name:
        raise HADraftError("Node display name is required.")
    api_base_url = _normalise_api_url(update.api_base_url)
    duplicate = next(
        (
            peer
            for peer in cluster.nodes
            if peer.id != node.id and peer.api_base_url.casefold().rstrip("/") == api_base_url.casefold()
        ),
        None,
    )
    if duplicate:
        raise HADraftError("Each cluster node must use a different provider URL.")
    secret = update.secret if update.secret and update.secret.strip() else None
    matching_integration = _matching_integration(db, cluster.provider_key, api_base_url)
    current_ha_connection = node.ha_connection if node.ha_connection and node.ha_connection.deleted_at is None else None
    current_url = _normalise_api_url(node.api_base_url)
    credential_changed = secret is not None

    if current_ha_connection and (secret is not None or api_base_url.casefold() == current_url.casefold()):
        current_ha_connection.name = name
        current_ha_connection.api_base_url = api_base_url
        current_ha_connection.ssl_verify = update.ssl_verify
        current_ha_connection.timeout_seconds = update.timeout_seconds
        if secret is not None:
            current_ha_connection.encrypted_secret = encrypt_secret(secret)
        node.ha_connection_id = current_ha_connection.id
        node.integration_reference_id = None
    elif matching_integration is not None and secret is None:
        if node.integration is not None and (
            matching_integration.ssl_verify != update.ssl_verify
            or matching_integration.timeout_seconds != update.timeout_seconds
        ):
            raise HADraftError("Enter an application password to create an HA-owned connection before changing TLS or timeout settings.")
        if current_ha_connection is not None:
            current_ha_connection.deleted_at = datetime.utcnow()
        node.integration_reference_id = matching_integration.id
        node.ha_connection_id = None
    elif secret is not None:
        connection = HAProviderConnection(
            provider_key=cluster.provider_key,
            name=name,
            api_base_url=api_base_url,
            encrypted_secret=encrypt_secret(secret),
            ssl_verify=update.ssl_verify,
            timeout_seconds=update.timeout_seconds,
            created_by_user_id=user.id,
        )
        db.add(connection)
        db.flush()
        if current_ha_connection is not None:
            current_ha_connection.deleted_at = datetime.utcnow()
        node.integration_reference_id = None
        node.ha_connection_id = connection.id
    else:
        raise HADraftError("Enter an application password for this new provider address.")

    node.display_name = name
    node.management_host = urlsplit(api_base_url).hostname
    node.api_base_url = api_base_url
    node.network_interface = (update.network_interface or "").strip() or None
    node.status = "UNVALIDATED"
    node.provider_version = None
    node.capabilities_json = None
    node.configuration_snapshot_json = None
    node.configuration_checksum = None
    node.last_health_at = None
    cluster.status = "DRAFT"
    cluster.cluster_generation += 1
    cluster.last_healthy_at = None
    db.query(HAHealthCheck).filter(HAHealthCheck.cluster_id == cluster.id).delete(synchronize_session=False)
    db.commit()
    db.refresh(node)
    return node, credential_changed


def soft_delete_cluster(db: Session, cluster: HACluster, confirmation: str, acknowledged: bool) -> HACluster:
    if cluster.deleted_at is not None:
        raise HADraftError("This cluster has already been deleted.")
    if not acknowledged or confirmation.strip() != cluster.name:
        raise HADraftError("Enter the exact cluster name and acknowledge the preservation notice before deleting.")
    cluster.deleted_at = datetime.utcnow()
    cluster.status = "DELETED"
    cluster.maintenance_mode = True
    cluster.automatic_failover_enabled = False
    cluster.automatic_failback_enabled = False
    cluster.cluster_generation += 1
    for node in cluster.nodes:
        if node.agent_credential is not None:
            node.agent_credential.revoked_at = cluster.deleted_at
            node.agent_credential.bootstrap_token_hash = None
            node.agent_credential.bootstrap_expires_at = None
    db.commit()
    db.refresh(cluster)
    return cluster


def _normalise_virtual_ip(value: str | None, prefix_length: int | None) -> tuple[str | None, int | None]:
    clean = (value or "").strip()
    if not clean:
        if prefix_length is not None:
            raise HADraftError("Enter a virtual IP before selecting its prefix length.")
        return None, None
    try:
        address = IPv4Address(clean)
    except ValueError as exc:
        raise HADraftError("Virtual IP must be a valid IPv4 address.") from exc
    return str(address), prefix_length if prefix_length is not None else 24


def create_cluster_draft(db: Session, draft: HAClusterDraftCreate, user: User) -> HACluster:
    name = " ".join(draft.name.split())
    if not name:
        raise HADraftError("Cluster name is required.")
    provider = provider_for_key(draft.provider_key)
    if not provider or not provider.selectable:
        raise HADraftError("Choose a supported provider or application.")
    primary = _resolve_node(db, draft.primary, draft.provider_key)
    secondary = _resolve_node(db, draft.secondary, draft.provider_key)
    if primary.api_base_url.casefold() == secondary.api_base_url.casefold():
        raise HADraftError("Choose two different provider nodes.")
    virtual_ip, prefix_length = _normalise_virtual_ip(draft.virtual_ip, draft.prefix_length)
    if virtual_ip and db.query(HACluster).filter(HACluster.virtual_ip == virtual_ip, HACluster.deleted_at.is_(None)).first():
        raise HADraftError("That virtual IP is already assigned to another HA cluster.")

    cluster = HACluster(
        name=name,
        description=(draft.description or "").strip() or None,
        provider_key=draft.provider_key,
        status="DRAFT",
        virtual_ip=virtual_ip,
        prefix_length=prefix_length,
        created_by_user_id=user.id,
    )
    db.add(cluster)
    db.flush()
    created_nodes = []
    for node, role in ((primary, "ACTIVE"), (secondary, "STANDBY")):
        connection = None
        if node.integration is None:
            connection = HAProviderConnection(
                provider_key=draft.provider_key,
                name=node.name,
                api_base_url=node.api_base_url,
                encrypted_secret=encrypt_secret(node.secret),
                ssl_verify=node.ssl_verify,
                created_by_user_id=user.id,
            )
            db.add(connection)
            db.flush()
        created_node = HANode(
                cluster_id=cluster.id,
                display_name=node.name,
                management_host=node.management_host,
                api_base_url=node.api_base_url,
                integration_reference_id=node.integration.id if node.integration else None,
                ha_connection_id=connection.id if connection else None,
                role=role,
                desired_role=role,
                status="UNVALIDATED",
            )
        db.add(created_node)
        db.flush()
        created_nodes.append(created_node)
    cluster.authoritative_node_id = created_nodes[0].id
    db.commit()
    db.refresh(cluster)
    return cluster


@dataclass(frozen=True)
class LocalValidation:
    check_key: str
    status: str
    severity: str
    summary: str


def validate_cluster_draft(db: Session, cluster: HACluster) -> list[HAHealthCheck]:
    """Validate stored references only; never contact or mutate provider nodes."""
    checks = [
        LocalValidation("provider", "PASS" if provider_for_key(cluster.provider_key) else "FAIL", "blocking", "The cluster uses a provider supported by the HA registry."),
        LocalValidation("node_count", "PASS" if len(cluster.nodes) == 2 else "FAIL", "blocking", "The draft must contain exactly two nodes."),
        LocalValidation("unique_nodes", "PASS" if len({node.api_base_url.casefold().rstrip('/') for node in cluster.nodes}) == 2 else "FAIL", "blocking", "The two nodes must use different provider connections."),
        LocalValidation("virtual_ip", "PASS" if cluster.virtual_ip else "PENDING", "warning", "A virtual IP is required before deployment, but may be added to a draft later."),
    ]
    db.query(HAHealthCheck).filter(HAHealthCheck.cluster_id == cluster.id).delete(synchronize_session=False)
    rows = [
        HAHealthCheck(
            cluster_id=cluster.id,
            check_key=item.check_key,
            status=item.status,
            severity=item.severity,
            summary=item.summary,
            technical_detail_redacted="Local draft validation only; no provider request was made.",
        )
        for item in checks
    ]
    db.add_all(rows)
    db.commit()
    return rows
