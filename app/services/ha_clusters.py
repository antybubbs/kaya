from dataclasses import dataclass
from ipaddress import IPv4Address
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.models.models import DNSProviderConfig, HACluster, HAHealthCheck, HANode, User
from app.schemas.high_availability import HAClusterDraftCreate


class HADraftError(ValueError):
    pass


def available_pihole_integrations(db: Session) -> list[DNSProviderConfig]:
    return (
        db.query(DNSProviderConfig)
        .filter(DNSProviderConfig.provider_type == "pihole", DNSProviderConfig.is_enabled == True)  # noqa: E712
        .order_by(DNSProviderConfig.name.asc())
        .all()
    )


def _integration(db: Session, integration_id: int) -> DNSProviderConfig:
    row = db.get(DNSProviderConfig, integration_id)
    if not row or row.provider_type != "pihole" or not row.is_enabled:
        raise HADraftError("Choose an enabled Pi-hole connection already configured in DNS Manager.")
    return row


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
    if draft.primary_integration_id == draft.secondary_integration_id:
        raise HADraftError("Choose two different Pi-hole connections.")
    primary = _integration(db, draft.primary_integration_id)
    secondary = _integration(db, draft.secondary_integration_id)
    virtual_ip, prefix_length = _normalise_virtual_ip(draft.virtual_ip, draft.prefix_length)
    if virtual_ip and db.query(HACluster).filter(HACluster.virtual_ip == virtual_ip, HACluster.deleted_at.is_(None)).first():
        raise HADraftError("That virtual IP is already assigned to another HA cluster.")

    cluster = HACluster(
        name=name,
        description=(draft.description or "").strip() or None,
        provider_key="pihole",
        status="DRAFT",
        virtual_ip=virtual_ip,
        prefix_length=prefix_length,
        created_by_user_id=user.id,
    )
    db.add(cluster)
    db.flush()
    for provider, role in ((primary, "ACTIVE"), (secondary, "STANDBY")):
        host = urlsplit(provider.base_url).hostname
        db.add(
            HANode(
                cluster_id=cluster.id,
                display_name=provider.name,
                management_host=host,
                api_base_url=provider.base_url,
                integration_reference_id=provider.id,
                role=role,
                desired_role=role,
                status="UNVALIDATED",
            )
        )
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
        LocalValidation("provider", "PASS" if cluster.provider_key == "pihole" else "FAIL", "blocking", "Pi-hole is the supported Phase 1 provider."),
        LocalValidation("node_count", "PASS" if len(cluster.nodes) == 2 else "FAIL", "blocking", "The draft must contain exactly two nodes."),
        LocalValidation("unique_nodes", "PASS" if len({node.integration_reference_id for node in cluster.nodes}) == 2 else "FAIL", "blocking", "The two nodes must use different Pi-hole connections."),
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
