from __future__ import annotations

from datetime import datetime
import json

from sqlalchemy.orm import Session

from app.models.models import AuditLog, IPAddress, RemoteAccess, User


_UNSET = object()
_SAFE_REASONS = {
    "primary_ip_editor": "primary IP editor",
    "remote_host_editor": "Remote Manager host editor",
    "dns_managed_update": "explicit DNS-managed address update",
    "dns_automatic_update": "automatic DNS-managed address update",
}


def update_remote_endpoint(
    db: Session,
    record: IPAddress,
    *,
    remote: RemoteAccess | None = None,
    address: str | object = _UNSET,
    protocol: str | object = _UNSET,
    port: int | object = _UNSET,
    actor: User | None = None,
    audit_ip: str | None = None,
    reason: str,
) -> bool:
    """Mutate effective endpoint identity and atomically invalidate existing RDP pins."""
    if reason not in _SAFE_REASONS:
        raise ValueError("Unsupported endpoint-change reason.")
    if remote is None:
        remote = db.query(RemoteAccess).filter_by(ip_address_id=record.id).one_or_none()
    old_endpoint = {
        "address": record.address,
        "protocol": remote.protocol if remote else None,
        "port": remote.port if remote else None,
    }
    if address is not _UNSET:
        record.address = str(address)
    if remote is not None and protocol is not _UNSET:
        remote.protocol = str(protocol)
    if remote is not None and port is not _UNSET:
        remote.port = int(port)
    new_endpoint = {
        "address": record.address,
        "protocol": remote.protocol if remote else None,
        "port": remote.port if remote else None,
    }
    if (
        remote is None
        or old_endpoint == new_endpoint
        or (not remote.rdp_cert_fingerprints and remote.rdp_trust_invalidated_at is None)
    ):
        return False

    remote.rdp_cert_fingerprints = None
    remote.rdp_trust_invalidated_at = datetime.utcnow()
    remote.rdp_trust_invalidated_reason = reason
    db.add(AuditLog(
        user_id=actor.id if actor else None,
        action="rdp_certificate_trust_invalidated",
        entity="remote_access",
        entity_id=str(remote.id),
        ip_address=audit_ip,
        detail=f"RDP certificate trust invalidated after endpoint change via {_SAFE_REASONS[reason]}",
        category="security",
        severity="warning",
        metadata_json=json.dumps(
            {"reason": reason, "old_endpoint": old_endpoint, "new_endpoint": new_endpoint},
            separators=(",", ":"),
        ),
    ))
    return True
