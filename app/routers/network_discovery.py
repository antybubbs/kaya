"""Authenticated, bounded API for flow discovery review and decisions."""
from __future__ import annotations

import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.csrf import validate_csrf_token
from app.db.session import get_db
from app.models.models import IPAddress, TrafficDiscoveryConfiguration, TrafficDiscoveryLink, TrafficDiscoveryNetworkMapping, TrafficDiscoveryObservation, TrafficSource, VLAN
from app.routers.auth import require_admin, require_module_access, require_user
from app.services.audit import write_audit
from app.services.client_ip import client_ip as trusted_client_ip
from app.services.network_discovery import DISCOVERY_FLOW_PROVIDERS
from app.services.network_discovery_matching import (
    current_link,
    latest_observation,
    match_endpoint,
    observation_keys_query,
)
from app.services.network_discovery_mapping import mapped_network_contexts


router = APIRouter(prefix="/api/network-discovery", dependencies=[Depends(require_module_access("network_monitor"))])
MAX_PAGE_SIZE = 100
MAX_QUERY_ROWS = 10_000
VALID_ENDPOINT_ROLES = {
    "original_source",
    "original_destination",
    "translated_source",
    "translated_destination",
}
LINKABLE_ENDPOINT_ROLES = {"original_source", "original_destination"}


class DiscoveryDecision(BaseModel):
    confirmation: bool = False
    managed_ip_address_id: int | None = Field(None, ge=1)
    reason: str | None = Field(None, max_length=255)


class DiscoveryConfigurationPayload(BaseModel):
    is_enabled: bool
    detailed_retention_hours: int = Field(72, ge=1, le=720)
    summary_retention_days: int = Field(30, ge=1, le=3650)
    max_detail_rows: int = Field(100000, ge=1, le=1_000_000)
    max_summary_rows: int = Field(100000, ge=1, le=1_000_000)


class DiscoveryNetworkMappingPayload(BaseModel):
    source_id: int = Field(..., ge=1)
    exporter_identity: str = Field(..., min_length=1, max_length=45)
    vlan_id: int = Field(..., ge=1)
    is_enabled: bool = True


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _linked_validity(db: Session, link: TrafficDiscoveryLink) -> tuple[str, str, int | None]:
    """Revalidate a stored link against the current exporter trust context."""
    if link.endpoint_role not in LINKABLE_ENDPOINT_ROLES:
        return "unresolved", "translated_endpoint_not_linkable", None
    source = db.get(TrafficSource, link.source_id)
    target = db.get(IPAddress, link.managed_ip_address_id) if link.managed_ip_address_id else None
    if not source or source.is_deleted or source.provider_key not in DISCOVERY_FLOW_PROVIDERS:
        return "unresolved", "source_no_longer_eligible", None
    if not target:
        return "unresolved", "managed_ip_record_missing", None
    try:
        endpoint = ipaddress.ip_address(link.endpoint_ip)
    except ValueError:
        return "unresolved", "invalid_endpoint", None
    contexts = [context for context in mapped_network_contexts(db, link.source_id, link.exporter_identity) if endpoint.version == context[2].version and endpoint in context[2]]
    if len(contexts) > 1:
        return "ambiguous", "overlapping_local_networks", None
    if not contexts:
        return "stale", "mapping_disabled_or_endpoint_outside_network", None
    vlan_id, network_cidr, _network = contexts[0]
    if link.mapping_vlan_id is None or not link.mapping_network_cidr:
        return "stale", "legacy_link_requires_review", None
    if link.mapping_vlan_id != vlan_id or link.mapping_network_cidr != network_cidr:
        return "stale", "mapping_network_changed", None
    if target.address != str(endpoint) or target.vlan_id != vlan_id:
        return "unresolved", "managed_ip_context_changed", None
    return "valid", "administrator_link", target.id


def _row_payload(db: Session, row) -> dict:
    latest = latest_observation(db, row.source_id, row.exporter_identity, row.endpoint_ip, row.endpoint_role)
    classification = latest.classification if latest else "unknown"
    confidence = latest.confidence if latest else "unknown"
    match = match_endpoint(db, row.source_id, row.exporter_identity, row.endpoint_ip, classification=classification)
    link = current_link(db, row.source_id, row.exporter_identity, row.endpoint_ip, row.endpoint_role)
    status = match.status
    managed_id = match.managed_ip_address_id
    reason = match.reason
    link_state = link.state if link else None
    link_validity = None
    historical_managed_id = link.managed_ip_address_id if link and link.state == "linked" else None
    if link and link.state == "ignored":
        status, managed_id, reason = "ignored", None, link.reason or "ignored_by_administrator"
    elif link and link.state == "linked":
        link_validity, reason, managed_id = _linked_validity(db, link)
        status = "linked" if link_validity == "valid" else link_validity
    return {
        "source_id": row.source_id,
        "exporter_identity": row.exporter_identity,
        "endpoint_ip": row.endpoint_ip,
        "endpoint_role": row.endpoint_role,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "observation_count": int(row.observation_count or 0),
        "classification": classification,
        "confidence": confidence,
        "status": status,
        "status_reason": reason,
        "managed_ip_address_id": managed_id,
        "link_state": link_state,
        "link_validity": link_validity,
        "historical_managed_ip_address_id": historical_managed_id,
    }


@router.get("/observations")
def list_discovered_ips(
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    source_id: int | None = Query(None, ge=1),
    exporter_identity: str | None = Query(None, min_length=1, max_length=45),
    endpoint_ip: str | None = Query(None, min_length=1, max_length=45),
    status: str | None = Query(None, pattern=r"^(linked|unlinked|ignored|stale|ambiguous|unmatched)$"),
    db: Session = Depends(get_db),
    _user=Depends(require_user),
):
    if endpoint_ip:
        try:
            endpoint_ip = str(ipaddress.ip_address(endpoint_ip))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid endpoint IP address.") from exc
    query = observation_keys_query(db, source_id=source_id, exporter_identity=exporter_identity, endpoint_ip=endpoint_ip)
    query = query.order_by(func.max(TrafficDiscoveryObservation.last_seen_at).desc(), TrafficDiscoveryObservation.endpoint_ip.asc())
    rows = query.limit(MAX_QUERY_ROWS).all()
    items = [_row_payload(db, row) for row in rows]
    if status:
        items = [item for item in items if item["status"] == status]
    total = len(items)
    start = (page - 1) * page_size
    return {"page": page, "page_size": page_size, "total": total, "items": items[start:start + page_size], "truncated": len(rows) == MAX_QUERY_ROWS}


@router.get("/summary")
def discovery_summary(db: Session = Depends(get_db), _user=Depends(require_user)):
    rows = observation_keys_query(db).limit(MAX_QUERY_ROWS).all()
    counts = {key: 0 for key in ("linked", "unlinked", "ignored", "stale", "ambiguous", "unmatched")}
    for row in rows:
        counts[_row_payload(db, row)["status"]] += 1
    return {"total": sum(counts.values()), "counts": counts, "truncated": len(rows) == MAX_QUERY_ROWS}


@router.get("/capabilities")
def discovery_capabilities(db: Session = Depends(get_db), _user=Depends(require_user)):
    configuration = db.get(TrafficDiscoveryConfiguration, 1)
    sources = db.query(TrafficSource).filter(TrafficSource.is_deleted.is_(False)).order_by(TrafficSource.name.asc()).all()
    return {
        "discovery_enabled": bool(configuration and configuration.is_enabled),
        "sources": [
            {
                "id": source.id,
                "name": source.name,
                "provider_key": source.provider_key,
                "supports_discovery": source.provider_key in DISCOVERY_FLOW_PROVIDERS,
                "source_enabled": bool(source.is_enabled),
                "capability_enabled": bool(configuration and configuration.is_enabled and source.is_enabled and source.provider_key in DISCOVERY_FLOW_PROVIDERS),
            }
            for source in sources
        ],
    }


@router.get("/configuration")
def get_discovery_configuration(db: Session = Depends(get_db), _user=Depends(require_user)):
    configuration = db.get(TrafficDiscoveryConfiguration, 1)
    return {
        "is_enabled": bool(configuration and configuration.is_enabled),
        "detailed_retention_hours": configuration.detailed_retention_hours if configuration else 72,
        "summary_retention_days": configuration.summary_retention_days if configuration else 30,
        "max_detail_rows": configuration.max_detail_rows if configuration else 100000,
        "max_summary_rows": configuration.max_summary_rows if configuration else 100000,
    }


@router.get("/network-mappings")
def list_network_mappings(db: Session = Depends(get_db), _user=Depends(require_user)):
    rows = db.query(TrafficDiscoveryNetworkMapping).order_by(TrafficDiscoveryNetworkMapping.source_id, TrafficDiscoveryNetworkMapping.exporter_identity, TrafficDiscoveryNetworkMapping.vlan_id).all()
    return {"mappings": [{"id": row.id, "source_id": row.source_id, "exporter_identity": row.exporter_identity, "vlan_id": row.vlan_id, "is_enabled": row.is_enabled} for row in rows]}


@router.post("/network-mappings", status_code=201)
def create_network_mapping(request: Request, payload: DiscoveryNetworkMappingPayload, db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    exporter_identity = payload.exporter_identity.strip()
    if not exporter_identity:
        raise HTTPException(status_code=400, detail="Exporter identity must not be blank.")
    source = db.get(TrafficSource, payload.source_id)
    vlan = db.get(VLAN, payload.vlan_id)
    if not source or source.is_deleted or source.provider_key not in DISCOVERY_FLOW_PROVIDERS:
        raise HTTPException(status_code=404, detail="Supported flow source not found.")
    if not vlan or not vlan.subnet_cidr:
        raise HTTPException(status_code=409, detail="VLAN must exist and have a subnet CIDR.")
    try:
        ipaddress.ip_network(vlan.subnet_cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="VLAN subnet CIDR is invalid.") from exc
    duplicate = db.query(TrafficDiscoveryNetworkMapping).filter_by(source_id=payload.source_id, exporter_identity=exporter_identity, vlan_id=payload.vlan_id).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="This exporter-to-VLAN mapping already exists.")
    row = TrafficDiscoveryNetworkMapping(source_id=payload.source_id, exporter_identity=exporter_identity, vlan_id=payload.vlan_id, is_enabled=payload.is_enabled, created_by_user_id=user.id, updated_by_user_id=user.id)
    db.add(row)
    db.flush()
    audit = write_audit(db, user, "create", "traffic_discovery_network_mapping", str(row.id), trusted_client_ip(request), detail="Created exporter-to-VLAN discovery mapping", metadata={"source_id": row.source_id, "exporter_identity": row.exporter_identity, "vlan_id": row.vlan_id}, force=True, commit=False)
    if audit is None:
        db.rollback()
        raise HTTPException(status_code=500, detail="The discovery mapping could not be audited.")
    db.commit()
    return {"id": row.id, "source_id": row.source_id, "exporter_identity": row.exporter_identity, "vlan_id": row.vlan_id, "is_enabled": row.is_enabled}


@router.put("/network-mappings/{mapping_id}")
def update_network_mapping(request: Request, mapping_id: int, payload: DiscoveryNetworkMappingPayload, db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    exporter_identity = payload.exporter_identity.strip()
    if not exporter_identity:
        raise HTTPException(status_code=400, detail="Exporter identity must not be blank.")
    row = db.get(TrafficDiscoveryNetworkMapping, mapping_id)
    if not row:
        raise HTTPException(status_code=404, detail="Discovery mapping not found.")
    source = db.get(TrafficSource, payload.source_id)
    vlan = db.get(VLAN, payload.vlan_id)
    if not source or source.is_deleted or source.provider_key not in DISCOVERY_FLOW_PROVIDERS or not vlan or not vlan.subnet_cidr:
        raise HTTPException(status_code=409, detail="Mapping source and VLAN must remain valid supported records.")
    try:
        ipaddress.ip_network(vlan.subnet_cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="VLAN subnet CIDR is invalid.") from exc
    duplicate = db.query(TrafficDiscoveryNetworkMapping).filter(TrafficDiscoveryNetworkMapping.source_id == payload.source_id, TrafficDiscoveryNetworkMapping.exporter_identity == exporter_identity, TrafficDiscoveryNetworkMapping.vlan_id == payload.vlan_id, TrafficDiscoveryNetworkMapping.id != row.id).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="This exporter-to-VLAN mapping already exists.")
    row.source_id, row.exporter_identity, row.vlan_id, row.is_enabled = payload.source_id, exporter_identity, payload.vlan_id, payload.is_enabled
    row.updated_by_user_id = user.id
    audit = write_audit(db, user, "update", "traffic_discovery_network_mapping", str(row.id), trusted_client_ip(request), detail="Updated exporter-to-VLAN discovery mapping", metadata={"source_id": row.source_id, "exporter_identity": row.exporter_identity, "vlan_id": row.vlan_id, "is_enabled": row.is_enabled}, force=True, commit=False)
    if audit is None:
        db.rollback()
        raise HTTPException(status_code=500, detail="The discovery mapping could not be audited.")
    db.commit()
    return {"id": row.id, "source_id": row.source_id, "exporter_identity": row.exporter_identity, "vlan_id": row.vlan_id, "is_enabled": row.is_enabled}


@router.delete("/network-mappings/{mapping_id}")
def delete_network_mapping(request: Request, mapping_id: int, payload: DiscoveryDecision, db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    if not payload.confirmation:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required.")
    row = db.get(TrafficDiscoveryNetworkMapping, mapping_id)
    if not row:
        raise HTTPException(status_code=404, detail="Discovery mapping not found.")
    metadata = {"source_id": row.source_id, "exporter_identity": row.exporter_identity, "vlan_id": row.vlan_id}
    audit = write_audit(db, user, "delete", "traffic_discovery_network_mapping", str(row.id), trusted_client_ip(request), detail="Deleted exporter-to-VLAN discovery mapping", metadata=metadata, force=True, commit=False)
    if audit is None:
        db.rollback()
        raise HTTPException(status_code=500, detail="The discovery mapping could not be audited.")
    db.delete(row)
    db.commit()
    return {"deleted": True, "id": mapping_id}


@router.put("/configuration")
def update_discovery_configuration(
    request: Request,
    payload: DiscoveryConfigurationPayload,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    configuration = db.get(TrafficDiscoveryConfiguration, 1)
    if configuration is None:
        configuration = TrafficDiscoveryConfiguration(id=1)
        db.add(configuration)
    for field in ("is_enabled", "detailed_retention_hours", "summary_retention_days", "max_detail_rows", "max_summary_rows"):
        setattr(configuration, field, getattr(payload, field))
    db.commit()
    write_audit(db, user, "update", "traffic_discovery_configuration", "1", trusted_client_ip(request), detail="Network discovery configuration changed", metadata={"is_enabled": payload.is_enabled})
    return get_discovery_configuration(db, user)


def _decision(request: Request, db: Session, user, source_id: int, exporter_identity: str, endpoint_role: str, endpoint_ip: str, payload: DiscoveryDecision, *, action: str):
    if not payload.confirmation:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required.")
    if len(exporter_identity) > 45 or len(exporter_identity) < 1:
        raise HTTPException(status_code=400, detail="Invalid exporter identity.")
    if endpoint_role not in VALID_ENDPOINT_ROLES:
        raise HTTPException(status_code=400, detail="Invalid endpoint role.")
    if action == "link" and endpoint_role not in LINKABLE_ENDPOINT_ROLES:
        raise HTTPException(status_code=409, detail="Translated endpoints cannot be linked.")
    try:
        endpoint_ip = str(ipaddress.ip_address(endpoint_ip))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid endpoint IP address.") from exc
    source = db.get(TrafficSource, source_id)
    observation = latest_observation(db, source_id, exporter_identity, endpoint_ip, endpoint_role)
    if not source or source.is_deleted or source.provider_key not in DISCOVERY_FLOW_PROVIDERS or not observation:
        raise HTTPException(status_code=404, detail="Discovered endpoint not found.")
    if observation.classification != "internal" or observation.ambiguity_reason:
        raise HTTPException(status_code=409, detail="Only an unambiguous internal discovery can be changed.")
    link = current_link(db, source_id, exporter_identity, endpoint_ip, endpoint_role)
    if action == "link":
        match = match_endpoint(db, source_id, exporter_identity, endpoint_ip, classification=observation.classification)
        if match.status == "ambiguous" or match.managed_ip_address_id != payload.managed_ip_address_id:
            raise HTTPException(status_code=409, detail="The candidate no longer matches the selected managed IP record.")
        try:
            endpoint = ipaddress.ip_address(endpoint_ip)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid endpoint IP address.") from exc
        contexts = [context for context in mapped_network_contexts(db, source_id, exporter_identity) if endpoint.version == context[2].version and endpoint in context[2]]
        if len(contexts) != 1:
            raise HTTPException(status_code=409, detail="The endpoint no longer has one unambiguous mapped network.")
        mapping_vlan_id, mapping_network_cidr, _network = contexts[0]
        if not link:
            link = TrafficDiscoveryLink(source_id=source_id, exporter_identity=exporter_identity, endpoint_ip=endpoint_ip, endpoint_role=endpoint_role, created_by_user_id=user.id)
            db.add(link)
        link.state, link.managed_ip_address_id, link.reason, link.updated_by_user_id = "linked", payload.managed_ip_address_id, "administrator_link", user.id
        link.mapping_vlan_id, link.mapping_network_cidr = mapping_vlan_id, mapping_network_cidr
    elif action == "ignore":
        if not link:
            link = TrafficDiscoveryLink(source_id=source_id, exporter_identity=exporter_identity, endpoint_ip=endpoint_ip, endpoint_role=endpoint_role, created_by_user_id=user.id)
            db.add(link)
        link.state, link.managed_ip_address_id, link.reason, link.updated_by_user_id = "ignored", None, payload.reason or "ignored_by_administrator", user.id
    elif action == "unignore":
        if link:
            link.state, link.managed_ip_address_id, link.reason, link.updated_by_user_id = "unlinked", None, "administrator_unignored", user.id
    else:  # unlink
        if link:
            link.state, link.managed_ip_address_id, link.reason, link.updated_by_user_id = "unlinked", None, "administrator_unlinked", user.id
    audit = write_audit(db, user, f"discovery_{action}", "traffic_discovery_endpoint", f"{source_id}:{exporter_identity}:{endpoint_role}:{endpoint_ip}", trusted_client_ip(request), detail=f"Discovery endpoint {action} decision", metadata={"managed_ip_address_id": payload.managed_ip_address_id if action == "link" else None}, force=True, commit=False)
    if audit is None:
        db.rollback()
        raise HTTPException(status_code=500, detail="The discovery decision could not be audited.")
    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="The discovery decision could not be saved.") from exc
    row = observation_keys_query(db, source_id=source_id, exporter_identity=exporter_identity, endpoint_ip=endpoint_ip).filter(TrafficDiscoveryObservation.endpoint_role == endpoint_role).first()
    return _row_payload(db, row)


@router.post("/sources/{source_id}/endpoints/{exporter_identity}/{endpoint_role}/{endpoint_ip}/link")
def link_discovery(request: Request, source_id: int, exporter_identity: str = Path(..., min_length=1, max_length=45), endpoint_role: str = Path(..., pattern=r"^(original_source|original_destination|translated_source|translated_destination)$"), endpoint_ip: str = Path(..., min_length=1, max_length=45), payload: DiscoveryDecision = ..., db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    return _decision(request, db, user, source_id, exporter_identity, endpoint_role, endpoint_ip, payload, action="link")


@router.post("/sources/{source_id}/endpoints/{exporter_identity}/{endpoint_role}/{endpoint_ip}/unlink")
def unlink_discovery(request: Request, source_id: int, exporter_identity: str = Path(..., min_length=1, max_length=45), endpoint_role: str = Path(..., pattern=r"^(original_source|original_destination|translated_source|translated_destination)$"), endpoint_ip: str = Path(..., min_length=1, max_length=45), payload: DiscoveryDecision = ..., db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    return _decision(request, db, user, source_id, exporter_identity, endpoint_role, endpoint_ip, payload, action="unlink")


@router.post("/sources/{source_id}/endpoints/{exporter_identity}/{endpoint_role}/{endpoint_ip}/ignore")
def ignore_discovery(request: Request, source_id: int, exporter_identity: str = Path(..., min_length=1, max_length=45), endpoint_role: str = Path(..., pattern=r"^(original_source|original_destination|translated_source|translated_destination)$"), endpoint_ip: str = Path(..., min_length=1, max_length=45), payload: DiscoveryDecision = ..., db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    return _decision(request, db, user, source_id, exporter_identity, endpoint_role, endpoint_ip, payload, action="ignore")


@router.post("/sources/{source_id}/endpoints/{exporter_identity}/{endpoint_role}/{endpoint_ip}/unignore")
def unignore_discovery(request: Request, source_id: int, exporter_identity: str = Path(..., min_length=1, max_length=45), endpoint_role: str = Path(..., pattern=r"^(original_source|original_destination|translated_source|translated_destination)$"), endpoint_ip: str = Path(..., min_length=1, max_length=45), payload: DiscoveryDecision = ..., db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    return _decision(request, db, user, source_id, exporter_identity, endpoint_role, endpoint_ip, payload, action="unignore")
