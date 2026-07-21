from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.core.security import decrypt_secret, encrypt_secret
from app.models.models import HACluster, HALeaseReplicationState, HALeaseSnapshot, HANode
from app.services.dns_providers import PiHoleProvider
from app.services.ha_validation import connection_for_node


MAX_LEASES = 10000
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


class HALeaseError(ValueError):
    pass


@dataclass(frozen=True)
class LeasePlan:
    applicable: bool
    source: HANode
    target: HANode
    leases: list[dict[str, Any]]
    reservations: set[str]
    range_start: ipaddress.IPv4Address | None
    range_end: ipaddress.IPv4Address | None


def _state(db: Session, cluster: HACluster) -> HALeaseReplicationState:
    row = cluster.lease_replication
    if row is None:
        row = HALeaseReplicationState(cluster_id=cluster.id)
        db.add(row)
        db.flush()
    return row


def _nodes(cluster: HACluster) -> tuple[HANode, HANode]:
    source = next((node for node in cluster.nodes if node.id == cluster.authoritative_node_id), None)
    source = source or next((node for node in cluster.nodes if node.role == "ACTIVE"), None)
    if source is None:
        raise HALeaseError("Kaya cannot identify the main Pi-hole for lease replication.")
    target = next((node for node in cluster.nodes if node.id != source.id), None)
    if target is None:
        raise HALeaseError("Lease replication requires a standby Pi-hole.")
    return source, target


def _dict_at(value: Any, *keys: str) -> dict[str, Any]:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _dhcp_payload(configuration_result: Any) -> dict[str, Any]:
    data = configuration_result if isinstance(configuration_result, dict) else {}
    configuration = data.get("configuration", data)
    raw = configuration.get("dhcp", {}) if isinstance(configuration, dict) else {}
    config = _dict_at(raw, "config", "dhcp")
    if config:
        return config
    config = _dict_at(raw, "config")
    return config.get("dhcp", config) if isinstance(config, dict) else {}


def _is_enabled(dhcp: dict[str, Any]) -> bool:
    value = dhcp.get("active", dhcp.get("enabled", False))
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "enabled"}


def _reservation_ips(dhcp: dict[str, Any]) -> set[str]:
    values = dhcp.get("hosts", dhcp.get("reservations", []))
    result: set[str] = set()
    if not isinstance(values, list):
        return result
    for item in values:
        candidate = item.get("ip") or item.get("address") if isinstance(item, dict) else None
        if candidate is None and isinstance(item, str):
            candidate = next((part.strip() for part in item.split(",") if _valid_ipv4(part.strip())), None)
        if candidate and _valid_ipv4(str(candidate)):
            result.add(str(ipaddress.IPv4Address(str(candidate))))
    return result


def _valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _range(dhcp: dict[str, Any]) -> tuple[ipaddress.IPv4Address | None, ipaddress.IPv4Address | None]:
    start = dhcp.get("start") or dhcp.get("range_start") or dhcp.get("from")
    end = dhcp.get("end") or dhcp.get("range_end") or dhcp.get("to")
    if not start and isinstance(dhcp.get("range"), dict):
        start, end = dhcp["range"].get("start"), dhcp["range"].get("end")
    if not start and isinstance(dhcp.get("range"), list) and len(dhcp["range"]) >= 2:
        start, end = dhcp["range"][:2]
    if not start or not end or not _valid_ipv4(str(start)) or not _valid_ipv4(str(end)):
        return None, None
    first, last = ipaddress.IPv4Address(str(start)), ipaddress.IPv4Address(str(end))
    if first > last:
        raise HALeaseError("The main Pi-hole returned an invalid DHCP range.")
    return first, last


def _lease_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("leases", "data"):
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
    raise HALeaseError("The main Pi-hole returned an unrecognised DHCP lease response.")


def normalise_leases(
    data: Any,
    *,
    range_start: ipaddress.IPv4Address | None,
    range_end: ipaddress.IPv4Address | None,
    reservation_ips: set[str],
) -> list[dict[str, Any]]:
    rows = _lease_rows(data)
    if len(rows) > MAX_LEASES:
        raise HALeaseError(f"The Pi-hole returned more than the safe limit of {MAX_LEASES} leases.")
    normalised: list[dict[str, Any]] = []
    owners: dict[str, str] = {}
    for row in rows:
        ip_text = str(row.get("ip") or row.get("address") or "").strip()
        mac = str(row.get("hwaddr") or row.get("mac") or row.get("mac_address") or "").strip().lower().replace("-", ":")
        if not _valid_ipv4(ip_text):
            raise HALeaseError("Pi-hole returned a lease with an invalid IPv4 address.")
        ip_text = str(ipaddress.IPv4Address(ip_text))
        if not MAC_RE.fullmatch(mac):
            raise HALeaseError(f"Pi-hole returned an invalid hardware address for lease {ip_text}.")
        if range_start is not None and range_end is not None and not (range_start <= ipaddress.IPv4Address(ip_text) <= range_end) and ip_text not in reservation_ips:
            raise HALeaseError(f"Lease {ip_text} is outside the configured DHCP range and is not a reservation.")
        if ip_text in owners and owners[ip_text] != mac:
            raise HALeaseError(f"Conflicting leases assign {ip_text} to more than one device.")
        owners[ip_text] = mac
        try:
            expires = max(0, int(row.get("expires") or row.get("expiry") or 0))
        except (TypeError, ValueError) as exc:
            raise HALeaseError(f"Pi-hole returned an invalid expiry for lease {ip_text}.") from exc
        hostname = str(row.get("name") or row.get("hostname") or "").strip()[:255]
        client_id = str(row.get("clientid") or row.get("client_id") or "").strip()[:255]
        normalised.append({"expires": expires, "hwaddr": mac, "ip": ip_text, "name": hostname, "clientid": client_id})
    return sorted(normalised, key=lambda item: (int(ipaddress.IPv4Address(item["ip"])), item["hwaddr"]))


def inspect_cluster_leases(cluster: HACluster, *, client_factory: Callable = PiHoleProvider) -> LeasePlan:
    source, target = _nodes(cluster)
    connection = connection_for_node(source)
    if connection is None:
        raise HALeaseError("The main Pi-hole connection is unavailable.")
    client = client_factory(connection)
    configuration = client.get_ha_configuration()
    if not configuration.ok:
        raise HALeaseError(configuration.message)
    dhcp = _dhcp_payload(configuration.data)
    reservations = _reservation_ips(dhcp)
    range_start, range_end = _range(dhcp)
    if not _is_enabled(dhcp):
        return LeasePlan(False, source, target, [], reservations, range_start, range_end)
    if range_start is None or range_end is None:
        raise HALeaseError("Pi-hole DHCP is enabled, but Kaya could not validate its address range.")
    result = client.get_dhcp_leases()
    if not result.ok:
        raise HALeaseError(result.message)
    leases = normalise_leases(result.data, range_start=range_start, range_end=range_end, reservation_ips=reservations)
    return LeasePlan(True, source, target, leases, reservations, range_start, range_end)


def reconcile_cluster_leases(db: Session, cluster: HACluster, *, client_factory: Callable = PiHoleProvider) -> HALeaseReplicationState:
    state = _state(db, cluster)
    now = datetime.utcnow()
    try:
        plan = inspect_cluster_leases(cluster, client_factory=client_factory)
        state.source_node_id, state.target_node_id = plan.source.id, plan.target.id
        state.last_full_reconciliation_at = now
        state.last_error_redacted = None
        if not plan.applicable:
            state.status = "NOT_APPLICABLE"
            state.lease_count = state.difference_count = state.conflict_count = 0
            db.commit()
            return state
        # Only lease content belongs in the checksum. Snapshot timestamps live on
        # the database row; including one here would create false drift on every
        # periodic check even when no lease changed.
        payload = {"version": 1, "cluster_id": cluster.public_id, "source_node_id": plan.source.public_id, "leases": plan.leases}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        checksum = hashlib.sha256(encoded.encode()).hexdigest()
        latest = db.query(HALeaseSnapshot).filter(HALeaseSnapshot.cluster_id == cluster.id).order_by(HALeaseSnapshot.generation.desc()).first()
        state.lease_count = len(plan.leases)
        state.difference_count = 0 if latest and latest.checksum == checksum else max(1, len(plan.leases), latest.lease_count if latest else 0)
        state.conflict_count = 0
        if latest and latest.checksum == checksum and latest.status in {"PENDING", "STAGED"}:
            state.status = "CURRENT" if latest.status == "STAGED" else "PENDING"
            db.commit()
            return state
        generation = max(state.desired_generation, latest.generation if latest else 0) + 1
        snapshot = HALeaseSnapshot(cluster_id=cluster.id, source_node_id=plan.source.id, target_node_id=plan.target.id, generation=generation, checksum=checksum, encrypted_payload=encrypt_secret(encoded), lease_count=len(plan.leases), status="PENDING", validation_summary_json=json.dumps({"range": f"{plan.range_start}-{plan.range_end}", "reservation_count": len(plan.reservations), "conflicts": 0}, sort_keys=True))
        db.add(snapshot)
        state.desired_generation = generation
        state.status = "PENDING"
        state.last_event_at = now
        db.commit()
        db.refresh(state)
        return state
    except HALeaseError as exc:
        state.status = "BLOCKED"
        state.conflict_count = 1 if "conflict" in str(exc).lower() else 0
        state.last_error_redacted = str(exc)[:1000]
        state.last_full_reconciliation_at = now
        db.commit()
        raise


def desired_lease_action(cluster: HACluster, node: HANode) -> dict[str, Any] | None:
    state = cluster.lease_replication
    if state is None or state.status != "PENDING" or state.target_node_id != node.id:
        return None
    snapshot = next((item for item in cluster.lease_snapshots if item.generation == state.desired_generation), None)
    if snapshot is None or snapshot.status != "PENDING":
        return None
    return {"action_id": f"lease:{cluster.public_id}:{node.public_id}:{snapshot.generation}:{snapshot.checksum[:12]}", "action_type": "LEASE_SNAPSHOT_STAGE", "generation": snapshot.generation, "checksum": snapshot.checksum, "snapshot_path": f"/api/ha/agent/v1/lease-snapshot/{snapshot.generation}"}


def snapshot_for_agent(node: HANode, generation: int) -> dict[str, Any]:
    state = node.cluster.lease_replication
    if state is None or state.target_node_id != node.id or state.desired_generation != generation:
        raise HALeaseError("This lease snapshot is not assigned to this node.")
    snapshot = next((item for item in node.cluster.lease_snapshots if item.generation == generation), None)
    if snapshot is None or snapshot.status != "PENDING":
        raise HALeaseError("The requested lease snapshot is unavailable.")
    payload = json.loads(decrypt_secret(snapshot.encrypted_payload))
    return {"generation": snapshot.generation, "checksum": snapshot.checksum, "payload": payload}


def record_lease_stage_result(db: Session, node: HANode, *, generation: int, checksum: str | None, status: str, message: str) -> None:
    state = node.cluster.lease_replication
    if state is None or state.target_node_id != node.id or state.desired_generation != generation:
        raise HALeaseError("The lease result does not match the target's current desired generation.")
    snapshot = next((item for item in node.cluster.lease_snapshots if item.generation == generation), None)
    if snapshot is None or (status == "APPLIED" and checksum != snapshot.checksum):
        raise HALeaseError("The staged lease checksum does not match Kaya's validated snapshot.")
    now = datetime.utcnow()
    if status == "APPLIED":
        snapshot.status = "STAGED"
        snapshot.staged_at = now
        state.status = "CURRENT"
        state.applied_generation = generation
        state.difference_count = 0
        state.last_applied_at = now
        state.last_error_redacted = None
        node.lease_generation = generation
    else:
        snapshot.status = "FAILED"
        state.status = "ERROR"
        state.last_error_redacted = message[:1000]


def latest_snapshot_summary(cluster: HACluster) -> dict[str, Any] | None:
    if not cluster.lease_snapshots:
        return None
    snapshot = max(cluster.lease_snapshots, key=lambda item: item.generation)
    try:
        validation = json.loads(snapshot.validation_summary_json or "{}")
    except json.JSONDecodeError:
        validation = {}
    return {"generation": snapshot.generation, "status": snapshot.status, "checksum": snapshot.checksum[:12], "lease_count": snapshot.lease_count, "created_at": snapshot.created_at, "staged_at": snapshot.staged_at, "reservation_count": validation.get("reservation_count", 0), "range": validation.get("range")}
