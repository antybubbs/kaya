from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from sqlalchemy.orm import Session, defer, object_session

from app.core.security import decrypt_secret, encrypt_secret
from app.models.models import HACluster, HALeaseReplicationState, HALeaseSnapshot, HANode
from app.services.dns_providers import PiHoleProvider
from app.services.ha_sync import HASyncError, authority_and_target
from app.services.ha_validation import PiHoleConnectionAdapter, connection_for_node
from app.services.ha_topology import lease_continuity_enabled


MAX_LEASES = 10000
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


class HALeaseError(ValueError):
    pass


@dataclass(frozen=True)
class LeaseInspectionInputs:
    """Plain, session-independent data needed to inspect Pi-hole leases.

    Captured while `cluster` (and the `nodes`/`integration`/`ha_connection`
    relationships `prepare_lease_inspection` reads) are still attached to a
    live session. Holds no reference to any ORM object or session, so it is
    safe to use after the caller has released its database connection --
    letting the (potentially slow) Pi-hole network calls in
    `inspect_lease_plan` run without a PostgreSQL connection checked out.
    """

    source_id: int
    source_public_id: str
    target_id: int
    continuity_enabled: bool
    connection: PiHoleConnectionAdapter | None
    role_generation: int
    keepalived_generation: int
    cluster_generation: int


@dataclass(frozen=True)
class LeasePlan:
    applicable: bool
    source_id: int
    source_public_id: str
    target_id: int
    leases: list[dict[str, Any]]
    reservations: set[str]
    range_start: ipaddress.IPv4Address | None
    range_end: ipaddress.IPv4Address | None
    role_generation: int | None = None
    keepalived_generation: int | None = None
    cluster_generation: int | None = None


def _state(db: Session, cluster: HACluster) -> HALeaseReplicationState:
    row = cluster.lease_replication
    if row is None:
        row = HALeaseReplicationState(cluster_id=cluster.id)
        db.add(row)
        db.flush()
    return row


def _nodes(cluster: HACluster) -> tuple[HANode, HANode]:
    try:
        source, target, verified = authority_and_target(cluster)
    except HASyncError as exc:
        raise HALeaseError(str(exc)) from exc
    if not verified:
        raise HALeaseError("Kaya cannot verify one safe VIP owner for lease replication.")
    return source, target


def _revalidate_plan_authority(cluster: HACluster, plan: LeasePlan) -> None:
    source, target = _nodes(cluster)
    if (source.id, target.id) != (plan.source_id, plan.target_id):
        raise HALeaseError("Lease inspection authority changed before the snapshot was persisted.")
    if (
        plan.role_generation is not None
        and plan.keepalived_generation is not None
        and plan.cluster_generation is not None
        and (plan.role_generation, plan.keepalived_generation, plan.cluster_generation)
        != (cluster.role_generation, cluster.keepalived_generation, cluster.cluster_generation)
    ):
        raise HALeaseError("Lease inspection generation changed before the snapshot was persisted.")


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


def _material_checksum(payload: dict[str, Any]) -> str:
    """Checksum of the lease set alone: the same leases with only renewed expiry times match."""
    material = {**payload, "leases": [{key: value for key, value in lease.items() if key != "expires"} for lease in payload.get("leases", [])]}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _summary(snapshot: HALeaseSnapshot) -> dict[str, Any]:
    try:
        value = json.loads(snapshot.validation_summary_json or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def prepare_lease_inspection(cluster: HACluster) -> LeaseInspectionInputs:
    """Load everything `inspect_lease_plan` needs from `cluster`'s session.

    Must be called while `cluster.nodes` and the source node's
    `integration`/`ha_connection` relationships are still reachable on a
    live session. The returned value is plain data with no session ties,
    so a caller can release its database connection before performing the
    (potentially slow) Pi-hole network calls in `inspect_lease_plan`.
    """
    continuity_enabled = lease_continuity_enabled(cluster)
    if continuity_enabled:
        source, target = _nodes(cluster)
    else:
        if len(cluster.nodes) != 2:
            raise HALeaseError("Lease replication requires a standby Pi-hole.")
        source, target = cluster.nodes
    connection = connection_for_node(source) if continuity_enabled else None
    return LeaseInspectionInputs(
        source_id=source.id,
        source_public_id=source.public_id,
        target_id=target.id,
        continuity_enabled=continuity_enabled,
        connection=connection,
        role_generation=cluster.role_generation,
        keepalived_generation=cluster.keepalived_generation,
        cluster_generation=cluster.cluster_generation,
    )


def inspect_lease_plan(inputs: LeaseInspectionInputs, *, client_factory: Callable = PiHoleProvider) -> LeasePlan:
    """Perform the Pi-hole lease inspection using only plain, session-free data.

    This function touches no database session or connection -- it is safe
    to call after the session that produced `inputs` has been closed.
    """
    if not inputs.continuity_enabled:
        return LeasePlan(False, inputs.source_id, inputs.source_public_id, inputs.target_id, [], set(), None, None, inputs.role_generation, inputs.keepalived_generation, inputs.cluster_generation)
    if inputs.connection is None:
        raise HALeaseError("The main Pi-hole connection is unavailable.")
    client = client_factory(inputs.connection)
    configuration = client.get_ha_configuration()
    if not configuration.ok:
        raise HALeaseError(configuration.message)
    dhcp = _dhcp_payload(configuration.data)
    reservations = _reservation_ips(dhcp)
    range_start, range_end = _range(dhcp)
    if not _is_enabled(dhcp):
        return LeasePlan(False, inputs.source_id, inputs.source_public_id, inputs.target_id, [], reservations, range_start, range_end, inputs.role_generation, inputs.keepalived_generation, inputs.cluster_generation)
    if range_start is None or range_end is None:
        raise HALeaseError("Pi-hole DHCP is enabled, but Kaya could not validate its address range.")
    result = client.get_dhcp_leases()
    if not result.ok:
        raise HALeaseError(result.message)
    leases = normalise_leases(result.data, range_start=range_start, range_end=range_end, reservation_ips=reservations)
    return LeasePlan(True, inputs.source_id, inputs.source_public_id, inputs.target_id, leases, reservations, range_start, range_end, inputs.role_generation, inputs.keepalived_generation, inputs.cluster_generation)


def inspect_cluster_leases(cluster: HACluster, *, client_factory: Callable = PiHoleProvider) -> LeasePlan:
    """Inspect Pi-hole leases for `cluster` using its current session.

    Convenience wrapper combining `prepare_lease_inspection` and
    `inspect_lease_plan` for callers that already hold `cluster` inside a
    live, multi-purpose session -- e.g. failover/maintenance reconciliation
    and the admin "reconcile now" action -- where the database connection
    is already committed to being held for the duration of surrounding
    work, so splitting the two phases would buy nothing.
    """
    inputs = prepare_lease_inspection(cluster)
    return inspect_lease_plan(inputs, client_factory=client_factory)


def reconcile_cluster_leases(
    db: Session,
    cluster: HACluster,
    *,
    client_factory: Callable = PiHoleProvider,
    precomputed_inspection: LeasePlan | HALeaseError | None = None,
) -> HALeaseReplicationState:
    """Reconcile `cluster`'s lease-replication state against Pi-hole.

    By default this inspects Pi-hole itself (via `inspect_cluster_leases`),
    which holds `db`'s connection for the duration of that inspection.
    Callers that can perform inspection separately -- releasing their
    database connection first -- may pass the already-computed result (a
    `LeasePlan`, or the `HALeaseError` inspection raised) as
    `precomputed_inspection` to skip repeating the Pi-hole calls here and
    avoid holding `db`'s connection across them.
    """
    state = _state(db, cluster)
    now = datetime.utcnow()
    try:
        if precomputed_inspection is not None:
            if isinstance(precomputed_inspection, HALeaseError):
                raise precomputed_inspection
            plan = precomputed_inspection
        else:
            inputs = prepare_lease_inspection(cluster)
            db.commit()  # no transaction open during the Pi-hole calls
            plan = inspect_lease_plan(inputs, client_factory=client_factory)
        if plan.applicable:
            _revalidate_plan_authority(cluster, plan)
        state.source_node_id, state.target_node_id = plan.source_id, plan.target_id
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
        payload = {"version": 1, "cluster_id": cluster.public_id, "source_node_id": plan.source_public_id, "leases": plan.leases}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        checksum = hashlib.sha256(encoded.encode()).hexdigest()
        material_checksum = _material_checksum(payload)
        latest = db.query(HALeaseSnapshot).filter(HALeaseSnapshot.cluster_id == cluster.id).order_by(HALeaseSnapshot.generation.desc()).first()
        state.lease_count = len(plan.leases)
        state.difference_count = 0 if latest and latest.checksum == checksum else max(1, len(plan.leases), latest.lease_count if latest else 0)
        state.conflict_count = 0
        if latest and latest.checksum == checksum and latest.status in {"PENDING", "STAGED"}:
            state.status = "CURRENT" if latest.status == "STAGED" else "PENDING"
            db.commit()
            return state
        generation = max(state.desired_generation, latest.generation if latest else 0) + 1
        # Renewals still produce a new staged generation (the failover helper
        # writes staged expiry times into the lease file), but only a change to
        # the lease set itself advances the material generation that standby
        # readiness depends on.
        renewal_only = bool(latest and _summary(latest).get("material_checksum") == material_checksum)
        snapshot = HALeaseSnapshot(cluster_id=cluster.id, source_node_id=plan.source_id, target_node_id=plan.target_id, generation=generation, checksum=checksum, encrypted_payload=encrypt_secret(encoded), lease_count=len(plan.leases), status="PENDING", validation_summary_json=json.dumps({"range": f"{plan.range_start}-{plan.range_end}", "reservation_count": len(plan.reservations), "conflicts": 0, "material_checksum": material_checksum, "renewal_only": renewal_only}, sort_keys=True))
        db.add(snapshot)
        state.desired_generation = generation
        if not renewal_only or state.material_generation is None:
            state.material_generation = generation
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


def _snapshot_query(cluster: HACluster, *, include_payload: bool):
    """Query one cluster's snapshots without materialising its full history.

    Returns None only for an object with no session. Such an object cannot
    lazy-load, so callers fall back to whatever collection is already in
    memory; that fallback never issues a database query.
    """
    db = object_session(cluster)
    if db is None:
        return None
    query = db.query(HALeaseSnapshot).filter(HALeaseSnapshot.cluster_id == cluster.id)
    return query if include_payload else query.options(defer(HALeaseSnapshot.encrypted_payload))


def _snapshot_for_generation(cluster: HACluster, generation: int, *, include_payload: bool = False) -> HALeaseSnapshot | None:
    query = _snapshot_query(cluster, include_payload=include_payload)
    if query is None:
        return next((item for item in cluster.lease_snapshots if item.generation == generation), None)
    # uq_ha_lease_snapshot_generation guarantees at most one row.
    return query.filter(HALeaseSnapshot.generation == generation).one_or_none()


def desired_lease_action(cluster: HACluster, node: HANode) -> dict[str, Any] | None:
    state = cluster.lease_replication
    if state is None or state.status != "PENDING" or state.target_node_id != node.id:
        return None
    snapshot = _snapshot_for_generation(cluster, state.desired_generation)
    if snapshot is None or snapshot.status != "PENDING":
        return None
    return {"action_id": f"lease:{cluster.public_id}:{node.public_id}:{snapshot.generation}:{snapshot.checksum[:12]}", "action_type": "LEASE_SNAPSHOT_STAGE", "generation": snapshot.generation, "checksum": snapshot.checksum, "snapshot_path": f"/api/ha/agent/v1/lease-snapshot/{snapshot.generation}"}


def snapshot_for_agent(node: HANode, generation: int) -> dict[str, Any]:
    state = node.cluster.lease_replication
    if state is None or state.target_node_id != node.id or state.desired_generation != generation:
        raise HALeaseError("This lease snapshot is not assigned to this node.")
    snapshot = _snapshot_for_generation(node.cluster, generation, include_payload=True)
    if snapshot is None or snapshot.status != "PENDING":
        raise HALeaseError("The requested lease snapshot is unavailable.")
    payload = json.loads(decrypt_secret(snapshot.encrypted_payload))
    return {"generation": snapshot.generation, "checksum": snapshot.checksum, "payload": payload}


def record_lease_stage_result(db: Session, node: HANode, *, generation: int, checksum: str | None, status: str, message: str) -> None:
    state = node.cluster.lease_replication
    if state is None or state.target_node_id != node.id or state.desired_generation != generation:
        raise HALeaseError("The lease result does not match the target's current desired generation.")
    snapshot = _snapshot_for_generation(node.cluster, generation)
    if snapshot is None or (status == "APPLIED" and checksum != snapshot.checksum):
        raise HALeaseError("The staged lease checksum does not match Kaya's validated snapshot.")
    if status == "APPLIED":
        source, target = _nodes(node.cluster)
        if target.id != node.id or source.id == node.id:
            raise HALeaseError("Lease staging target is no longer the verified standby node.")
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
    query = _snapshot_query(cluster, include_payload=False)
    if query is None:
        snapshot = max(cluster.lease_snapshots, key=lambda item: item.generation, default=None)
    else:
        snapshot = query.order_by(HALeaseSnapshot.generation.desc()).limit(1).one_or_none()
    if snapshot is None:
        return None
    try:
        validation = json.loads(snapshot.validation_summary_json or "{}")
    except json.JSONDecodeError:
        validation = {}
    return {"generation": snapshot.generation, "status": snapshot.status, "checksum": snapshot.checksum[:12], "lease_count": snapshot.lease_count, "created_at": snapshot.created_at, "staged_at": snapshot.staged_at, "reservation_count": validation.get("reservation_count", 0), "range": validation.get("range")}
