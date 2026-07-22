from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.core.security import encrypt_secret
from app.models.models import HABackup, HACluster, HADriftItem, HANode, HASyncRun, User
from app.services.dns_providers import PiHoleProvider
from app.services.ha_validation import GROUP_LABELS, HIGH_RISK_GROUPS, _safe_configuration, connection_for_node


WRITABLE_CONFIGURATION_GROUPS = {"filtering", "groups", "clients", "local_dns", "cname", "upstream_dns", "dhcp"}
COLLECTION_RECONCILIATION_GROUPS = {"filtering", "groups", "clients"}
GROUP_EXPLANATIONS = {
    "filtering": "Subscribed block/allow lists and the domains that Pi-hole allows or blocks.",
    "groups": "Pi-hole groups used to organise filtering rules for different devices.",
    "clients": "Known Pi-hole clients and the filtering groups assigned to them.",
    "local_dns": "Local host names and the IP addresses they resolve to on your network.",
    "cname": "Local DNS aliases that point one name at another name.",
    "upstream_dns": "The external DNS servers and conditional forwarding rules Pi-hole uses.",
    "dhcp": "DHCP range and reservation settings. DHCP on/off state and active leases are not copied.",
}


class HASyncError(ValueError):
    pass


class HAStaleSyncPlanError(HASyncError):
    def __init__(self, changed_groups: list[str]):
        self.changed_groups = sorted(changed_groups)
        labels = [GROUP_LABELS.get(key, key.replace("_", " ").title()) for key in self.changed_groups]
        super().__init__("Live configuration changed in: " + ", ".join(labels) + ". Review the refreshed plan before synchronising.")


def _checksum(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _snapshot(node: HANode) -> dict[str, Any]:
    try:
        value = json.loads(node.configuration_snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise HASyncError(f"{node.display_name} has no valid configuration snapshot. Run validation first.") from exc
    if not isinstance(value, dict) or not value:
        raise HASyncError(f"{node.display_name} has no configuration snapshot. Run validation first.")
    return value


def _without_dhcp_activation(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_dhcp_activation(item)
            for key, item in value.items()
            if str(key).casefold().replace("-", "_") not in {"active", "enabled"}
        }
    if isinstance(value, list):
        return [_without_dhcp_activation(item) for item in value]
    return value


def _sync_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Exclude runtime ownership from milestone-6 configuration synchronisation."""
    return {
        key: _without_dhcp_activation(value) if key == "dhcp" else value
        for key, value in snapshot.items()
    }


def _canonical_sync_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    value = _sync_snapshot(snapshot)
    groups_value = value.get("groups") if isinstance(value.get("groups"), dict) else {}
    group_rows = groups_value.get("groups") if isinstance(groups_value.get("groups"), list) else []
    group_names = {str(row.get("id")): str(row.get("name")) for row in group_rows if isinstance(row, dict) and row.get("id") is not None and row.get("name")}

    def memberships(row: dict[str, Any]) -> list[str]:
        return sorted(group_names.get(str(item), str(item)) for item in row.get("groups", []))

    canonical = {key: item for key, item in value.items() if key not in COLLECTION_RECONCILIATION_GROUPS}
    canonical["groups"] = {"groups": sorted(
        ({"name": str(row.get("name")), "comment": row.get("comment") or "", "enabled": bool(row.get("enabled", True))} for row in group_rows if isinstance(row, dict) and row.get("name")),
        key=lambda row: row["name"],
    )}
    clients_value = value.get("clients") if isinstance(value.get("clients"), dict) else {}
    client_rows = clients_value.get("clients") if isinstance(clients_value.get("clients"), list) else []
    canonical["clients"] = {"clients": sorted(
        ({"client": str(row.get("client")), "comment": row.get("comment") or "", "groups": memberships(row)} for row in client_rows if isinstance(row, dict) and row.get("client")),
        key=lambda row: row["client"],
    )}
    filtering = value.get("filtering") if isinstance(value.get("filtering"), dict) else {}
    lists_wrapper = filtering.get("lists") if isinstance(filtering.get("lists"), dict) else {}
    list_rows = lists_wrapper.get("lists") if isinstance(lists_wrapper.get("lists"), list) else []
    domains_wrapper = filtering.get("domains") if isinstance(filtering.get("domains"), dict) else {}
    domain_rows = domains_wrapper.get("domains") if isinstance(domains_wrapper.get("domains"), list) else []
    canonical["filtering"] = {
        "lists": {"lists": sorted((
            {"address": str(row.get("address")), "type": str(row.get("type") or "block"), "comment": row.get("comment") or "", "enabled": bool(row.get("enabled", True)), "groups": memberships(row)}
            for row in list_rows if isinstance(row, dict) and row.get("address")
        ), key=lambda row: (row["type"], row["address"]))},
        "domains": {"domains": sorted((
            {"domain": str(row.get("domain")), "type": str(row.get("type") or "allow"), "kind": str(row.get("kind") or "exact"), "comment": row.get("comment") or "", "enabled": bool(row.get("enabled", True)), "groups": memberships(row)}
            for row in domain_rows if isinstance(row, dict) and row.get("domain")
        ), key=lambda row: (row["type"], row["kind"], row["domain"]))},
    }
    return canonical


def _collection_identities(group: str, value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    if group in {"groups", "clients"}:
        key = group
        identity = "name" if group == "groups" else "client"
        rows = value.get(key)
        return {str(row.get(identity)) for row in rows or [] if isinstance(row, dict) and row.get(identity)}
    if group == "filtering":
        identities = set()
        lists_value = value.get("lists") if isinstance(value.get("lists"), dict) else {}
        for row in lists_value.get("lists") or []:
            if isinstance(row, dict) and row.get("address"):
                identities.add(f"list:{row.get('type', 'block')}:{row['address']}")
        domains_value = value.get("domains") if isinstance(value.get("domains"), dict) else {}
        for row in domains_value.get("domains") or []:
            if isinstance(row, dict) and row.get("domain"):
                identities.add(f"domain:{row.get('type', 'allow')}:{row.get('kind', 'exact')}:{row['domain']}")
        return identities
    return set()


def authority_and_target(cluster: HACluster) -> tuple[HANode, HANode]:
    if len(cluster.nodes) != 2:
        raise HASyncError("Exactly two nodes are required for synchronisation.")
    source = next((node for node in cluster.nodes if node.id == cluster.authoritative_node_id), None)
    if source is None:
        raise HASyncError("Choose an authoritative node before synchronising configuration.")
    target = next(node for node in cluster.nodes if node.id != source.id)
    return source, target


def sync_plan(cluster: HACluster) -> dict[str, Any]:
    source, target = authority_and_target(cluster)
    raw_source_snapshot = _snapshot(source)
    source_snapshot = _canonical_sync_snapshot(raw_source_snapshot)
    target_snapshot = _canonical_sync_snapshot(_snapshot(target))
    groups = []
    for key in sorted(set(source_snapshot) | set(target_snapshot)):
        source_value, target_value = source_snapshot.get(key), target_snapshot.get(key)
        if source_value == target_value:
            continue
        writable = key in WRITABLE_CONFIGURATION_GROUPS
        deletion_count = len(_collection_identities(key, target_value) - _collection_identities(key, source_value))
        groups.append({
            "key": key,
            "label": GROUP_LABELS.get(key, key.replace("_", " ").title()),
            "risk": "high" if key in HIGH_RISK_GROUPS else "medium" if key in COLLECTION_RECONCILIATION_GROUPS else "low",
            "writable": writable,
            "source_checksum": _checksum(source_value),
            "target_checksum": _checksum(target_value),
            "message": "Ready for guarded item reconciliation." if key in COLLECTION_RECONCILIATION_GROUPS else "Ready for guarded Pi-hole configuration patch." if writable else "This configuration group is not supported.",
            "description": GROUP_EXPLANATIONS.get(key, "A supported Pi-hole configuration area."),
            "deletion_count": deletion_count,
        })
    dhcp_value = raw_source_snapshot.get("dhcp")
    dhcp_text = json.dumps(dhcp_value, sort_keys=True).casefold() if dhcp_value is not None else ""
    dhcp_mode = "PIHOLE_MANAGED" if '"active": true' in dhcp_text or '"enabled": true' in dhcp_text else "EXTERNAL" if dhcp_value is not None else "UNKNOWN"
    return {
        "source_node_id": source.id,
        "source_name": source.display_name,
        "target_node_id": target.id,
        "target_name": target.display_name,
        "groups": groups,
        "blocked_groups": [item["key"] for item in groups if not item["writable"]],
        "deletion_count": sum(item["deletion_count"] for item in groups),
        "lease_replication": False,
        "dhcp_mode": dhcp_mode,
    }


def create_sync_plan(db: Session, cluster: HACluster, user: User | None = None) -> HASyncRun:
    plan = sync_plan(cluster)
    run = HASyncRun(
        cluster_id=cluster.id,
        source_node_id=plan["source_node_id"],
        target_node_id=plan["target_node_id"],
        status="PLANNED" if plan["groups"] else "IN_SYNC",
        plan_json=json.dumps(plan, sort_keys=True, separators=(",", ":")),
        created_by_user_id=user.id if user else None,
        completed_at=datetime.utcnow() if not plan["groups"] else None,
    )
    db.add(run)
    db.flush()
    for item in plan["groups"]:
        db.add(HADriftItem(
            sync_run_id=run.id,
            group_key=item["key"],
            risk=item["risk"],
            status="BLOCKED" if not item["writable"] else "DRIFT",
            source_checksum=item["source_checksum"],
            target_checksum=item["target_checksum"],
            message=item["message"],
        ))
    db.commit()
    db.refresh(run)
    return run


def _live_configuration(node: HANode, client_factory: Callable = PiHoleProvider) -> tuple[PiHoleProvider, dict[str, Any]]:
    connection = connection_for_node(node)
    if connection is None:
        raise HASyncError(f"{node.display_name} has no usable provider connection.")
    client = client_factory(connection)
    result = client.get_ha_configuration()
    if not result.ok or not isinstance(result.data, dict):
        raise HASyncError(f"Could not read {node.display_name} before synchronisation: {result.message}")
    raw = result.data.get("configuration")
    if not isinstance(raw, dict):
        raise HASyncError(f"{node.display_name} returned no supported configuration.")
    return client, {key: _safe_configuration(value) for key, value in raw.items() if key in GROUP_LABELS}


def create_live_sync_plan(
    db: Session,
    cluster: HACluster,
    user: User | None = None,
    *,
    client_factory: Callable = PiHoleProvider,
) -> HASyncRun:
    """Refresh both read-only snapshots before creating a plan the user can review."""
    source, target = authority_and_target(cluster)
    for node in (source, target):
        _, configuration = _live_configuration(node, client_factory)
        snapshot = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
        node.configuration_snapshot_json = snapshot
        node.configuration_checksum = hashlib.sha256(snapshot.encode()).hexdigest()
    db.commit()
    return create_sync_plan(db, cluster, user)


def execute_sync(db: Session, cluster: HACluster, run: HASyncRun, *, allow_deletions: bool = False, client_factory: Callable = PiHoleProvider) -> HASyncRun:
    if run.cluster_id != cluster.id or run.status != "PLANNED":
        raise HASyncError("This synchronisation plan is no longer executable.")
    if cluster.status != "HEALTHY" or cluster.keepalived_status != "DEPLOYED":
        raise HASyncError("The cluster must be healthy and Keepalived deployed before synchronisation.")
    plan = json.loads(run.plan_json)
    if plan.get("blocked_groups"):
        raise HASyncError("Resolve collection drift before applying this Beta synchronisation plan: " + ", ".join(plan["blocked_groups"]))
    if plan.get("deletion_count") and not allow_deletions:
        raise HASyncError("This plan contains deletions. Review the plan and explicitly confirm them before applying.")
    source = db.get(HANode, run.source_node_id)
    target = db.get(HANode, run.target_node_id)
    if source is None or target is None or cluster.authoritative_node_id != source.id:
        raise HASyncError("The authoritative node changed; create a new plan.")

    run.status = "RUNNING"
    run.started_at = datetime.utcnow()
    db.commit()
    applied: list[str] = []
    target_before: dict[str, Any] = {}
    target_client = None
    collections_applied = False
    try:
        _, source_live_raw = _live_configuration(source, client_factory)
        target_client, target_before_raw = _live_configuration(target, client_factory)
        source_live = _canonical_sync_snapshot(source_live_raw)
        target_before = _canonical_sync_snapshot(target_before_raw)
        source_apply = _sync_snapshot(source_live_raw)
        target_rollback = _sync_snapshot(target_before_raw)
        planned = {item["key"]: item for item in plan["groups"]}
        planned_keys = set(planned)
        changed_after_plan = [
            key for key, item in planned.items()
            if _checksum(source_live.get(key)) != item["source_checksum"]
            or _checksum(target_before.get(key)) != item["target_checksum"]
        ]
        if changed_after_plan:
            raise HAStaleSyncPlanError(changed_after_plan)
        backup_text = json.dumps(target_before_raw, sort_keys=True, separators=(",", ":"))
        backup = HABackup(
            sync_run_id=run.id,
            node_id=target.id,
            encrypted_snapshot=encrypt_secret(backup_text),
            checksum=hashlib.sha256(backup_text.encode()).hexdigest(),
        )
        db.add(backup)
        db.commit()  # The encrypted last-known-good backup must exist before any provider write.

        collection_keys = planned_keys & COLLECTION_RECONCILIATION_GROUPS
        if collection_keys:
            collections_applied = True  # A failed reconciliation may still have completed earlier item writes.
            result = target_client.reconcile_ha_collections(source_apply, allow_deletions=allow_deletions)
            if not result.ok:
                raise HASyncError(result.message)
            applied.extend(sorted(collection_keys))
        for key in sorted(planned_keys - COLLECTION_RECONCILIATION_GROUPS):
            result = target_client.apply_ha_configuration_group(key, source_apply.get(key))
            if not result.ok:
                raise HASyncError(result.message)
            applied.append(key)
        _, verified_raw = _live_configuration(target, client_factory)
        verified = _canonical_sync_snapshot(verified_raw)
        failed = [key for key in planned_keys if verified.get(key) != source_live.get(key)]
        if failed:
            raise HASyncError("Verification failed for: " + ", ".join(sorted(failed)))

        snapshot = json.dumps(verified_raw, sort_keys=True, separators=(",", ":"))
        target.configuration_snapshot_json = snapshot
        target.configuration_checksum = hashlib.sha256(snapshot.encode()).hexdigest()
        target.last_sync_at = datetime.utcnow()
        cluster.desired_sync_generation += 1
        run.status = "SUCCEEDED"
        run.completed_at = datetime.utcnow()
        for item in run.drift_items:
            item.status = "RESOLVED"
        db.commit()
        return run
    except Exception as exc:
        rollback_failed = False
        if target_client is not None:
            if collections_applied:
                result = target_client.reconcile_ha_collections(target_rollback, allow_deletions=True)
                rollback_failed = rollback_failed or not result.ok
            for key in reversed([item for item in applied if item not in COLLECTION_RECONCILIATION_GROUPS]):
                result = target_client.apply_ha_configuration_group(key, target_rollback.get(key))
                rollback_failed = rollback_failed or not result.ok
        run.status = "FAILED" if rollback_failed or not applied else "ROLLED_BACK"
        run.error_redacted = str(exc)[:1000]
        run.completed_at = datetime.utcnow()
        db.commit()
        if isinstance(exc, HASyncError):
            raise
        raise HASyncError("Synchronisation failed; the target was restored from its last-known-good backup.") from exc
