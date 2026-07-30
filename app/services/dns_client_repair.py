"""SQLite repair for historical DNS logical-client duplication.

This module deliberately uses the DB-API cursor so the same repair can run from
the entrypoint migration and from application startup without loading ORM
models whose schema may be newer than the database being repaired.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


WEAK_IDENTITY_GAP = timedelta(hours=24)


def _columns(cur: Any, table: str) -> set[str]:
    return {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}


def _table(cur: Any, table: str) -> bool:
    return cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _normalise_mac(value: Any) -> str | None:
    compact = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-f]{12}", compact):
        return None
    mac = ":".join(compact[index:index + 2] for index in range(0, 12, 2))
    return None if mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} else mac


def _normalise_hostname(value: Any, ip: str | None) -> str | None:
    hostname = str(value or "").strip().rstrip(".").lower()
    return None if hostname in {"", "-", "unknown", "localhost", "none", "null", str(ip or "").lower()} else hostname


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return datetime.min


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _canonical_key(row: dict[str, Any], period_start: datetime | None = None) -> str:
    mac = _normalise_mac(row.get("normalised_mac") or row.get("mac_address"))
    provider_client_id = str(row.get("provider_client_id") or "").strip()
    if mac:
        return f"mac:{mac}"
    if provider_client_id:
        return f"provider-client:{_digest(provider_client_id)}"
    ip = str(row.get("current_ip") or "").strip()
    hostname = _normalise_hostname(row.get("normalised_hostname") or row.get("hostname"), ip)
    base = f"{hostname or '-'}|{ip or '-'}"
    anchor = (period_start or _dt(row.get("first_seen_at"))).date().isoformat()
    return f"weak:{_digest(base)}:{anchor}"


def _merge_history(cur: Any, table: str, survivor: int, duplicate: int, key_column: str) -> None:
    if not _table(cur, table):
        return
    rows = cur.execute(
        f"SELECT id, {key_column}, first_seen_at, last_seen_at, observation_count FROM {table} WHERE dns_client_id=?",
        (duplicate,),
    ).fetchall()
    for row_id, key, first_seen, last_seen, count in rows:
        existing = cur.execute(
            f"SELECT id, first_seen_at, last_seen_at, observation_count FROM {table} WHERE dns_client_id=? AND {key_column}=?",
            (survivor, key),
        ).fetchone()
        if existing:
            cur.execute(
                f"UPDATE {table} SET first_seen_at=MIN(COALESCE(first_seen_at, ?), ?), last_seen_at=MAX(COALESCE(last_seen_at, ?), ?), observation_count=COALESCE(observation_count,0)+? WHERE id=?",
                (first_seen, first_seen, last_seen, last_seen, int(count or 1), existing[0]),
            )
            cur.execute(f"DELETE FROM {table} WHERE id=?", (row_id,))
        else:
            cur.execute(f"UPDATE {table} SET dns_client_id=? WHERE id=?", (survivor, row_id))


def repair_dns_client_identities(dbapi_connection: Any) -> dict[str, int]:
    """Consolidate unambiguous legacy rows and enforce logical identity uniqueness."""
    cur = dbapi_connection.cursor()
    if not _table(cur, "dns_recognised_devices"):
        return {"before": 0, "after": 0, "merged": 0, "ambiguous": 0}
    if "identity_key" not in _columns(cur, "dns_recognised_devices"):
        cur.execute("ALTER TABLE dns_recognised_devices ADD COLUMN identity_key VARCHAR(128)")

    provider_clusters = {}
    if _table(cur, "dns_providers") and "ha_cluster_id" in _columns(cur, "dns_providers"):
        provider_clusters = {row[0]: row[1] for row in cur.execute("SELECT id, ha_cluster_id FROM dns_providers")}
    raw_rows = cur.execute("SELECT * FROM dns_recognised_devices ORDER BY id").fetchall()
    names = [item[0] for item in cur.description]
    rows = [dict(zip(names, row)) for row in raw_rows]
    before = len(rows)

    for row in rows:
        cluster_id = provider_clusters.get(row["provider_id"])
        row["logical_provider_key"] = f"ha-cluster:{cluster_id}" if cluster_id else f"provider:{row['provider_id']}"
        row["normalised_mac"] = _normalise_mac(row.get("normalised_mac") or row.get("mac_address"))
        row["normalised_hostname"] = _normalise_hostname(row.get("normalised_hostname") or row.get("hostname"), row.get("current_ip"))
        cur.execute(
            "UPDATE dns_recognised_devices SET logical_provider_key=?, normalised_mac=?, normalised_hostname=? WHERE id=?",
            (row["logical_provider_key"], row["normalised_mac"], row["normalised_hostname"], row["id"]),
        )

    # Preserve every legacy logical row as a raw sighting before consolidation.
    if _table(cur, "dns_client_observations"):
        for row in rows:
            if cur.execute("SELECT 1 FROM dns_client_observations WHERE dns_client_id=? LIMIT 1", (row["id"],)).fetchone():
                continue
            observation_key = hashlib.sha256(f"legacy-client-row:{row['id']}".encode()).hexdigest()
            cur.execute(
                "INSERT OR IGNORE INTO dns_client_observations (dns_client_id, provider_id, observation_key, ip_address, mac_address, hostname, logical_provider_key, source, source_member, observed_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'legacy identity repair', NULL, COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)",
                (row["id"], row["provider_id"], observation_key, row.get("current_ip"), row.get("normalised_mac"), row.get("hostname"), row["logical_provider_key"], row.get("last_seen_at")),
            )

    parent = {row["id"]: row["id"] for row in rows}

    def find(value: int) -> int:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: int, right: int) -> None:
        left, right = find(left), find(right)
        if left != right:
            parent[right] = left

    strong: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    weak: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["normalised_mac"]:
            strong[(row["logical_provider_key"], "mac", row["normalised_mac"])].append(row["id"])
        provider_client_id = str(row.get("provider_client_id") or "").strip()
        if provider_client_id:
            strong[(row["logical_provider_key"], "provider", provider_client_id)].append(row["id"])
        if row.get("current_ip"):
            weak[(row["logical_provider_key"], row.get("normalised_hostname") or "", row["current_ip"])].append(row)
    for ids in strong.values():
        for duplicate in ids[1:]:
            union(ids[0], duplicate)
    for candidates in weak.values():
        candidates.sort(key=lambda item: (_dt(item.get("first_seen_at") or item.get("last_seen_at")), item["id"]))
        windows: list[list[dict[str, Any]]] = []
        for row in candidates:
            seen = _dt(row.get("first_seen_at") or row.get("last_seen_at"))
            if not windows or seen - _dt(windows[-1][-1].get("last_seen_at") or windows[-1][-1].get("first_seen_at")) > WEAK_IDENTITY_GAP:
                windows.append([row])
            else:
                windows[-1].append(row)
        for window in windows:
            macs = {row["normalised_mac"] for row in window if row["normalised_mac"]}
            provider_ids = {str(row.get("provider_client_id") or "").strip() for row in window if row.get("provider_client_id")}
            if len(macs) <= 1 and len(provider_ids) <= 1:
                for duplicate in window[1:]:
                    union(window[0]["id"], duplicate["id"])

    components: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        components[find(row["id"])].append(row)
    merged = ambiguous = 0
    for component in components.values():
        if len(component) < 2:
            continue
        linked = {row.get("linked_ip_record_id") for row in component if row.get("linked_ip_record_id") is not None}
        if len(linked) > 1:
            ambiguous += len(component)
            continue
        component.sort(key=lambda row: (not bool(row.get("linked_ip_record_id")), not bool(row.get("is_known")), row["id"]))
        survivor = component[0]
        first_seen = min((_dt(row.get("first_seen_at")) for row in component), default=datetime.min)
        latest = max(component, key=lambda row: (_dt(row.get("last_seen_at")), row["id"]))
        mac = next((row["normalised_mac"] for row in component if row["normalised_mac"]), None)
        provider_client = next((row.get("provider_client_id") for row in component if row.get("provider_client_id")), None)
        hostname_row = next((row for row in reversed(sorted(component, key=lambda item: _dt(item.get("last_seen_at")))) if row.get("normalised_hostname")), latest)
        for duplicate in component[1:]:
            duplicate_id = duplicate["id"]
            _merge_history(cur, "dns_client_ip_history", survivor["id"], duplicate_id, "ip_address")
            _merge_history(cur, "dns_client_hostname_history", survivor["id"], duplicate_id, "normalised_hostname")
            for table in ("dns_client_observations", "dns_client_events", "dns_client_traffic_events", "dhcp_lease_history"):
                if _table(cur, table):
                    cur.execute(f"UPDATE {table} SET dns_client_id=? WHERE dns_client_id=?", (survivor["id"], duplicate_id))
            cur.execute("DELETE FROM dns_recognised_devices WHERE id=?", (duplicate_id,))
            merged += 1
        observation_count = cur.execute("SELECT COUNT(*) FROM dns_client_observations WHERE dns_client_id=?", (survivor["id"],)).fetchone()[0] if _table(cur, "dns_client_observations") else sum(int(row.get("observation_count") or 1) for row in component)
        survivor.update({"normalised_mac": mac, "provider_client_id": provider_client})
        cur.execute(
            "UPDATE dns_recognised_devices SET first_seen_at=?, last_seen_at=?, current_ip=?, hostname=?, normalised_hostname=?, mac_address=?, normalised_mac=?, provider_client_id=?, is_known=?, is_ignored=?, is_suppressed=?, linked_ip_record_id=COALESCE(linked_ip_record_id, ?), suggested_ip_record_id=COALESCE(suggested_ip_record_id, ?), hardware_asset_id=COALESCE(hardware_asset_id, ?), friendly_name=COALESCE(friendly_name, ?), notes=COALESCE(notes, ?), observation_count=? WHERE id=?",
            (first_seen if first_seen != datetime.min else None, latest.get("last_seen_at"), latest.get("current_ip"), hostname_row.get("hostname"), hostname_row.get("normalised_hostname"), mac, mac, provider_client, int(any(row.get("is_known") for row in component)), int(any(row.get("is_ignored") for row in component)), int(any(row.get("is_suppressed") for row in component)), next(iter(linked), None), next((row.get("suggested_ip_record_id") for row in component if row.get("suggested_ip_record_id")), None), next((row.get("hardware_asset_id") for row in component if row.get("hardware_asset_id")), None), next((row.get("friendly_name") for row in component if row.get("friendly_name")), None), next((row.get("notes") for row in component if row.get("notes")), None), observation_count, survivor["id"]),
        )

    survivors = cur.execute("SELECT * FROM dns_recognised_devices ORDER BY id").fetchall()
    names = [item[0] for item in cur.description]
    used: set[tuple[str, str]] = set()
    for values in survivors:
        row = dict(zip(names, values))
        key = _canonical_key(row)
        pair = (row["logical_provider_key"], key)
        if pair in used:
            key = f"{key}:conflict:{row['id']}"
            ambiguous += 1
        used.add((row["logical_provider_key"], key))
        cur.execute("UPDATE dns_recognised_devices SET identity_key=? WHERE id=?", (key, row["id"]))
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_dns_devices_logical_identity ON dns_recognised_devices (logical_provider_key, identity_key)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_dns_recognised_devices_identity_key ON dns_recognised_devices (identity_key)")
    return {"before": before, "after": before - merged, "merged": merged, "ambiguous": ambiguous}
