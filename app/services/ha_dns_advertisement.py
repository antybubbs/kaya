from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Interface
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAEvent, HANode
from app.services.dns_providers import PiHoleProvider
from app.services.ha_topology import advertised_dns_addresses, pihole_manages_dhcp
from app.services.ha_validation import connection_for_node, probe_dns


OPTION_6 = re.compile(
    r"^\s*dhcp-option(?:-force)?\s*=\s*(?:(?:tag:[^,\s]+|set:[^,\s]+)\s*,\s*)?(?:6|option:dns-server)(?:\s*,|$)",
    re.IGNORECASE,
)
SNAPSHOT_KEY = "_ha_dhcp_dns_advertisement"
WARNING_MESSAGE = (
    "DHCP is not advertising the HA DNS configuration. Existing clients may lose DNS "
    "during a node failure until their DHCP lease is renewed."
)


class HADNSAdvertisementError(ValueError):
    pass


@dataclass(frozen=True)
class DNSAdvertisementState:
    node_id: int
    node_name: str
    expected: tuple[str, str] | None
    observed: tuple[str, ...]
    configured_lines: tuple[str, ...]
    matches: bool
    error: str | None = None
    checked: bool = True


def _dnsmasq_lines(value: Any) -> list[str]:
    """Extract only the supported string array from a Pi-hole v6 response."""
    if isinstance(value, dict):
        direct = value.get("dnsmasq_lines")
        if isinstance(direct, list):
            return [line for line in direct if isinstance(line, str)]
        for key in ("config", "misc"):
            nested = value.get(key)
            if isinstance(nested, dict):
                result = _dnsmasq_lines(nested)
                if result or "dnsmasq_lines" in nested:
                    return result
    return []


def _option_6_addresses(line: str) -> tuple[str, ...]:
    if not OPTION_6.match(line):
        return ()
    values = line.split("=", 1)[1].split(",")
    start = next(
        (index for index, value in enumerate(values) if value.strip().casefold() in {"6", "option:dns-server"}),
        -1,
    )
    if start < 0:
        return ()
    addresses: list[str] = []
    for value in values[start + 1 :]:
        candidate = value.strip()
        try:
            addresses.append(str(IPv4Address(candidate)))
        except ValueError:
            continue
    return tuple(addresses)


def generated_dnsmasq_lines(existing: list[str], expected: tuple[str, str]) -> list[str]:
    """Preserve unrelated custom lines and install exactly one IPv4 Option 6."""
    primary, secondary = (str(IPv4Address(value)) for value in expected)
    if primary == secondary:
        raise HADNSAdvertisementError("The DNS Virtual IP and standby address must be different.")
    retained = [
        line.strip()
        for line in existing
        if isinstance(line, str) and line.strip() and not OPTION_6.match(line)
    ]
    generated = f"dhcp-option=6,{primary},{secondary}"
    if len(retained) >= 256:
        raise HADNSAdvertisementError("Pi-hole has too many custom dnsmasq lines to add the HA DNS advertisement safely.")
    return [*retained, generated]


def _validate_topology(cluster: HACluster) -> None:
    if not pihole_manages_dhcp(cluster):
        raise HADNSAdvertisementError("DHCP DNS advertisement is only managed for DNS + DHCP clusters.")
    if len(cluster.nodes) != 2 or not cluster.virtual_ip or cluster.prefix_length is None:
        raise HADNSAdvertisementError("The cluster requires two nodes and a DNS Virtual IP.")
    network = IPv4Interface(f"{cluster.virtual_ip}/{cluster.prefix_length}").network
    addresses: list[IPv4Address] = []
    for node in cluster.nodes:
        try:
            address = IPv4Address(node.management_host or "")
        except ValueError as exc:
            raise HADNSAdvertisementError(f"{node.display_name} must use an IPv4 management address.") from exc
        if address not in network:
            raise HADNSAdvertisementError(f"{node.display_name} is not on the DNS Virtual IP subnet.")
        addresses.append(address)
    if len(set(addresses + [IPv4Address(cluster.virtual_ip)])) != 3:
        raise HADNSAdvertisementError("The DNS Virtual IP and both node addresses must be unique.")


def _dhcp_active(value: Any) -> bool | None:
    if isinstance(value, dict):
        dhcp = value.get("dhcp")
        if isinstance(dhcp, dict):
            for key in ("active", "enabled"):
                if isinstance(dhcp.get(key), bool):
                    return dhcp[key]
            nested_dhcp = _dhcp_active(dhcp)
            if nested_dhcp is not None:
                return nested_dhcp
        for key in ("configuration", "config"):
            nested = value.get(key)
            result = _dhcp_active(nested)
            if result is not None:
                return result
    return None


def _client(node: HANode, client_factory: Callable = PiHoleProvider):
    connection = connection_for_node(node)
    if connection is None:
        raise HADNSAdvertisementError(f"{node.display_name} has no usable Pi-hole connection.")
    return client_factory(connection)


def inspect_dns_advertisement(cluster: HACluster, *, client_factory: Callable = PiHoleProvider) -> list[DNSAdvertisementState]:
    if not pihole_manages_dhcp(cluster):
        return []
    states: list[DNSAdvertisementState] = []
    for node in cluster.nodes:
        expected = advertised_dns_addresses(cluster, node)
        try:
            result = _client(node, client_factory).get_ha_dhcp_dns_advertisement()
            if not result.ok:
                raise HADNSAdvertisementError(result.message)
            lines = _dnsmasq_lines(result.data)
            observed = tuple(address for line in lines for address in _option_6_addresses(line))
            states.append(DNSAdvertisementState(
                node.id,
                node.display_name,
                expected,
                observed,
                tuple(lines),
                expected is not None and observed == expected,
            ))
        except Exception as exc:
            states.append(DNSAdvertisementState(
                node.id,
                node.display_name,
                expected,
                (),
                (),
                False,
                str(exc)[:500],
            ))
    return states


def cached_dns_advertisement(cluster: HACluster) -> list[DNSAdvertisementState]:
    if not pihole_manages_dhcp(cluster):
        return []
    states: list[DNSAdvertisementState] = []
    for node in cluster.nodes:
        expected = advertised_dns_addresses(cluster, node)
        payload: dict[str, Any] = {}
        try:
            payload = json.loads(node.configuration_snapshot_json or "{}")
        except (TypeError, json.JSONDecodeError):
            pass
        stored = payload.get(SNAPSHOT_KEY) if isinstance(payload, dict) else None
        observed = tuple(stored.get("observed") or ()) if isinstance(stored, dict) else ()
        error = str(stored.get("error"))[:500] if isinstance(stored, dict) and stored.get("error") else None
        states.append(DNSAdvertisementState(
            node.id,
            node.display_name,
            expected,
            observed,
            tuple(stored.get("configured_lines") or ()) if isinstance(stored, dict) else (),
            expected is not None and observed == expected,
            error,
            isinstance(stored, dict),
        ))
    return states


def cache_dns_advertisement(node: HANode, state: DNSAdvertisementState) -> None:
    try:
        snapshot = json.loads(node.configuration_snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        snapshot = {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    snapshot[SNAPSHOT_KEY] = {
        "observed": list(state.observed),
        "configured_lines": list(state.configured_lines),
        "matches": state.matches,
        "error": state.error,
        "checked_at": datetime.utcnow().isoformat(),
    }
    node.configuration_snapshot_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))


def preserve_cached_dns_advertisement(node: HANode, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Keep HA-owned observation metadata when ordinary sync refreshes a snapshot."""
    try:
        existing = json.loads(node.configuration_snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        existing = {}
    preserved = existing.get(SNAPSHOT_KEY) if isinstance(existing, dict) else None
    return {**snapshot, **({SNAPSHOT_KEY: preserved} if isinstance(preserved, dict) else {})}


def repair_dns_advertisement(
    db: Session,
    cluster: HACluster,
    *,
    client_factory: Callable = PiHoleProvider,
    dns_probe: Callable[[str], tuple[bool, str]] = probe_dns,
) -> list[DNSAdvertisementState]:
    """Install node-specific, VIP-first Option 6 with rollback and read-back."""
    _validate_topology(cluster)
    owners = [node for node in cluster.nodes if node.vip_owned]
    dhcp_reporters = [node for node in cluster.nodes if node.dhcp_running]
    if cluster.keepalived_status == "DEPLOYED" and (
        len(owners) != 1 or len(dhcp_reporters) != 1 or owners[0].id != dhcp_reporters[0].id
    ):
        raise HADNSAdvertisementError(
            "Repair is blocked until exactly one node owns the Virtual IP and that same node reports DHCP active."
        )
    original_owner_id = owners[0].id if len(owners) == 1 else None
    clients: dict[int, Any] = {}
    before: dict[int, list[str]] = {}
    applied: list[HANode] = []
    try:
        for node in cluster.nodes:
            client = _client(node, client_factory)
            clients[node.id] = client
            result = client.get_ha_dhcp_dns_advertisement()
            if not result.ok:
                raise HADNSAdvertisementError(f"Could not read {node.display_name}: {result.message}")
            before[node.id] = _dnsmasq_lines(result.data)

        # Configure the non-owner first so the active DHCP service is touched last.
        ordered = sorted(cluster.nodes, key=lambda node: bool(node.vip_owned))
        for node in ordered:
            expected = advertised_dns_addresses(cluster, node)
            if expected is None:
                raise HADNSAdvertisementError(f"Could not determine the DNS advertisement for {node.display_name}.")
            generated = generated_dnsmasq_lines(before[node.id], expected)
            result = clients[node.id].apply_ha_dhcp_dns_advertisement(generated)
            if not result.ok:
                raise HADNSAdvertisementError(f"{node.display_name} rejected the generated DHCP DNS advertisement: {result.message}")
            applied.append(node)

        states = inspect_dns_advertisement(cluster, client_factory=client_factory)
        failed = [state.node_name for state in states if not state.matches]
        if failed:
            raise HADNSAdvertisementError("Read-back verification failed for: " + ", ".join(failed) + ".")
        live_dhcp: dict[int, bool | None] = {}
        for node in cluster.nodes:
            configuration = clients[node.id].get_ha_configuration()
            live_dhcp[node.id] = _dhcp_active(configuration.data) if configuration.ok else None
        if original_owner_id is not None and (
            live_dhcp.get(original_owner_id) is not True
            or any(active is True for node_id, active in live_dhcp.items() if node_id != original_owner_id)
        ):
            raise HADNSAdvertisementError(
                "Post-repair verification could not confirm DHCP active only on the Virtual IP owner."
            )
        if original_owner_id is not None and not next(node for node in cluster.nodes if node.id == original_owner_id).vip_owned:
            raise HADNSAdvertisementError("The Virtual IP owner changed during repair.")
        unhealthy = [node.display_name for node in cluster.nodes if not dns_probe(node.management_host or "")[0]]
        if unhealthy:
            raise HADNSAdvertisementError("DNS health verification failed for: " + ", ".join(unhealthy) + ".")
    except Exception as exc:
        rollback_failures: list[str] = []
        for node in reversed(applied):
            result = clients[node.id].apply_ha_dhcp_dns_advertisement(before[node.id])
            if not result.ok:
                rollback_failures.append(node.display_name)
        if rollback_failures:
            raise HADNSAdvertisementError(
                "Repair failed and rollback could not be confirmed for: "
                + ", ".join(rollback_failures)
                + ". Check Pi-hole before retrying."
            ) from exc
        if isinstance(exc, HADNSAdvertisementError):
            raise
        raise HADNSAdvertisementError("Pi-hole DNS advertisement repair failed and prior settings were restored.") from exc

    for state in states:
        node = next(node for node in cluster.nodes if node.id == state.node_id)
        cache_dns_advertisement(node, state)
    db.add(HAEvent(
        cluster_id=cluster.id,
        event_type="dhcp_dns_advertisement_repaired",
        severity="info",
        source="kaya",
        message="DHCP now advertises the DNS Virtual IP first and each node's peer address second.",
        details_json_redacted=json.dumps({"verified": True, "nodes": len(states)}, sort_keys=True),
        occurred_at=datetime.utcnow(),
    ))
    db.commit()
    return states
