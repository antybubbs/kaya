from __future__ import annotations

import hashlib
import json
import socket
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAHealthCheck, HANode
from app.services.dns_providers import DNSProviderResult, PiHoleProvider


GROUP_LABELS = {
    "filtering": "Filtering",
    "groups": "Groups",
    "clients": "Clients",
    "local_dns": "Local DNS",
    "cname": "CNAME",
    "upstream_dns": "Upstream DNS",
    "dhcp": "DHCP scope and reservations",
}
HIGH_RISK_GROUPS = {"upstream_dns", "dhcp"}
FORBIDDEN_KEYS = {
    "password",
    "passwd",
    "secret",
    "sid",
    "session",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "certificate",
}
NODE_SPECIFIC_KEYS = {
    "hostname",
    "host_name",
    "interface",
    "interface_name",
    "management_ip",
    "management_host",
    "path",
    "pidfile",
    "socket",
    "took",
}
SECRET_KEY_MARKERS = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "certificate", "session", "sid")


@dataclass(frozen=True)
class PiHoleConnectionAdapter:
    id: str
    base_url: str
    auth_method: str
    encrypted_secret: str | None
    ssl_verify: bool
    timeout_seconds: int


@dataclass(frozen=True)
class ValidationFinding:
    node_id: int | None
    key: str
    status: str
    severity: str
    summary: str
    detail: str
    remediation: str | None = None


@dataclass(frozen=True)
class ConfigurationDifference:
    group_key: str
    group_label: str
    primary_value: str
    secondary_value: str
    proposed_value: str
    source_of_truth: str
    risk: str


def connection_for_node(node: HANode) -> PiHoleConnectionAdapter | None:
    if node.integration is not None:
        source = node.integration
        return PiHoleConnectionAdapter(
            id=f"dns-{source.id}",
            base_url=source.base_url,
            auth_method=source.auth_method,
            encrypted_secret=source.encrypted_secret,
            ssl_verify=source.ssl_verify,
            timeout_seconds=source.timeout_seconds,
        )
    if node.ha_connection is not None and node.ha_connection.deleted_at is None:
        source = node.ha_connection
        return PiHoleConnectionAdapter(
            id=f"ha-{source.id}",
            base_url=source.api_base_url,
            auth_method=source.auth_method,
            encrypted_secret=source.encrypted_secret,
            ssl_verify=source.ssl_verify,
            timeout_seconds=source.timeout_seconds,
        )
    return None


def probe_dns(host: str, timeout_seconds: float = 2.0) -> tuple[bool, str]:
    """Send a minimal read-only A query for pi.hole to UDP/53."""
    transaction_id = 0x4B41
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b"\x02pi\x04hole\x00" + struct.pack("!HH", 1, 1)
    last_error = "No DNS response was received."
    try:
        addresses = socket.getaddrinfo(host, 53, type=socket.SOCK_DGRAM)
    except OSError as exc:
        return False, f"DNS host resolution failed: {exc}."
    for family, socktype, protocol, _, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as client:
                client.settimeout(timeout_seconds)
                client.sendto(header + question, address)
                response, _ = client.recvfrom(512)
            if len(response) >= 12 and struct.unpack("!H", response[:2])[0] == transaction_id:
                return True, "The node answered a local DNS query on UDP port 53."
        except (OSError, TimeoutError) as exc:
            last_error = f"DNS query failed: {exc}."
    return False, last_error


def _safe_configuration(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            normalised_key = key.casefold().replace("-", "_")
            if normalised_key in FORBIDDEN_KEYS or any(marker in normalised_key for marker in SECRET_KEY_MARKERS) or normalised_key in NODE_SPECIFIC_KEYS:
                continue
            cleaned[key] = _safe_configuration(item)
        return {key: cleaned[key] for key in sorted(cleaned)}
    if isinstance(value, list):
        cleaned = [_safe_configuration(item) for item in value]
        return sorted(cleaned, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _version_from(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("version", "core", "ftl", "web"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip().lstrip("v")[:80]
            nested = _version_from(candidate)
            if nested:
                return nested
        for candidate in value.values():
            nested = _version_from(candidate)
            if nested:
                return nested
    return None


def _result_finding(node_id: int, key: str, result: DNSProviderResult, success: str, remediation: str) -> ValidationFinding:
    return ValidationFinding(
        node_id,
        key,
        "PASS" if result.ok else "FAIL",
        "info" if result.ok else "blocking",
        success if result.ok else result.message,
        result.message,
        None if result.ok else remediation,
    )


def _collect_node(
    node_id: int,
    host: str,
    connection: PiHoleConnectionAdapter | None,
    client_factory: Callable[[PiHoleConnectionAdapter], PiHoleProvider],
    dns_probe: Callable[[str], tuple[bool, str]],
) -> tuple[list[ValidationFinding], str | None, list[str], dict[str, Any]]:
    if connection is None:
        return [ValidationFinding(node_id, "connection", "FAIL", "blocking", "The provider connection is no longer available.", "No usable HA or DNS integration reference remains.", "Edit the node connection before validating again.")], None, [], {}
    client = client_factory(connection)
    authentication = client.test_connection()
    version_result = client.get_version()
    status_result = client.get_status()
    configuration_result = client.get_ha_configuration()
    leases_result = client.get_dhcp_leases()
    findings = [
        _result_finding(node_id, "api_authentication", authentication, "Pi-hole API authentication succeeded.", "Check the node URL and application password."),
        _result_finding(node_id, "ftl_service", status_result, "Pi-hole FTL status is readable.", "Confirm Pi-hole FTL is running and the API is reachable."),
    ]
    version = _version_from(version_result.data) if version_result.ok else None
    if version and version.split(".", 1)[0].isdigit() and int(version.split(".", 1)[0]) >= 6:
        findings.append(ValidationFinding(node_id, "provider_version", "PASS", "info", f"Pi-hole {version} is supported for Phase 1 validation.", version_result.message))
    elif version:
        findings.append(ValidationFinding(node_id, "provider_version", "FAIL", "blocking", f"Pi-hole {version} is outside the supported Phase 1 version range.", version_result.message, "Upgrade this node to Pi-hole 6 or later."))
    else:
        findings.append(ValidationFinding(node_id, "provider_version", "UNKNOWN", "blocking", "Kaya could not determine the Pi-hole version.", version_result.message, "Confirm the version endpoint is available and the credential has read access."))
    dns_ok, dns_detail = dns_probe(host)
    findings.append(ValidationFinding(node_id, "dns_response", "PASS" if dns_ok else "FAIL", "info" if dns_ok else "blocking", "Local DNS responded successfully." if dns_ok else "Local DNS did not respond.", dns_detail, None if dns_ok else "Confirm UDP port 53 is reachable and Pi-hole DNS is running."))

    configuration: dict[str, Any] = {}
    unavailable: dict[str, str] = {}
    if configuration_result.ok and isinstance(configuration_result.data, dict):
        raw_configuration = configuration_result.data.get("configuration")
        raw_unavailable = configuration_result.data.get("unavailable")
        if isinstance(raw_configuration, dict):
            configuration = {key: _safe_configuration(value) for key, value in raw_configuration.items() if key in GROUP_LABELS}
        if isinstance(raw_unavailable, dict):
            unavailable = {str(key): str(value) for key, value in raw_unavailable.items() if key in GROUP_LABELS}
    capabilities = sorted(configuration)
    if configuration:
        findings.append(ValidationFinding(node_id, "api_capabilities", "PASS" if not unavailable else "WARNING", "info" if not unavailable else "warning", f"Read-only configuration is available for {len(configuration)} of {len(GROUP_LABELS)} capability groups.", ", ".join(GROUP_LABELS[key] for key in capabilities), "Review unavailable API groups before deployment." if unavailable else None))
    else:
        findings.append(ValidationFinding(node_id, "api_capabilities", "FAIL", "blocking", "No supported configuration capability could be read.", configuration_result.message, "Check Pi-hole version, API permissions, and authentication."))
    dhcp_available = "dhcp" in configuration
    findings.append(ValidationFinding(node_id, "dhcp_configuration", "PASS" if dhcp_available else "UNKNOWN", "info" if dhcp_available else "blocking", "DHCP configuration is readable." if dhcp_available else "DHCP configuration could not be read.", unavailable.get("dhcp", configuration_result.message), None if dhcp_available else "Grant read access to the DHCP configuration endpoint before deployment."))
    findings.append(_result_finding(node_id, "dhcp_lease_access", leases_result, "DHCP lease data is readable.", "Confirm the DHCP lease endpoint is available to the Pi-hole application password."))
    return findings, version, capabilities, configuration


def run_live_validation(
    db: Session,
    cluster: HACluster,
    *,
    client_factory: Callable[[PiHoleConnectionAdapter], PiHoleProvider] = PiHoleProvider,
    dns_probe: Callable[[str], tuple[bool, str]] = probe_dns,
) -> list[HAHealthCheck]:
    node_inputs = [(node.id, node.management_host or "", connection_for_node(node)) for node in cluster.nodes]
    cluster_id = cluster.id
    db.rollback()  # End the read transaction before contacting either provider.
    collected = [
        (node_id, *_collect_node(node_id, host, connection, client_factory, dns_probe))
        for node_id, host, connection in node_inputs
    ]
    db.query(HAHealthCheck).filter(HAHealthCheck.cluster_id == cluster_id).delete(synchronize_session=False)
    findings: list[ValidationFinding] = []
    for node_id, node_findings, version, capabilities, configuration in collected:
        node = db.get(HANode, node_id)
        if node is None:
            continue
        findings.extend(node_findings)
        node.provider_version = version
        node.capabilities_json = json.dumps(capabilities, separators=(",", ":"))
        snapshot = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
        node.configuration_snapshot_json = snapshot
        node.configuration_checksum = hashlib.sha256(snapshot.encode()).hexdigest() if configuration else None
        node.last_health_at = datetime.utcnow()
        node.status = "VALIDATED" if not any(item.severity == "blocking" and item.status != "PASS" for item in node_findings) else "VALIDATION_FAILED"
    cluster_row = db.get(HACluster, cluster_id)
    if len(collected) != 2:
        findings.append(ValidationFinding(None, "node_count", "FAIL", "blocking", "Exactly two nodes are required.", f"Found {len(collected)} nodes.", "Return the cluster to draft configuration and add two unique nodes."))
    blocking = any(item.severity == "blocking" and item.status != "PASS" for item in findings)
    warning = any(item.status == "WARNING" for item in findings)
    if cluster_row is not None:
        cluster_row.status = "VALIDATION_FAILED" if blocking else "VALIDATED_WITH_WARNINGS" if warning else "VALIDATED"
        cluster_row.last_healthy_at = None if blocking else datetime.utcnow()
    rows = [
        HAHealthCheck(
            cluster_id=cluster_id,
            node_id=item.node_id,
            check_key=item.key,
            status=item.status,
            severity=item.severity,
            summary=item.summary,
            technical_detail_redacted=item.detail[:2000],
            remediation=item.remediation,
        )
        for item in findings
    ]
    db.add_all(rows)
    db.commit()
    return rows


def configuration_differences(cluster: HACluster) -> list[ConfigurationDifference]:
    nodes = sorted(cluster.nodes, key=lambda node: 0 if node.role == "ACTIVE" else 1)
    if len(nodes) != 2 or any(not node.configuration_snapshot_json for node in nodes):
        return []
    try:
        primary = json.loads(nodes[0].configuration_snapshot_json or "{}")
        secondary = json.loads(nodes[1].configuration_snapshot_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return []
    differences = []
    for group in sorted(set(primary) | set(secondary)):
        if primary.get(group) == secondary.get(group):
            continue
        primary_text = json.dumps(primary.get(group), sort_keys=True, ensure_ascii=False)
        secondary_text = json.dumps(secondary.get(group), sort_keys=True, ensure_ascii=False)
        differences.append(
            ConfigurationDifference(
                group,
                GROUP_LABELS.get(group, group.replace("_", " ").title()),
                primary_text[:4000],
                secondary_text[:4000],
                primary_text[:4000],
                nodes[0].display_name,
                "medium" if group in HIGH_RISK_GROUPS else "low",
            )
        )
    return differences
