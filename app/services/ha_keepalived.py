import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Interface

from sqlalchemy.orm import Session

from app.models.models import HACluster, HANode


INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
KEEPALIVED_HOOK = "/usr/lib/kaya-ha-agent/kaya_ha_transition.py"


class HAKeepalivedError(ValueError):
    pass


@dataclass(frozen=True)
class KeepalivedConfig:
    content: str
    checksum: str


def _node_address(node: HANode) -> IPv4Address:
    try:
        return IPv4Address(node.management_host or "")
    except ValueError as exc:
        raise HAKeepalivedError(f"{node.display_name} must use an IPv4 management address before Keepalived deployment.") from exc


def validate_network(cluster: HACluster, router_id: int | None = None) -> None:
    if len(cluster.nodes) != 2:
        raise HAKeepalivedError("Exactly two nodes are required for Keepalived deployment.")
    if not cluster.virtual_ip or not cluster.prefix_length:
        raise HAKeepalivedError("Set a virtual IPv4 address and prefix length before deployment.")
    try:
        vip_interface = IPv4Interface(f"{cluster.virtual_ip}/{cluster.prefix_length}")
    except ValueError as exc:
        raise HAKeepalivedError("The virtual IP and prefix length are invalid.") from exc
    vip = vip_interface.ip
    network = vip_interface.network
    if vip in {network.network_address, network.broadcast_address}:
        raise HAKeepalivedError("The virtual IP cannot be the network or broadcast address.")
    addresses = [_node_address(node) for node in cluster.nodes]
    if vip in addresses:
        raise HAKeepalivedError("The virtual IP cannot match either node address.")
    if any(address not in network for address in addresses):
        raise HAKeepalivedError("Both nodes and the virtual IP must be on the same IPv4 subnet.")
    for node in cluster.nodes:
        if not node.network_interface or not INTERFACE_PATTERN.fullmatch(node.network_interface):
            raise HAKeepalivedError(f"Enter a valid network interface for {node.display_name}.")
    effective_router_id = router_id if router_id is not None else cluster.vrrp_router_id
    if effective_router_id is None or not 1 <= effective_router_id <= 255:
        raise HAKeepalivedError("VRRP router ID must be between 1 and 255.")


def deployment_blockers(cluster: HACluster, *, now: datetime | None = None, router_id: int | None = None) -> list[str]:
    blockers: list[str] = []
    invalid_interface_nodes = [
        node
        for node in cluster.nodes
        if not node.network_interface or not INTERFACE_PATTERN.fullmatch(node.network_interface)
    ]
    try:
        validate_network(cluster, router_id)
    except HAKeepalivedError as exc:
        if invalid_interface_nodes:
            blockers.extend(
                f"Enter a valid network interface for {node.display_name}."
                for node in invalid_interface_nodes
            )
        else:
            blockers.append(str(exc))
    if cluster.status not in {"VALIDATED", "VALIDATED_WITH_WARNINGS", "READY_TO_DEPLOY", "DEPLOYING", "HEALTHY"}:
        blockers.append("Complete read-only validation without blocking failures before deployment.")
    current = now or datetime.utcnow()
    for node in cluster.nodes:
        credential = node.agent_credential
        if not credential or not credential.registered_at or credential.revoked_at:
            blockers.append(f"Register an active agent for {node.display_name}.")
        if not node.last_heartbeat_at or node.last_heartbeat_at < current - timedelta(minutes=2):
            blockers.append(f"Wait for a recent agent heartbeat from {node.display_name}.")
    return list(dict.fromkeys(blockers))


def render_keepalived_config(cluster: HACluster, node: HANode) -> KeepalivedConfig:
    validate_network(cluster)
    if node not in cluster.nodes or node.vrrp_priority not in range(1, 255):
        raise HAKeepalivedError("Each node requires a Keepalived priority between 1 and 254.")
    instance = f"KAYA_HA_{cluster.public_id.replace('-', '')[:8].upper()}"
    generation = cluster.keepalived_generation
    content = (
        "# Managed by Kaya High Availability. Do not edit.\n"
        f"# cluster={cluster.public_id} generation={generation}\n"
        "global_defs {\n"
        "    script_user kaya-ha kaya-ha\n"
        "    enable_script_security\n"
        "}\n\n"
        f"vrrp_script KAYA_DNS_{cluster.public_id.replace('-', '')[:8].upper()} {{\n"
        "    script \"/usr/lib/kaya-ha-agent/check-pihole-dns\"\n"
        "    interval 2\n    timeout 2\n    fall 3\n    rise 3\n    weight -60\n}\n\n"
        f"vrrp_instance {instance} {{\n"
        "    state BACKUP\n"
        f"    interface {node.network_interface}\n"
        f"    virtual_router_id {cluster.vrrp_router_id}\n"
        f"    priority {node.vrrp_priority}\n"
        "    advert_int 1\n    nopreempt\n\n"
        "    virtual_ipaddress {\n"
        f"        {cluster.virtual_ip}/{cluster.prefix_length}\n"
        "    }\n\n"
        "    track_script {\n"
        f"        KAYA_DNS_{cluster.public_id.replace('-', '')[:8].upper()}\n"
        "    }\n\n"
        f"    notify_master \"{KEEPALIVED_HOOK} master {generation}\"\n"
        f"    notify_backup \"{KEEPALIVED_HOOK} backup {generation}\"\n"
        f"    notify_fault \"{KEEPALIVED_HOOK} fault {generation}\"\n"
        "}\n"
    )
    return KeepalivedConfig(content, hashlib.sha256(content.encode()).hexdigest())


def prepare_deployment(db: Session, cluster: HACluster, router_id: int, acknowledged: bool) -> HACluster:
    if not acknowledged:
        raise HAKeepalivedError("Confirm that this milestone will not enable, disable, or move DHCP.")
    cluster.vrrp_router_id = router_id
    blockers = deployment_blockers(cluster)
    if blockers:
        raise HAKeepalivedError(" ".join(blockers))
    ordered = sorted(cluster.nodes, key=lambda item: 0 if item.desired_role == "ACTIVE" else 1)
    ordered[0].vrrp_priority = 150
    ordered[1].vrrp_priority = 100
    cluster.cluster_generation += 1
    cluster.keepalived_generation += 1
    cluster.keepalived_status = "PENDING_AGENT"
    cluster.keepalived_requested_at = datetime.utcnow()
    cluster.status = "DEPLOYING"
    for node in cluster.nodes:
        node.keepalived_status = "PENDING_AGENT"
        node.keepalived_last_error = None
    db.commit()
    db.refresh(cluster)
    return cluster


def request_manual_vip_move(db: Session, cluster: HACluster, target: HANode, acknowledged: bool) -> HACluster:
    if not acknowledged:
        raise HAKeepalivedError("Confirm the manual VIP move and that DHCP remains outside this action.")
    if cluster.keepalived_status != "DEPLOYED" or any(node.keepalived_status != "DEPLOYED" for node in cluster.nodes):
        raise HAKeepalivedError("Both nodes must have a validated Keepalived deployment before moving the VIP.")
    owners = [node for node in cluster.nodes if node.vip_owned]
    if len(owners) != 1:
        raise HAKeepalivedError("A manual VIP move requires exactly one currently reported VIP owner.")
    if owners[0].id == target.id:
        raise HAKeepalivedError(f"{target.display_name} already owns the virtual IP.")
    blockers = deployment_blockers(cluster)
    if blockers:
        raise HAKeepalivedError(" ".join(blockers))
    if any(node.dhcp_running for node in cluster.nodes):
        raise HAKeepalivedError("Manual VIP testing is blocked while an agent reports DHCP running; DHCP transition control is not implemented yet.")
    for node in cluster.nodes:
        node.desired_role = "ACTIVE" if node.id == target.id else "STANDBY"
        node.vrrp_priority = 150 if node.id == target.id else 100
        node.keepalived_status = "PENDING_AGENT"
    cluster.role_generation += 1
    cluster.cluster_generation += 1
    cluster.keepalived_generation += 1
    cluster.keepalived_status = "PENDING_AGENT"
    cluster.keepalived_requested_at = datetime.utcnow()
    cluster.status = "DEPLOYING"
    db.commit()
    db.refresh(cluster)
    return cluster


def desired_keepalived_action(cluster: HACluster, node: HANode) -> dict | None:
    if cluster.keepalived_status not in {"PENDING_AGENT", "DEPLOYING"} or node.keepalived_status != "PENDING_AGENT":
        return None
    generated = render_keepalived_config(cluster, node)
    return {
        "action_id": f"keepalived:{cluster.public_id}:{cluster.keepalived_generation}:{node.public_id}",
        "action_type": "KEEPALIVED_APPLY",
        "generation": cluster.keepalived_generation,
        "configuration": generated.content,
        "checksum": generated.checksum,
        "dhcp_transition": "DISABLED",
    }
