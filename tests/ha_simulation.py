"""Deterministic two-node HA simulation harness (Gate A, test-only).

This module drives Kaya's real server-side HA code (heartbeat processing,
topology reconciliation, recovery, maintenance) with simulated agents whose
observations come from a deliberately small VRRP model.

IMPORTANT LIMITATIONS
---------------------
* ``VRRPModel`` is a simplified model of the documented Keepalived behaviour
  Kaya relies on (``state BACKUP``, ``nopreempt``/``preempt_delay``, a
  priority-0 advert on graceful stop, a master-down takeover when no MASTER
  exists).  It is NOT Keepalived.  Tests using it prove what *Kaya* decides
  given those observations; they do not prove real VRRP timing, reload
  semantics, gratuitous ARP or notify-hook ordering.
* Agents are simulated: heartbeats are constructed ``HAAgentHeartbeat``
  objects passed straight to ``record_heartbeat``.  HTTP signing is covered by
  the existing agent API tests and is bypassed here.

All data is synthetic: RFC 5737 documentation addresses, ``.invalid`` hosts
and ``example.invalid`` users.  No live service is contacted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import (
    HAAgentCredential,
    HACluster,
    HAEvent,
    HALeaseReplicationState,
    HANode,
    HASyncRun,
    User,
)
from app.schemas.high_availability import HAAgentHeartbeat
from app.services.ha_agents import record_heartbeat

# Synthetic stand-ins for the HAL-Home-DNS topology (documentation range only).
VIP = "192.0.2.10"
NODE_ONE_IP = "192.0.2.2"
NODE_TWO_IP = "192.0.2.8"
AGENT_VERSION = "0.2.14"
GENERATION = 37


def sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine, expire_on_commit=False)


# ---------------------------------------------------------------------------
# VRRP model
# ---------------------------------------------------------------------------


@dataclass
class SimNode:
    name: str
    ip: str
    priority: int
    nopreempt: bool = True
    keepalived_running: bool = True
    vrrp_state: str = "BACKUP"  # MASTER | BACKUP | FAULT | STOPPED
    keepalived_generation: int = GENERATION
    dhcp_running: bool = False
    dns_healthy: bool = True
    ftl_active: bool = True
    report_sequence: int = 0
    # Agent-local automation gates as last applied from Kaya's desired state.
    gates: dict = field(default_factory=lambda: {"automatic_failover": False, "maintenance_mode": True, "dhcp_managed": True})
    lease_file: bytes = b"synthetic-lease-file\n"
    lease_generation: int = 8  # the lease generation this node's agent last staged

    @property
    def vip_owned(self) -> bool:
        return self.keepalived_running and self.vrrp_state == "MASTER"


@dataclass(frozen=True)
class NotifyCall:
    node: str
    transition: str  # master | backup | fault
    generation: int


class VRRPModel:
    """Simplified two-node VRRP behaviour.  Not a substitute for Keepalived."""

    def __init__(self, one: SimNode, two: SimNode):
        self.nodes = {one.name: one, two.name: two}
        self.notify: list[NotifyCall] = []
        self.link_up = True

    def peer(self, node: SimNode) -> SimNode:
        return next(item for item in self.nodes.values() if item is not node)

    def _set(self, node: SimNode, state: str) -> None:
        if node.vrrp_state == state:
            return
        node.vrrp_state = state
        hook = {"MASTER": "master", "BACKUP": "backup", "FAULT": "fault"}.get(state)
        if hook:
            self.notify.append(NotifyCall(node.name, hook, node.keepalived_generation))

    def _eligible(self, node: SimNode) -> bool:
        return node.keepalived_running and node.dns_healthy

    def stop(self, name: str) -> None:
        """Graceful stop: a MASTER sends a priority-0 advert; the peer takes over."""
        node = self.nodes[name]
        was_master = node.vrrp_state == "MASTER"
        node.keepalived_running = False
        node.vrrp_state = "STOPPED"
        peer = self.peer(node)
        if was_master and self._eligible(peer) and peer.vrrp_state != "MASTER":
            self._set(peer, "MASTER")

    def start(self, name: str) -> None:
        """Start in ``state BACKUP``; preempt only when allowed and higher priority."""
        node = self.nodes[name]
        node.keepalived_running = True
        if not node.dns_healthy:
            self._set(node, "FAULT")
            return
        node.vrrp_state = "INIT"
        peer = self.peer(node)
        peer_master = self.link_up and peer.vrrp_state == "MASTER"
        if not peer_master:
            self._set(node, "MASTER")  # master-down timer expires
        elif not node.nopreempt and node.priority > peer.priority:
            self._set(node, "MASTER")
            self._set(peer, "BACKUP")
        else:
            self._set(node, "BACKUP")

    def restart(self, name: str) -> None:
        self.stop(name)
        self.start(name)

    def dns_fault(self, name: str) -> None:
        node = self.nodes[name]
        node.dns_healthy = False
        was_master = node.vrrp_state == "MASTER"
        self._set(node, "FAULT")
        peer = self.peer(node)
        if was_master and self._eligible(peer):
            self._set(peer, "MASTER")

    def partition(self) -> None:
        """VRRP adverts lost both ways: every eligible BACKUP becomes MASTER."""
        self.link_up = False
        for node in self.nodes.values():
            if self._eligible(node) and node.vrrp_state == "BACKUP":
                self._set(node, "MASTER")


# ---------------------------------------------------------------------------
# Simulated agents driving the real Kaya heartbeat path
# ---------------------------------------------------------------------------


def heartbeat_for(sim: SimNode, *, observed_generation: int = GENERATION, config_generation: int | None = None) -> HAAgentHeartbeat:
    sim.report_sequence += 1
    role = {"MASTER": "ACTIVE", "BACKUP": "STANDBY", "FAULT": "FAULT"}.get(sim.vrrp_state, "UNKNOWN")
    return HAAgentHeartbeat(
        report_sequence=sim.report_sequence,
        reported_at=datetime.utcnow(),
        observed_role=role,
        observed_generation=observed_generation,
        vip_owned=sim.vip_owned,
        dhcp_running=sim.dhcp_running,
        dhcp_configured=sim.dhcp_running,
        dhcp_listener_active=sim.dhcp_running,
        ftl_active=sim.ftl_active,
        dhcp_runtime_state="RUNNING" if sim.dhcp_running else "STOPPED",
        dhcp_observation_status="FRESH",
        dhcp_observed_at=datetime.utcnow(),
        dns_healthy=sim.dns_healthy,
        peer_reachable=True,
        peer_icmp_probe_status="AVAILABLE",
        peer_dns_reachable=True,
        lease_generation=sim.lease_generation,
        config_generation=sim.keepalived_generation if config_generation is None else config_generation,
        agent_version=AGENT_VERSION,
        keepalived_runtime_state=(
            "RUNNING" if sim.keepalived_running and sim.vrrp_state != "FAULT"
            else "FAULT" if sim.vrrp_state == "FAULT" else "STOPPED"
        ),
    )


@dataclass
class SimCluster:
    db: Session
    cluster: HACluster
    one: HANode  # preferred ACTIVE, DHCP owner (stand-in for PiHole1)
    two: HANode  # preferred STANDBY (stand-in for PiHole2)
    sim_one: SimNode
    sim_two: SimNode
    vrrp: VRRPModel
    admin: User

    def node_for(self, sim: SimNode) -> HANode:
        return self.one if sim is self.sim_one else self.two

    def report(self, sim: SimNode, **kwargs) -> HANode:
        """Record a signed heartbeat, then let the coordinator evaluate it (as the
        background coordinator loop does in production)."""
        from app.services.ha_watchdog import drain_evaluations

        node = self.node_for(sim)
        record_heartbeat(self.db, node, heartbeat_for(sim, **kwargs))
        drain_evaluations(self.db)
        return node

    def report_both(self, rounds: int = 1) -> None:
        for _ in range(rounds):
            self.report(self.sim_one)
            self.report(self.sim_two)

    def events(self, event_type: str | None = None) -> list[HAEvent]:
        query = self.db.query(HAEvent).filter(HAEvent.cluster_id == self.cluster.id)
        if event_type:
            query = query.filter(HAEvent.event_type == event_type)
        return query.order_by(HAEvent.id).all()

    def make_stale(self, sim: SimNode, seconds: int = 600) -> None:
        node = self.node_for(sim)
        node.last_heartbeat_at = datetime.utcnow() - timedelta(seconds=seconds)
        node.dhcp_observed_at = node.last_heartbeat_at
        self.db.commit()


def hal_like_cluster(db: Session, *, maintenance_mode: bool = True, automatic_failover: bool = False, suffix: str = "sim") -> SimCluster:
    """Build the pre-incident topology: node one MASTER + sole DHCP, generation 37, nopreempt."""
    now = datetime.utcnow()
    admin = User(email=f"ha-sim-{suffix}@example.invalid", password_hash="synthetic", role="admin", is_active=True)
    cluster = HACluster(
        name=f"Synthetic HAL pair {suffix}",
        provider_key="pihole",
        deployment_mode="DNS_DHCP",
        status="HEALTHY",
        virtual_ip=VIP,
        prefix_length=24,
        keepalived_status="DEPLOYED",
        vrrp_router_id=51,  # synthetic; lets Kaya render Keepalived configurations
        keepalived_generation=GENERATION,
        cluster_generation=GENERATION,
        role_generation=GENERATION,
        automatic_failover_enabled=automatic_failover,
        automatic_sync_enabled=False,
        maintenance_mode=maintenance_mode,
    )
    db.add_all([admin, cluster])
    db.flush()

    def node(name: str, ip: str, active: bool, priority: int) -> HANode:
        return HANode(
            cluster_id=cluster.id,
            display_name=name,
            management_host=ip,
            api_base_url=f"https://{name.lower()}.invalid",
            network_interface="eth0",
            role="ACTIVE" if active else "STANDBY",
            desired_role="ACTIVE" if active else "STANDBY",
            observed_role="ACTIVE" if active else "STANDBY",
            observed_generation=GENERATION,
            agent_version=AGENT_VERSION,
            vrrp_priority=priority,
            vip_owned=active,
            dhcp_running=active,
            dhcp_configured=active,
            dhcp_listener_active=active,
            ftl_active=True,
            dhcp_runtime_state="RUNNING" if active else "STOPPED",
            dhcp_observation_status="FRESH",
            dhcp_observed_at=now,
            dns_healthy=True,
            keepalived_status="DEPLOYED",
            keepalived_runtime_state="RUNNING",
            config_generation=GENERATION,
            lease_generation=8,
            recovery_state="ACTIVE" if active else "STANDBY_READY",
            vip_stable_since=now - timedelta(minutes=5) if active else None,
            last_heartbeat_at=now,
        )

    one = node("SimPiHole1", NODE_ONE_IP, True, 150)
    two = node("SimPiHole2", NODE_TWO_IP, False, 100)
    db.add_all([one, two])
    db.flush()
    cluster.preferred_node_id = one.id
    cluster.current_active_node_id = cluster.authoritative_node_id = one.id
    db.add_all([
        HAAgentCredential(node_id=one.id, agent_id=f"sim-agent-one-{suffix}", public_key=f"fake-sim-key-one-{suffix}", registered_at=now),
        HAAgentCredential(node_id=two.id, agent_id=f"sim-agent-two-{suffix}", public_key=f"fake-sim-key-two-{suffix}", registered_at=now),
        HALeaseReplicationState(cluster_id=cluster.id, source_node_id=one.id, target_node_id=two.id, status="CURRENT", desired_generation=8, applied_generation=8),
        # Durable post-recovery comparison evidence so the healthy baseline is STANDBY_READY.
        HASyncRun(cluster_id=cluster.id, source_node_id=one.id, target_node_id=two.id, status="IN_SYNC", plan_json='{"groups":[]}', created_at=now - timedelta(minutes=5), completed_at=now - timedelta(minutes=5)),
    ])
    two.recovery_started_at = now - timedelta(minutes=10)
    two.recovery_stable_since = now - timedelta(minutes=4)
    db.commit()
    gates = {"automatic_failover": automatic_failover, "maintenance_mode": maintenance_mode, "dhcp_managed": True}
    sim_one = SimNode("SimPiHole1", NODE_ONE_IP, 150, vrrp_state="MASTER", dhcp_running=True, gates=dict(gates))
    sim_two = SimNode("SimPiHole2", NODE_TWO_IP, 100, vrrp_state="BACKUP", dhcp_running=False, gates=dict(gates))
    return SimCluster(db, cluster, one, two, sim_one, sim_two, VRRPModel(sim_one, sim_two), admin)


def ownership_snapshot(sim: SimCluster) -> dict:
    """Compact, comparable view of observed vs stored ownership."""
    from app.services.ha_topology import reconcile_topology

    topology = reconcile_topology(sim.cluster)
    names = {sim.one.id: sim.one.display_name, sim.two.id: sim.two.display_name}
    return {
        "status": sim.cluster.status,
        "vip_owners": [names[item] for item in topology.vip_owner_ids],
        "dhcp_owners": [names[item] for item in topology.dhcp_owner_ids],
        "topology_safe": topology.topology_safe,
        "issues": sorted(issue.code for issue in topology.issues),
        "stored_active": names.get(sim.cluster.current_active_node_id),
        "authority": names.get(sim.cluster.authoritative_node_id),
        "roles": {sim.one.display_name: sim.one.role, sim.two.display_name: sim.two.role},
        "recovery": {sim.one.display_name: sim.one.recovery_state, sim.two.display_name: sim.two.recovery_state},
        "automatic_failover": bool(sim.cluster.automatic_failover_enabled),
        "maintenance_mode": bool(sim.cluster.maintenance_mode),
    }


def dump(snapshot: dict) -> str:
    return json.dumps(snapshot, sort_keys=True, indent=2)
