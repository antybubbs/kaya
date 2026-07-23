# High Availability (BETA)

Kaya High Availability is a provider and application resilience framework. Supported integrations can define their own node topology, validation, agent actions, deployment, synchronisation, failover, recovery, and safety controls.

Pi-hole is the first supported integration. Its current Beta implementation protects a two-node Pi-hole v6 service with a shared virtual IP, Keepalived, guarded configuration synchronisation, optional DHCP continuity, live health, and controlled or local automatic failover. Those are Pi-hole integration capabilities, not permanent assumptions of the High Availability module.

For the complete user and operator workflow, see:

- [High Availability guide](../guides/high-availability.mdx)

## Framework principles

- Kaya is the management plane, not the application or network traffic path.
- Provider and application connections are created and managed inside High Availability.
- Integrations expose only the pages and actions supported by their declared capabilities.
- Unknown or ambiguous high-risk state fails closed.
- Writes are validated, audited, and recoverable where the integration supports rollback.
- Removing a cluster does not implicitly delete history or data owned by another Kaya module.
- Local services continue using their last deployed state if Kaya is unavailable.

## Current provider/app support

| Provider or application | Maturity | Current topology and capabilities |
|---|---|---|
| Pi-hole v6 | Beta | Two nodes, Layer 2 IPv4 virtual IP, Keepalived, configuration sync, optional DHCP continuity, controlled and automatic failover |

Future integrations may use different node counts, service-address mechanisms, deployment tools, configuration models, health checks, consuming modules, and failover strategies.

## Pi-hole safety summary

- Both nodes and the virtual IP must share a Layer 2 IPv4 network.
- Exactly one node may own the virtual IP.
- If Pi-hole provides DHCP, only the current virtual-IP owner may run DHCP.
- Automatic failover is opt-in and automatic failback is disabled.
- A recovered node returns as standby.
- Ambiguous ownership, stale continuity data, or split-brain evidence blocks DHCP activation.
- DNS, DHCP, Keepalived, and local agent operation do not depend on Kaya remaining online.
- DNS Manager consumes a healthy HA Pi-hole cluster as one logical provider through its virtual IP.

## Data retention

Cluster removal is a soft deletion. Stored nodes, connection references, validation records, DNS Manager links, linked IP details, and history remain preserved unless the user explicitly deletes them through the module that owns the data.
