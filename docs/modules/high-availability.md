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
| Pi-hole v6 | Beta | Two nodes, DNS-only or DNS+DHCP topology, Layer 2 IPv4 DNS Virtual IP, configuration sync, optional DHCP continuity, controlled and automatic failover |

Future integrations may use different node counts, service-address mechanisms, deployment tools, configuration models, health checks, consuming modules, and failover strategies.

## Pi-hole safety summary

- Both nodes and the virtual IP must share a Layer 2 IPv4 network.
- DNS-only deployments leave the external DHCP service untouched and direct clients to the DNS Virtual IP.
- DNS+DHCP deployments use the DNS Virtual IP as primary DNS and the standby node address as secondary DNS.
- Exactly one node may own the virtual IP.
- If Pi-hole provides DHCP, only the current virtual-IP owner may run DHCP.
- Automatic failover is opt-in and automatic failback is disabled.
- A recovered node returns as standby.
- Ambiguous ownership, stale continuity data, or split-brain evidence blocks DHCP activation.
- Kaya configuration repair requires the reported VIP owner to remain continuously eligible for 10 seconds (current ACTIVE role, VIP, DNS, and generations). This matches the local Keepalived hold-down and filters brief elections during service restarts; it is a stability gate, not a fixed sleep in the action path.
- DHCP promotion is fenced both before and after activation. Losing the VIP during promotion disables DHCP and fails the action; a local BACKUP transition also remains responsible for releasing DHCP when Kaya is unavailable.
- DNS, DHCP, Keepalived, and local agent operation do not depend on Kaya remaining online.
- DNS Manager consumes a healthy HA Pi-hole cluster as one logical provider through its virtual IP.
- Live cluster status separates operational standby readiness from recovery workflow and configuration-sync state. Routine comparisons can report checking or running while the standby remains operationally ready; controlled handover still requires its independent recovery stability gate.
- Controlled failover/failback started, completed, and safely failed outcomes publish through Kaya's central notification framework after the HA state commit. Operation history shows redacted per-channel counts for diagnosis; notification failure never reverses a verified network transition.

## Data retention

Cluster removal is a soft deletion. Stored nodes, connection references, validation records, DNS Manager links, linked IP details, and history remain preserved unless the user explicitly deletes them through the module that owns the data.
