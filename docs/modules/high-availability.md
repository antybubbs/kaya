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
- A failed-safe reinitialisation restores the authoritative node and configuration baselines it replaced, unless a later verified change has already superseded them. A retry never re-enables automatic failover from an earlier run's saved settings; re-enable it explicitly after review.
- **Agent 0.2.16 (pending approval): no second DHCP server on a Keepalived stop.** The isolated lab (real hook, privileged helper, sudo and a real DHCP server) showed that with automatic failover on, a *graceful* Keepalived stop on the DHCP owner ran no transition hook, so that node kept serving DHCP while the peer took the Virtual IP and promoted DHCP: two DHCP servers until an administrator intervened. Two fail-closed fixes, both requiring 0.2.16 on both nodes:
  - **Stop hook.** Kaya renders `notify_stop` (only when both agents are 0.2.16+, since older agents reject it). A graceful stop then releases DHCP on that node, under the same automation gates and generation fence as `backup` and `fault`. Lab-verified that reloads, including a new generation, never fire it.
  - **Promotion fence.** Before an automatic promotion, the privileged helper broadcasts DHCP discovery on the Virtual IP interface. If another server answers, or the check cannot be made, it refuses. It retries briefly so a releasing peer can finish. A refused promotion is recorded and Kaya shows the split as a VIP/DHCP mismatch.
  - **Effect:** a short DHCP gap (about 10 s in the lab) during an automatic failover instead of two servers. Assumption: the other server answers a DISCOVER from an unknown client (Pi-hole's range-based DHCP does).
- The updater confirms an update only when the new agent stays up for 20 s with the same process and Kaya has accepted a heartbeat reporting the new version; otherwise it stops the new agent and restores the previous files.
- Agent 0.2.15 never restarts a running Keepalived: a failed reload is rolled back, and only a stopped service is started. Notify hooks fired while a new Keepalived generation is being applied are recorded, not fenced out. The agent reports its applied automation gates in signed heartbeats once Kaya advertises support. Upgrade Kaya before the agents.
- Controlled failover/failback started, completed, and safely failed outcomes publish through Kaya's central notification framework after the HA state commit. Operation history shows redacted per-channel counts for diagnosis; notification failure never reverses a verified network transition.

## Who decides what

High availability never waits for Kaya to keep DNS and DHCP safe. Kaya coordinates; it is not in the failover path.

**Done locally on each node, with or without Kaya:**

- **Keepalived** elects the single Virtual IP owner (VRRP), moves the VIP when a node or its DNS health check fails, and runs the agent's transition hook on every MASTER, BACKUP or FAULT change.
- **The transition hook** records the change. When automatic failover is enabled, maintenance is off and Pi-hole manages DHCP, it disables DHCP on a node that becomes BACKUP. After a hold-down, a DNS check and a duplicate-address check, it enables DHCP on the new MASTER. When automatic failover is disabled, or maintenance is on, it never touches DHCP or leases. Hooks for an older or unknown Keepalived generation are rejected.
- **The agent** applies only signed, generation-fenced actions that Kaya has authorised. Each one is validated locally before it runs.

**Decided by Kaya's HA coordinator:**

Kaya records what agents report and decides:

- the recorded VIP owner and authority, and adopting a verified local failover
- cluster health
- controlled failover and failback steps
- standby recovery and readiness
- maintenance and repair steps
- safe DHCP self-heal
- which actions each agent may perform

**How the decision process is structured:**

- **One decision process.** Signed heartbeats, action results and events only record what they report and signal the coordinator (the HA watchdog loop). The coordinator makes all of these decisions, one cluster at a time, under a per-cluster lock. A heartbeat waits up to two seconds for its evaluation, so its reply normally carries any resulting action. If Kaya is slow, the reply carries the current state and the next heartbeat delivers the rest. Local safety actions are unaffected either way.
- **Periodic pass.** Every 10 seconds the coordinator also advances in-flight operations and checks for safe DHCP drift, so progress never depends on a heartbeat arriving.
- **Pi-hole calls.** No database transaction is held open across a Pi-hole call made by a coordinated step.
- **Administrator actions that call Pi-hole.** Test connection, Validate, Plan and Apply synchronisation, DHCP lease reconciliation, DHCP DNS advertisement repair and controlled failover start run in background worker threads, so a slow or unreachable Pi-hole never delays other pages or agent heartbeats. At most three run at once per Kaya process; further requests wait without holding a database connection.
- **One change at a time.** Apply synchronisation, DNS advertisement repair and lease reconciliation make their changes under the cluster's coordination lock, like controlled failover. If the coordinator is busy with the cluster, they wait up to five seconds, then ask you to try again. Validate and Plan only read from Pi-hole, so they never delay the coordinator. A second Validate or Plan for the same cluster is refused while one is already running.

**Process limits:**

- **PostgreSQL:** coordination uses advisory locks, so several Kaya processes may share one database. Use direct database connections, not a transaction-mode pooler such as PgBouncer in transaction mode.
- **SQLite:** coordination uses a lock file beside the database, so several processes are coordinated only on Linux and other POSIX hosts. Otherwise run a single Kaya process, which is the default container configuration.

## Assigned and observed state

Kaya keeps two things apart:

- **Observed state** comes only from fresh signed agent reports: which node currently holds the Virtual IP and which serves DHCP. The overview's "Current active node" is the observed Virtual IP owner.
- **Assigned state** is what Kaya decided: the node assigned the ACTIVE role. Only a verified, authorised operation changes it: adopting a verified local automatic failover, completing a controlled failover or failback, a reconciliation that finds one clean owner, or a reinitialisation. Seeing the Virtual IP on another node never reassigns it.

When the two differ, the overview shows the assigned node next to the observed one, and the Health assessment explains the mismatch and the safe next step.

## Standby readiness

A standby is READY only while its current evidence is good: a fresh signed report, healthy DNS, Keepalived running, the standby role without the Virtual IP or DHCP, a post-recovery configuration comparison, and the current lease set staged. Pages re-check this evidence, so a standby that has gone stale or unhealthy is never shown as READY, even between coordinator checks.

- **Renewals don't reset readiness.** A client renewing its DHCP lease changes only an expiry time. Kaya still copies those renewals to the standby, because it restores staged expiry times if it ever takes over DHCP. But a renewal alone no longer resets readiness unless the standby stops staging renewals for more than five minutes. A change to the leases themselves must be staged before the standby is ready. A controlled failover still requires the exact current lease generation.
- **Ownership conflict.** A node that serves DHCP or claims the Virtual IP while it is not the sole Virtual IP owner is shown as *Ownership conflict*, not as a recovering standby. Its recovery starts afresh once ownership is consistent.
- **No churn.** Unchanged evidence causes no state changes or events.

## Ownership notifications

- **DNS and DHCP on different nodes.** When one node holds the Virtual IP and the other serves DHCP for more than 60 seconds, Kaya sends one notification. It names both nodes and the assigned Active node, and gives the safe next step from the Health assessment.
- **Split-brain.** When two nodes report the Virtual IP, or two DHCP servers run, for more than 20 seconds, Kaya sends one urgent notification.
- **No owner.** When no node holds the Virtual IP, or no node serves DHCP, for more than 60 seconds, Kaya sends one "cluster degraded" notification that says which.
- **One alert per incident.** When the cause of a degradation is one of these ownership conditions, Kaya sends only the confirmed ownership notification, not also a generic "cluster degraded" alert. Other causes, such as unhealthy DNS, still alert immediately. The overview and Health assessment always show the current state at once.
- **Deduplication and clearing.** Each condition notifies once while it persists. When fresh reports from both nodes show it has cleared, Kaya resolves it, records the event in the cluster history, and sends one "ownership restored" notification. Losing contact with the nodes never counts as cleared. Brief overlaps during a normal failover clear before they are confirmed, so they never notify.

## Reinitialise and the stable Keepalived configuration

- **Reinitialise when the selected Active node already serves DHCP.** If it is the only DHCP server and the other node has DHCP released, Reinitialise moves only the Virtual IP to it and then stages leases. DHCP never moves and no DHCP action is issued. Leases are staged with the full authority checks once that node holds both services. If DHCP ownership changes during the move, Reinitialise stops safely. Reinitialise is still not the recommended repair for a VIP/DHCP split: use Align service ownership.
- **Bounded configuration wait.** Reinitialise now stops safely if both nodes haven't applied and reported the new HA configuration within three minutes.
- **Stable configuration.** Kaya's stable Keepalived configuration never lets a node take the Virtual IP back on its own (`nopreempt`). A reinitialisation or controlled failover gives only the destination a temporary preempt-capable configuration. Kaya records this. While a node may still hold that configuration after the operation ends, the Health assessment shows *A node may still preempt the Virtual IP*.
- **Automatic restoration is off by default.** When enabled with the `HA_KEEPALIVED_BASELINE_RESTORATION` setting, the coordinator restores the stable configuration on the node without the Virtual IP first, then reloads (never restarts) the owner, and declares success only from fresh reports showing the same owner. A rejected configuration, an uncertain rollback, a timeout or any ownership change stops it, with no automatic retry.
- **Approved restoration (P7).** While automatic restoration is off, an administrator can approve one restoration attempt on Health & Repair, with the same steps, when every safety check passes (agents 0.2.15+). It works under a retained maintenance latch with an extra, audited authorisation and never releases the latch. With older agents, redeploy Keepalived from the Deployment page instead; Kaya then verifies the stable configuration from the agents' applied checksums.

## Align service ownership

When one node holds the Virtual IP and a different node is the only DHCP server, an administrator can approve **Align service ownership** on the Health & Repair page. Kaya moves only the Virtual IP to the DHCP server, restores the stable Keepalived configuration and verifies the result from fresh signed reports. DHCP and leases are never changed, and the only agent actions are Keepalived reloads. DNS through the Virtual IP may pause briefly during the handover.

- **Never automatic.** Each run needs an administrator's approval and the typed cluster name.
- **Requires agents 0.2.15 or newer** on both nodes, fresh reports, healthy DNS and Keepalived on both nodes, and current generations. When a prerequisite fails, the panel and the Health assessment say which and why.
- **Stops safely, never retries and never moves the Virtual IP back** if a check fails. The evidence stays with the run.
- **Works under a retained maintenance safety latch** only with an extra, audited authorisation, after the failed operation is acknowledged. The latch stays held; release it separately afterwards.
- **Split-brain, no Virtual IP owner and no DHCP server are separate faults.** Alignment is not offered for them.
- **If it stops after changing Keepalived**, the panel lists what is still outstanding and offers the approved baseline restoration when its checks pass. A stop sends one *repair stopped safely* notification; a later verified repair resolves it.

Details: [Health & Repair design](high-availability-health-and-repair.md#align-service-ownership).

## Health & Repair

Each cluster's **Health & Repair** tab (formerly *Reconcile or reinitialise*) is the one place to see and fix HA problems. It starts with one status (Healthy, Recovering automatically, Needs approval or Blocked), the single recommended repair or the exact reason nothing can be done safely, and the observed service state: Virtual IP and DHCP owners, assigned roles, standby readiness, configuration and lease synchronisation, the Keepalived configuration and maintenance holds. Approved repairs (Align service ownership, Keepalived baseline restoration, the maintenance latch review) and their progress appear there when relevant. Reinitialise is under *Advanced* and is not needed for routine recovery. Details: [Health & Repair design](high-availability-health-and-repair.md#the-workspace).

## Health assessment

The Overview, Health & Repair and Diagnostics pages show the same **Health assessment**, and the diagnostics export includes it. It is computed from Kaya's stored, signed observations only. It is read-only: it never contacts a node or Pi-hole and never changes anything.

**Each finding states:**

- what is wrong, with the observations that show it
- how severe it is and what it affects
- whether it is temporary, being fixed automatically, needs an administrator's approval, or cannot be fixed by Kaya automatically
- its safety prerequisites, each marked met or not
- the existing repair page to use, or why Kaya is not repairing it
- what automatic recovery has already tried

**Repairs only link to existing pages.** The assessment never offers a repair that cannot succeed. For example, when DNS and DHCP are on different nodes, it offers Align service ownership only when every prerequisite passes, and otherwise says which prerequisite fails.

## Data retention

Cluster removal is a soft deletion. Stored nodes, connection references, validation records, DNS Manager links, linked IP details, and history remain preserved unless the user explicitly deletes them through the module that owns the data.
