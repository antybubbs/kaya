# High Availability: Health & Repair design

This document describes how the **Health & Repair** workspace fixes High Availability problems. Each problem gets one dedicated, bounded repair action, chosen by the unified Health assessment. No repair is a general-purpose "rebuild everything" button.

Status: implemented (P7). Health & Repair is the cluster's former Maintenance (Reconcile) page, consolidated; there is no separate page. The actions marked *Yes* exist. Align service ownership was added in P6; the administrator-approved Keepalived baseline restoration and repair-outcome notifications in P7.

## The workspace

**Where:** the **Health & Repair** tab of each cluster (`/high-availability/clusters/<id>/maintenance`). The Overview and Diagnostics pages show the same Health assessment and link here when something needs attention.

From top to bottom:

1. **One status**, from the assessment:
   - **Healthy**: no action required. Informational notes (for example an available agent update) never change this.
   - **Recovering automatically**: every open problem is temporary or being fixed by Kaya, or an approved operation is running. Lists what Kaya is doing.
   - **Needs approval**: shows the one recommended repair (the most severe problem that has a safe repair), with its effect on services.
   - **Blocked**: a critical problem has no safe repair. Shows the exact reason and, when one exists, the next safe step (for example the agent update that would unblock alignment).
2. **Service state**: the Virtual IP and DHCP owners Kaya observes, the assigned Active and Standby, standby readiness, configuration and lease synchronisation, the Keepalived configuration (stable, or a node that may still preempt), maintenance holds and the automation settings.
3. **All findings** (the Health assessment), each with its prerequisites.
4. **Approved repairs**, shown only when relevant: Align service ownership, Restore the stable Keepalived configuration, and the maintenance safety latch review. Each shows its prerequisites, expected impact, confirmation and progress.
5. **Node reports** (collapsed).
6. **Reconcile State** (records only), and **Advanced: Reinitialise HA cluster** (collapsed; not needed for routine recovery).

## Principles

1. **The Health assessment is the single source of truth.** Every repair starts from one assessment finding. The finding states the condition, its prerequisites and why a repair is or isn't offered.
2. **One condition, one dedicated action.** Each action changes only what its condition needs. A repair never moves services the condition doesn't involve.
3. **Bounded.** Each action has fixed steps, a time limit per step and a defined safe stop (FAILED_SAFE or BLOCKED). None retries in a loop.
4. **Verified, never assumed.** An action succeeds only when fresh signed reports from both nodes show the expected result. An agent's "applied" response alone isn't proof.
5. **The coordinator runs everything.** Actions are steps of the existing HA coordinator, under the per-cluster lock. There is no separate scheduler or maintenance engine.
6. **Administrator approval.** Any action that changes a service (DHCP, the Virtual IP or Keepalived runtime) needs explicit approval for that specific run. Automatic actions are limited to configuration repairs proven not to move a service.
7. **Reinitialise is not the default repair.** Reinitialise rebuilds the whole HA runtime around a chosen Active node, which is legitimate for re-establishing a cluster after major changes. The assessment never recommends it for a condition that has a dedicated action.

## Conditions and their repair actions

| Assessment finding | Dedicated repair action | Changes | Never changes | Available |
|---|---|---|---|---|
| `STORED_ROLE_MISMATCH` (stored roles differ from one clean owner) | **Reconcile stored state** | Kaya's records only | Any service | Yes (Reconcile) |
| `ACTIVE_DHCP_CONFIGURATION_DISABLED` / `STANDBY_DHCP_CONFIGURATION_ENABLED` | **DHCP configuration self-heal** (automatic, latched on failure) | The persisted Pi-hole DHCP setting only | Live leases, running DHCP service, the Virtual IP | Yes (automatic; explicit retry) |
| `CONFIGURATION_DRIFT` | **Review and apply synchronisation** | Allowlisted settings on the standby | DHCP on/off, leases, the Virtual IP | Yes |
| `LEASE_REPLICATION_STOPPED` | **Lease reconciliation** | The staged lease copy on the standby | DHCP service state | Yes |
| `KEEPALIVED_PREEMPT_RETAINED` | **Restore the stable Keepalived configuration**: node without the VIP first, then a reload (not a restart) of the owner, then verification | Keepalived configuration (`nopreempt`) | DHCP, the Virtual IP owner, the maintenance latch | Yes: one administrator-approved attempt (agents 0.2.15+). With older agents, redeploy Keepalived. Automatic restoration stays off |
| `KEEPALIVED_REJECTED` / `KEEPALIVED_GENERATION_BEHIND` | **Redeploy Keepalived** | Keepalived configuration (reload) | DHCP | Yes |
| `MAINTENANCE_HOLD` | **Review and release the hold** | The hold only; automatic failover stays off | Any service | Yes |
| `OWNERSHIP_MISMATCH` (VIP and DHCP on different nodes) | **Align service ownership**: move only the Virtual IP to the verified sole DHCP server, then restore and verify the stable Keepalived configuration | The Virtual IP (Keepalived reloads only), in one approved run | DHCP, leases, lease files, automation settings, the maintenance latch | Yes (administrator approval; agents 0.2.15+). Lease replication resumes normally afterwards |
| `DUPLICATE_VIP` / `MULTIPLE_DHCP` (split-brain) | **None automatic.** Guided manual steps: identify and stop the stale owner | — | — | Guidance only; Kaya blocks DHCP activation |
| `NO_VIP_OWNER` / `NO_DHCP_OWNER` | **None automatic.** Guided checks: Keepalived, DNS health and agent reports on both nodes | — | — | Guidance only |
| `AGENT_NOT_REPORTING` / `AGENT_UPDATE_AVAILABLE` | **Agent bootstrap or update** | The agent on one node | DNS and DHCP keep running | Yes |

## Align service ownership

This is the dedicated repair for the 4 November 2026 condition: the Virtual IP on one node while a different node is the only DHCP server. It moves only the Virtual IP to the DHCP server. It never starts, stops, promotes or demotes DHCP, never stages leases and never writes a lease file. Its only agent actions are Keepalived reloads. It never runs automatically.

**Where:** the *Align service ownership* panel on the cluster's Health & Repair page. The Health assessment's DNS-and-DHCP finding links to it when every prerequisite passes, and otherwise lists exactly which prerequisite fails and what is needed.

**Prerequisites** (from stored, signed agent reports; all must pass):

- exactly one Virtual IP owner and a different, single DHCP server (split-brain, no Virtual IP owner and no DHCP server are separate faults and are never treated as alignment);
- fresh signed reports, with fresh DHCP observations, from both registered agents;
- the DHCP server reports DHCP enabled, FTL active and UDP port 67 listening; the other node reports DHCP released;
- DNS healthy on both nodes;
- Keepalived deployed and running on both nodes, with no pending change, and both nodes on the current configuration and role generations;
- both agents 0.2.15 or newer (older agents may restart Keepalived when a reload fails and do not report their local gates);
- both agents' reported automation gates match the cluster settings;
- no other operation running;
- if the maintenance safety latch is held: the failed operation that set it has been acknowledged.

**Approval:** an administrator reviews the owners, the prerequisites and the expected impact, ticks the approval, and types the cluster name. Kaya refuses the request if the cluster changed since the preview was shown. Refusals are audited.

**Steps** (each bounded; Kaya stops at the first failed check):

1. **Confirm gates** (60 s): Kaya holds maintenance mode for the run and waits until both agents report, in signed heartbeats, that their local maintenance gate is on. A transition hook then never acts on DHCP.
2. **Move the Virtual IP** (90 s): one Keepalived generation gives the DHCP server the higher priority and a preempt-capable configuration; the current owner keeps `nopreempt`. Both apply it as a reload. Kaya waits for fresh reports showing the DHCP server as the only Virtual IP owner.
3. **Restore the stable configuration** (120 s per node): `nopreempt` on the node without the Virtual IP first, then on the owner, each verified by its applied checksum.
4. **Verify** (60 s): fresh reports from both nodes must show one Virtual IP owner, the same single DHCP server, the other node released, healthy DNS, Keepalived running, current generations and the stable configuration. Only then does Kaya record the new Active and Standby assignment and the finding resolves.

**Stops safely** when an agent stops reporting for 45 s, DHCP ownership changes or cannot be confirmed, DNS health deteriorates, Keepalived stops or rejects a configuration, another change alters a generation, or two nodes report the Virtual IP for more than 20 s. It never retries and never moves the Virtual IP back. It does not claim a rollback succeeded: when an agent reports a failed reload, Kaya records the agent's own rollback outcome and treats the running configuration as unconfirmed until fresh reports show it. The evidence (both nodes' last reports, Keepalived status, generations and errors) is kept with the run. If Keepalived had already been changed, the maintenance hold stays on as a safety latch for review; any preempt-capable configuration left behind remains visible in the Health assessment.

**Kaya restarts** resume the run from its persisted step, using only reports received after the restart; the step limits are not extended.

**Retained maintenance safety latch:** the repair may run while the latch is held, so the 4 November state can be repaired without clearing the latch first. This requires, for that run only, an explicit extra authorisation on top of the approval, after the failed operation has been acknowledged. The latch is never cleared: maintenance mode stays on during and after the run, so automatic failover hooks, DHCP self-heal and automatic synchronisation stay paused. The authorisation, the failed run it was given under and `latch_released: false` are recorded in the audit log. If Kaya cannot identify the failed operation behind the latch, the repair is blocked.

**Incomplete repair.** When Align service ownership stops after it changed Keepalived, its panel lists exactly what is still outstanding, each with where to fix it: whether the Virtual IP and DHCP are still split, which node may still preempt (and from which generation), any node whose last Keepalived apply failed, and the retained maintenance latch.

**Not handled:** a stale Virtual IP left by a killed Keepalived (lab-confirmed: the crashed node keeps the address while the peer also takes it) is split-brain. Kaya blocks alignment, raises the urgent split-brain notification and explains how to find and stop the stale owner. It never removes Virtual IP addresses itself.

## Restore the stable Keepalived configuration (approved)

A maintenance step, controlled failover or Align service ownership can leave one node with a preempt-capable Keepalived configuration if it stops before restoring the stable one. Automatic restoration stays **disabled**. Instead an administrator can approve **one** restoration attempt on Health & Repair.

**Prerequisites** (stored, signed reports; all must pass): a preempt-capable configuration is outstanding and no restoration is running; registered agents with fresh reports; exactly one Virtual IP owner; no second DHCP server and fresh DHCP observations; healthy DNS on the owner; Keepalived deployed and running on both nodes with no pending change and no rejected apply; current generations; agents 0.2.15+; agents' gates matching the cluster; no other operation; and, if the maintenance latch is held, the failed operation acknowledged.

**Approval:** tick the approval, type the cluster name, and (under a retained latch) authorise this single attempt. The preview fingerprint must still match.

**Steps:** the existing bounded restoration: the stable configuration on the node without the Virtual IP, then a reload of the owner, then verification from fresh reports that both run it and the owner did not change (120 s per step).

**Stops safely** (state *Blocked*) on a rejected or uncertain apply, an ownership change or a timeout. It is never retried without a new approval. If a node reported a failed apply, a new attempt is refused (Kaya will not stage another change on an unconfirmed configuration); check that node, re-run the Safety checks (a degraded cluster must pass validation before a redeployment), then redeploy Keepalived, which also satisfies the baseline once verified.

**Never:** moves the Virtual IP, touches DHCP or leases, restarts Keepalived, or releases the maintenance latch. The audit records the approval, `authorised_under_retained_latch`, `latch_released: false`, and the outcome.

## Notifications

- **Ownership conditions:** VIP/DHCP mismatch, split-brain or a missing owner. Each raises one confirmed notification per episode and resolves once.
- **Generic "degraded" alert:** now reserved for other causes, so one incident never sends both. The cluster overview and assessment show health immediately; only the notification waits for confirmation.
- **Repair outcomes** (P7): when Align service ownership or a Keepalived baseline restoration stops safely, Kaya sends one *repair stopped safely* notification (critical). It is one active incident per cluster: a further stop while it is unresolved is recorded in Activity but not notified again. A verified successful repair sends one *repair completed* notification and resolves the open incident. Both link to Health & Repair. The repair's own events and audit entries are the durable record.

## Lab validation

The isolated two-node lab runs real Keepalived (2.2.8 on Alpine, and 2.2.4 on Ubuntu 22.04) with Kaya-rendered configurations and the repository's real Keepalived helper. Results that shaped these actions:

- **Reloading the MASTER kept the Virtual IP** in every run (about 50 MASTER reloads per version), including `preempt_delay` ↔ `nopreempt` changes.
- **Restarting the MASTER moved the Virtual IP** to the peer in under a second, which reproduces 4 November. Repairs therefore reload, never restart.
- **Killing every Keepalived process (SIGKILL)** left the VIP address on the crashed node while the peer also took it: lasting dual ownership. Repairs therefore verify ownership from fresh reports and never assume success.

## Page review (P7 proposal)

Routine recovery now needs only **Health & Repair**: every repair the assessment recommends either runs there (Align service ownership, baseline restoration, latch review, Reconcile State, DHCP configuration retry) or links to the one page that owns it (agent update, synchronisation review, lease reconciliation). No routine finding recommends Reinitialise. Proposals for the remaining pages, to be applied only once equivalence is proven in use:

| Page | Proposal | Reason |
|---|---|---|
| Overview | **Keep**: status, assessment, link to Health & Repair | Entry point |
| Health & Repair (was Reconcile or reinitialise) | **Keep** as the primary workspace (done in P7) | Single place for findings and approved repairs |
| Sync | **Keep**; later show its drift summary in Health & Repair's service state | Owns the sync plan and approval |
| DHCP | **Keep** for lease reconciliation; candidate to fold into Health & Repair once lease repair is a dedicated action there | Only routine use is the lease-conflict repair |
| Activity | **Keep** | Durable history; repair outcomes appear here |
| Failover | **Keep** (controlled failover and tests) | Deliberate operator action, not recovery |
| Diagnostics | **Keep** (administrators); already shares the assessment | Support export |
| Setup: Service responsibilities (topology) | **Move to Advanced** | Rarely changed after setup |
| Setup: Safety checks (validation) | **Keep under Setup** | Needed for redeploys |
| Setup: Node agents | **Keep under Setup**; link from the agent-update finding | Agent install, update and re-link |
| Setup: Shared DNS address (deployment) | **Move redeploy and manual VIP move to Advanced** after approved restoration is proven live | Approved restoration replaces redeploy as the routine fix for a retained preempt grant |
| Reinitialise | **Advanced** (done in P7) | Rebuild only after interrupted setup or a deliberate re-pairing |
| Manual VIP move (deployment page) | **Retire** once alignment and controlled failover are proven live | Superseded by bounded, verified operations |

