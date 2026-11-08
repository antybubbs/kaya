# DHCP protocol rollout and rollback runbook (proposal)

**Status: not approved.** Each stage below needs its own written approval before it starts. Nothing here
is automatic. Automatic Virtual IP return and automatic Keepalived baseline restoration stay disabled
throughout.

The revised DHCP protocol is described in [High Availability: DHCP authority](high-availability.md#dhcp-authority-proposal-not-enabled-not-released).
It ships as Kaya server changes (migration `20261107_01`) plus agent 0.2.16 with the FTL drop-in.

## Before any stage

1. **Backups.** Take and verify a Kaya database backup. Note the current Kaya version and agent versions.
2. **Preflight.** Run the read-only check for the stage and continue only if it says `"safe": true`:

   ```
   KAYA_HA_REPORT_DATABASE_URL=... python scripts/ha_dhcp_preflight.py --step agent_rollout
   ```

   It confirms: both nodes reporting, no failover, maintenance or repair running, one node holding the
   Virtual IP and serving DHCP alone, no node running DNS-only, and (for agent rollout) a verified lease
   snapshot of the holder staged on the standby.
3. **Health & Repair** shows no critical finding.
4. **Window.** Choose a quiet period. Expect no DHCP or DNS interruption from the steps themselves, but
   keep the stage short: see "Exposure while mixed" below.

## Stage 1: Kaya server

1. Upgrade Kaya. The migration adds three nullable columns; existing data is untouched.
2. Confirm older agents keep working: Health & Repair is unchanged, and the agents report normally.
   Older agents never receive DHCP authority instructions.

*Stop condition:* any new critical finding. Roll back Kaya (see below).

## Stage 2: agents, standby first

1. Preflight `agent_rollout`.
2. Update the **standby** agent (Health & Repair, or `update.sh`). The updater installs the FTL drop-in
   without restarting FTL. If the new agent does not report healthy, the updater restores the previous
   files and removes the drop-in by itself.
3. Wait until Kaya shows the standby on 0.2.16 and healthy.
4. Update the **DHCP holder** the same way.
5. Wait until Kaya shows DHCP authority on the holder and Health & Repair is clear.

*Exposure while mixed (one node old, one new):* automatic DHCP handover is off, because it needs both
agents on the revised protocol. If the DHCP holder fails during this time, DHCP stops until an
administrator acts (Health & Repair names the node to update). Keep the gap between steps 2 and 4 short.

*Exposure until authority is recorded (minutes):* if FTL restarts on the holder before Kaya has recorded
authority and the holder has recorded its grant, DHCP stays off until Kaya re-grants it.

## Stage 3: activate and observe

The protocol is active once both agents run 0.2.16. Observe for an agreed period. Health & Repair should
show no `DHCP_SERVED_WITHOUT_AUTHORITY`, `DHCP_AUTHORITY_RECORD_BEHIND`, `DHCP_DNS_ONLY_FALLBACK` or
`DHCP_HANDOVER_BLOCKED` finding.

## Rollback

**Agents only (Kaya stays on the new version).** Preflight `agent_rollback`, then re-install the previous
agent on each node. DHCP keeps running. The FTL drop-in is left in place but steps aside for the older
helper, so on the next FTL start `pihole.toml` decides DHCP exactly as before.

**Kaya and agents.** Agents can only be re-installed from the Kaya version that serves them, so:

1. Preflight `kaya_rollback`; read its warnings.
2. Roll back Kaya (downgrade the database to `20261105_02` first, or restore the pre-upgrade backup).
3. **Immediately** run the agent update on both nodes, so the older Kaya installs the older agent.

Between steps 2 and 3, DHCP keeps running and an FTL restart on the holder keeps DHCP. If the DHCP holder
*reboots* in that window, DHCP stays off until step 3 is complete. DNS is unaffected.

**Database restore.** If Kaya's database is restored from a backup taken before later DHCP handovers,
Kaya detects that the nodes have seen newer authority, sends no DHCP instructions, and re-establishes
authority from the verified topology. No administrator action is needed; Health & Repair shows it.

## What can stop DHCP (by design)

| Event | DHCP | DNS | Recovery |
|---|---|---|---|
| FTL restart or crash on the holder | Continues | Brief restart | None needed |
| Holder reboot | Off until Kaya hands over or re-grants | Unaffected | Automatic |
| Holder reboot while Kaya is down | Off until Kaya returns | Unaffected | Automatic |
| Holder frozen, partitioned or powered off | Off until it returns (no fencing provider) | Via the Virtual IP owner | Bring the node back |
| `pihole.toml` read-only or environment-controlled | Off on that node | Available (DNS-only) | Repair, restart FTL |
| No verified lease snapshot of the holder on the standby | Not moved | Unaffected | Restart Keepalived on the standby (Virtual IP returns) |
| A promotion refused by the node (stale or corrupted snapshot) | Off; operation stops safely | Unaffected | Health & Repair |
