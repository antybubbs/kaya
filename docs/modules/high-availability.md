# High Availability (BETA)

Kaya High Availability manages a pair of Pi-hole v6 servers behind one virtual IP. Kaya is the management plane only: DNS, DHCP, Keepalived and local failover continue on the Pi-holes when Kaya is unavailable.

## Before enabling automatic failover

1. Validate both Pi-holes.
2. Install the current agent on both nodes.
3. Deploy Keepalived and confirm one virtual-IP owner.
4. Synchronise supported configuration.
5. Confirm DHCP continuity is current, or that DHCP is external.
6. Complete one controlled failover successfully.
7. Review the generated Keepalived configuration and restricted sudo policy.

Automatic failover is opt-in and automatic failback is always disabled. A recovered node joins as standby.

## What happens during local failover

Keepalived requires repeated DNS-health failures before changing ownership. The standby waits through a hold-down, verifies its own DNS service and performs a duplicate-address probe for the virtual IP. If ownership is ambiguous, DHCP remains disabled and a `split_brain_prevented` event is retained locally. If checks pass, the latest validated lease snapshot is installed with Pi-hole ownership, DHCP is enabled, and DNS is verified again. Failure disables DHCP and restores the previous lease file.

Kaya adopts the safe active node when agent connectivity returns. It does not force the former active node back into service.

## Day-to-day use

The cluster Overview is the operational dashboard. It updates once per second and provides current ownership, DNS/DHCP status, heartbeat age, alerts, controlled failover and automatic-failover controls. Setup and maintenance pages remain under the cluster navigation.

Download a redacted JSON report from the cluster header. Activity records privileged actions and replays agent events created while Kaya was offline.

## Backups and data retention

Kaya creates encrypted Pi-hole configuration backups before synchronisation writes and local lease-file backups before DHCP promotion. Removing a cluster is a soft deletion: DNS Manager links, IP associations, validation records and history remain preserved unless the user explicitly deletes them through their owning module.

## Recovery

If controlled failover stops, use **Roll back safely**. If the promoted node later stops answering DNS, use **Return safely**. Never enable DHCP manually on both Pi-holes.

To repair a Pi-hole lease file left by an older beta agent:

```bash
sudo chown pihole:pihole /etc/pihole/dhcp.leases
sudo chmod u+rw /etc/pihole/dhcp.leases
sudo systemctl restart pihole-FTL
```

## Known beta limits

- Pi-hole v6 on Debian, Ubuntu or Raspberry Pi OS is the only supported provider.
- Both nodes and the virtual IP must share a Layer 2 IPv4 network.
- Two-node clusters do not provide full distributed consensus. Unsafe or ambiguous partitions fail closed and require operator recovery.
- Dynamic leases are staged for continuity; Kaya never becomes the DHCP server or network gateway.
