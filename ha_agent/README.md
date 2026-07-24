# Kaya High Availability agent

The agent provides signed registration, live health reporting, generated Keepalived deployment, validated lease staging, controlled failover and opt-in local automatic failover. It exposes no arbitrary command endpoint. Privileged work is limited to fixed helpers named in `kaya-ha-agent.sudoers`.

Automatic failover is disabled by default. When an administrator enables it after a successful controlled test, Keepalived performs the local election. The agent applies a hold-down, confirms functional DNS and exclusive VIP ownership, and only then enables Pi-hole DHCP from the latest validated local lease snapshot. A node that loses ownership disables DHCP. Recovered nodes remain standby because generated configurations use `nopreempt`; automatic failback is not supported.

Events are stored in the local SQLite queue while Kaya is offline and replayed with stable IDs when connectivity returns.

The systemd service runs as the unprivileged `kaya-ha` account. It receives only the ambient `CAP_NET_RAW` capability required for the optional ICMP peer diagnostic. Installation and update validate, replace, reload, and verify the unit so this capability is reconciled without running the agent as root.
