# Kaya HA agent bootstrap transport

The agent provides secure registration, signed heartbeats, desired-state receipt, and a durable offline event queue. Milestone 5 adds generated Keepalived configuration and VIP ownership reporting. It intentionally has no arbitrary command interface and does not modify Pi-hole or control DHCP.

The recommended installation method is the per-node command generated on the cluster's **Agents** page. Select **Install Agent**, paste the command into that Pi-hole's SSH terminal, and enter the one-time token at the hidden prompt. The installer supports Debian, Ubuntu, and Raspberry Pi OS. It installs Keepalived and required packages, checksum-verifies the installer, validates the restricted sudo policy, registers the node, and starts the service.

For development or manual registration, use the one-time cluster/node registration values shown in Kaya:

```text
python3 kaya_ha_agent.py register --kaya-url https://kaya.example --cluster-id CLUSTER_ID --node-id NODE_ID --token ONE_TIME_TOKEN
python3 kaya_ha_agent.py run
```

The node must trust Kaya's TLS certificate. There is no insecure TLS bypass. Run the service as a dedicated `kaya-ha` account; the supplied systemd unit restricts its filesystem access to `/var/lib/kaya-ha-agent`.

The Ed25519 private key, configuration, observed state, and unsent events remain on the node. Files are written with restrictive permissions, and desired state with an older cluster generation is rejected.

## Keepalived helper

Install `kaya_ha_keepalived_helper.py`, `kaya_ha_transition.py`, and `check-pihole-dns` under `/usr/lib/kaya-ha-agent/` as root-owned executable files. Validate and install `kaya-ha-agent.sudoers` under `/etc/sudoers.d/` with mode `0440`.

The agent can then request only two privileged operations: apply the fixed pending configuration path, or read ownership of a validated IPv4 address. The helper backs up Kaya's include and the main Keepalived file, adds the standard `conf.d` include without replacing unrelated content, runs Keepalived's configuration test, and rolls back both files if validation or activation fails.

Transition hooks record Keepalived role and VIP state. They explicitly leave DHCP control disabled in this milestone.
