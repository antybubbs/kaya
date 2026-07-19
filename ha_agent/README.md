# Kaya HA agent bootstrap transport

This milestone agent provides secure registration, signed heartbeats, desired-state receipt, and a durable offline event queue. It intentionally has no arbitrary command interface and does not install or control Pi-hole, DHCP, Keepalived, or the virtual IP.

Use the one-time cluster/node registration values shown in Kaya:

```text
python3 kaya_ha_agent.py register --kaya-url https://kaya.example --cluster-id CLUSTER_ID --node-id NODE_ID --token ONE_TIME_TOKEN
python3 kaya_ha_agent.py run
```

The node must trust Kaya's TLS certificate. There is no insecure TLS bypass. Run the service as a dedicated `kaya-ha` account; the supplied systemd unit restricts its filesystem access to `/var/lib/kaya-ha-agent`.

The Ed25519 private key, configuration, observed state, and unsent events remain on the node. Files are written with restrictive permissions, and desired state with an older cluster generation is rejected.
