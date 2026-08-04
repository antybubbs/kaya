# Backup Agent protocol v2 operations

Provision Kaya's dispatch-signing key once from the authenticated administrator control, create a Docker-agent host, then issue its one-time bootstrap. The bootstrap is bound to that host, expires in 15 minutes and is never recoverable from Kaya.

Set `KAYA_AGENT_BOOTSTRAP_TOKEN` only for the first agent start and mount a persistent `KAYA_AGENT_STATE_DIR` at `/var/lib/kaya-agent`. After enrollment succeeds, remove the bootstrap variable and restart. Protect and back up the state volume: it contains the agent-generated Ed25519 and X25519 private keys. Never copy one state volume between hosts.

For rotation, issue a fresh bootstrap, invoke the agent's protocol-v2 rotation with that value, then remove it. Rotation is refused while a dispatch is claimed or running. Revocation or decommissioning immediately retires the active signing key and invalidates grants; the agent then fails closed with authentication errors.

The 14-day v1 window begins at deployment. V1 can submit inventory only. It cannot poll jobs, report backup status or receive secrets. At cutoff Kaya clears legacy hashes. The deadline is not extended by rollback.

Back up the Kaya database, uploads and the original `ENCRYPTION_KEY` together. The wrapped server dispatch-signing private key is unusable without that key. Validate restore by confirming the stored public key matches the unwrapped private key before enabling dispatch. If validation fails, leave jobs queued and perform an explicit administrator-authorised recovery; Kaya does not silently replace the signing key.

Downgrade below the protocol-v2 migration is intentionally blocked. Safe recovery pauses dispatch and rolls forward to a security-equivalent build. It never restores bearer-token secret delivery.
