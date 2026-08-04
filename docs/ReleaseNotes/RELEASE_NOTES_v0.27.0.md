# Kaya v0.27.0 Release Notes

Kaya v0.27.0 is a security and reliability hardening release following an internal and community-led review. It does not claim that Kaya is fully secure or independently security audited.

## Security hardening

- Privileged OIDC administrator linking now requires recipient-bound assurance, signed fresh authentication evidence, atomic state consumption and a revocable invitation lifecycle.
- RDP certificate validation is strict by default. Self-signed or privately issued RDP certificates require explicit administrator trust through a SHA-256 certificate pin.
- The shared public demo and all demo-mode application behavior were retired. Its cross-cutting security policy and maintenance burden no longer served the core self-hosted product.
- Backup-agent protocol v2 replaces bearer secret delivery with agent-owned Ed25519/X25519 keys, signed replay-resistant requests, secret-free offers and server-signed encrypted dispatch envelopes. Protocol v1 is inventory-only during a fixed migration window and is then disabled.

## Known limitations

- KAYA-RDP-001 remains High and open: encrypted credential-bearing connection data is still present in WebSocket query data. Operators should minimise proxy/access logging and restrict Remote Manager exposure.
- KAYA-HA-001, KAYA-BG-001 and KAYA-DB-001 remain deferred High-priority hardening work.

The coordinated Kaya and Docker Agent protocol-v2 changes have been merged, and Docker Agent v0.2.1 contains the reviewed agent implementation. Release readiness, including the explicitly deferred High risks above, is recorded in `security-review/V0.27_RELEASE_VALIDATION.md`.
