# ADR-0003: Strict RDP certificate trust

**Status:** Accepted (manual-entry mechanism superseded by [ADR-0006](ADR-0006-rdp-certificate-discovery.md))
**Date:** 2026-08-04  
**Decision owners:** Kaya maintainers

> **Note:** ADR-0006 replaces the manual fingerprint-paste workflow described below with guided, read-only Kaya-side discovery and an admin-confirmed trust step. Every other decision here — NLA required, `ignore-cert=false`, `cert-tofu=false`, per-host pin scoping, endpoint-change invalidation, guacd/FreeRDP as the authoritative comparison — is unchanged and remains authoritative.

## Context

Kaya previously set Apache Guacamole's `ignore-cert` option to true in every RDP connection token and in the local bridge defaults. Encryption was present, but an active network attacker could present any certificate without Kaya or guacd rejecting it (`KAYA-RDP-002`).

RDP trust crosses the authenticated browser, Kaya, the local Guacamole bridge, guacd/FreeRDP and the selected remote host. Kaya cannot safely use trust-on-first-use because first contact may already be intercepted, and automatic enrollment would convert an attack into durable trust.

Apache Guacamole 1.6.0 supports normal system CA validation and explicit FreeRDP-format `cert-fingerprints` matching.

## Decision

- Kaya and the Guacamole bridge require NLA (TLS-backed authentication), set `ignore-cert=false` and set `cert-tofu=false`. Legacy non-TLS RDP security is not an accepted fallback.
- With no host pin, guacd validates the RDP certificate against its system CA store.
- Administrators may enroll up to three per-host SHA-256 certificate pins in normalized `sha256:<64 hexadecimal characters>` form. At the Guacamole boundary, Kaya renders each validated digest as `sha256:<colon-separated bytes>`, the representation required by the supported FreeRDP 2.x runtime, and passes that allowlist through `cert-fingerprints`.
- Pin enrollment and removal require an active administrator session, CSRF validation and explicit acknowledgement that the host, port and fingerprint were compared using an independent trusted channel. Editors may view the trust state but cannot change it.
- The effective RDP endpoint identity is the stored hostname/IP address, protocol and port. A shared domain service owns changes to that tuple from the primary IP editor, Remote Manager editor, explicit DNS-managed update and automatic DNS synchronization. Import/bulk currently has no endpoint-changing remote path; host duplication and RDP gateway fields are not supported.
- Any effective endpoint change clears existing RDP pins, records an invalidated-trust timestamp/reason and stages a redacted audit event in the same database transaction. The invalidated state blocks RDP token creation across workers and restarts until an administrator independently verifies the new endpoint and explicitly re-authorizes either pins or system-CA trust. Same-address and non-endpoint metadata changes preserve trust. No certificate is observed or trusted automatically.
- Trust changes are audited by host record and pin count only. Fingerprint values, RDP credentials and upstream certificate details are not placed in audit text.
- Kaya does not scan and auto-trust an RDP certificate. Operational tooling outside Kaya is used to obtain and compare the fingerprint.

## Consequences

- CA-issued hosts work without per-host enrollment when guacd trusts their CA and the certificate identity matches.
- Existing self-signed hosts fail closed after upgrade until an administrator enrolls a verified fingerprint or installs the issuing private CA in guacd's system trust store. Hosts that cannot support NLA must be upgraded rather than re-enabled through legacy RDP security.
- Up to two old/new pins may coexist briefly for planned rotation, with a third slot reserved for exceptional staged deployments. The old pin must be removed after all endpoints rotate.
- Guacd/FreeRDP performs the presented-certificate comparison. Kaya's responsibility is strict defaults, validated configuration, per-host scoping and safe transport of the pin allowlist.
- A supported rollback cannot cross below the safe application/database boundary at Alembic revision `20260804_02`. If the secure release cannot run, disable RDP connectivity and roll forward; do not downgrade the database or deploy an image that universally accepts certificates.

## Security and privacy impact

Positive. Universal certificate bypass and automatic first-use trust are removed. Certificate fingerprints identify infrastructure and are therefore restricted to authenticated settings views and excluded from audit content.

## Compatibility and migration

The migration adds nullable per-host pin and invalidated-trust fields and does not auto-enroll any certificate. Legacy RDP hosts immediately use system CA validation. Operators must inventory RDP hosts before upgrade, obtain self-signed/private-CA fingerprints through an independent channel, and enroll them after upgrade. Existing remote records and credentials are preserved.

The minimum safe boundary is revision `20260804_02` together with application/bridge code that enforces NLA, `ignore-cert=false` and `cert-tofu=false`. Downgrade below that revision is blocked and retains pins and invalidation evidence. An older application cannot start against the newer unknown revision through Kaya's supported database preparation path.

Restoring a backup from before this fix under the secure application upgrades it with no auto-pins and strict CA validation. Do not start an older image against a restored pre-fix database; it contains the confirmed universal bypass. The supported recovery is to remain at or above the safe boundary, disable RDP if necessary, correct trust enrollment or CA installation, and roll forward.

## References

- Apache Guacamole 1.6.0 manual, RDP `ignore-cert`, `cert-tofu` and `cert-fingerprints`
- `SECURITY_ENGINEERING.md`
- `security-review/FINDINGS_REGISTER.md` (`KAYA-RDP-002`)
