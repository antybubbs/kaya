# ADR-0003: Strict RDP certificate trust

**Status:** Proposed  
**Date:** 2026-08-04  
**Decision owners:** Kaya maintainers

## Context

Kaya previously set Apache Guacamole's `ignore-cert` option to true in every RDP connection token and in the local bridge defaults. Encryption was present, but an active network attacker could present any certificate without Kaya or guacd rejecting it (`KAYA-RDP-002`).

RDP trust crosses the authenticated browser, Kaya, the local Guacamole bridge, guacd/FreeRDP and the selected remote host. Kaya cannot safely use trust-on-first-use because first contact may already be intercepted, and automatic enrollment would convert an attack into durable trust.

Apache Guacamole 1.6.0 supports normal system CA validation and explicit FreeRDP-format `cert-fingerprints` matching.

## Decision

- Kaya and the Guacamole bridge require NLA (TLS-backed authentication), set `ignore-cert=false` and set `cert-tofu=false`. Legacy non-TLS RDP security is not an accepted fallback.
- With no host pin, guacd validates the RDP certificate against its system CA store.
- Administrators may enroll up to three per-host SHA-256 certificate pins in normalized `sha256:<64 hexadecimal characters>` form. When pins exist, Kaya passes the exact allowlist through Guacamole's `cert-fingerprints` setting.
- Pin enrollment and removal require an active administrator session, CSRF validation and explicit acknowledgement that the host, port and fingerprint were compared using an independent trusted channel. Editors may view the trust state but cannot change it.
- Host protocol or port changes clear existing RDP pins. A changed certificate is rejected until an administrator independently verifies and enrolls the new fingerprint.
- Trust changes are audited by host record and pin count only. Fingerprint values, RDP credentials and upstream certificate details are not placed in audit text.
- Kaya does not scan and auto-trust an RDP certificate. Operational tooling outside Kaya is used to obtain and compare the fingerprint.

## Consequences

- CA-issued hosts work without per-host enrollment when guacd trusts their CA and the certificate identity matches.
- Existing self-signed hosts fail closed after upgrade until an administrator enrolls a verified fingerprint or installs the issuing private CA in guacd's system trust store. Hosts that cannot support NLA must be upgraded rather than re-enabled through legacy RDP security.
- Up to two old/new pins may coexist briefly for planned rotation, with a third slot reserved for exceptional staged deployments. The old pin must be removed after all endpoints rotate.
- Guacd/FreeRDP performs the presented-certificate comparison. Kaya's responsibility is strict defaults, validated configuration, per-host scoping and safe transport of the pin allowlist.

## Security and privacy impact

Positive. Universal certificate bypass and automatic first-use trust are removed. Certificate fingerprints identify infrastructure and are therefore restricted to authenticated settings views and excluded from audit content.

## Compatibility and migration

The migration adds a nullable per-host pin field and does not auto-enroll any certificate. Legacy RDP hosts immediately use system CA validation. Operators must inventory RDP hosts before upgrade, obtain self-signed/private-CA fingerprints through an independent channel, and enroll them after upgrade. Existing remote records and credentials are preserved.

Rollback removes stored pins and reintroduces the old vulnerable behavior if old application code is restored; rollback is not a security-equivalent recovery. Prefer correcting trust enrollment or CA installation while remaining on the secure release.

## References

- Apache Guacamole 1.6.0 manual, RDP `ignore-cert`, `cert-tofu` and `cert-fingerprints`
- `SECURITY_ENGINEERING.md`
- `security-review/FINDINGS_REGISTER.md` (`KAYA-RDP-002`)
