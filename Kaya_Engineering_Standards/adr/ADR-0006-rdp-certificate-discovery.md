# ADR-0006: Guided RDP certificate discovery

**Status:** Accepted
**Date:** 2026-08-04
**Decision owners:** Kaya maintainers

## Context

ADR-0003 correctly closed a universal certificate bypass (`ignore-cert=true`) by requiring administrators to obtain a SHA-256 fingerprint through tooling outside Kaya and paste it into a textarea. That is secure but unusable for Kaya's actual audience: homelab operators who do not routinely compute or compare TLS fingerprints, alongside enterprise administrators who expect a guided workflow. ADR-0003 states plainly that "Kaya does not scan and auto-trust an RDP certificate."

Kaya already runs an equivalent workflow for SSH: `scan_ssh_host_key` shells out to `ssh-keyscan` to retrieve a candidate host key, shows it for review, and only stores it after re-scanning and confirming an exact match at the moment of trust (`app/routers/remote_manager.py`, `scan_remote_host_key` / `trust_remote_host_key`). Its own identity page states the honest limitation plainly: "Kaya can confirm the key is stable during enrolment, but only an independent console can prove the first key was not intercepted." This ADR extends that same reviewed pattern to RDP certificates, replacing the raw-fingerprint textarea, rather than introducing a new trust model.

## Decision

- Kaya performs read-only RDP certificate discovery (`app/services/rdp_certificate_discovery.py`): it completes the RDP pre-TLS negotiation and TLS handshake with certificate verification disabled (`ssl.CERT_NONE`), retrieves the presented certificate, and never uses that connection or certificate for a real session.
- Discovery never stores or trusts anything. The administrator reviews the subject, issuer, self-signed heuristic, validity window, SANs and fingerprint, with an explicit on-screen warning that the certificate is not yet trusted.
- Trusting a certificate ("Trust Certificate" / "Replace Trusted Certificate") re-runs discovery immediately before persisting and only stores the fingerprint if it exactly matches what was reviewed, closing the gap between "shown to the administrator" and "saved to the trust store" — the same TOCTOU guard `trust_remote_host_key` already applies for SSH. A mismatch refuses to store anything and is audited at `critical` severity (`rdp_certificate_changed_during_enrolment`).
- `ignore-cert=false` and `cert-tofu=false` (ADR-0003) are unchanged. guacd/FreeRDP's `cert-fingerprints` comparison remains the sole authoritative enforcement of RDP certificate trust; Kaya's discovery service is never consulted by the real session.
- Starting an RDP session with an existing trusted certificate runs a short, best-effort pre-flight discovery (2.5s timeout) to compare the live certificate against the stored pin before creating a Guacamole token. A mismatch blocks the token and redirects to a "previously trusted vs. currently presented" comparison page instead of a generic connection failure. A pre-flight timeout or discovery error is not a mismatch: it falls through to the normal connection attempt unchanged, so a transient network hiccup can never block a legitimate connection, and it can never weaken or substitute for guacd's own check.
- Both discovery and trust changes require an authenticated administrator (`require_admin`), not the editor-level bar used for SSH host-key scanning. This is a deliberate, existing asymmetry (the manual RDP fingerprint flow was already admin-only) that this change preserves rather than relaxes.
- The manual raw-fingerprint textarea and its acknowledgement checkbox are removed. ADR-0003's rotation allowance (up to three pins, so an old and new certificate can coexist during a planned rotation) is preserved through a guided "keep previous certificate trusted during rotation" option on Replace, instead of manual pin management.
- Certificate metadata (subject, issuer, validity, SANs) is never persisted. It is ephemeral, request-scoped data shown immediately after a discovery action. A persisted snapshot would go stale with no invalidation trigger (unlike the fingerprint pin, which ADR-0003's endpoint-change invalidation already covers), so it is fetched live, on demand, only.
- Kaya still cannot prove that first contact with a never-before-seen host was not already intercepted. This is disclosed to the administrator in the discovery/trust UI, matching the equivalent SSH disclosure, rather than presented as a stronger guarantee than it is.

## Consequences

- Administrators no longer compute or paste SHA-256 fingerprints for RDP. The guided flow covers first-trust, planned rotation and forced re-review after an endpoint change or certificate mismatch.
- A host that cannot complete the RDP TLS negotiation (very old RDP-Standard-Security-only servers) cannot be discovered through Kaya; the manual pathway no longer exists for that rare case, and such hosts should be upgraded to support TLS-secured RDP.
- The pre-flight check adds a bounded, short-timeout discovery attempt to session start only when a certificate is already trusted; it is advisory and fails open, so it cannot make a working connection fail, only make a failing one fail with a clearer reason.

## Security and privacy impact

No weakening of ADR-0003's enforcement. Discovery is read-only and never trusted implicitly; every trust-affecting write path re-verifies live immediately before persisting; guacd/FreeRDP remains the authoritative comparison point. Certificate fingerprints and subject/issuer/SAN values continue to be excluded from audit `detail`/`metadata_json` (only counts, mode and structural labels are recorded), consistent with ADR-0003's treatment of fingerprints as infrastructure-identifying data.

## Compatibility and migration

No database migration. This reuses the existing `rdp_cert_fingerprints`, `rdp_trust_invalidated_at` and `rdp_trust_invalidated_reason` columns from ADR-0003 unchanged. Existing trusted pins and invalidation state carry over exactly as they were.

## References

- ADR-0003: Strict RDP certificate trust (superseded in part by this ADR — the manual-entry mechanism only; NLA/`ignore-cert`/`cert-tofu`/endpoint-invalidation remain authoritative from ADR-0003)
- `app/routers/remote_manager.py` (`scan_ssh_host_key` / `trust_remote_host_key` — the mirrored SSH pattern)
- `app/services/rdp_certificate_discovery.py`
