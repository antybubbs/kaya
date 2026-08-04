# RDP Certificate-Trust Independent Review

**Finding:** `KAYA-RDP-002`

**Pull request:** [#60](https://github.com/antybubbs/kaya/pull/60)

**Corrective implementation commit:** `8ae6fbe731906898eb605099b9222dca7240b37e`

**Independent result:** **Verified with conditions**

**Current corrective status:** **Resolved; eligible for the controlled stack merge**

## Scope

The fresh independent pass treated certificate settings, endpoint-writer coverage, trust invalidation, migration/rollback and synthetic transport evidence as untrusted. It does not remediate `KAYA-RDP-001` or waive final combined release gates.

The trust boundary runs from an authenticated administrator's host settings, through every effective endpoint writer and the database transaction, into the encrypted Guacamole token and guacd/FreeRDP certificate validation. RDP credentials and certificate fingerprints are treated as sensitive infrastructure data.

## Corrective changes

- A central endpoint-trust service binds pins to address/hostname, protocol and port. Effective identity changes through the primary-IP editor, direct host editor, managed DNS editor and automatic DNS synchronization clear pins, retain an invalidation marker, and add a redacted audit event in the same transaction.
- Same-address observations and non-endpoint metadata changes preserve trust. The reviewed import path does not mutate an existing address; no supported bulk, API, duplication or gateway endpoint writer exists.
- Token creation fails closed while the invalidation marker remains. Only the administrator-only, CSRF-protected trust action with explicit acknowledgement clears it.
- Migration `20260804_02` adds durable invalidation timestamp/reason fields. Its downgrade is blocked before pins or evidence can be removed. Kaya's revision validation prevents an older supported application from starting against the newer database, while a pre-fix backup restored under secure code upgrades to strict CA validation with no automatic pins.
- Canonical stored pins remain `sha256:<64 lowercase hexadecimal characters>`. Kaya renders them as `sha256:<colon-separated bytes>` at the Guacamole boundary, matching the supported FreeRDP 2.11.7 representation. Bypass and TOFU remain false.

## Focused verification

Environment: Debian GNU/Linux 13.6 (trixie), Linux `6.6.87.2-microsoft-standard-WSL2` x86_64, Python 3.12.13. Key dependency versions: pytest 9.1.1, Ruff 0.12.9, FastAPI 0.136.3, SQLAlchemy 2.0.36, Alembic 1.16.5, cryptography 50.0.0, Pydantic 2.13.4 and pydantic-settings 2.14.2. The review image installs the production requirements plus pytest and Ruff.

Command:

```text
python -m pytest -p no:cacheprovider tests/test_release_security_boundaries.py tests/test_rdp_endpoint_trust.py tests/test_database_migrations.py -q
```

Fresh re-verification on 2026-08-04 repeated the command: **56 passed, 0 failed, 0 skipped, 0 subtests**, 164 warnings, 83.03 seconds. The earlier 81.46-second result remains corroborating evidence.

Additional checks:

- `python -m ruff check --no-cache <all changed RDP Python files>`: passed.
- `node --check scripts/guacamole-server.cjs`: passed.
- `git diff --check`: passed.

Complete supported-Linux command:

```text
python -m pytest -p no:cacheprovider -q
```

Result on the final OIDC → RDP stack: **743 passed, 0 failed, 0 skipped, 31 subtests passed**, 11,247 warnings, 135.26 seconds.

## Live synthetic RDP checks

The isolated Docker network exposed no host ports and used only synthetic certificates and clearly fake credentials. Apache Guacamole 1.6.0 was linked to FreeRDP 2.11.7. The disposable XRDP server does not implement NLA, so certificate-handshake cases used TLS security mode; production configuration and static regression tests continue to require NLA and prohibit legacy fallback.

1. Unknown self-signed certificate without a pin: **rejected**; guacd recorded certificate validation failure.
2. Private-CA certificate presented for the wrong hostname: **rejected**.
3. Expired private-CA certificate: **rejected**.
4. Exact independently configured SHA-256 self-signed certificate pin: **accepted** using the FreeRDP `sha256:<colon-separated bytes>` wire form.
5. Certificate replaced while the old pin remained: **rejected**.
6. Bypass/TOFU review: **passed for `KAYA-RDP-002`**. Application settings and bridge defaults set `ignore-cert=false` and `cert-tofu=false`; malformed and non-SHA-256 stored values are rejected before transport. No observe-and-enrol path exists.
7. URL/log review: **confirmed `KAYA-RDP-001`; not passed**. Direct inspection confirms that the encrypted credential-bearing token remains in the browser WebSocket query and is forwarded in the upstream WebSocket query, making it visible to browser tooling and any reverse proxy that records query strings. Upstream exception text is returned to the browser and written to audit detail, so a library exception containing its URI could duplicate the token into application-visible output. Fresh count-only inspection of the isolated guacd logs found zero fake-username, fake-password, pin-prefix and certificate-PEM hits. No reverse proxy was instantiated in the isolated certificate lab; its exposure is deterministic from the unchanged browser/server query construction and remains a confirmed High finding.

A valid private-CA certificate for the requested hostname was also accepted as a positive control.

The certificate matrix supports the remediation claim but is not a substitute for a new independent reviewer. Public-CA and NLA negotiation against a real Windows endpoint remain operational compatibility assumptions, not blockers to the synthetic certificate decision.

## Rollback and recovery result

Supported downgrade below `20260804_02` raises a clear error and retains the schema, pins and invalidation evidence. Restoring a pre-fix database with secure code upgrades it to strict system-CA validation. The minimum safe application/database boundary is documented; emergency recovery must disable RDP or roll forward rather than start the universal-bypass code.

## Remaining risks

- `KAYA-RDP-001` remains High and open, including the exception/audit amplification path described above.
- A trusted CA, administrator-approved pin, host, guacd trust store or administrator account can still be compromised.
- Real Windows NLA and public-CA compatibility require deployment-specific validation.
- The disposable lab resources remain temporarily available for the required final combined-branch run and must be removed afterward.

## Final review result

Result: **Verified with conditions**. No Critical certificate-validation, endpoint-transfer or rollback bypass remains in the reviewed scope. `KAYA-RDP-002` is resolved and PR #60 is eligible for the controlled stack merge after PR #61. Conditions are the documented TLS-only synthetic server limitation, deployment-specific Windows NLA/public-CA validation, and the separate unresolved High `KAYA-RDP-001` query-token exposure.

## References

- [Apache Guacamole 1.6.0 RDP certificate settings](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)
- [FreeRDP 2.11.7 fingerprint comparison](https://github.com/FreeRDP/FreeRDP/blob/2.11.7/libfreerdp/crypto/tls.c)
- ADR-0003 and `docs/modules/remote-manager.md`
