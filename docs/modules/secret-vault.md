# Secret Vault

Secret Vault is Kaya's encrypted workspace for recovery keys, sensitive operational notes, documents, certificates and break-glass information. It is not a password manager, credential-injection service, SSH agent or machine-to-machine secrets API.

## Security model

Access requires an active Kaya account, module access, a separate vault PIN or passphrase, fresh multi-factor verification and an unexpired server-side vault session. Verification may use Kaya TOTP or a fresh OIDC step-up whose signed claims prove the configured MFA assurance. A normal Kaya login never unlocks the vault. Sessions auto-lock after inactivity, have an eight-hour absolute lifetime, are bound to the active Kaya session and are revoked on manual lock, logout or recovery.

Each private vault receives a random 256-bit master key. Kaya encrypts sensitive JSON payloads and file contents with AES-256-GCM using unique 96-bit nonces and record-specific associated data. The master key is wrapped independently with:

- a Scrypt-derived key from the vault PIN or passphrase;
- a Scrypt-derived key from the high-entropy recovery key;
- an application wrapping key derived from Kaya's `ENCRYPTION_KEY`.

Argon2 verifiers are also stored for the PIN and recovery key. Database rows contain ciphertext, nonces, hashes, key/schema versions and the minimum control metadata needed for access checks. Original filenames, record titles, notes, tags, dates, descriptions and field values are encrypted. Encrypted attachments use random storage identifiers under `data/secret-vault` in local development and `/app/data/secret-vault` in the container.

Administrators do not receive a route or permission that opens another user's private vault. The application key exists so an authorised server process can serve an owner after successful vault authentication and perform backups; it is not exposed in the interface. Host administrators who control the running process and its keys remain inside the threat boundary.

## Enrolment and daily use

1. Configure Kaya TOTP, or link an OIDC identity whose provider supplies verified MFA assurance.
2. Open **Security → Secret Vault**.
3. Confirm the current Kaya password and a fresh TOTP code, or complete a fresh identity-provider MFA challenge.
4. Choose an eight-or-more digit PIN, or a passphrase of at least 12 characters.
5. Print or save the one-time recovery kit and confirm its key.
6. Unlock with the vault PIN/passphrase and fresh Kaya TOTP or identity-provider MFA.

Masked fields are withheld from HTML until Reveal is selected. Highly Sensitive fields require another PIN/passphrase and a one-use fresh MFA approval. Reveal and download events are written to Kaya's security audit without titles or values.

OIDC step-up requests use a new state, nonce and PKCE transaction with `prompt=login` and `max_age=0`. Kaya verifies that the issuer and subject match the linked identity, requires an `auth_time` no more than five minutes old, and accepts MFA only when the returned `acr` matches an administrator-configured value or `amr` explicitly contains `mfa`. The resulting vault approval is bound to the current user and purpose, expires after five minutes and is consumed once.

## Backup and recovery

A Kaya system backup and a portable vault export solve different recovery problems. Users should maintain both.

Full Kaya backups must include the database, `data/secret-vault` attachment directory and the separately protected `ENCRYPTION_KEY`. A database or attachment copy without the original application key cannot be restored and must fail closed.

The **Backup and Recovery** page creates a `.kayavault` package after fresh PIN and TOTP authentication. The complete portable payload is encrypted with AES-256-GCM under a Scrypt-derived export-passphrase key. Kaya immediately performs a real authenticated decrypt before recording the export as verified. The package needs neither a running Kaya instance nor Kaya's application key.

Validate or extract a package offline:

```text
python scripts/kayavault_recovery.py backup.kayavault --list
python scripts/kayavault_recovery.py backup.kayavault --extract recovered-vault
```

The utility prompts without echoing the passphrase. `--passphrase-file` is available for controlled automation. Extraction refuses to overwrite an existing directory, strips path components from filenames and validates every attachment hash.

To restore into an enrolled vault, open **Backup and Recovery → Restore**, select the package, and provide its export passphrase, current vault PIN and a fresh TOTP code. Kaya authenticates the complete package before importing encrypted records.

If the PIN is forgotten or the Kaya authenticator is unavailable, the owner can recover from the locked page using the vault recovery key plus either the current Kaya password or fresh verified OIDC MFA. Recovery re-wraps the existing master key, revokes every vault session, consumes the old recovery key and displays a replacement key that must be saved and confirmed. It does not disable or reset account-wide two-factor authentication. If both PIN and recovery key are lost, the private vault cannot be recovered under the user-controlled recovery model.

## Disaster scenarios

- **Container lost, data survives:** reinstall the same or a compatible Kaya version, attach the data volume, restore the original configuration and `ENCRYPTION_KEY`, then validate and unlock.
- **Host lost, full backup exists:** restore the database and encrypted attachment directory, supply the external application key, check its fingerprint operationally, and verify a portable export.
- **Kaya and application key lost:** use a `.kayavault` export and the offline recovery utility.
- **Database exists but application key is missing:** stop restoration. Do not generate a replacement key or report success.
- **Package modified:** AES-GCM authentication fails and no content is extracted or restored.

## Administration and deployment

Site Administration → Module Settings → Secret Vault controls the minimum PIN length, maximum auto-lock interval, collection-sharing policy and OIDC MFA policy. Administrators may require Kaya TOTP, verified IdP MFA, or either method, and may list accepted OIDC ACR values. Readiness requires a valid backed-up `ENCRYPTION_KEY`, working MFA, writable protected data storage and a tested portable export.

No new environment variable is mandatory. `KAYA_VAULT_STORAGE_DIR` may override the encrypted attachment path for specialised deployments; that directory must be permission-restricted and included in full backups. Never place `ENCRYPTION_KEY`, recovery keys or export passphrases inside the same backup without separate protection.

## Upgrade and rollback

Startup creates the version-one vault tables without creating vaults for existing users. `scripts/migrate_sqlite.py` contains the equivalent idempotent migration for deployment entrypoints. Back up Kaya before upgrading.

To roll back the application, restore the pre-upgrade database and data snapshot. Do not drop vault tables or encrypted attachments as a routine rollback: older Kaya versions ignore them, and retaining them enables a forward upgrade without data loss.

## Current limitations

The initial implementation supports private vaults, collections, the required item types, protected fields, one encrypted attachment at item creation, recovery-key PIN reset, portable export/restore and offline extraction. Editing/version-restore UI, collection membership management, emergency access, key rotation, notifications, malware scanning and organisation-managed escrow remain future hardening work. Browser clipboard clearing is not claimed because browsers cannot guarantee it.
