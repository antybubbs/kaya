# Deployment Architecture

## Supported model

Kaya is primarily deployed as a Dockerised web application with persistent storage and environment-based configuration.

A typical deployment contains:

```text
Browser
   |
HTTPS reverse proxy
   |
Kaya application container
   |
Persistent database / mounted data
   |
Managed infrastructure and external services
```

## Reverse proxy

The reverse proxy should terminate TLS and forward traffic to Kaya over a trusted network.

Kaya must only trust forwarding headers from explicitly configured proxy addresses or networks.

Required forwarded information commonly includes:

- original scheme;
- original host;
- client address.

Deployments must not expose the application port directly to untrusted clients while simultaneously trusting arbitrary forwarding headers.

## TLS

Production access should use HTTPS.

Session cookies should be secure, and HSTS should only be enabled when the administrator understands that the hostname will remain HTTPS-capable for the configured period.

## Persistence

The deployment must identify every persistent path.

Upgrading or recreating the application container must not remove:

- the primary database;
- uploaded or generated protected files;
- encryption-key material;
- backups;
- configuration that is intentionally persisted.

## Secrets

Secrets must be supplied through environment variables, mounted secret files or a supported secret-management mechanism.

Do not bake secrets into images or Compose files committed to the repository.

## Health checks

The container health endpoint should report process availability without exposing sensitive state.

A healthy HTTP process does not necessarily mean all monitoring integrations are healthy. Operational dashboards should report subsystem status separately.

## Workers

Kaya's current in-process background services require careful worker configuration. Unless an ADR introduces safe distributed task ownership, the supported production configuration should use one application process for the task-owning instance.

## Upgrades

An upgrade procedure must:

1. take or verify a backup;
2. pull the intended version;
3. apply migrations safely;
4. start the new version;
5. verify health and critical pages;
6. retain a rollback path where practical.

## Backup and recovery

Documentation must distinguish:

- application configuration backup;
- database backup;
- Secure Vault backup;
- uploaded file backup;
- encryption key backup.

A backup that omits the key required to decrypt protected data is not a complete recoverable backup.
