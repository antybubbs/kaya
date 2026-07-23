# Kaya v0.25.0 — High Availability Beta

Kaya v0.25.0 introduces the first complete Pi-hole High Availability Beta, expands DNS Manager to consume an HA cluster as one logical provider, refreshes Runbook Manager, and hardens authentication and infrastructure trust paths.

## High Availability Beta

- New High Availability module with Overview, Clusters, and Providers/Apps navigation.
- Guided Pi-hole cluster creation with active and standby nodes, connection testing, validation, and editable node settings.
- Simple node-agent installation, registration, update/reinstall, revocation, version visibility, and uninstall guidance.
- Keepalived deployment with generated configuration, validation, backup, rollback, VIP ownership reporting, and live status.
- Controlled and automatic failover, split-brain protection, hold-down checks, safe recovery as standby, and failover history.
- Configuration comparison and synchronisation from one explicit authority, including review, backup, apply, read-back verification, rollback, and optional automatic sync.
- DHCP continuity with validated local lease snapshots while leaving DNS and DHCP operation independent of Kaya availability.
- Live cluster screens, activity and alerts, current node roles, health, DNS/DHCP/VIP state, and report download.
- Data-preserving cluster removal: node, validation, DNS-link, and history records remain unless explicitly deleted by the owning module.

## DNS Manager integration

- A healthy deployed Kaya HA Pi-hole cluster can be selected as a DNS Manager connection source.
- DNS Manager continues to see one logical Pi-hole through the cluster virtual IP.
- Existing provider identity, linked IP details, observations, investigations, and history are preserved when moving from standalone to HA.
- Standalone Pi-hole providers continue to work as before.
- Pi-hole-managed and external DHCP modes are handled explicitly; network services remain local if Kaya is offline.

## Runbook Manager

- Redesigned overview and editor layouts with a narrower, clearer editing surface.
- Dedicated Runbooks view with tile and sortable table presentation.
- Improved spaces, tags, templates, filters, table settings, and dark-mode controls.
- Navigation, overflow, button visibility, and dropdown clipping fixes.

## Authentication and account experience

- Hardened OpenID Connect policy, identity linking, role handling, and recovery paths.
- Redesigned profile and user-edit pages with aligned fields and clearer authentication status.
- Improved dark-mode account dropdown.
- Authoritative server-side application sessions for HTTP and Remote Manager WebSockets.
- Session revocation after password, MFA, or administrator account-security changes.
- Current-password confirmation before starting local TOTP enrolment.
- Deployment-generated first-run setup token and transactional single-winner administrator creation.

## Remote Manager security

- SSH connections now require an enrolled, operator-verified server fingerprint.
- Host keys are rechecked during enrolment and verified before SSH authentication.
- RDP and SSH WebSockets require an active user and active server-side application session.
- Recording uploads stream in bounded chunks and clean up rejected partial files.

## Backup Manager Beta and secure storage

- Backup Manager now follows the same Beta module enable/disable pattern as High Availability.
- Legacy plaintext FTP targets remain stored for migration but cannot be tested or dispatched.
- Use SFTP, SMB, or a securely mounted local path.

## Demo and release safety

- The public demo blocks all HA agent endpoints and all HA mutations while retaining read-only presentation.
- Demo resets remain deterministic and infrastructure workers remain disabled.
- Production startup rejects trust-all proxy configuration; configure the exact reverse-proxy IP or CIDR.
- Existing DNS Manager history and linked data are not deleted as a side effect of HA or provider removal.

## Upgrade notes

- Existing installations receive a generated first-run setup token in the protected runtime-secret file; it is ignored after an administrator already exists.
- Existing SSH entries must enrol and verify their host key before opening a new SSH session.
- Existing FTP backup-target metadata is retained, but the target must be migrated before it can be used.
- v0.25.0 is a Beta intended for trusted private LAN or VPN deployment. It is not approved for direct exposure of the main Kaya interface to the public internet.
