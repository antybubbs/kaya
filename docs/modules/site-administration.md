# Site Administration Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

Site Administration is the central admin area for settings, security, integrations, users, audit, import/export, custom fields, and managed lists.

## Routes

- `/admin`
- `/system/site-administration`
- `/system/audit-logs`
- `/system/about`
- `/team/users`
- `/team/users/new`
- `/team/users/{user_id}/edit`
- `/team/users/{user_id}/reset-2fa`
- `/data/import-export`
- `/data/custom-fields`
- `/data/categories`

## Models Used

- `User`
- `AppSession`
- `AuditLog`
- `RemoteManagerSetting`
- `DNSProviderConfig`
- `CustomField`
- `ManagedListItem`
- Several module tables for counts/import/export

## Settings

Site Administration includes settings for:

- General application identity
- Base URL
- GitHub/version checking
- Upload limits
- Security headers and trusted hosts
- RDP token lifetime
- Remote Manager / Guacamole
- DNS Manager / Pi-hole provider
- Backup targets
- SMTP and email templates

Settings are stored primarily in `remote_manager_settings` as key/value rows. This table is used for more than remote manager settings, including global site settings, backup targets, DNS flags, SMTP configuration, and security configuration.

## Permissions

- Admin only for most pages.
- User profile security is separate and available to the current user.

## Workflows

- Create/edit users.
- Reset user 2FA.
- View audit logs.
- View system/about information.
- Configure site/security/email/remote/DNS/backup settings.
- Test backup storage.
- Test DNS provider.
- Send test email.
- Manage custom fields.
- Manage categories/managed lists.
- Import/export supported data.

## Edge Cases And Risks

- The admin router is large and mixes unrelated settings concerns.
- Site settings are stored in `RemoteManagerSetting`, which now has broader meaning than its name suggests.
- Settings that contain secrets must be encrypted before storage.
- Some test actions reach outside Kaya and must remain blocked or constrained in demo mode.
