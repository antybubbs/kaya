# Remote Manager Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

Remote Manager provides browser-based SSH and RDP access to configured hosts, plus session recording.

## Routes

- `/remote-manager`
- `/remote-manager/settings`
- `/remote-manager/recordings`
- `/remote-manager/{remote_id}/session`
- `/remote-manager/{remote_id}/panel`
- `/remote-manager/{remote_id}/settings`
- SSH websocket routes
- RDP websocket routes
- RDP check/start endpoints
- Recording upload/media/download/delete endpoints

## Models Used

- `RemoteAccess`
- `IPAddress`
- `RemoteManagerSetting`
- `RemoteSessionRecording`
- `User`

## Workflows

- List configured remotes.
- Configure global remote settings.
- Configure per-host remote display/protocol/terminal/RDP settings.
- Start SSH sessions through the local Node websocket service.
- Start RDP sessions through Guacamole bridge and guacd.
- Upload and manage session recordings.
- Download recordings, including MP4 conversion path for WebM recordings.

## Permissions

- Viewing and starting sessions requires authenticated user.
- Per-host settings require editor.
- Global settings and recording administration require admin.
- RDP certificate trust enrollment, rotation and removal require admin.

## Settings

Settings include Guacamole enablement, guacd host/port, split screen mode, idle timeout, recording controls, terminal preferences, and RDP display/performance options.

## RDP certificate trust

RDP certificate verification is always enabled. Kaya requires NLA and disables Guacamole/FreeRDP certificate bypass and trust-on-first-use. Legacy non-TLS RDP security is not supported as a fallback.

- With no per-host pin, guacd requires a certificate valid under its system CA store.
- For a self-signed host, an administrator may enroll up to three SHA-256 pins under the host's **RDP certificate trust** settings. Obtain and compare each fingerprint outside Kaya using a trusted administrative path; Kaya never scans and trusts the first certificate automatically.
- Kaya stores pins in canonical lowercase form and renders them as FreeRDP 2.x-compatible colon-separated bytes only inside the Guacamole connection settings. Fingerprint values are not placed in logs or URLs.
- A missing, unknown or changed certificate is rejected by guacd. Independently investigate unexpected changes before modifying trust.
- For planned rotation, independently obtain the replacement fingerprint, temporarily retain the old and new pins, deploy the new certificate, verify access, then remove the old pin. Do not leave unused rotation pins indefinitely.
- Changing the configured protocol or port clears stored pins.

### Upgrade inventory

The secure-default migration does not trust legacy certificates. Before upgrade, inventory every enabled RDP host and determine whether it uses a public/system-trusted CA, a private CA installed in guacd, or a self-signed certificate that needs a pin. After upgrade, legacy self-signed connections fail closed until trust is explicitly enrolled. Remote records and recordings are preserved.

## Dependencies

- `RemoteAccess` records are linked one-to-one with IP address records.
- Node SSH helper service.
- Node Guacamole bridge service.
- guacd container/service.
- Recording storage under `/app/data/remote-recordings`.

## Edge Cases And Risks

- Remote credentials are not stored, but they pass through the application process and helper services at connection time.
- RDP certificate fingerprints identify infrastructure. Kaya stores them per host but excludes their values from audit details.
- RDP pins are bound to the effective IP/hostname, protocol and port. Changes through the IP editor, Remote Manager or DNS-managed updates clear pins atomically, record a safe audit event and block RDP until an administrator explicitly re-authorizes the endpoint. Same-address DNS observations and non-endpoint metadata changes do not invalidate trust.
- An invalidated endpoint may be re-authorized with independently verified SHA-256 pins or explicit system-CA trust. Kaya never observes and trusts the replacement certificate automatically.
- Recordings can contain sensitive information.
- Websocket origin checks are important for safety.
- `KAYA-RDP-001` remains open: the current WebSocket flow still carries a credential-bearing encrypted token in query data. Certificate validation does not resolve that separate exposure.
- Node helper processes are managed by the web process.
