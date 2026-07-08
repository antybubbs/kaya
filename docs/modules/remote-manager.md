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

## Settings

Settings include Guacamole enablement, guacd host/port, split screen mode, idle timeout, recording controls, terminal preferences, and RDP display/performance options.

## Dependencies

- `RemoteAccess` records are linked one-to-one with IP address records.
- Node SSH helper service.
- Node Guacamole bridge service.
- guacd container/service.
- Recording storage under `/app/data/remote-recordings`.

## Edge Cases And Risks

- Remote credentials are not stored, but they pass through the application process and helper services at connection time.
- Recordings can contain sensitive information.
- Websocket origin checks are important for safety.
- Node helper processes are managed by the web process.
