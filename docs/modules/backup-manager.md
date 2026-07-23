# Backup Manager Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

Backup Manager tracks manual backup records and coordinates Docker workload backup/restore jobs through the Docker agent.

## Routes

- `/infrastructure/backup-manager`
- Manual backup creation
- Docker workload policy/backup/restore routes
- Backup agent job polling/status APIs

## Models Used

- `BackupRecord`
- `BackupJob`
- `ComputeHost`
- `ComputeWorkload`
- `RemoteManagerSetting`

## Workflows

- Create manual backup records.
- Show Docker-backup-capable workloads.
- Configure per-workload backup policy and target.
- Queue backup jobs.
- Queue restore jobs from latest successful backup.
- Dispatch queued jobs to agents.
- Receive job status, logs, artifacts, and size.

## Permissions

- Viewing requires authenticated user.
- Creating/queueing/changing requires editor.
- Agent APIs use bearer token hash.

## Settings

- Backup targets are stored in settings JSON.
- Target types include local, SMB, and SFTP-style configuration. Legacy plaintext FTP targets remain visible so their metadata is not lost, but Kaya blocks tests and job dispatch until they are migrated.
- Remote passwords are encrypted.
- Backup job encryption keys are encrypted before storage and decrypted for agent dispatch.

## Dependencies

- Compute hosts and workloads.
- Docker agent capability metadata.
- Backup target site settings.

## Edge Cases And Risks

- Agents receive decrypted backup credentials and job encryption keys.
- Backup target validation varies by target type.
- Restore assumes the agent can access and interpret artifact paths.
- The application's own database/upload backup is not fully handled by this module.
