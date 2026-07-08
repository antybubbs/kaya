# Docker / Compute Manager Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

The VM/Docker Manager monitors compute hosts and workloads from Proxmox and Docker agent sources.

## Routes

- `/infrastructure/vm-docker-manager`
- Host create/edit/detail/sync/delete routes
- Agent check-in API
- Workload detail/update routes
- Summary API

## Models Used

- `ComputeHost`
- `ComputeWorkload`
- `ComputeInventoryItem`
- `ComputeMetric`
- `ComputeEvent`
- `IPAddress`

## Workflows

- Add Proxmox hosts.
- Add Docker agent hosts and generate one-time agent token.
- Poll/sync compute hosts.
- Accept Docker agent check-ins.
- Track workloads, inventory, metrics, and events.
- Link workload addresses to IP records.
- Update workload owner/backup policy.

## Permissions

- Read requires authenticated user.
- Host/workload changes require editor.
- Agent API uses bearer token hash, not user session.

## Settings And Secrets

- Proxmox API tokens are encrypted.
- Docker agent token hashes are stored.
- Host poll intervals are configurable.

## Dependencies

- Compute background monitor loop.
- Docker agent check-ins.
- Proxmox API where configured.

## Edge Cases And Risks

- Direct Docker support exists in service code, while UI is focused on Docker agent and Proxmox.
- Background polling can duplicate in multi-instance deployments.
- Agent API security depends heavily on token secrecy.
