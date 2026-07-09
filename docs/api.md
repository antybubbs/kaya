# API And Integration Surface

**Kaya version:** `dev`  
**Documentation version:** `dev`

Kaya is primarily a server-rendered web application. It does not currently expose a broad public REST API for normal UI operations. The current API-like surface is made up of agent endpoints, websocket endpoints, JSON helper routes, import/export contracts, and provider integrations.

## Health Check

- `GET /healthz`

Returns a simple health response for container/reverse-proxy checks.

## Compute Agent API

The Docker/compute agent posts inventory and metrics to:

- `POST /infrastructure/vm-docker-manager/api/agent/checkin`

Authentication is by bearer token. Kaya stores a SHA-256 token hash on the `ComputeHost` row.

The endpoint updates:

- Host status and metrics
- Workloads
- Inventory items
- Events
- Agent last-seen metadata

## Backup Agent API

Backup agents poll and update jobs through:

- `GET /infrastructure/backup-manager/api/agent/jobs`
- `POST /infrastructure/backup-manager/api/agent/jobs/{job_id}/status`

Authentication is by bearer token. The API dispatches queued jobs to the matching host and accepts status updates, logs, artifact paths, sizes, and errors.

Security note: job dispatch can include decrypted backup target credentials and decrypted backup job encryption keys.

## Remote Manager Websockets

Remote Manager uses websocket endpoints for browser sessions:

- SSH websocket under `/remote-manager/{remote_id}/ssh/ws`
- RDP websocket under `/remote-manager/{remote_id}/rdp/ws`

These endpoints validate the user session and websocket origin. RDP startup uses short-lived in-memory tokens.

## DNS Provider Integration

DNS Manager currently supports Pi-hole.

The provider service supports Pi-hole v6 session-style auth and legacy Pi-hole API fallback. Data pulled from Pi-hole includes status, summary stats, history, query log, network devices, local DNS hosts, DHCP leases, and lists/blocklists where available.

## Import/Export Contracts

Admin CSV import/export currently supports:

- Licences
- IP addresses

Licence export includes decrypted product keys. This is intentional current behaviour and should be treated as sensitive.

## JSON Helper Routes

Several modules expose JSON or partial-refresh endpoints for UI interactions, including:

- Compute summary updates
- Network monitor card refresh/manual check
- IP ping checks
- Remote RDP preflight/start
- Site Administration test actions

These are internal UI endpoints rather than a stable public API.
