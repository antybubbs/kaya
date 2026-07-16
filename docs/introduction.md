# Introduction

**Kaya version:** `dev`  
**Documentation version:** `dev`

Kaya is a self-hosted infrastructure management application for homelabs, small IT environments, and technical administrators who want a single place to track infrastructure assets, IP space, remote access, runbooks, licences, DNS, backups, compute hosts, and operational history.

The application combines lightweight CMDB-style documentation with practical operational workflows:

- Inventory tracking
- SSH/RDP launch workflows
- Network reachability checks
- DNS visibility through Pi-hole
- Docker/Proxmox monitoring
- Backup job coordination
- Audit trails
- Site and security administration

## Target Users

- Homelab administrators
- Small business IT owners
- Infrastructure engineers managing a compact environment
- Operators who want documentation and tooling in one web UI

## Core Concepts

- **Users and roles:** admin, editor, viewer
- **Infrastructure records:** hardware, racks, IP addresses, VLANs, licences, domains
- **Operational modules:** remote access, monitoring, DNS, compute, backup jobs
- **Documentation:** runbook spaces and pages
- **Settings:** stored mostly in the database via `RemoteManagerSetting`
- **Auditability:** user and request activity is recorded in `AuditLog`
- **Demo mode:** seeds synthetic data and blocks sensitive actions

## Functional Boundaries

Kaya currently focuses on small single-instance deployments. It can track and operate against real infrastructure, but it is not yet a distributed control plane. Background polling, monitoring, compute sync, and domain polling run in the web application process.

Planned or disabled features shown in the UI, such as SSL Certificate Manager, Secret Vault, Groups, Duplication Check, System Backups, and IDP Integration, should be treated as future/planned until implemented.
