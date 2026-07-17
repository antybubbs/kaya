# Kaya
Dark Mode
<img width="2551" height="1272" alt="Screenshot 2026-07-07 203240" src="https://github.com/user-attachments/assets/2a956170-9e90-4562-af47-1ed581ad9db2" />

Light Mode
<img width="2547" height="1270" alt="Dashboard-Light" src="https://github.com/user-attachments/assets/f69d9ba3-9c2d-4b30-b875-2d0ae2d0fbf4" />


> **Your Infrastructure. Your Home.**
>
> A self-hosted infrastructure platform built for homelabs,
> and users who want complete control of their
> infrastructure.

![GitHub
release](https://img.shields.io/github/v/release/antybubbs/kaya)
![License](https://img.shields.io/github/license/antybubbs/kaya)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)

------------------------------------------------------------------------

## Welcome Home

Lets be honest, homelab infrastrcuture never stays small. I am guilty of this.

A Raspberry Pi becomes a server. One Docker container becomes twenty. A
virtual machine becomes a cluster. Before long we are all juggling IP
addresses, documentation, credentials, licences, runbooks and bookmarks
across half a dozen different places all while trying to keep your end users (family, friends) happy!

**Kaya brings it all together.**

Named after the Southern African word for **home**, Kaya gives your
infrastructure a place to belong. Whether you're managing your own home infrastructure, a
business environment or customer systems, Kaya provides one clean,
modern workspace to organise everything that matters.

I personally use Kaya for my homelab management. This repo is for me to manage the App and updates and to share the journey as I go.

Use it, dont use it. Its up to you really (but it is quite cool if I do say so myself)

------------------------------------------------------------------------

# Features

Kaya is more than a homelab inventory. It is a self-hosted operations hub for the infrastructure, access, documentation, monitoring and recovery information that usually ends up scattered across spreadsheets, bookmarks, terminals and password-protected files.

| Area | What Kaya gives you |
|------|---------------------|
| **One live operations dashboard** | Customisable widgets, health summaries, warnings, recent activity and monitor mode |
| **Infrastructure visibility** | Proxmox hosts, Docker hosts, workloads, physical assets, racks and backups |
| **Network intelligence** | VLANs, IPAM, DHCP history, DNS analytics, domains and WAN monitoring |
| **Remote workspace** | Browser-based SSH and RDP, split-screen sessions and session recordings |
| **Security workspace** | Private encrypted vaults, secure temporary delivery and encrypted licence keys |
| **Operational knowledge** | Searchable Markdown runbooks, images, tags, spaces and page history |
| **Team-ready access** | Local login, TOTP, OpenID Connect, roles, account linking and audit logs |
| **Self-hosted by design** | Docker Compose, SQLite, persistent volumes, PWA support and no mandatory cloud service |

## Live, customisable dashboard

- A modular dashboard that brings infrastructure, compute, DNS, backups, networking, remote access, licences, documentation, users, audit activity and Secret Vault health into one view.
- Silent live refreshes without full-page reloads, plus clear **Live**, **Delayed**, **Stale**, **Offline** and **Connection lost** states.
- A central **Attention Required** feed that surfaces offline hosts, unhealthy workloads, DNS warnings, failed backups and other actionable events.
- Per-user widget preferences with show/hide controls, multiple widget sizes and automatic saving.
- Drag-and-drop ordering on desktop, keyboard reordering and touch-friendly move controls on mobile.
- Optional full-screen **Monitor mode** for a wallboard-style operational view.
- Role-aware widgets: users only see data and modules they are authorised to access.
- Widget failure isolation, so one unavailable integration does not take down the rest of the dashboard.

## VM and Docker Manager

- Monitor **Proxmox** hosts and **Docker Agent** hosts from the same interface.
- Track host state, CPU, memory, storage, version, last-seen time and configurable polling intervals.
- Inventory VMs and containers with running, stopped, unhealthy and restarting states.
- Retain workload metrics, inventory items and operational events.
- View workload CPU, memory, storage, uptime, ownership, tags and platform metadata.
- Link discovered workload addresses back to managed Kaya IP records.
- Assign workload owners and backup policies.
- Generate one-time Docker Agent enrolment tokens; only token hashes are retained by Kaya.
- Encrypt stored Proxmox API tokens and support manual host synchronisation.

## Hardware Asset Manager

- Track servers, switches, storage, laptops, appliances, power equipment and any other physical asset.
- Search and filter by category, status, location and other managed values.
- Store asset tags, manufacturer, model, serial number, assignment, purchase details, warranty, supplier and notes.
- Add asset photos and downloadable supporting attachments.
- Extend asset records with administrator-defined custom fields.
- Use configurable category, location and status lists instead of hard-coded choices.
- Associate physical assets directly with rack equipment.

## Rack Manager

- Model multiple racks with real rack-unit positions.
- Add, edit, move and remove mounted equipment through a visual rack layout.
- Drag equipment into position and persist the layout.
- Track item height, category, colour and front, rear or both-side mounting.
- Validate rack height and prevent overlapping equipment on the same mount side.
- Link rack items to Hardware Asset Manager records for a joined physical inventory.

## Backup Manager

- Keep manual backup records alongside automated Docker workload jobs.
- See backup-capable workloads and configure a policy and target per workload.
- Queue encrypted backup jobs and restore the latest successful backup through the Kaya Docker Agent.
- Track queued, dispatched, running, successful and failed jobs with logs, artifact paths and sizes.
- Configure multiple backup targets, including local, SMB, FTP and SFTP-style storage.
- Encrypt remote target passwords and per-job backup encryption keys at rest.
- Test backup storage from Site Administration before relying on it.

## VLAN and IP Manager

- Maintain a searchable IP address inventory organised by **VLAN → Category → device/allocation**.
- Create multiple VLANs and DHCP ranges with subnet-aware validation.
- Track hostname, MAC address, assignment type, owner/category context, notes and custom fields.
- Bulk-update VLAN, category and assignment type across multiple records.
- Ping managed addresses directly from Kaya.
- Enable monitoring and Remote Manager access while editing an IP record.
- Link IP records to compute workloads and retained DNS clients.
- Review current and historical DHCP leases even when the DNS provider is unavailable.
- Preserve lease intervals so historical DNS traffic remains attributed to the correct device after an address is reused.
- Surface observed DNS clients that have not yet been promoted into managed IP records.

## IP and WAN Monitor

- Background ICMP monitoring for LAN devices, services, gateways and external WAN targets.
- Retain availability, latency and packet-loss evidence without probing targets just because somebody opened a page.
- Set warning and critical latency/packet-loss thresholds and a consecutive-failure threshold per monitor.
- Open and close outage records automatically and retain warning, critical, outage and recovery events.
- View status cards, last latency, recent uptime, outage counts and availability timelines.
- Switch a browser dashboard temporarily to Live, 5-second, 10-second, 1-minute or 5-minute collection.
- Pause rapid collection when the dashboard tab is hidden and automatically return to the saved schedule afterward.
- Detail views combine raw and summarised observations across 24-hour, 7-day, 30-day and 1-year ranges.
- Tiered retention keeps raw checks for 24 hours, five-minute summaries for 30 days, hourly summaries for a year and completed outages/events for a year.

## DNS Manager

- First-class **Pi-hole** integration with Pi-hole v6 session authentication and a legacy API fallback.
- Provider status, blocking state, query totals, blocked-query rates, active clients, DHCP leases, local DNS records and blocklists.
- Searchable query logs and factual analysis of top requested domains, blocked domains and client-domain relationships.
- A deterministic DNS health score with **Excellent**, **Healthy**, **Attention Required**, **Poor** and **Critical** bands.
- Provider-neutral Insights covering connectivity, stale data, disabled blocking, blocklist age, new devices, client IP changes, query growth, high block rates, NXDOMAIN rates and repeated blocked-domain requests.
- Critical, warning and informational findings with active, acknowledged, resolved and automatically reactivated lifecycles.
- Bounded hourly snapshots and configurable traffic retention for explainable trend comparisons.
- Preserve the last successful provider data when a new collection fails or Pi-hole is temporarily unavailable.
- Create and manage DNS investigations from interesting query activity.
- Recognised-device inventory with conservative MAC/provider-ID identity matching.
- Detailed client profiles with current observations, IP history, hostname history, event history, top requested/blocked domains, notes and a searchable DNS activity timeline.
- Confirm, unlink, create or update managed VLAN/IP records from DNS observations.
- Optional exact-MAC linking and safe automatic updates for dynamic records; static records are never silently changed.
- DHCP-aware identity handling that avoids treating a temporary lease address as a permanent device identity.
- Background collection with configurable intervals and no provider calls during ordinary page rendering.

## Domain Manager

- Track domain registrations, registrars, DNS providers, status, expiry and auto-renew state.
- Retain nameservers, DNS records, notes and lookup errors.
- Run manual RDAP, WHOIS and DNS lookups.
- Poll domains automatically on a configurable cadence.
- Store lookup changes in history so registration and DNS drift can be reviewed later.

## Remote Manager

- Launch **SSH** and **RDP** sessions directly in the browser.
- SSH is delivered through Kaya's local WebSocket helper; RDP is bridged through Apache Guacamole and `guacd`.
- Optional split-screen workspace for working with multiple remote systems together.
- Configure each host's display name, protocol, terminal behaviour and RDP display/performance preferences.
- Global idle timeouts, recording controls, Guacamole settings and short-lived RDP connection tokens.
- Remote targets are linked to VLAN/IP Manager rather than maintained as a disconnected address book.
- Kaya does not persist remote login credentials; they are supplied when the connection is started.
- Record remote sessions, review them in an admin library and stream or download retained recordings.
- Convert supported WebM session recordings to MP4 for download.
- Fine-grained roles: users may connect, editors may manage host settings and administrators control global settings and recordings.

## Secret Vault

- A private encrypted workspace for recovery keys, certificates, sensitive operational notes, documents and break-glass information.
- Every user receives an independent vault; administrators do not get a route that opens somebody else's vault.
- A normal Kaya login is not enough: vault access requires a separate PIN/passphrase and fresh TOTP or verified OIDC MFA.
- Random per-vault 256-bit master keys and **AES-256-GCM** encryption with unique nonces and record-specific authenticated data.
- Encrypt titles, notes, tags, dates, descriptions, field values, original filenames and attachment contents at rest.
- Purpose-built Secure Note, Secure Document, Recovery Record, Sensitive Data, Certificate and Recovery Kit item types.
- Collections, favourites, tags, classifications, expiry/review dates and custom protected fields.
- Optional MFA-gated collection sharing with named Kaya users at Viewer, Viewer + Downloader, Contributor, Manager or Owner permission levels.
- Masked fields stay out of the HTML until revealed.
- Highly Sensitive fields require another PIN/passphrase check and a one-use fresh MFA approval.
- Automatic inactivity locking, an absolute session lifetime, manual locking and revocation on logout or recovery.
- One-time recovery kits and recovery-key-based PIN reset without disabling account-wide MFA.
- Portable encrypted `.kayavault` exports protected by a separate passphrase.
- Built-in restore plus an offline recovery utility for listing and safely extracting a vault when Kaya itself is unavailable.
- Authenticated package verification, attachment hash checking, safe extraction paths and overwrite protection.
- Security audit events for setup, unlock, reveal, download, backup, restore and recovery without logging vault content.
- Share a temporary independent copy through Secure Send without weakening or exposing the original vault item.

## Secure Send

- Deliver temporary encrypted files and secure notes to people inside or outside Kaya.
- Send multiple files, a secure note and recipient context in one package.
- Set expiry, permit or prevent saving into Secret Vault and optionally destroy access after one download.
- Per-package **AES-256-GCM** encryption for file content and sensitive metadata.
- Three-factor recipient access using a high-entropy URL token, sender-selected PIN and generated ten-word passphrase.
- A separate, minimal recipient gateway with no Kaya login, admin pages or access to the main application.
- Opaque recipient sessions, dedicated CSRF protection, throttling, lockouts, strict route/host validation and hardened no-store responses.
- Send recipient links through Kaya's SMTP integration; PINs and passphrases are never placed in the email.
- Optional sender notifications when a recipient first opens or downloads the package.
- Download the complete package as a ZIP or download individual files.
- Track access and downloads, extend expiry, revoke access or delete a package immediately.
- Expiry, revocation, deletion and one-download completion revoke active recipient sessions.
- Expired/deleted payload ciphertext is removed while minimal lifecycle history remains available for audit correlation.
- Internal recipients can see received packages and save an independent encrypted copy into an unlocked Secret Vault when allowed.
- Live gateway health reporting in the authenticated Kaya interface.

## Licence Manager

- Store software licences, subscriptions and product keys in one searchable register.
- Search, filter and mark important licences as favourites.
- Encrypt product keys at rest and reveal them only to authorised editors.
- Audit product-key reveal actions.
- Add custom fields and administrator-managed licence types.
- Import and export licence data by CSV.

## Runbook Manager

- Create documentation spaces for teams, platforms, customers or operational areas.
- Write maintenance procedures, recovery steps, build notes and checklists in Markdown-style pages.
- Live preview with formatting controls, fenced code blocks and syntax highlighting.
- Paste or upload PNG, JPEG, GIF and WebP images directly into a runbook.
- Convert useful rich-text clipboard content into Markdown while pasting.
- Organise pages with summaries, tags and spaces.
- Search and filter by text, space and tag.
- Switch between visual tile and dense table views.
- Retain recent page history before edits for accountability and reference.
- Role-aware editing: every signed-in user can read, while editors manage content.

## Users, roles and authentication

- Multi-user access with **Administrator**, **Editor** and **Viewer** roles.
- Local email/password authentication with Argon2 password hashing.
- Optional TOTP two-factor authentication with encrypted authenticator secrets.
- Self-service profile name, password, MFA and linked-identity management.
- Rate-limited login and password-reset flows with one-hour, hashed reset tokens.
- SMTP-powered password reset email.
- Full **OpenID Connect** support using Authorization Code flow, mandatory PKCE `S256`, discovery, JWKS validation, state and nonce checks.
- Local only, Local + OIDC, OIDC preferred and guarded OIDC required modes.
- Compatible with standards-based providers such as authentik, Keycloak and Microsoft Entra ID.
- Configurable nested claim mappings, verified-email requirements and exact allowed-email domains.
- Group-to-role mapping, safe role precedence, optional role synchronisation and protection for the last active administrator.
- Controlled just-in-time user provisioning with a Viewer default.
- Self-service identity linking, administrator-generated single-use linking invitations and optional first-login email matching.
- A designated emergency local administrator and break-glass `/auth/local` route for identity-provider outages.
- Provider configuration tests and a real OIDC test-login flow before OIDC-required mode can be enabled.
- Fresh OIDC MFA step-up support for Secret Vault when the provider supplies acceptable assurance claims.

## Auditing and security controls

- Searchable audit logs for authentication, administration and important module actions.
- Role-based route protection and permission-aware navigation throughout the application.
- CSRF protection for browser mutations and dedicated bearer-token authentication for agents.
- Encrypted storage for TOTP secrets, licence keys, SMTP passwords, DNS secrets, backup passwords and API tokens.
- Configurable trusted hosts, trusted reverse-proxy networks and secure session cookies.
- Content Security Policy, frame controls, referrer policy, permissions policy, content-type protection, cache controls and optional HSTS.
- Security diagnostics for the current host allow-list, inbound DNS, outbound public IP, frame policy, HTTPS/HSTS state and RDP token lifetime.
- Explicit Danger Zone confirmations and related-record cleanup for destructive operations.
- A privacy-conscious public-demo mode with synthetic role accounts, scheduled resets, blocked sensitive operations and visitor network-identifier redaction.

## Site Administration and customisation

- Central settings for application identity, public base URL, version checking and upload limits.
- Configure Remote Manager, Guacamole, DNS Manager, Secret Vault, Secure Send, dashboard behaviour and backup targets from the UI.
- SMTP server configuration, custom email templates and built-in test email delivery.
- Built-in tests for DNS providers and backup storage.
- Create, edit, disable and reset MFA for team accounts.
- Define custom text, textarea, radio and select fields for IP addresses, hardware assets and licences.
- Manage reusable categories and lists for assets, IP addresses and licence types.
- Administrator-only CSV import/export for licences and IP addresses.
- About/system views with installed version, release channel and update availability.

## Mobile, PWA and interface

- Purpose-built **Command** dark mode and **Light Ops** light mode.
- Fully responsive navigation, forms, dashboards, detail views and operational tables.
- Mobile drawer navigation, touch-friendly controls and safe-area support.
- Horizontally scrollable, keyboard-focusable tables retain important operational columns on small screens.
- Install Kaya as a **Progressive Web App** on supported desktop and mobile browsers.
- Built-in iPhone Home Screen guidance, offline fallback and user-controlled update notifications.
- Security-conscious service worker: authenticated pages, API data, uploads, remote sessions, WebSockets and mutations are never cached for offline replay.
- Browser-local timezone presentation for server-generated timestamps.
- Collapsible, role-aware navigation and a version/update panel.

## Deployment and integration

- Fast, lightweight FastAPI application with SQLite storage and a Docker-first deployment.
- Start with `docker compose up -d`; no environment file is mandatory for a basic installation.
- Automatic generation and persistence of runtime secrets when they are not supplied.
- Read-only application container, `no-new-privileges`, restricted temporary storage and dedicated persistent volumes.
- Bundled `guacd` service in the standard Compose stack.
- Works behind Nginx, Nginx Proxy Manager, Caddy, Traefik, NetBird and Cloudflare Tunnel.
- Configurable base paths, trusted hosts, proxy networks, secure cookies and public URLs.
- Startup schema migration support and optional pre-migration SQLite backups.
- Health-check endpoint for container and reverse-proxy monitoring.
- Docker Agent check-in API, Backup Agent job API, Remote Manager WebSockets and JSON helper endpoints for live module updates.
- All core data stays on infrastructure you control: the database, uploads, encrypted vault data and recordings live in your mounted volumes.

------------------------------------------------------------------------

# Live Demo

Want to kick the tyres? Go ahead. https://demo.kaya-app.uk 

However, a few caveats.
- The demo does not have a functional Remote Manager module.
- It does not have everything active - this is for security reasons.
- The data resets every night.
- Its probably (highly likley to be) rough around the edges, this is because its the main app with a few restrictions in place - I probably have not picked up everything and most likley broke things trying to "make it safe"

My suggestion - install it in your own environment and throw the kitchen sink at it.

If you need any support - come on over to our Dicord Server: https://discord.gg/2hn6G7Qr9N 

------------------------------------------------------------------------

# Quick Start

## Prerequisites

-   Docker
-   Docker Compose
*   Guacd (the below docker compose file includes a guacd container, however - you may have your own. Once you are in the app you can change the guacd server in remote settings.)

Clone the repository:

``` bash
git clone https://github.com/antybubbs/kaya.git
cd kaya
```

Start Kaya:

``` bash
docker compose up -d
```

Open your browser:

``` text
http://SERVER-IP:8080/setup
```

Kaya works without an environment file, I wanted this to be easier to install. By default it accepts the hostname or IP address you use to reach it, whether that is direct Docker port access or a reverse proxy such as NetBird.

For hardened installs, set `ALLOWED_HOSTS` to your known hostnames or IPs in your compose file. When `ALLOWED_HOSTS` is blank, Kaya does not enforce host filtering.

Complete the setup wizard to create your administrator account.

After first sign-in, open **System Settings -> Site Administration -> Security** to harden the install. This page lets you restrict trusted hostnames, tune frame-embedding rules, enable HTTPS security headers and shorten browser RDP token lifetime without editing an environment file.

The Security tab includes a current-request check so you can confirm the host allow-list, inbound DNS, outbound public IP, frame policy, HSTS state and RDP token lifetime after saving.

My suggestion, install Kaya and sort the settings out in your Site Administration. 

------------------------------------------------------------------------

# Docker Compose

``` yaml
services:
  kaya:
    image: ghcr.io/antybubbs/kaya:latest
    container_name: kaya
    restart: unless-stopped

    ports:
      - "8080:8080"

    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
      - ./data/remote-recordings:/app/data/remote-recordings

    environment:
      DATABASE_URL: sqlite:////app/data/kaya.db

    security_opt:
      - no-new-privileges:true

    cap_add:
      - NET_RAW

    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=128m

  guacd:
    image: guacamole/guacd:1.6.0
    restart: unless-stopped
```

Launch:

``` bash
docker compose up -d
```

------------------------------------------------------------------------

# Persistent Data

  | Path        | Description                    |
  |-------------| -------------------------------|
  |`./data`     | Database and application data  | 
  |`./uploads`  | User uploads                   |
  |`./data/remote-recordings`| SSH and RDP session recordings |

Back up these folders regularly.

------------------------------------------------------------------------

# Updating

``` bash
docker compose pull
docker compose up -d
```

------------------------------------------------------------------------

# Reverse Proxy

Kaya works behind Nginx, Caddy, Traefik, Netbird and Cloudflare.

Typical environment variables:

``` env
BASE_URL=https://kaya.example.com
ALLOWED_HOSTS=kaya.example.com
SESSION_COOKIE_SECURE=true
FORWARDED_ALLOW_IPS=172.20.0.0/16 (This is important)
```

These are optional hardening settings. Kaya will still work through a reverse proxy without them, but `BASE_URL` should be set before enabling password reset emails so links point at the public address.

When Kaya sits behind a reverse proxy on the same host, you can bind the container to loopback with `127.0.0.1:8080:8080` and let the proxy be the public entry point.

The same host allow-list and HTTPS hardening can also be managed from **System Settings -> Site Administration -> Security** after setup.

`FORWARDED_ALLOW_IPS` must contain only the IP address or CIDR of the proxy that
connects directly to Kaya. It secure default is `127.0.0.1`, suitable for
direct LAN use. Docker proxy users normally set a dedicated Docker network
CIDR; NetBird proxy users may use the proxy's single `100.x` address (or
`100.64.0.0/10` only when all peers are trusted). For Cloudflare Tunnel, trust
the local `cloudflared` container rather than Cloudflare's public ranges. Do not
use `*`. See [Reverse proxies and real client IPs](docs/deployment.md#reverse-proxies-and-real-client-ips).

This setting is separate from `ALLOWED_HOSTS`: trusted proxies control which
machine may report client IP/protocol headers, while allowed hosts control the
hostname entered in the browser.

------------------------------------------------------------------------

# Architecture

``` text
Browser
   │
Reverse Proxy
   │
Kaya
├── SQLite Database
├── Upload Storage
└── Guacamole (SSH / RDP)
```

------------------------------------------------------------------------

# Roadmap

I mean, I could throw something here that looks like a roadmap. 

But who am I kidding, the roadmap is like a pub crawl, we hopping all through them.

------------------------------------------------------------------------

# Contributing

Feel free

------------------------------------------------------------------------

# Why "Kaya"?

*Kaya* means **home** in several Southern African languages.

It reflects the philosophy behind the project: our infrastructure
should feel organised, trusted and completely under our control.

I am orignally from South Africa and thus wanted something to remind me of "Home" :-)

------------------------------------------------------------------------
