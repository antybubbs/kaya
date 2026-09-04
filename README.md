<div align="center">
<a href=""><img src="https://github.com/user-attachments/assets/736dd838-34db-4d04-8efd-199163182edb" alt="Kaya Logo" width="150"/></a>

## Your Infrastructure. Your Home. 
 
A self-hosted infrastructure platform built for homelabs, and users who want complete control of their infrastructure.

![GitHub
release](https://img.shields.io/github/v/release/antybubbs/kaya)
![License](https://img.shields.io/github/license/antybubbs/kaya)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)

⭐ If you find Kaya useful for you, please star us on GitHub! ⭐

## Dark Mode
<img width="2402" height="1149" alt="Dashboard" src="https://github.com/user-attachments/assets/ee00e957-ac35-4684-9ac8-a6239e3401b1" />

## Light Mode
<img width="2402" height="1149" alt="Screenshot 2026-07-27 212234" src="https://github.com/user-attachments/assets/4cf746a4-2338-44a4-83ef-27a8d5b1a31d" />

More ScreenShots - https://www.kaya-app.uk/screenshots
</div>
<br /><br />

# Welcome Home

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

# Our Supporters

[<img width="289" height="67" alt="image" src="https://github.com/user-attachments/assets/c9563e0e-b9bb-4e96-b33a-a8cabaccba1d" />](https://www.aikido.dev/)


# Features

Kaya is more than a homelab inventory. It is a self-hosted operations hub for the infrastructure, access, documentation, monitoring and recovery information that usually ends up scattered across spreadsheets, bookmarks, terminals and password-protected files.

### Infrastructure Management
- Hardware Asset Manager
- Rack Manager
- IP & VLAN Management
- Domain Manager
- Licence Manager

### Monitoring
- Docker & Proxmox monitoring
- IP/WAN monitoring
- Historical performance
- Dashboard & Wallboard
- Live alerts

### DNS & Networking
- Pi-hole integration
- DNS analytics
- DHCP tracking
- High Availability (Beta)
- Client history

### Documentation
- Runbook Manager
- Markdown editor
- Image uploads
- Search
- Version history

### Remote Access
- Browser SSH
- Browser RDP
- Session recording
- Split-screen console
- Role-based permissions

### Security
- Secret Vault
- Secure Send
- MFA
- OIDC / SSO
- Audit logging
- Encryption

### Administration
- User management
- Module permissions
- Custom fields
- Categories
- SMTP
- Backup Manager

## Notifications

Kaya includes an in-application notification centre and optional PWA Web Push. Push remains disabled until an administrator configures VAPID keys and a user intentionally grants permission on a device. See [Notification setup, privacy, troubleshooting, and developer integration](docs/notifications.md).

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

Kaya works without an environment file, I wanted this to be easier to install. The default stack uses PostgreSQL 16.14 on a private Compose network and accepts the hostname or IP address you use to reach it, whether that is direct Docker port access or a reverse proxy such as NetBird.

For hardened installs, set `ALLOWED_HOSTS` to your known hostnames or IPs in your compose file. When `ALLOWED_HOSTS` is blank, Kaya does not enforce host filtering.

Complete the setup wizard to create your administrator account. Please note that you will need to copy the Secret Key from the container logs of Kaya to paste into the initial setup page.

After first sign-in, open **System Settings -> Site Administration -> Security** to harden the install. This page lets you restrict trusted hostnames, tune frame-embedding rules, enable HTTPS security headers and shorten browser RDP token lifetime without editing an environment file.

For a public deployment, set `KAYA_VERSION` to the exact released image tag,
configure the legitimate hostname under Security, enable trusted-host
validation, and enable HSTS only after HTTPS is confirmed. For example,
`kaya.app.strubens.uk` may be entered as an allowed host; this is an example,
not a Kaya-wide hardcoded hostname. Do not enable HSTS `includeSubDomains` or
preload until every inherited hostname is HTTPS-ready and the wildcard DNS
policy has been reviewed.

To publish `/.well-known/security.txt`, set the deployment-managed
`SECURITY_CONTACT` environment variable to a real `mailto:` or HTTPS contact
URI. Kaya returns 404 until this is configured; it never publishes a fabricated
contact address.

The Security tab includes a current-request check so you can confirm the host allow-list, inbound DNS, outbound public IP, frame policy, HSTS state and RDP token lifetime after saving.

My suggestion, install Kaya and sort the settings out in your Site Administration. 

------------------------------------------------------------------------

# Docker Compose

The repository's `docker-compose.yml` is the supported production stack. It
starts Kaya, PostgreSQL 16.14, the secure-send gateway and guacd. PostgreSQL
is private to the Compose network and is persisted in the Docker volume
`kaya_postgres_data`; it is not published on host port 5432. Existing SQLite
installations use the separate, explicit `docker-compose.upgrade.yml` override
described in the deployment guide.

Launch:

``` bash
docker compose up -d
```

For an existing SQLite installation, stop the old Kaya deployment, preserve
the existing data directory and follow the [SQLite upgrade procedure](docs/deployment.md#existing-sqlite-to-postgresql-upgrade).

------------------------------------------------------------------------

# Persistent Data

  | Path        | Description                    |
  |-------------| -------------------------------|
  |`./data`     | Application data and retained legacy/upgrade artifacts  |
  |`./uploads`  | User uploads                   |
  |`./data/remote-recordings`| SSH and RDP session recordings |
  |`kaya_postgres_data`| PostgreSQL production database |

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
├── PostgreSQL Database
├── Upload Storage
└── Guacamole (SSH / RDP)
```

------------------------------------------------------------------------

# Contributing

Over here: https://github.com/antybubbs/kaya?tab=contributing-ov-file

------------------------------------------------------------------------

# Why "Kaya"?

*Kaya* means **home** in several Southern African languages.

It reflects the philosophy behind the project: our infrastructure
should feel organised, trusted and completely under our control.

I am orignally from South Africa and thus wanted something to remind me of "Home" :-)

------------------------------------------------------------------------

# Support me

If you like what you see, [buy me a coffee](https://buymeacoffee.com/antybubbs). It helps with my hosting and licensing/subscription fees. 

Please dont feel obligated, I am just happy if you enjoy Kaya as much as i enjoy creating it!

Thank you for all your support :-)

[<img width="75" height="75" alt="bmc_qr" src="https://github.com/user-attachments/assets/51ffe46d-5c43-49a2-aa28-8e45476804bf" />](https://buymeacoffee.com/antybubbs)
