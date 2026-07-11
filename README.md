# 🏡 Kaya
<img width="2551" height="1272" alt="Screenshot 2026-07-07 203240" src="https://github.com/user-attachments/assets/2a956170-9e90-4562-af47-1ed581ad9db2" />

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

Lets be honest, homelab infrastrcuture never stays small.

A Raspberry Pi becomes a server. One Docker container becomes twenty. A
virtual machine becomes a cluster. Before long you're juggling IP
addresses, documentation, credentials, licences, runbooks and bookmarks
across half a dozen different places all while trying to keep your end users (family, friends) happy!

**Kaya brings it all together.**

Named after the Southern African word for **home**, Kaya gives your
infrastructure a place to belong. Whether you're managing a homelab, a
business environment or customer systems, Kaya provides one clean,
modern workspace to organise everything that matters.

I personally use Kaya for my homelab management. This repo is for me to manage the App and updates and to share the journey as I go.

Use it, dont use it. Its up to you really (but it is quite cool if I do say so myself)

------------------------------------------------------------------------

# ✨ Features
 | Feature                | Description                                     |
 |------------------------|-------------------------------------------------|
 | 🖥️ Infrastructure      | Manage servers, VMs, devices and assets         |
 | 🐳 Docker              | Monitor Docker hosts and containers             |
 | 🔐 Remote Access       | Browser-based SSH and RDP with session recording|
 | 🌐 Networking          | IP addresses, VLANs, DNS, domains and WAN links |
 | 📚 Documentation       | Built-in runbooks and operational notes         |
 | 🔑 Licence Management  | Organise software licences and keys             |
 | 👥 Multi-user          | Role-based access control                       |
 | 📝 Audit Logs          | Track important actions                         |
 | 📁 File Storage        | Secure document uploads                         |
 | ⚡ Lightweight         | Fast, simple and self-hosted                    |

------------------------------------------------------------------------

# 📸 Live Demo

Want to kick the tyres? Go ahead. https://demo.kaya-app.uk 

However, a few caveats.
- The demo does not have a functional Remote Manager module.
- The data resets every night.
- Its probably (highly likley to be) rough around the edges, this is because its the main app with a few restrictions in place - we may have not picked up everything and most likley broke things trying to "make it safe"

My suggestion - install it in your own environment and throw the kitchen sink at it.

------------------------------------------------------------------------

# 🚀 Quick Start

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

# 🐳 Docker Compose

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

# 📂 Persistent Data

  | Path        | Description                    |
  |-------------| -------------------------------|
  |`./data`     | Database and application data  | 
  |`./uploads`  | User uploads                   |
  |`./data/remote-recordings`| SSH and RDP session recordings |

Back up these folders regularly.

------------------------------------------------------------------------

# 🔄 Updating

``` bash
docker compose pull
docker compose up -d
```

------------------------------------------------------------------------

# 🌐 Reverse Proxy

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

# 🏗️ Architecture

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

# 🗺️ Roadmap

-   ✅ Infrastructure Management
-   ✅ Browser-based Remote Access
-   ✅ Documentation & Runbooks
-   🚧 Monitoring & Metrics
-   🚧 REST API Expansion
-   🚧 Notifications
-   🧪 Mobile Companion
-   🧪 High Availability

------------------------------------------------------------------------

# 🤖 AI Disclosure

Kaya is developed by me with AI acting as my assisstant.

I have over 20 years in the IT field as 1st/2nd/3rd, Dev Ops and now senior management.

I have developed small tools in the past within my roles without AI which took me ages.

I am not looking to sell Kaya or make any money from it, I thought what I created would be cool to share. 

------------------------------------------------------------------------

# 🤝 Contributing

Feel free

------------------------------------------------------------------------

# ❤️ Why "Kaya"?

*Kaya* means **home** in several Southern African languages.

It reflects the philosophy behind the project: our infrastructure
should feel organised, trusted and completely under our control.

I am orignally from South Africa and thus wanted something to remind me of "Home" :-)

------------------------------------------------------------------------
