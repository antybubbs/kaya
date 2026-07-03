# Kaya

> **Your Infrastructure. Your Home.**
>
> A modern, self-hosted infrastructure platform built for homelabs,
> businesses and IT professionals who want complete control of their
> infrastructure.

![GitHub
release](https://img.shields.io/github/v/release/antybubbs/kaya)
![License](https://img.shields.io/github/license/antybubbs/kaya)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)

------------------------------------------------------------------------

## Welcome Home

Most infrastructure doesn't stay small.

A Raspberry Pi becomes a server. One Docker container becomes twenty. A
virtual machine becomes a cluster. Before long you're juggling IP
addresses, documentation, credentials, licences, runbooks and bookmarks
across half a dozen different places.

**Kaya brings it all together.**

Named after the Southern African word for **home**, Kaya gives your
infrastructure a place to belong. Whether you're managing a homelab, a
business environment or customer systems, Kaya provides one clean,
modern workspace to organise everything that matters.

No subscriptions.

No cloud dependency.

No vendor lock-in.

Just your infrastructure, your data and your rules.

------------------------------------------------------------------------

# ✨ Features

  Feature                 Description
  ----------------------- -------------------------------------------------
  �️ Infrastructure       Manage servers, VMs, devices and assets
  � Docker               Monitor Docker hosts and containers
  � Remote Access        Browser-based SSH and RDP
  � Networking           IP addresses, VLANs, DNS, domains and WAN links
  � Documentation        Built-in runbooks and operational notes
  � Licence Management   Organise software licences and keys
  � Multi-user           Role-based access control
  � Audit Logs           Track important actions
  � File Storage         Secure document uploads
  ⚡ Lightweight          Fast, simple and self-hosted

------------------------------------------------------------------------

# � Screenshots

> *Screenshots coming soon.*

-   Dashboard
-   Infrastructure
-   Remote Manager
-   Networking
-   Documentation
-   Settings

------------------------------------------------------------------------

# � Quick Start

## Prerequisites

-   Docker
-   Docker Compose

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

Complete the setup wizard to create your administrator account.

Within a few moments Kaya will:

-   Generate its application secrets
-   Create the SQLite database
-   Prepare persistent storage
-   Guide you through first-time setup

------------------------------------------------------------------------

# � Docker Compose

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

    environment:
      DATABASE_URL: sqlite:////app/data/kaya.db

    security_opt:
      - no-new-privileges:true

    cap_add:
      - NET_RAW

  guacd:
    image: guacamole/guacd:1.6.0
    restart: unless-stopped
```

Launch:

``` bash
docker compose up -d
```

------------------------------------------------------------------------

# � Persistent Data

  Path          Description
  ------------- -------------------------------
  `./data`      Database and application data
  `./uploads`   User uploads

Back up these folders regularly.

------------------------------------------------------------------------

# � Updating

``` bash
docker compose pull
docker compose up -d
```

------------------------------------------------------------------------

# � Reverse Proxy

Kaya works behind Nginx, Caddy, Traefik and Cloudflare.

Typical environment variables:

``` env
BASE_URL=https://kaya.example.com
ALLOWED_HOSTS=kaya.example.com
SESSION_COOKIE_SECURE=true
```

------------------------------------------------------------------------

# �️ Architecture

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

# �️ Roadmap

-   ✅ Infrastructure Management
-   ✅ Browser-based Remote Access
-   ✅ Documentation & Runbooks
-   � Monitoring & Metrics
-   � REST API Expansion
-   � Notifications
-   � Mobile Companion
-   � High Availability

------------------------------------------------------------------------

# � AI-Assisted Development

Kaya is developed by a human developer with AI acting as a development
assistant.

AI is used to speed up repetitive coding tasks, explore implementation
ideas and improve productivity. Every suggestion is reviewed, tested and
refined before becoming part of the project.

The architecture, security decisions and overall direction of Kaya
remain entirely human-led.

------------------------------------------------------------------------

# � Contributing

Ideas, bug reports, feature requests and pull requests are always
welcome.

If you've built something with Kaya or have suggestions to improve it,
we'd love to hear from you.

------------------------------------------------------------------------

# ❤️ Why "Kaya"?

*Kaya* means **home** in several Southern African languages.

It reflects the philosophy behind the project: your infrastructure
should feel organised, trusted and completely under your control.

------------------------------------------------------------------------

# � Licence

Licensed under **GPL-3.0**.
