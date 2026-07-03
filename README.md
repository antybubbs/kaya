<p align="center">
  <img src="app/static/brand/logo.jpg" width="140">
</p>

<h1 align="center">Kaya</h1>

<p align="center">
Your Infrastructure. Your Home.
</p>

<p align="center">
A beautiful self-hosted infrastructure management platform built for homelabs, businesses and modern IT teams.
</p>

<p align="center">

[Documentation] • [Demo] • [Docker Hub] • [Releases]

</p>

------------------------------------------------------------------------

## Why Kaya?

Infrastructure grows.

What starts as a Raspberry Pi, a Docker host or a small server quickly
becomes dozens of services, virtual machines, IP addresses,
certificates, containers and notes spread across bookmarks, spreadsheets
and sticky notes.

Kaya brings everything together into one beautiful workspace.

Whether you're running a homelab, managing a business, hosting customer
environments or simply love self-hosting, Kaya gives you a single place
to understand your infrastructure.

No subscriptions.

No cloud dependency.

No vendor lock-in.

Just your infrastructure, your data and your rules.

------------------------------------------------------------------------

# ✨ Features

-   🌐 Infrastructure inventory
-   🖥️ Servers, VMs and containers
-   🔐 Browser-based SSH & RDP
-   🌍 Domains, DNS and networking
-   📦 Docker monitoring
-   📚 Runbooks & documentation
-   🔑 Licence management
-   👥 Multi-user with role-based access
-   📝 Audit logging
-   📁 Secure file uploads
-   ⚡ Fast, lightweight and self-hosted

------------------------------------------------------------------------

# 🚀 Quick Start

## Prerequisites

-   Docker
-   Docker Compose

## Installation

``` bash
mkdir -p /opt/kaya
cd /opt/kaya

curl -fsSLO https://raw.githubusercontent.com/antybubbs/kaya/main/docker-compose.yml

docker compose up -d
```

Open your browser:

``` text
http://SERVER-IP:8080/setup
```

Complete the first-run setup wizard to create your administrator
account.

------------------------------------------------------------------------

# 🐳 Docker Compose

``` yaml
name: kaya

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

Start Kaya:

``` bash
docker compose up -d
```

------------------------------------------------------------------------

# 📂 Persistent Data

  Folder        Purpose
  ------------- -------------------------------
  `./data`      Database and application data
  `./uploads`   User uploaded files

Back up both folders regularly.

------------------------------------------------------------------------

# 🔄 Updating

``` bash
docker compose pull
docker compose up -d
```

------------------------------------------------------------------------

# 🌍 Reverse Proxy

Kaya works behind Nginx, Caddy, Traefik and other reverse proxies.

Set:

``` env
BASE_URL=https://kaya.example.com
SESSION_COOKIE_SECURE=true
ALLOWED_HOSTS=kaya.example.com
```

------------------------------------------------------------------------

# 🤖 AI Development

Kaya is developed with assistance from OpenAI Codex inside Visual Studio
Code.

AI helps accelerate development by suggesting implementations,
identifying improvements and reducing repetitive work. Every change is
reviewed, tested and validated before becoming part of the project.

Human judgement always has the final say.

------------------------------------------------------------------------

# ❤️ Philosophy

Kaya is named after the Southern African word meaning **home**.

It reflects the idea that your infrastructure should feel like your own
space: organised, trusted and entirely under your control.

------------------------------------------------------------------------

# 🗺️ Roadmap

-   Mobile companion
-   API expansion
-   High Availability
-   Notifications
-   Plugin framework
-   Metrics dashboards
-   Additional infrastructure integrations

------------------------------------------------------------------------

# 🤝 Contributing

Bug reports, ideas and pull requests are always welcome.

If you've built something cool with Kaya, we'd love to see it.

------------------------------------------------------------------------

# 📄 Licence

GPL-3.0
