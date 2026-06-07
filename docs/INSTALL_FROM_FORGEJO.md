# Install KeyVault from Forgejo

This deployment model lets Forgejo host both the Git repository and the Docker image package.

> Note: the Git repository is `cheezy/KeyVault`, but the container image is published as lowercase `cheezy/keyvault` because Docker/OCI image names must be lowercase.


## 1. Push the repository to Forgejo

Create an empty repository in Forgejo, then from this folder run:

```bash
git init
git add .
git commit -m "Initial KeyVault release"
git branch -M main
git remote add origin https://forg.app.strubens.uk/cheezy/KeyVault.git
git push -u origin main
```

## 2. Enable Forgejo Actions

On your Forgejo server, make sure Actions and the container package registry are enabled.

The workflow lives at:

```text
.forgejo/workflows/build-and-publish.yml
```

Create a repository secret called:

```text
FORGEJO_TOKEN
```

The token needs permission to publish packages/container images.

Optional repository variable:

```text
FORGEJO_REGISTRY=forg.app.strubens.uk
```

If omitted, the workflow uses the Forgejo server host from the repository URL.

## 3. Build and publish the image

Push to `main`, or create a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Forgejo Actions will publish images similar to:

```text
forg.app.strubens.uk/cheezy/keyvault:latest
forg.app.strubens.uk/cheezy/keyvault:v1.0.0
forg.app.strubens.uk/cheezy/keyvault:<commit-sha>
```

## 4. Install on your Docker host

Copy `install-from-forgejo.sh` to the server where KeyVault will run, then execute:

```bash
chmod +x install-from-forgejo.sh
./install-from-forgejo.sh
```

The installer creates:

```text
/opt/keyvault/docker-compose.yml
/opt/keyvault/.env
/opt/keyvault/data
/opt/keyvault/uploads
```

Start the app:

```bash
cd /opt/keyvault
docker compose up -d
```

Open:

```text
http://server-ip:8080
```

The installer prints a temporary admin password. Change it after first sign-in.

## 5. Update KeyVault

When a new image is published:

```bash
cd /opt/keyvault
docker compose pull
docker compose up -d
```

## 6. HTTPS and reverse proxy

For production, place KeyVault behind HTTPS using Caddy, Traefik, Nginx Proxy Manager or another reverse proxy.

Once HTTPS is working, edit `/opt/keyvault/.env`:

```text
BASE_URL=https://keyvault.example.local
SESSION_COOKIE_SECURE=true
```

Then restart:

```bash
docker compose up -d
```

## 7. Backups

Back up these folders:

```text
/opt/keyvault/data
/opt/keyvault/uploads
```

The encryption key in `/opt/keyvault/.env` is also critical. Without it, encrypted product keys cannot be decrypted.
