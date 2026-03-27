# GitHub Deploy

Use this when your real servers still run `systemd` and you want GitHub Actions to deploy them.

This repo now has two GitHub deploy workflows:

- `Deploy Dev`
  - runs manually from the Actions tab
- `Deploy Production`
  - runs when a GitHub Release is published
  - can also be run manually with a specific `ref`

They do not replace the current server model. They call the same scripts you already use locally:

- [`scripts/deploy-api.sh`](../scripts/deploy-api.sh)
- [`scripts/deploy-tunnel.sh`](../scripts/deploy-tunnel.sh)

That means this GitHub path is for existing `systemd` hosts first. Docker Compose is still available for local stacks or full container-based self-hosting, but GitHub deploys here are based on the proven VM workflow.

## GitHub environments

Create two GitHub Environments:

- `development`
- `production`

Put the same secret and variable names in both environments. The values are different per environment.

Copy-paste starting points are in:

- [`.github/examples/development.vars.example`](../.github/examples/development.vars.example)
- [`.github/examples/development.single-host.vars.example`](../.github/examples/development.single-host.vars.example)
- [`.github/examples/production.vars.example`](../.github/examples/production.vars.example)
- [`.github/examples/api.env.secret.example`](../.github/examples/api.env.secret.example)
- [`.github/examples/development.api.env.secret.example`](../.github/examples/development.api.env.secret.example)
- [`.github/examples/development.tunnel.env.secret.example`](../.github/examples/development.tunnel.env.secret.example)
- [`.github/examples/tunnel.env.secret.example`](../.github/examples/tunnel.env.secret.example)

## Environment secrets

| Name | Required | Purpose |
| --- | --- | --- |
| `DEPLOY_SSH_KEY` | Yes | Private SSH key used by GitHub Actions to reach the server(s) |
| `API_ENV_FILE` | Recommended for API | Full multi-line API env file uploaded by `deploy-api.sh` |
| `TUNNEL_ENV_FILE` | Tunnel only | Full multi-line `.env.prod` content uploaded by `deploy-tunnel.sh` |

### Exactly what to paste

`DEPLOY_SSH_KEY`

- Create a dedicated deploy key if you do not already have one:

```bash
ssh-keygen -t ed25519 -C "github-actions-deploy" -f ~/.ssh/mekong_github_actions
```

- Install the public key on the servers:

```bash
ssh-copy-id -p 2222 -i ~/.ssh/mekong_github_actions.pub root@139.59.108.158
ssh-copy-id -p 2222 -i ~/.ssh/mekong_github_actions.pub root@proxy.angkorsearch.dev
```

- Paste the private key file content into the GitHub secret named `DEPLOY_SSH_KEY`:

```bash
cat ~/.ssh/mekong_github_actions
```

The secret value should look like:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

`TUNNEL_ENV_FILE`

- Paste the full content of your real `.env.prod` into the GitHub secret named `TUNNEL_ENV_FILE`
- If you need a clean starting point, copy from [`.env.prod.example`](../.env.prod.example) or [`.github/examples/tunnel.env.secret.example`](../.github/examples/tunnel.env.secret.example)

For example:

```bash
cat .env.prod
```

`TUNNEL_ENV_FILE` should contain the real tunnel server env file, for example:

```env
DOMAIN=proxy.angkorsearch.dev
SSH_ADDR=:22
HTTP_ADDR=127.0.0.1:8081
HTTPS_ADDR=127.0.0.1:8443
STATS_ADDR=127.0.0.1:9090
HOST_KEY_PATH=/opt/mekongtunnel/host_key
TLS_CERT=/etc/letsencrypt/live/proxy.angkorsearch.dev/fullchain.pem
TLS_KEY=/etc/letsencrypt/live/proxy.angkorsearch.dev/privkey.pem
DATABASE_URL=postgres://USER:PASS@HOST:5432/DB?sslmode=disable
```

`API_ENV_FILE`

- Paste the full content of your real API env file into the GitHub secret named `API_ENV_FILE`
- If you need a clean starting point, copy from [`.github/examples/api.env.secret.example`](../.github/examples/api.env.secret.example)

For example:

```bash
cat .github/examples/api.env.secret.example
```

When `API_ENV_FILE` is present:

- `deploy-api.sh` uploads it to `${API_REMOTE_DIR}/.env.prod`
- symlinks `${API_REMOTE_DIR}/.env`
- uploads `migrations/`
- installs the API systemd unit when needed
- keeps an existing API unit file unless you set `FORCE_INSTALL_SERVICE_UNIT=true`

When `API_ENV_FILE` is omitted:

- the workflow keeps the old behavior
- GitHub only uploads the API binary and `migrations/`
- the existing API service env on the server stays in charge

`DEPLOY_SSH_KEY` should be the full private key text for a deploy key that can SSH into the API and tunnel servers. For example:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

## Environment variables

| Name | Required | Purpose |
| --- | --- | --- |
| `API_REMOTE_HOST` | API only | SSH target for the API host, for example `root@139.59.108.158` |
| `API_SSH_PORT` | API only | Admin SSH port for the API host, for example `2222` |
| `API_REMOTE_DIR` | API only | Remote install directory, for example `/opt/mekong/api` |
| `API_SERVICE_NAME` | API only | Remote `systemd` service name, for example `mekong-api` |
| `PUBLIC_API_BASE` | API only | Public base URL used for post-deploy checks, for example `https://api.angkorsearch.dev` |
| `TUNNEL_REMOTE_HOST` | Tunnel only | SSH target for the tunnel host, for example `root@proxy.angkorsearch.dev` |
| `TUNNEL_SSH_PORT` | Tunnel only | Admin SSH port for the tunnel host, usually `2222` |
| `TUNNEL_REMOTE_APP_DIR` | Tunnel only | Remote app dir, for example `/opt/mekongtunnel` |
| `TUNNEL_SERVICE_NAME` | Tunnel only | Tunnel `systemd` service name, usually `mekongtunnel.service` |
| `TUNNEL_SERVER_BIN` | Tunnel only | Remote binary install path, for example `/usr/local/bin/mekongtunnel` |
| `TUNNEL_WILDCARD_DOMAIN` | Optional | Branded wildcard domain such as `mekongtunnel.dev` |
| `TUNNEL_WILDCARD_UPSTREAM` | Optional | Override nginx upstream for the branded wildcard site |

### Current production values in this repo

These are already written in [`.github/examples/production.vars.example`](../.github/examples/production.vars.example):

```env
API_REMOTE_HOST=root@139.59.108.158
API_SSH_PORT=2222
API_REMOTE_DIR=/opt/mekong/api
API_SERVICE_NAME=mekong-api
PUBLIC_API_BASE=https://api.angkorsearch.dev

TUNNEL_REMOTE_HOST=root@proxy.angkorsearch.dev
TUNNEL_SSH_PORT=2222
TUNNEL_REMOTE_APP_DIR=/opt/mekongtunnel
TUNNEL_SERVICE_NAME=mekongtunnel.service
TUNNEL_SERVER_BIN=/usr/local/bin/mekongtunnel
TUNNEL_WILDCARD_DOMAIN=mekongtunnel.dev
TUNNEL_WILDCARD_UPSTREAM=https://127.0.0.1:8443
```

## Redis on existing systemd servers

Redis is optional.

You do not need Redis before using [`deploy-api.sh`](../scripts/deploy-api.sh).

If `REDIS_URL` is unset, the API and tunnel edge still run in single-node mode:

- Postgres remains the source of truth
- notifications stay local to one API instance
- rate limits stay process-local
- OTP falls back to PostgreSQL

If you want Redis on a current Ubuntu or Debian server:

```bash
sudo apt update
sudo apt install -y redis-server
sudo systemctl enable --now redis-server
redis-cli ping
```

Then add this to your existing API or tunnel env file and restart the service:

```env
REDIS_URL=redis://127.0.0.1:6379/0
REDIS_PREFIX=mekong
REDIS_CACHE_TTL=30s
REDIS_DOMAIN_CACHE_TTL=1m
REDIS_NOTIFICATION_CHANNEL=notifications
```

Important:

- [`deploy-api.sh`](../scripts/deploy-api.sh) manages the API host env only when `API_ENV_FILE` is set
- [`deploy-tunnel.sh`](../scripts/deploy-tunnel.sh) does upload the tunnel env file from `TUNNEL_ENV_FILE`

So for API Redis changes on a `systemd` host, either:

- update `API_ENV_FILE` in the GitHub Environment and redeploy, or
- update the service env where it already lives on the server if you still use the legacy restart-only path

## Flow

### Development

1. Run `Deploy Dev` manually from the Actions tab
2. It runs tests and builds
3. GitHub deploys the API and tunnel edge through SSH

You can also run it manually and choose only API or only tunnel.

If you do not have a separate staging server yet, do not point `development` at the live production host. In that case either:

- leave `development` unset for now, or
- use the manual production workflow only

If you have one testing server that already runs these units:

- `mekong-api.service` -> `/opt/mekong/api`, `EnvironmentFile=/opt/mekong/api/.env`
- `mekongtunnel.service` -> `/opt/mekongtunnel`, `EnvironmentFile=/opt/mekongtunnel/.env`

use these copy-paste files:

- [`.github/examples/development.single-host.vars.example`](../.github/examples/development.single-host.vars.example)
- [`.github/examples/development.api.env.secret.example`](../.github/examples/development.api.env.secret.example)
- [`.github/examples/development.tunnel.env.secret.example`](../.github/examples/development.tunnel.env.secret.example)

### Production

1. Create a Git tag such as `v1.5.7`
2. Push the tag
3. [`release.yml`](../.github/workflows/release.yml) builds the CLI release assets
4. Publish the GitHub Release
5. `Deploy Production` deploys the matching ref to the production servers

You can also run `Deploy Production` manually and enter a `ref` such as:

- `main`
- `v1.5.7`
- a release branch name

## When to use Compose instead

Use the GitHub workflows above if:

- your servers already use `systemd`
- you want minimal change
- you want GitHub to run the same deploy scripts you already trust

Use the Compose path if:

- you want container-first servers
- you want Postgres and Redis managed in one Compose stack
- you want to move away from `systemd`-managed Go binaries
