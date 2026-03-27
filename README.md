# MekongTunnel

> Expose your local app to the internet in one command — no config, no account required.

**Open Source by [KhmerStack](https://github.com/KhmerStack)**

| | |
|---|---|
| Author | Ing Muyleang (អុឹង មួយលៀង) |
| Web UI | [angkorsearch.dev](https://angkorsearch.dev) |
| API | [api.angkorsearch.dev](https://api.angkorsearch.dev) |
| Tunnel Edge | `proxy.angkorsearch.dev` |
| License | MIT |
| Current Version | v1.5.7 |

---

## Install

**macOS / Linux**
```bash
curl -fsSL https://mekongtunnel.dev/install.sh | sh
```

**Windows (PowerShell)**
```powershell
irm https://mekongtunnel.dev/install.ps1 | iex
```

Auto-detects OS and architecture, installs to `PATH`, removes macOS Gatekeeper quarantine, unblocks Windows SmartScreen.

---

## Quick start

```bash
mekong login
mekong subdomain myapp
mekong 3000 --subdomain myapp
```

Plain `mekong 3000` keeps using a random generated tunnel URL. Add `--subdomain myapp`
only when you want a specific reserved name.

Generated tunnels use `*.proxy.angkorsearch.dev` by default. Branded custom domains such as
`app.mekongtunnel.dev` are supported through `mekong domain connect ...`.

Browser visitors to generated tunnel URLs see a one-time shared-tunnel notice first. If the
developer stops Mekong or the local app goes offline, Mekong serves branded tunnel status pages
instead of a raw 404 or generic bad gateway response.

For DNS setup:

- root / apex domains such as `example.com` usually use `A` / `AAAA` records
- subdomains such as `app.example.com` usually use a `CNAME`
- invalid hostnames such as `ttt..example.com` are rejected by both the CLI and API
- deleting a custom domain removes the MekongTunnel route only; DNS stays at the provider until you change it there

## Local dev workflow

For a normal frontend app such as Next.js, Vite, Nuxt, or React, run your app and the tunnel as
two separate processes:

```bash
# Terminal 1
npm run dev

# Terminal 2
mekong 3000
```

`mekong 3000` exposes an already-running local app. It does not start `npm run dev` for you unless
you use a wrapper such as `mekong-cli --with ...`.

If your local app depends on a vhost hostname such as `myapp.test`, use:

```bash
mekong 80 --upstream-host myapp.test
```

## Browser tunnel pages

- The first browser visit to a generated tunnel shows a one-time shared-tunnel notice.
- The `Continue to site` button is a one-click server redirect that sets the warning cookie before returning to the shared URL.
- If the tunnel process is offline, Mekong serves branded offline or custom-domain-pending pages instead of a raw server error.
- If the tunnel is live but the local app is still booting or not responding, Mekong shows a `Tunnel Status` page with a 4-step connection flow:
  `Internet -> Mekong Edge -> Mekong Agent -> Local Service`
- The first three steps stay green while the local service step fails in gray/red.
- That page retries automatically every 2 seconds and reloads into the real app once localhost starts responding.
- When the client reported a real local port, the page shows the expected local app target such as `localhost:3000`.
- Raw `ssh -R` sessions stay generic because the server cannot reliably know the client-side local port.

---

## CLI reference

```bash
# Expose ports
mekong 3000                    # single port with a random URL
mekong 3000 --subdomain myapp  # single port with a specific reserved subdomain
mekong 3000 8080               # multi-port, each gets its own URL
mekong 3000 --expire 48h       # with expiry (-e also works)

# Background (daemon) mode
mekong -d 3000                 # run in background
mekong status                  # list active tunnels
mekong logs                    # tail daemon log
mekong logs -f                 # follow daemon log
mekong logs 3000               # log for specific port
mekong stop 3000               # stop specific tunnel
mekong stop --all              # stop all tunnels

# Auth
mekong login                   # browser device flow
mekong whoami                  # show email + plan
mekong logout                  # clear saved token
mekong subdomain               # list reserved subdomains
mekong subdomain myapp         # reserve a reserved subdomain
mekong subdomain delete myapp  # remove a reserved subdomain
mekong domains                 # list custom domains
mekong domain add app.example.com
mekong domain connect app.example.com myapp
mekong doctor                  # connectivity/auth checks
mekong doctor app.example.com  # custom-domain DNS + HTTPS checks

# Project setup
mekong detect                  # detect the local stack in the current project
mekong init                    # write .mekong.json from detection
mekong help php                # Laragon/XAMPP/WAMP/Laravel examples

# Local virtual hosts
mekong 80 --upstream-host myapp.test

# Maintenance
mekong update                  # self-update binary (checksum-verified)
mekong test                    # run self-test
mekong --version               # print version
mekong --help                  # usage info
```

---

## Raw SSH (no install)

```bash
# Basic
ssh -t -R 80:localhost:3000 proxy.angkorsearch.dev

# With keep-alive
ssh -t -R 80:localhost:3000 -o ServerAliveInterval=60 -o ServerAliveCountMax=3 proxy.angkorsearch.dev

# With expiry
ssh -o SetEnv=MEKONG_EXPIRE=48h -t -R 80:localhost:3000 proxy.angkorsearch.dev
```

---

## Ecosystem

| Package | Install | Frameworks |
|---------|---------|------------|
| **mekong-cli** (npm) | `npm install -g mekong-cli` | Next.js, Vite, Nuxt, Remix, SvelteKit, Astro, Express |
| **mekong-tunnel** (PyPI) | `pip install mekong-tunnel` | FastAPI, Flask, Django, uvicorn, gunicorn, Granian, Hypercorn |
| **VS Code Extension** | `ext install KhmerStack.mekong-tunnel` | Sidebar panel, Login UI, Live Server |

```bash
# Node.js
mekong-cli --with "next dev" --port 3000

# Python
uvicorn-mekong main:app --port 8000 --domain
flask-mekong run --port 5000
django-mekong runserver 8000
```

---

## Self-hosting

```bash
# Local runtime env files
cp .env.dev.example .env.dev
cp .env.prod.example .env.prod

# Run the API with the matching env file
./scripts/run-api.sh dev

# Build from source
make build          # server + CLI
make build-all      # cross-compile server (Linux + macOS, amd64 + arm64)
make build-client-all  # cross-compile CLI (all platforms)
make release-cli-assets TAG=v1.5.7   # 6 CLI assets + SHA256SUMS + release-notes.md
make release-cli-publish TAG=v1.5.7  # push tag only; GitHub release workflow publishes assets

# Local API stack with Postgres + Redis
cp .env.compose.dev.example .env.compose.dev
docker compose --env-file .env.compose.dev -f docker-compose.yml -f docker-compose.dev.yml up -d
./scripts/init-stack.sh dev

# Production Compose stack
cp .env.compose.prod.example .env.compose.prod
docker compose --env-file .env.compose.prod -f docker-compose.yml -f docker-compose.prod.yml up -d
./scripts/init-stack.sh prod

# Optional tunnel edge locally or in staging
docker compose --env-file .env.compose.dev -f docker-compose.yml -f docker-compose.dev.yml --profile tunnel up -d mekong-tunnel

# Deploy scripts for existing VM workflows
./scripts/deploy-api.sh
./scripts/deploy-tunnel.sh
```

`deploy-tunnel.sh` uploads your local `.env.prod` to the tunnel host. `.env` and `.env.api` are no longer part of the supported workflow.

Supported env files now:

- `.env.dev`
- `.env.prod`
- `.env.compose.dev`
- `.env.compose.prod`

If your real servers still use `systemd`, GitHub Actions can run those same deploy scripts for you:

- run `Deploy Dev` manually from the Actions tab
- publish a GitHub Release -> `Deploy Production`

See [docs/GITHUB_DEPLOY.md](./docs/GITHUB_DEPLOY.md) for the required GitHub Environment secrets and variables, including the optional `API_ENV_FILE` and required `TUNNEL_ENV_FILE` multi-line secrets.

`api-init` runs the bootstrap path inside the API image:

- runs migrations
- ensures `server_config` exists
- promotes `ADMIN_EMAIL` to admin
- creates the admin account when `ADMIN_PASSWORD` is provided and the user does not exist yet

Optional Redis is recommended once you run more than one API instance or more than one tunnel edge. With `REDIS_URL` configured, Mekong uses Redis for:

- server config caching
- verified custom-domain target caching
- notification pub/sub across API instances
- email OTP code storage
- distributed API rate limiting

Example:

```bash
export REDIS_URL=redis://127.0.0.1:6379/0
export REDIS_PREFIX=mekong
export REDIS_CACHE_TTL=30s
export REDIS_DOMAIN_CACHE_TTL=1m
export REDIS_NOTIFICATION_CHANNEL=notifications
```

Without `REDIS_URL`, the API and tunnel edge still work normally in single-node mode.

See:

- [HANDBOOK.md](./HANDBOOK.md) for architecture, API, data model, and release notes
- [SETUP.md](./SETUP.md) for DNS, TLS, proxy host setup, and production deploy steps
- [docs/GITHUB_DEPLOY.md](./docs/GITHUB_DEPLOY.md) for GitHub Actions deployment on existing `systemd` servers
- [docs/API_FLOW.md](./docs/API_FLOW.md) for current API flow and target service-layer structure
- [docs/PERFORMANCE.md](./docs/PERFORMANCE.md) for stress testing and benchmark guidance

## Stress test

Local API benchmark:

```bash
go run ./cmd/apibench -base-url http://127.0.0.1:8080 -users 1000 -tunnels 5000 -concurrency 100
```

Or:

```bash
USERS=1000 TUNNELS=5000 CONCURRENCY=100 ./scripts/stress-local.sh
```

This measures the API control plane only: register/login-style throughput, tunnel report throughput, latency, and API-side bytes. It does not measure real SSH/HTTPS proxy bandwidth.

---

## Architecture

```
Internet
   │ HTTPS :443
   ▼
┌─────────────────────────────────────────┐
│       proxy.angkorsearch.dev            │
│                                         │
│  SSH Server :22   → assigns subdomain   │
│  HTTPS Proxy :443 → reverse proxy       │
│  HTTP  :80        → redirect to HTTPS   │
│  Dashboard :9090  → admin stats (local) │
└─────────────────────────────────────────┘
   │ SSH tunnel (tcpip-forward)
   ▼
localhost:3000  (your app)
```

Redis is optional in development. In multi-instance production it is used as a coordination layer for API-side cache, notification fan-out, email OTP codes, and shared rate limits, while PostgreSQL remains the source of truth.

Every tunnel gets a random subdomain such as:

- `adjective-noun-8hexchars.proxy.angkorsearch.dev`
- or a reserved/branded domain like `myapp.proxy.angkorsearch.dev`

Login for a reserved subdomain that stays the same across reconnects.

---

## Links

- Web UI: [angkorsearch.dev](https://angkorsearch.dev)
- API: [api.angkorsearch.dev](https://api.angkorsearch.dev)
- GitHub: [github.com/MuyleangIng/MekongTunnel](https://github.com/MuyleangIng/MekongTunnel)
- npm: [npmjs.com/package/mekong-cli](https://www.npmjs.com/package/mekong-cli)
- PyPI: [pypi.org/project/mekong-tunnel](https://pypi.org/project/mekong-tunnel/)
- VS Code: [marketplace.visualstudio.com — KhmerStack.mekong-tunnel](https://marketplace.visualstudio.com/items?itemName=KhmerStack.mekong-tunnel)
