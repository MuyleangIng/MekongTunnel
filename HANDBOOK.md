# MekongTunnel — Project Handbook

> Author: **Ing Muyleang** (អុឹង មួយលៀង) · KhmerStack · [angkorsearch.dev](https://angkorsearch.dev)
> Last updated: 2026-03-28 · Go v1.5.8 · npm v2.0.0 · PyPI v2.1.0 · VS Code v1.5.0

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Structure](#2-repository-structure)
3. [Architecture](#3-architecture)
4. [Build Commands](#4-build-commands)
5. [Database — Setup, Seed, Reset](#5-database--setup-seed-reset)
6. [Go Server — MekongTunnel](#6-go-server--mekongtunnel)
7. [Go CLI — mekong](#7-go-cli--mekong)
8. [Backend REST API — All Endpoints](#8-backend-rest-api--all-endpoints)
9. [Frontend — angkorsearch.dev](#9-frontend--angkorsearchdev)
10. [npm Package — mekong-cli](#10-npm-package--mekong-cli)
11. [Python Package — mekong-tunnel](#11-python-package--mekong-tunnel)
12. [VS Code Extension](#12-vs-code-extension)
13. [CI/CD Pipelines](#13-cicd-pipelines)
14. [Release Checklist](#14-release-checklist)
15. [Deployment Guide](#15-deployment-guide)

### Start Here

- Use [`README.md`](./README.md) for install, quick CLI usage, and the product overview
- Use [`SETUP.md`](./SETUP.md) for DNS, TLS, nginx, and production deployment
- Use [`HANDBOOK.md`](./HANDBOOK.md) when you need architecture, route, schema, and release context
- Use [`docs/API_FLOW.md`](./docs/API_FLOW.md) for the current API flow and the target service-layer direction
- Use [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md) for local stress testing and control-plane benchmark guidance

---

## 1. Project Overview

MekongTunnel is an **ngrok-style SSH tunneling service**. The current production layout separates the product into three public entrypoints:

- `angkorsearch.dev` — web UI and CLI approval flow
- `api.angkorsearch.dev` — REST API
- `proxy.angkorsearch.dev` — SSH + HTTPS tunnel edge

Optional branded custom domains such as `app.mekongtunnel.dev` are served through the same proxy host when wildcard DNS and TLS are configured.

```
Developer machine                  Proxy edge                     Public web/API
┌─────────────────┐   SSH tunnel   ┌───────────────────────────┐  ┌────────────────────────┐
│ localhost:3000  │◄──────────────►│ proxy.angkorsearch.dev    │  │ angkorsearch.dev       │
│ your app        │  tcpip-forward │ *.proxy.angkorsearch.dev  │  │ api.angkorsearch.dev   │
└─────────────────┘                └───────────────────────────┘  └────────────────────────┘
```

**Ecosystem versions:**

| Component | Language | Version | Link |
|-----------|----------|---------|------|
| Go Server + CLI | Go 1.24 | v1.5.7 | [GitHub](https://github.com/MuyleangIng/MekongTunnel) |
| npm CLI + SDK | Node.js 18+ | v2.0.0 | [npm](https://www.npmjs.com/package/mekong-cli) |
| Python CLI + SDK | Python 3.8+ | v2.1.0 | [PyPI](https://pypi.org/project/mekong-tunnel/) |
| VS Code Extension | TypeScript | v1.5.0 | [Marketplace](https://marketplace.visualstudio.com/items?itemName=KhmerStack.mekong-tunnel) |
| Frontend | Next.js 16 / React 19 | latest | [angkorsearch.dev](https://angkorsearch.dev) |

---

## 2. Repository Structure

```
tunnl.gg/                              ← Go monorepo root
├── cmd/
│   ├── apibench/                      ← local API stress / latency benchmark
│   ├── mekong/                        ← CLI client binary
│   │   ├── main.go                    (reconnect loop, QR, clipboard, expiry)
│   │   ├── auth.go                    (login, logout, whoami, token-info)
│   │   ├── subdomains.go              (reserve/list/delete reserved subdomains)
│   │   ├── domains.go                 (custom domains, doctor, connect, wait)
│   │   ├── selftest.go                (mekong test — self-diagnostic)
│   │   ├── platform_unix.go           (daemon via Setsid + isPIDAlive via signal)
│   │   └── platform_windows.go        (DETACHED_PROCESS + OpenProcess)
│   └── mekongtunnel/                  ← Server binary
│       └── main.go                    (reads env, starts 4 listeners)
│
├── internal/
│   ├── config/config.go               (all constants: limits, timeouts, author info)
│   ├── redisx/                        (optional Redis cache, pub/sub, OTP, rate limiting)
│   ├── domain/domain.go               (Generate(), IsValid() for subdomains)
│   ├── expiry/                        (tunnel lifetime, idle timeout handling)
│   ├── proxy/
│   │   ├── proxy.go                   (tunnel registry, reserved/custom domain lookups)
│   │   ├── ssh.go                     (SSH server handler — random + reserved subdomains)
│   │   ├── http.go                    (HTTPS reverse proxy, custom domain routing, WebSocket support)
│   │   ├── stats.go                   (HTML dashboard at /, JSON at /api/stats)
│   │   └── abuse.go                   (rate limiting, sliding-window, IP blocking)
│   ├── tunnel/
│   │   ├── tunnel.go                  (per-tunnel lifecycle, atomic request counter)
│   │   ├── ratelimit.go               (token bucket: 10 req/s, burst 20)
│   │   └── logger.go                  (async HTTP log streaming to SSH terminal)
│   ├── db/
│   │   ├── db.go                      (PostgreSQL connection pool setup)
│   │   ├── migrate.go                 (auto-migration runner)
│   │   ├── users.go                   (CRUD users, plan management)
│   │   ├── tokens.go                  (API token creation, validation, revocation)
│   │   ├── tunnels.go                 (tunnel session recording)
│   │   ├── teams.go                   (teams + members + invitations)
│   │   ├── domains.go                 (custom domains)
│   │   ├── subdomains.go              (reserved subdomain management)
│   │   ├── notifications.go           (user notification CRUD)
│   │   ├── cli_device.go              (CLI device session auth)
│   │   ├── newsletter.go              (email subscription)
│   │   ├── admin.go                   (admin queries)
│   │   ├── partners.go                (partner directory)
│   │   ├── sponsors.go                (sponsor listings)
│   │   ├── server_config.go           (live server config)
│   │   └── verify.go                  (student/teacher verification)
│   ├── models/
│   │   └── models.go                  (shared structs and constants)
│   └── auth/
│       ├── jwt.go                     (JWT sign + verify)
│       ├── apitoken.go                (API token prefix + hash)
│       ├── oauth.go                   (GitHub + Google OAuth)
│       ├── password.go                (bcrypt helpers)
│       └── totp.go                    (TOTP 2FA: setup, verify, backup codes)
│
├── internal/api/
│   ├── server.go                      (all HTTP routes registered here)
│   ├── middleware/
│   │   ├── auth.go                    (JWT auth, optional auth, admin auth)
│   │   ├── cors.go                    (CORS policy)
│   │   └── rate_limit.go              (Redis-backed API rate limiting)
│   └── handlers/
│       ├── auth.go                    (register, login, OAuth, 2FA, password reset)
│       ├── user.go                    (profile, password, deletion, verify request)
│       ├── tokens.go                  (API token CRUD)
│       ├── tunnels.go                 (list user tunnels, kill tunnel)
│       ├── teams.go                   (team CRUD, members, invitations)
│       ├── billing.go                 (Stripe checkout, portal, invoices)
│       ├── admin.go                   (admin: users, plans, abuse, server config)
│       ├── subdomain.go               (reserved subdomain management)
│       ├── domains.go                 (custom domain management)
│       ├── cli_device.go              (CLI device authentication)
│       ├── notifications.go           (user notifications)
│       ├── newsletter.go              (email subscription + unsubscribe by token)
│       ├── partners.go                (partner directory)
│       ├── sponsors.go                (sponsor listings)
│       ├── donations.go               (donation submit/list/approve)
│       ├── upload.go                  (file upload — reused for donation receipts)
│       └── monitor.go                 (system monitoring)
│
├── migrations/                        (17 PostgreSQL migration files)
├── api/                               (OpenAPI spec — if present)
├── mekong-node-sdk/                   ← local folder for the npm package
├── mekong-python-sdk/                 ← local folder for the Python package
├── mekong-vscode-extension/           ← local folder for the VS Code extension
├── .github/workflows/                 (5 CI/CD pipelines)
├── Makefile
├── Dockerfile.api
├── docker-compose.yml
├── docker-compose.dev.yml
├── docker-compose.prod.yml
├── install.sh                         (macOS + Linux one-liner)
├── install.ps1                        (Windows PowerShell one-liner)
├── go.mod
└── go.sum
```

---

## 3. Architecture

### Tunnel listeners

The `mekongtunnel` binary starts four concurrent servers:

| Port | Protocol | Purpose |
|------|----------|---------|
| `:22` | SSH | Accepts `ssh -R` port-forwarding connections, assigns subdomains |
| `:80` | HTTP | Redirects all traffic to HTTPS |
| `:443` | HTTPS/WSS | TLS-terminating reverse proxy to tunnel targets |
| `:9090` | HTTP | Admin dashboard + `/api/stats` (localhost only) |

In production, nginx usually owns public `:80` and `:443`, then proxies to the tunnel binary on loopback addresses such as `127.0.0.1:8081` and `127.0.0.1:8443`.

### Current production host split

| Public hostname | Role |
|-----------------|------|
| `angkorsearch.dev` | Frontend + CLI approval UI |
| `api.angkorsearch.dev` | API server |
| `proxy.angkorsearch.dev` | Tunnel SSH/HTTPS entrypoint |
| `*.proxy.angkorsearch.dev` | Generated tunnel URLs |
| `*.mekongtunnel.dev` | Optional branded wildcard custom domains |

### REST API Server (separate process)

| Port | Protocol | Purpose |
|------|----------|---------|
| `:8080` | HTTP | REST API for auth, tokens, billing, teams, admin |

### How a tunnel works

```
1. mekong 3000
   └─ opens SSH connection to proxy.angkorsearch.dev:22
   └─ sends tcpip-forward request for port 80

2. SSH server
   └─ generates adjective-noun-8hexchars subdomain or uses a reserved name
   └─ registers tunnel in registry
   └─ prints URL to SSH terminal

3. Browser visits https://happy-tiger-a1b2c3d4.proxy.angkorsearch.dev
   └─ first browser visit to a generated tunnel redirects to a shared-tunnel notice on the root domain
   └─ clicking Continue to site sets a 24-hour warning cookie and returns to the shared URL
   └─ HTTPS proxy matches generated host or custom domain → finds tunnel in registry
   └─ opens forwarded-tcpip SSH channel back to client
   └─ proxies HTTP/WebSocket bidirectionally

4. If the tunnel is live but the local app is not responding yet
   └─ browser sees a branded Tunnel Status page instead of a raw 502
   └─ Internet → Mekong Edge → Mekong Agent show active
   └─ Local Service shows failed
   └─ page retries automatically every 2 seconds and reloads into the app once localhost responds

5. When mekong disconnects
   └─ SSH server removes tunnel from registry
   └─ future requests to that subdomain → branded offline page
```

### Subdomain format

```
happy-tiger-a1b2c3d4.proxy.angkorsearch.dev
└─ adjective ─┘ └─noun─┘ └─8 hex chars─┘
```

By default, generated tunnels use `*.proxy.angkorsearch.dev`. Login with `mekong login` to get a **reserved** subdomain that persists across reconnects, and use `mekong domain connect ...` for custom domains.

### Browser tunnel pages

- Generated tunnel URLs show a one-time shared-tunnel notice for browsers before opening the app.
- The warning page uses a one-click Continue flow that sets the warning cookie and redirects back to the shared URL in the same request path.
- Offline tunnels and pending custom domains use branded HTML status pages instead of raw server responses.
- Upstream-unreachable tunnels use a `Tunnel Status` page with a 4-step connection flow:
  `Internet -> Mekong Edge -> Mekong Agent -> Local Service`
- The upstream page keeps retrying and automatically reloads into the real app when the local service starts responding again.
- When the client reported its true local port, the page can show an exact expected target such as `localhost:3000`.
- For raw `ssh -R` sessions, the server cannot safely infer the real client-side local port, so the page stays generic instead of faking `localhost:80`.

### Key dependencies (go.mod)

| Package | Use |
|---------|-----|
| `github.com/jackc/pgx/v5` | PostgreSQL driver |
| `github.com/redis/go-redis/v9` | Optional Redis cache, pub/sub, OTP, rate limiting |
| `github.com/golang-jwt/jwt/v5` | JWT auth |
| `github.com/stripe/stripe-go/v76` | Billing |
| `github.com/pquerna/otp` | TOTP 2FA |
| `golang.org/x/crypto` | SSH + bcrypt |
| `github.com/mdp/qrterminal/v3` | QR codes in terminal |
| `github.com/atotto/clipboard` | Auto-copy URL |
| `github.com/shirou/gopsutil/v4` | System metrics |

### Optional Redis layer

Redis is optional. The system still works without it on a single node.

When `REDIS_URL` is configured, Mekong uses Redis for:

- caching `server_config` reads
- caching verified custom-domain target lookups for the tunnel edge
- pub/sub fan-out of notifications across multiple API instances
- email login OTP code storage and verification
- distributed API rate limiting for public auth and CLI device endpoints

PostgreSQL stays the source of truth for users, tokens, domains, billing, and notification history.

### API flow

Current runtime flow:

```text
middleware -> handler -> db / notify / redisx / mailer -> response
```

Target flow from `STRUCTURE.md`:

```text
handler -> service -> repository -> models
```

The repo still has direct handler-to-db calls in several places, so the target service layer is documented but not finished. See [`docs/API_FLOW.md`](./docs/API_FLOW.md).

### Redis environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `REDIS_URL` | unset | Enable Redis integration |
| `REDIS_PREFIX` | `mekong` | Key prefix / namespace |
| `REDIS_CACHE_TTL` | `30s` | Generic cache TTL |
| `REDIS_DOMAIN_CACHE_TTL` | `1m` | Verified custom-domain lookup cache TTL |
| `REDIS_NOTIFICATION_CHANNEL` | `notifications` | Notification pub/sub channel |

---

## 4. Build Commands

### Prerequisites

```bash
go 1.24+
make
upx       # optional — for build-tiny
```

### Makefile targets

```bash
make build              # build server (bin/mekongtunnel) + CLI (bin/mekong)
make build-small        # max size optimization (~6 MB server, ~4 MB CLI)
make build-tiny         # UPX compression (~2 MB server)
make build-all          # cross-compile server: linux/darwin × amd64/arm64
make build-client-all   # cross-compile CLI: all platforms incl. windows/arm64
make release-cli-assets TAG=v1.5.7   # dist/v1.5.7 assets + checksum + release notes
make release-cli-publish TAG=v1.5.7  # push tag only; release.yml publishes the GitHub release
make test               # run all tests (excludes known flaky proxy tests)
make compose-dev-up     # start local Postgres + Redis + API
make compose-init-dev   # run migrations + server_config seed + admin bootstrap
make stress-local       # 1000 users + 5000 tunnel reports against local API
make clean              # remove bin/
```

### Cross-compile outputs (build-client-all)

```
bin/mekong-darwin-arm64
bin/mekong-darwin-amd64
bin/mekong-linux-amd64
bin/mekong-linux-arm64
bin/mekong-windows-amd64.exe
bin/mekong-windows-arm64.exe
```

### Run locally (development)

```bash
cp .env.dev.example .env.dev
cp .env.prod.example .env.prod
./scripts/run-api.sh dev
cp .env.compose.dev.example .env.compose.dev
docker compose --env-file .env.compose.dev -f docker-compose.yml -f docker-compose.dev.yml up -d
./scripts/init-stack.sh dev
go run ./cmd/apibench -base-url http://127.0.0.1:8080 -users 1000 -tunnels 5000 -concurrency 100
```

`.env` and `.env.api` are no longer part of the supported local workflow.

Supported env files now:

- `.env.dev`
- `.env.prod`
- `.env.compose.dev`
- `.env.compose.prod`

### Environment variables (API server)

```bash
DATABASE_URL=postgres://user:pass@localhost:5432/mekongtunnel
JWT_SECRET=your-secret-here
REFRESH_SECRET=your-refresh-secret
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
FRONTEND_URL=https://angkorsearch.dev
ALLOWED_ORIGINS=https://angkorsearch.dev,http://localhost:3000,http://localhost:3001
PUBLIC_URL=https://api.angkorsearch.dev
API_ADDR=:8080
RESEND_API_KEY=re_...               # Resend HTTP API key (preferred over SMTP on cloud)
RESEND_FROM=Mekong Tunnel <noreply@angkorsearch.dev>
# SMTP fallback (only used if RESEND_API_KEY is not set)
SMTP_USER=you@gmail.com
SMTP_PASS=app-specific-password
```

### Environment variables (tunnel server)

```bash
DOMAIN=proxy.angkorsearch.dev
SSH_ADDR=:22
HTTP_ADDR=127.0.0.1:8081
HTTPS_ADDR=127.0.0.1:8443
STATS_ADDR=127.0.0.1:9090
HOST_KEY_PATH=/opt/mekongtunnel/host_key
TLS_CERT=/etc/letsencrypt/live/proxy.angkorsearch.dev/fullchain.pem
TLS_KEY=/etc/letsencrypt/live/proxy.angkorsearch.dev/privkey.pem
```

---

## 5. Database — Setup, Seed, Reset

### Requirements

- PostgreSQL 16+
- Redis 7+ (optional in code, included in the Compose stack)

### Start database (Docker)

```bash
cp .env.compose.dev.example .env.compose.dev
docker compose --env-file .env.compose.dev -f docker-compose.yml -f docker-compose.dev.yml up -d postgres redis api
```

The local Compose stack includes:

- PostgreSQL 16
- Redis 7
- `api-init` bootstrap job
- Go API
- optional `adminer` and `redis-commander` tools via `--profile tools`

Development defaults:
```
DB: mekong
User: mekong
Pass: (see .env.compose.dev)
```

### Run migrations

Migrations run automatically in two places:

- API startup
- `api-init` bootstrap job

Bootstrap also:

- ensures the single `server_config` row exists
- promotes `ADMIN_EMAIL` to admin
- creates the admin account when `ADMIN_PASSWORD` is set and the user does not exist yet

To run manually:

```bash
./scripts/init-stack.sh dev
./scripts/init-stack.sh prod
```

### Migration files

| File | Description |
|------|-------------|
| `001_init.sql` | Core schema: users, tokens, tunnels, teams, invitations |
| `002_verify_requests.sql` | Student/teacher verification workflow |
| `003_stripe_customer.sql` | Stripe customer ID on users |
| `004_plan_configs_full.sql` | Admin-editable plan limits table |
| `005_partners.sql` | Partner directory |
| `006_verify_requests_v2.sql` | Verification schema update |
| `007_subscription_plan.sql` | Stripe subscription_plan field |
| `008_notifications.sql` | User notifications |
| `009_subdomain_rules.sql` | Reserved subdomain rules |
| `010_custom_domains.sql` | User custom domains |
| `011_server_config.sql` | Admin live server config |
| `012_sponsors.sql` | Sponsor directory |
| `013_cli_device_sessions.sql` | CLI device auth sessions |
| `014_email_otp.sql` | Email OTP 2FA codes |
| `015_trial_newsletter.sql` | Free trial + newsletter subscriber fields |
| `016_donations.sql` | Donation submissions table |

### Seed data

```bash
# Insert default plan configs (needed after fresh migration)
psql $DATABASE_URL -c "
INSERT INTO plan_configs (plan, max_tunnels, max_reserved_subdomains, ...)
VALUES ('free', 1, 0, ...), ('pro', 20, 5, ...) ...
ON CONFLICT DO NOTHING;
"
```

### Reset database

```bash
# Drop and recreate (destroys all data)
psql $DATABASE_URL -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Then restart API server — migrations re-apply automatically
go run ./cmd/api
```

### Key tables

| Table | Purpose |
|-------|---------|
| `users` | email, password_hash, plan, account_type, totp_secret, totp_enabled, email_otp_enabled, suspended, github_id, google_id |
| `api_tokens` | prefix, token_hash, user_id, name, last_used_at, revoked_at |
| `refresh_tokens` | session tokens for JWT refresh |
| `password_reset_tokens` | email recovery |
| `email_verify_tokens` | email verification |
| `totp_backup_codes` | 2FA backup codes |
| `email_otp_codes` | id, user_id, code_hash (SHA256), expires_at (5 min), used_at |
| `tunnels` | subdomain, local_port, remote_ip, status, started_at, total_requests, total_bytes |
| `teams` | name, type (project/class/company), owner_id, plan |
| `team_members` | team_id, user_id, role (owner/admin/member) |
| `invitations` | email, role, token, expires_at, accepted_at |
| `reserved_subdomains` | user_id, subdomain, active |
| `custom_domains` | user_id, domain, verified_at |
| `plan_configs` | per-plan limits (admin-editable) |
| `notifications` | user_id, type, title, body, read_at |
| `cli_device_sessions` | device_code, user_code, user_id, expires_at |
| `verify_requests` | user_id, type, status, org_name, document, reject_reason |
| `partners` | name, url, logo, description |
| `sponsors` | type (github/coffee/bakong/paypal/bank/referral), title, description, url, button_text, icon, bank_name, account_name, account_number, currency, note, is_active, sort_order |
| `server_config` | global server settings (JSON) — includes freeTrialEnabled, trialDurationDays, bakongDiscountPercent |
| `newsletter_subscribers` | email, subscribed_at, unsubscribed_at, unsubscribe_token |
| `donation_submissions` | id, name, email, amount, currency, payment_method, receipt_url, social_url, message, status (pending/approved/rejected), show_on_home, created_at |

---

## 6. Go Server — MekongTunnel

The server binary (`cmd/mekongtunnel/main.go`) reads environment variables and starts 4 servers concurrently.

### Subdomain generation

```
internal/domain/domain.go
  Generate()   → adjective + "-" + noun + "-" + 8 hex chars
  IsValid()    → validates format

internal/proxy/proxy.go
  GenerateUniqueSubdomain()  → calls Generate() until unique in registry
```

### Abuse protection (`internal/proxy/abuse.go`)

- Sliding-window connection rate limiting per IP
- Configurable auto-block duration
- Admin unblock via API
- All limits live-configurable via `/api/admin/server-config`

### Per-tunnel rate limiting (`internal/tunnel/ratelimit.go`)

- Token bucket: 10 req/s, burst 20
- Applied per tunnel (not per IP)

### Live request log (`internal/tunnel/logger.go`)

Each HTTP request is streamed asynchronously back to the SSH terminal:

```
[GET] /api/users → 200 OK  42ms
[POST] /api/auth/login → 201 Created  89ms
```

---

## 7. Go CLI — mekong

### Default install paths

| Platform | Default install dir | Notes |
|----------|--------------------|------------------------------------|
| macOS | `/usr/local/bin/mekong` | Always; sudo used if not writable |
| Linux | `~/.local/bin/mekong` | Falls back from `/usr/local/bin` |
| Windows | `%LOCALAPPDATA%\Programs\mekong\mekong.exe` | No admin required; User PATH updated |

### Binary search order (VS Code ext · npm SDK · pip SDK)

```
macOS/Linux:  /usr/local/bin  →  ~/.local/bin  →  ~/bin  →  /usr/bin  →  /opt/homebrew/bin
Windows:      %LOCALAPPDATA%\Programs\mekong\  →  %LOCALAPPDATA%\  →  ~/.local/bin
```

All SDKs also try `which`/`where mekong` first via shell PATH before falling back to fixed paths.

### Auth flow (`mekong login`)

1. CLI calls `POST /api/cli/device` → gets `session_id` + `login_url`
2. Opens `https://angkorsearch.dev/cli-auth?session=SESSION_ID` in browser
3. Polls `GET /api/cli/device?session_id=` every few seconds until approved
4. Saves token to `~/.mekong/config.json`

### Self-test (`mekong test`)

Runs a diagnostic sequence:
1. Checks binary path
2. Checks SSH connectivity to `proxy.angkorsearch.dev:22`
3. Opens a real tunnel to a local test server
4. Makes an HTTP request through the tunnel URL
5. Reports pass/fail for each step

### Daemon mode

```bash
mekong -d 3000
# Forks child process with DETACHED_PROCESS (Windows) or Setsid (Unix)
# Writes PID + tunnel info to ~/.mekong/state.json
# Streams logs to ~/.mekong/mekong.log
```

---

## 7.5 Email — Mailer

**Package:** `internal/mailer/mailer.go`

The mailer supports two backends. **Resend is preferred** — DigitalOcean and most cloud providers block outbound SMTP ports (25, 465, 587) at the network level.

### Backend priority

1. **Resend HTTP API** — used when `RESEND_API_KEY` is set
   - Endpoint: `POST https://api.resend.com/emails`
   - Auth: `Authorization: Bearer <RESEND_API_KEY>`
   - From: `RESEND_FROM` env var (default: `Mekong Tunnel <onboarding@resend.dev>`)
   - No port requirements — works on all cloud VMs
   - Domain must be verified in Resend dashboard

2. **Gmail SMTP** — fallback when no Resend key
   - `smtp.gmail.com:587` STARTTLS
   - Uses `SMTP_USER` + `SMTP_PASS` (app-specific password)

### Emails sent

| Trigger | Subject |
|---------|---------|
| Register | Email verification link |
| Resend verify | Email verification link |
| Admin resend verify (`/api/admin/users/:id/resend-verify`) | Email verification link |
| Forgot password | Password reset link (expires 1h) |
| Request admin verify (`/api/auth/request-admin-verify`) | Admin notification |
| Verify request approved/rejected | Status notification |

### Config struct

```go
mailer.Config{
    ResendKey:  os.Getenv("RESEND_API_KEY"),
    ResendFrom: os.Getenv("RESEND_FROM"),
    User:       os.Getenv("SMTP_USER"),
    Pass:       os.Getenv("SMTP_PASS"),
    // Host defaults to smtp.gmail.com, Port to 587
}
```

---

## 8. Backend REST API — All Endpoints

Base URL: `https://api.angkorsearch.dev` (or `http://localhost:8080` for local dev)

Authentication: `Authorization: Bearer <jwt_or_api_token>`

API tokens have prefix `mkt_` and work on all authenticated endpoints.

When Redis-backed rate limiting is enabled, protected public endpoints also return:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `Retry-After` on `429`

---

### Auth

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| POST | `/api/auth/register` | — | `{name, email, password}` | Create account |
| POST | `/api/auth/login` | — | `{email, password}` | Login → `{access_token, user}` or `{requires_2fa, temp_token}` or `{requires_email_otp, temp_token}` |
| POST | `/api/auth/logout` | ✓ | — | Revoke refresh token |
| POST | `/api/auth/refresh` | — | `{refresh_token}` | Rotate JWT → `{access_token}` |
| GET | `/api/auth/me` | ✓ JWT only | — | Current user (JWT only — use `/api/auth/token-info` for API tokens) |
| GET | `/api/auth/token-info` | ✓ | — | Current user (works with JWT and API tokens) |
| POST | `/api/auth/forgot-password` | — | `{email}` | Send reset email |
| POST | `/api/auth/reset-password` | — | `{token, password}` | Apply reset |
| POST | `/api/auth/verify-email` | — | `{token}` | Verify email address |
| POST | `/api/auth/resend-verify` | — | `{email}` | Resend verification email |
| POST | `/api/auth/request-admin-verify` | — | `{email, message?}` | User requests admin to manually verify their email |
| POST | `/api/auth/2fa/verify` | — | `{code, temp_token}` | Complete TOTP 2FA login → `{access_token, user}` |
| POST | `/api/auth/2fa/setup` | ✓ | — | Start TOTP setup → `{secret, otpauth_url, qr_base64}` |
| POST | `/api/auth/2fa/enable` | ✓ | `{code}` | Activate TOTP → `{backup_codes[]}` |
| POST | `/api/auth/2fa/disable` | ✓ | `{code}` | Disable TOTP |
| POST | `/api/auth/email-otp/verify` | — | `{code, temp_token}` | Complete email OTP login → `{access_token, user}` |
| POST | `/api/auth/2fa/email/enable` | ✓ | — | Enable email OTP (sends 6-digit code at each login) |
| POST | `/api/auth/2fa/email/disable` | ✓ | — | Disable email OTP |
| GET | `/api/auth/github` | — | `?redirect_to=<origin>` | Start GitHub OAuth. Pass `redirect_to` to redirect back to a specific origin (localhost allowed for dev) |
| GET | `/api/auth/github/callback` | — | — | GitHub OAuth callback |
| GET | `/api/auth/google` | — | `?redirect_to=<origin>` | Start Google OAuth. Pass `redirect_to` to redirect back to a specific origin (localhost allowed for dev) |
| GET | `/api/auth/google/callback` | — | — | Google OAuth callback |
| POST | `/api/cli/device` | — | — | CLI device flow → `{session_id, login_url, expires_in, poll_interval}` |
| GET | `/api/cli/device` | — | `?session_id=` | Poll for token → `{status, token?}` |
| POST | `/api/cli/device/approve` | ✓ | `?session_id=` | Browser approves CLI login |

Rate-limited when Redis is enabled:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/token-info`
- `POST /api/auth/forgot-password`
- `POST /api/auth/verify-email`
- `POST /api/auth/resend-verify`
- `POST /api/auth/request-admin-verify`
- `POST /api/auth/email-otp/verify`
- `POST /api/cli/device`
- `GET /api/cli/device`

---

### User

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| PUT | `/api/user` | ✓ | `{name?, avatar_url?}` | Update profile |
| PUT | `/api/user/password` | ✓ | `{current_password, new_password}` | Change password |
| DELETE | `/api/user` | ✓ | — | Delete account permanently |
| GET | `/api/user/verify-request` | ✓ | — | Get own verification request |
| POST | `/api/user/verify-request` | ✓ | `{type, org_name, notes, document_name, document_data}` | Submit verify request |
| PATCH | `/api/user/plan` | ✓ | `{plan}` | Switch to free plan |

---

### API Tokens

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/tokens` | ✓ | — | List all tokens |
| POST | `/api/tokens` | ✓ | `{name, expires_in_days?}` | Create token → `{token: "mkt_...", record}` |
| DELETE | `/api/tokens/:id` | ✓ | — | Revoke token |

---

### Tunnels

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/tunnels` | ✓ | — | List user's tunnel sessions |
| GET | `/api/tunnels/stats` | — | — | Aggregate tunnel stats (used by tunnel server) |
| POST | `/api/tunnels` | internal | `{subdomain, local_port, ...}` | Tunnel server reports new tunnel (no auth) |
| PATCH | `/api/tunnels/:id` | internal | `{status}` | Update tunnel status (no auth) |

---

### Teams

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/team` | ✓ | — | List teams → `{teams[], limit}` |
| POST | `/api/team` | ✓ | `{name, type?}` | Create team |
| PATCH | `/api/team/:id` | ✓ | `{name}` | Rename team |
| DELETE | `/api/team/:id` | ✓ | — | Delete team |
| GET | `/api/team/members` | ✓ | `?team_id=` | List members |
| DELETE | `/api/team/members/:userId` | ✓ | `?team_id=` | Remove member |
| GET | `/api/team/invitations` | ✓ | `?team_id=` | List invitations |
| POST | `/api/team/invite` | ✓ | `{email, role?, team_id?}` | Invite by email |
| POST | `/api/team/invite/code` | ✓ | `{team_id?}` | Generate invite link → `{code, expires_at}` |
| DELETE | `/api/team/invite/:id` | ✓ | — | Revoke invitation |
| POST | `/api/team/invite/accept` | ✓ | `{token}` | Accept email invite |

---

### Subdomains

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/subdomains` | ✓ | — | List reserved subdomains |
| POST | `/api/subdomains` | ✓ | `{subdomain}` | Reserve subdomain |
| DELETE | `/api/subdomains/:id` | ✓ | — | Release subdomain |

---

### Custom Domains

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/domains` | ✓ | — | List custom domains |
| POST | `/api/domains` | ✓ | `{domain}` | Add custom domain |
| DELETE | `/api/domains/:id` | ✓ | — | Remove domain and return cleanup guidance |
| POST | `/api/domains/:id/verify` | ✓ | — | Trigger DNS/HTTPS verification |
| PATCH | `/api/domains/:id/target` | ✓ | `{subdomain}` | Route a custom domain to a reserved subdomain |

Notes:

- the API rejects malformed hostnames such as `ttt..example.com`
- deleting a domain removes the MekongTunnel route only; DNS remains at the provider until changed there

### Admin Custom Domains

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/admin/domains` | Admin | — | List custom domains across users |
| GET | `/api/admin/domains/:id` | Admin | — | Inspect one custom domain |
| POST | `/api/admin/domains/:id/verify` | Admin | — | Re-run DNS / HTTPS verification for any user domain |
| PATCH | `/api/admin/domains/:id/target` | Admin | `{target_subdomain}` | Re-point a user's domain to one of that user's reserved subdomains |
| DELETE | `/api/admin/domains/:id` | Admin | — | Delete any user's custom-domain mapping and return cleanup guidance |

---

### Billing (Stripe)

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/billing` | ✓ | — | Get plan, subscription status, invoices |
| POST | `/api/billing/checkout` | ✓ | `{plan}` | Create Stripe checkout → `{url}` |
| POST | `/api/billing/portal` | ✓ | — | Create Stripe portal → `{url}` |
| POST | `/api/billing/webhook` | — | Stripe event | Stripe webhook handler |

### Manual Payment Receipts (PayPal / ABA Pay / Bakong)

Receipts flow: user submits → admin reviews → approved/rejected/needs_resubmit.
Duplicate prevention: only one pending/needs_resubmit receipt per user per plan is allowed.

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| POST | `/api/billing/manual-payment` | ✓ | `{plan, method, receipt_url, note?, amount_usd?}` | Submit receipt (blocks duplicate pending) |
| GET | `/api/billing/manual-payment` | ✓ | — | List own receipts |
| GET | `/api/billing/manual-payment/count` | ✓ | — | Count of own pending/needs_resubmit receipts |
| GET | `/api/admin/billing/receipts` | ✓ admin | — | List all receipts |
| GET | `/api/admin/billing/receipts/count` | ✓ admin | — | Count of pending receipts |
| POST | `/api/admin/billing/receipts/:id/review` | ✓ admin | `{status, admin_note?, allow_resubmit?, refund_bank?, refund_amount?, refund_note?}` | Approve / reject / request resubmit |
| DELETE | `/api/admin/billing/receipts/:id` | ✓ admin | — | Delete receipt |

Status values: `pending` → `approved` \| `rejected` \| `needs_resubmit`

On approval: user plan is upgraded and a confirmation email is sent via Resend.

---

### Notifications

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/notifications` | ✓ | `?limit=&offset=` | List notifications → `{notifications[], total, unread}` |
| PATCH | `/api/notifications/:id/read` | ✓ | — | Mark one read → `{unread}` |
| PATCH | `/api/notifications/read-all` | ✓ | — | Mark all read → `{unread}` |
| DELETE | `/api/notifications/:id` | ✓ | — | Delete notification |

---

### Public

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/health` | — | — | `{ok: true, service: "mekong-api"}` |
| GET | `/api/plans` | — | — | Public plan limits (used by landing page) |
| GET | `/api/server-limits` | — | — | Current server rate limits |
| GET | `/api/partners` | — | — | Partner directory |
| GET | `/api/sponsors` | — | — | Sponsor listings |
| POST | `/api/newsletter/subscribe` | — | `{email}` | Subscribe to newsletter |
| GET | `/api/newsletter/unsubscribe` | — | `?token=` | Unsubscribe via email token |
| POST | `/api/donations/submit` | — | `{name, email?, amount, currency, payment_method, receipt_url?, social_url?, message?}` | Submit donation for review |
| GET | `/api/donations` | — | — | Public list of approved+show_on_home donations |

---

### Admin (requires `is_admin = true`)

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| GET | `/api/admin/stats` | ✓ admin | — | `{total_users, active_tunnels, total_tunnels, revenue_month, new_users_week}` |
| GET | `/api/admin/revenue` | ✓ admin | — | `{mrr, total_revenue, pro_count, org_count, recent_charges[]}` |
| GET | `/api/admin/users` | ✓ admin | `?search=&plan=&limit=&offset=` | Paginated user list |
| GET | `/api/admin/users/:id` | ✓ admin | — | Single user detail |
| PATCH | `/api/admin/users/:id` | ✓ admin | `{plan?, suspended?, is_admin?}` | Update user |
| DELETE | `/api/admin/users/:id` | ✓ admin | — | Delete user |
| POST | `/api/admin/users/:id/resend-verify` | ✓ admin | — | Send verification email to user |
| GET | `/api/admin/tunnels` | ✓ admin | `?limit=&offset=` | All active tunnels |
| DELETE | `/api/admin/tunnels/:id` | ✓ admin | — | Kill any tunnel |
| GET | `/api/admin/abuse/events` | ✓ admin | — | Abuse events |
| GET | `/api/admin/abuse/blocked` | ✓ admin | — | Blocked IPs |
| POST | `/api/admin/abuse/blocked` | ✓ admin | `{ip, reason?}` | Block IP |
| DELETE | `/api/admin/abuse/blocked/:id` | ✓ admin | — | Unblock IP |
| GET | `/api/admin/plans` | ✓ admin | — | All plan configs |
| PUT | `/api/admin/plans` | ✓ admin | `{plans[]}` | Update plan limits |
| GET | `/api/admin/server-limits` | ✓ admin | — | Live server config (includes freeTrialEnabled, trialDurationDays, bakongDiscountPercent) |
| PATCH | `/api/admin/server-limits` | ✓ admin | `ServerConfig` | Update server config |
| GET | `/api/admin/organizations` | ✓ admin | `?search=&limit=&offset=` | Organization list |
| POST | `/api/admin/organizations` | ✓ admin | — | Create org |
| GET | `/api/admin/organizations/:id` | ✓ admin | — | Get single org |
| PATCH | `/api/admin/organizations/:id` | ✓ admin | `{plan?, suspended?}` | Update org |
| DELETE | `/api/admin/organizations/:id` | ✓ admin | — | Delete org |
| GET | `/api/admin/organizations/:id/members` | ✓ admin | — | Org member list |
| GET | `/api/admin/verify-requests` | ✓ admin | `?status=` | Verification requests |
| GET | `/api/admin/verify-requests/:id` | ✓ admin | — | Single verify request |
| PATCH | `/api/admin/verify-requests/:id` | ✓ admin | `{status, reject_reason?, force_override?}` | Approve/reject |
| DELETE | `/api/admin/verify-requests/:id` | ✓ admin | — | Delete request |
| POST | `/api/admin/verify-requests/:id/notify` | ✓ admin | `{message}` | Send notification |
| POST | `/api/admin/verify-requests/:id/reset` | ✓ admin | `{note}` | Reset to pending |
| GET | `/api/admin/billing/subscribers` | ✓ admin | — | Newsletter subscribers list |
| POST | `/api/admin/billing/refund` | ✓ admin | `{charge_id}` | Issue Stripe refund |
| POST | `/api/admin/billing/receipt` | ✓ admin | `{user_id}` | Send receipt email |
| GET | `/api/admin/system` | ✓ admin | — | System snapshot (CPU, RAM, disk) |
| GET | `/api/admin/system/stream` | ✓ admin | — | SSE stream of live system metrics |
| GET | `/api/admin/newsletter/campaigns` | ✓ admin | — | Sent newsletter campaigns |
| POST | `/api/admin/newsletter/send` | ✓ admin | `{subject, body}` | Send newsletter to all subscribers |
| GET | `/api/admin/donations` | ✓ admin | `?status=` | All donation submissions |
| PATCH | `/api/admin/donations/:id` | ✓ admin | `{status, show_on_home?}` | Approve/reject donation, toggle donor wall visibility |

---

### Tunnel Server Stats (port 9090, localhost only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | HTML dashboard with live stats |
| GET | `/api/stats` | JSON `{activeTunnels, totalRequests, bandwidthBytes, tunnels[]}` |

---

## 9. Frontend — angkorsearch.dev

**Stack:** Next.js 16 · React 19 · TypeScript · Tailwind CSS v4 · Redux Toolkit + RTK Query · Framer Motion · next-mdx-remote

### Project structure

```
mekongtunnel.dev/
├── app/
│   ├── (marketing)/           ← Public landing page
│   │   └── page.tsx           (Hero, InstallTabs, HowItWorks, Features, Pricing, Limits, Ecosystem)
│   ├── (docs)/                ← Documentation
│   │   └── docs/[[...slug]]/  (MDX rendered docs with sidebar)
│   ├── auth/                  ← Login, register, forgot/reset password
│   ├── cli-auth/              ← CLI device flow approval page
│   ├── dashboard/             ← Authenticated user area
│   │   ├── page.tsx           (tunnel list, stats)
│   │   ├── tokens/            (API token management)
│   │   ├── team/              (team management)
│   │   └── billing/           (subscription, invoices)
│   ├── admin/                 ← Admin panel
│   │   ├── users/             (user management)
│   │   ├── plans/             (plan config editor + TrialSettingsCard)
│   │   ├── server-limits/     (rate limits + free trial + Bakong discount %)
│   │   ├── verify-requests/   (verification approvals)
│   │   ├── newsletter/        (compose + send newsletter, campaign list)
│   │   ├── donations/         (donation submissions — approve/reject, donor wall toggle)
│   │   ├── sponsors/          (sponsor card CRUD: github/coffee/bakong/paypal/bank/referral)
│   │   └── page.tsx           (admin dashboard stats + quick-access cards)
│   ├── invite/                ← Team invitation acceptance
│   └── api/                   ← Next.js API routes
│       └── domains/[id]/      (domain verification proxy)
├── components/
│   ├── hero.tsx               (landing hero with version badge)
│   ├── install-tabs.tsx       (CLI install + SDK accordion)
│   ├── how-it-works.tsx
│   ├── feature-card.tsx
│   ├── partners-section.tsx
│   ├── pricing-cta.tsx
│   ├── footer.tsx
│   ├── navbar.tsx
│   ├── copy-button.tsx
│   ├── terminal-window.tsx
│   ├── tunnel-architecture-flow.tsx
│   ├── doc-sidebar.tsx
│   ├── doc-content.tsx
│   ├── mdx-components.tsx     (custom MDX: Callout, Cards, Card, Steps, etc.)
│   └── dashboard/             (dashboard-specific components)
├── lib/
│   ├── i18n.ts                (English + Khmer translations)
│   ├── locale.ts              (server-side locale detection)
│   ├── locale-context.tsx     (client-side locale context)
│   ├── api.ts                 (raw fetch API client — 31 KB)
│   ├── types.ts               (all TypeScript types)
│   ├── plans.ts               (plan helpers + DEFAULT_PLANS)
│   ├── docs.ts                (MDX doc loading)
│   ├── nav.ts                 (sidebar nav config)
│   └── store/
│       ├── store.ts           (Redux store config)
│       ├── baseApi.ts         (RTK Query base with retry + auth)
│       ├── authSlice.ts       (auth state: user, token, loading)
│       ├── networkSlice.ts    (online/offline state)
│       └── endpoints/
│           ├── userEndpoints.ts
│           ├── tokenEndpoints.ts
│           ├── billingEndpoints.ts
│           ├── teamEndpoints.ts
│           ├── adminEndpoints.ts
│           └── notificationEndpoints.ts
└── content/docs/              ← MDX documentation files
    ├── getting-started.mdx
    ├── installation.mdx
    ├── cli-reference.mdx
    ├── how-it-works.mdx
    ├── self-hosting.mdx
    ├── authentication.mdx
    ├── configuration.mdx
    ├── npm-cli.mdx
    ├── python.mdx
    ├── vscode-extension.mdx
    ├── python-fastapi.mdx
    ├── python-flask.mdx
    ├── python-django.mdx
    ├── python-uvicorn.mdx
    ├── python-starlette.mdx
    ├── node-nextjs.mdx
    ├── node-vite.mdx
    ├── node-nuxt.mdx
    ├── node-remix.mdx
    ├── node-sveltekit.mdx
    ├── node-astro.mdx
    ├── node-express.mdx
    ├── faq.mdx
    ├── stats-api.mdx
    └── km/                    ← Khmer language versions
```

### Build commands

```bash
npm run dev              # development server on :3000
npm run build            # production build (--webpack flag)
npm run start            # serve production build
npm run lint             # ESLint
npm run dev:tunnel       # dev server + mekong tunnel combined
```

### Environment variables

```bash
NEXT_PUBLIC_API_URL=https://api.angkorsearch.dev
NEXT_PUBLIC_WS_URL=wss://proxy.angkorsearch.dev
```

---

### Color System

All colors are CSS custom properties defined in `app/globals.css`. Use them via Tailwind or directly in `style={}`.

#### Light theme

| Variable | Value | Usage |
|----------|-------|-------|
| `--color-bg` | `#f7f1e6` | Page background (warm beige) |
| `--color-card` | `#fffdf8` | Card surface (off-white) |
| `--color-surface` | `#efe4d2` | Raised surface (light tan) |
| `--color-paper` | `#fbf7ef` | Terminal / code block background |
| `--color-line` | `#d7c8ae` | Borders |
| `--color-gold` | `#a15f00` | Primary accent (dark gold) |
| `--color-mekong` | `#cc0001` | Brand red (secondary accent) |
| `--color-muted` | `#6a6f7d` | Secondary text |
| `--color-dim` | `#201b16` | Primary text (near-black) |
| `--color-code` | `#0f5fa8` | Inline code / monospace |
| `--color-purple` | `#7c3aed` | Purple accent |

#### Dark theme

| Variable | Value | Usage |
|----------|-------|-------|
| `--color-bg` | `#0d0d1a` | Dark navy background |
| `--color-card` | `#16162a` | Card surface |
| `--color-surface` | `#1e1e38` | Raised surface |
| `--color-paper` | `#0a0a14` | Terminal / code block |
| `--color-line` | `#2d3146` | Borders |
| `--color-gold` | `#ffd700` | Primary accent (bright gold) |
| `--color-muted` | `#a4a8b8` | Secondary text |
| `--color-dim` | `#e6e1d8` | Primary text (off-white) |
| `--color-code` | `#7c9fd4` | Inline code (light blue) |
| `--color-purple` | `#9b8de8` | Purple accent |

#### Tailwind class mapping

```
bg-bg        → var(--color-bg)
bg-card      → var(--color-card)
bg-surface   → var(--color-surface)
bg-paper     → var(--color-paper)
border-line  → var(--color-line)
text-gold    → var(--color-gold)
text-muted   → var(--color-muted)
text-dim     → var(--color-dim)
text-code    → var(--color-code)
text-purple  → var(--color-purple)
```

#### Status colors (semantic)

```css
/* Available in both themes */
--status-success-bg / --status-success-border / --status-success-fg
--status-warning-bg / --status-warning-border / --status-warning-fg
--status-info-bg    / --status-info-border    / --status-info-fg
--status-danger-bg  / --status-danger-border  / --status-danger-fg
```

#### Font stack

```css
/* Sans (body) */
"Avenir Next", "Segoe UI", "Helvetica Neue", Arial,
"Noto Sans Khmer", "Khmer OS System", sans-serif

/* Mono (code) */
"SFMono-Regular", "JetBrains Mono", "Cascadia Code",
Consolas, "Liberation Mono", Menlo, monospace
```

---

### Redux Store

#### Store shape

```typescript
{
  [baseApi.reducerPath]: RTKQueryCacheState,  // all API cache
  auth: {
    user: APIUser | null,
    accessToken: string | null,
    loading: boolean,
  },
  network: {
    isOnline: boolean,
  }
}
```

#### Base API config (`lib/store/baseApi.ts`)

```typescript
API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080'

// Features:
// - Auto-injects Bearer token from auth state
// - Exponential backoff retry (max 3, up to 10s delay)
// - 15s request timeout
// - credentials: 'include'
// - Tag invalidation for cache busting

tagTypes: [
  'User', 'Team', 'TeamMembers', 'Invitations',
  'Tokens', 'Tunnels', 'Billing', 'Notifications',
  'AdminUsers', 'AdminStats', 'Plans', 'Partners', 'VerifyRequest'
]
```

#### RTK Query hooks (all endpoints)

**User** (`userEndpoints.ts`)
```typescript
useGetMeQuery()                                    // GET /api/auth/me
useUpdateProfileMutation()                         // PUT /api/user
useUpdatePasswordMutation()                        // PUT /api/user/password
useDeleteAccountMutation()                         // DELETE /api/user
useGetVerifyRequestQuery()                         // GET /api/user/verify-request
useSubmitVerifyRequestMutation()                   // POST /api/user/verify-request
useSetActivePlanMutation()                         // PATCH /api/user/plan
```

**Tokens** (`tokenEndpoints.ts`)
```typescript
useListTokensQuery()                               // GET /api/tokens
useCreateTokenMutation()                           // POST /api/tokens
useRevokeTokenMutation()                           // DELETE /api/tokens/:id
```

**Billing** (`billingEndpoints.ts`)
```typescript
useGetBillingQuery()                               // GET /api/billing
useCreateCheckoutMutation()                        // POST /api/billing/checkout
useCreatePortalMutation()                          // POST /api/billing/portal
```

**Teams** (`teamEndpoints.ts`)
```typescript
useGetTeamsQuery()                                 // GET /api/team
useCreateTeamMutation()                            // POST /api/team
useRenameTeamMutation()                            // PATCH /api/team/:id
useDeleteTeamMutation()                            // DELETE /api/team/:id
useGetTeamMembersQuery(teamId?)                    // GET /api/team/members
useRemoveMemberMutation()                          // DELETE /api/team/members/:userId
useGetInvitationsQuery(teamId?)                    // GET /api/team/invitations
useInviteByEmailMutation()                         // POST /api/team/invite
useGenerateInviteCodeMutation()                    // POST /api/team/invite/code
useRevokeInviteMutation()                          // DELETE /api/team/invite/:id
useAcceptInviteMutation()                          // POST /api/team/invite/accept
```

**Admin** (`adminEndpoints.ts`)
```typescript
useGetAdminStatsQuery()                            // GET /api/admin/stats
useListAdminUsersQuery({search, plan, limit, offset})  // GET /api/admin/users
useUpdateAdminUserMutation()                       // PATCH /api/admin/users/:id
useDeleteAdminUserMutation()                       // DELETE /api/admin/users/:id
useGetPublicPlansQuery()                           // GET /api/plans
```

**Notifications** (`notificationEndpoints.ts`)
```typescript
useListNotificationsQuery()                        // GET /api/notifications
useMarkReadMutation()                              // PATCH /api/notifications/:id/read
useMarkAllReadMutation()                           // PATCH /api/notifications/read-all
```

---

### TypeScript types (`lib/types.ts`)

```typescript
type Plan = 'free' | 'student' | 'pro' | 'org'
type AccountType = 'free' | 'student' | 'teacher' | 'pro' | 'org' | 'personal' | 'team'
type TeamRole = 'owner' | 'admin' | 'member'
type TunnelStatus = 'active' | 'stopped'

interface APIUser {
  id: string
  email: string
  name: string
  avatarUrl?: string
  plan: Plan
  accountType: AccountType
  emailVerified: boolean
  totpEnabled: boolean
  emailOtpEnabled: boolean
  createdAt: string
  lastSeenAt?: string
  suspended?: boolean
  githubLogin?: string
  isAdmin?: boolean
  subscriptionPlan?: string
}

interface APIToken {
  id: string
  name: string
  prefix: string          // first 8 chars of token
  createdAt: string
  lastUsedAt?: string
  revokedAt?: string
  expiresAt?: string
}

interface APITunnel {
  id: string
  userId?: string
  subdomain: string
  url: string
  localPort: number
  remoteIp: string
  status: TunnelStatus
  startedAt: string
  endedAt?: string
  totalRequests: number
  totalBytes: number
}

interface APITeam {
  id: string
  name: string
  type: 'class' | 'company' | 'project'
  plan: Plan
  ownerId: string
  createdAt: string
}

interface APITeamMember {
  userId: string
  teamId: string
  name: string
  email: string
  avatarUrl?: string
  role: TeamRole
  joinedAt: string
}

interface APIInvitation {
  id: string
  email: string
  role: TeamRole
  expiresAt: string
  acceptedAt?: string
}

interface PlanLimits {
  id: Plan
  name: string
  price: number | null
  maxTunnels: number
  maxReservedSubdomains: number
  maxCustomDomains: number
  tunnelLifetimeHours: number
  bandwidthGbPerMonth: number
  requestLogDays: number
  maxTeamMembers: number
  requestInspection: boolean
  prioritySupport: boolean
  color: string
  badge?: string
}

interface ServerConfig {
  maxTunnelsPerIP: number
  maxTotalTunnels: number
  maxConnectionsPerMinute: number
  requestsPerSecond: number
  maxRequestBodyBytes: number
  maxWebSocketTransferBytes: number
  inactivityTimeoutSeconds: number
  maxTunnelLifetimeHours: number
  sshHandshakeTimeoutSeconds: number
  blockDurationMinutes: number
}

// WebSocket events (real-time tunnel updates)
type WsEvent =
  | { type: 'tunnel.open';   tunnel: APITunnel }
  | { type: 'tunnel.close';  tunnelId: string }
  | { type: 'tunnel.stats';  tunnelId: string; requests: number; bytes: number }
  | { type: 'stats.global';  activeTunnels: number; totalRequests: number; bandwidthBytes: number }
```

---

## 10. npm Package — mekong-cli

**Location:** `mekong-node-sdk/`
**npm:** [npmjs.com/package/mekong-cli](https://www.npmjs.com/package/mekong-cli)
**Version:** v2.0.0

### Files

```
mekong-node-sdk/
├── package.json
├── bin/mekong-cli.js          ← CLI entry point
├── lib/
│   ├── sdk.js                 ← JavaScript/TypeScript SDK
│   ├── runner.js              ← spawn mekong process + parse URL
│   ├── init.js                ← mekong-cli init (framework detection)
│   ├── find-mekong.js         ← binary path resolver
│   ├── detect-port.js         ← framework port detection
│   └── wait-for-port.js       ← poll until port is listening
└── test/
    ├── sdk.test.mjs           ← SDK tests (ESM)
    └── cli.test.mjs           ← CLI tests (ESM)
```

### CLI usage

```bash
mekong-cli 3000                                # tunnel existing server
mekong-cli --with "next dev" --port 3000       # start dev server + tunnel
mekong-cli --with "vite" --port 5173
mekong-cli --token mkt_xxx 3000               # with API token
mekong-cli --expire 2h 3000                   # with expiry
mekong-cli --daemon 3000                      # background mode
mekong-cli init                               # inject dev:tunnel script
```

### SDK usage

```javascript
const mekong = require('mekong-cli/sdk')
// ESM: import mekong from 'mekong-cli/sdk'

// Start tunnel
const { url, stop } = await mekong.expose(3000)
console.log(url)   // https://happy-tiger-a1b2.proxy.angkorsearch.dev
stop()

// With options
const { url, stop } = await mekong.expose(3000, {
  token: 'mkt_xxx',
  expire: '2h',
  noQr: true,
})

// Auth
const token = await mekong.login()     // browser device flow
mekong.logout()
const info = mekong.whoami()           // { token, email } or null
const token = mekong.getToken()        // from env or config
```

### Token resolution order

1. `opts.token` / `--token` flag
2. `MEKONG_TOKEN` env var
3. `~/.mekong/config.json` (written by `mekong login`)

### Supported frameworks (auto-detect)

| Framework | Detected from | Default port |
|-----------|--------------|-------------|
| Next.js | `next` in deps | 3000 |
| Vite | `vite` in deps | 5173 |
| Nuxt | `nuxt` in deps | 3000 |
| Remix | `@remix-run` in deps | 5173 |
| SvelteKit | `@sveltejs/kit` in deps | 5173 |
| Astro | `astro` in deps | 4321 |
| Gatsby | `gatsby` in deps | 8000 |
| Angular | `@angular/core` in deps | 4200 |
| Express / Fastify | script name match | 3000 |
| React CRA | `react-scripts` in deps | 3000 |

### Run tests

```bash
cd mekong-node-sdk && npm test     # 11 tests, 3 skipped (require live server)
```

---

## 11. Python Package — mekong-tunnel

**Location:** `mekong-python-sdk/`
**PyPI:** [pypi.org/project/mekong-tunnel](https://pypi.org/project/mekong-tunnel/)
**Version:** v2.1.0

### Files

```
mekong-python-sdk/
├── pyproject.toml
├── src/mekong_tunnel/
│   ├── __init__.py            ← public API: expose(), login(), logout(), whoami(), get_token()
│   ├── commands.py            ← CLI entry points for each framework
│   ├── runner.py              ← subprocess management + URL parsing (ANSI-clean)
│   ├── find_mekong.py         ← binary path resolver
│   └── detect_port.py        ← framework port detection
└── tests/
    ├── test_sdk.py            ← SDK integration tests
    ├── test_fastapi.py        ← FastAPI wrapper test
    └── test_*.py              ← per-framework tests
```

### CLI wrappers

```bash
uvicorn-mekong main:app --port 8000 --domain
fastapi-mekong main:app --port 8000
flask-mekong run --port 5000
django-mekong runserver 8000
gunicorn-mekong main:app --bind 0.0.0.0:8000
hypercorn-mekong main:app --port 8000
granian-mekong main:app --port 8000
```

#### Mode flags (all wrappers)

| Flag | Behavior |
|------|----------|
| _(none)_ | Start server + tunnel, print URL |
| `--local` | Start server, open `http://localhost:PORT` in browser |
| `--domain` | Start server + tunnel, open tunnel URL in browser |
| `--expire 1d` | Tunnel lifetime |
| `--no-qr` | Suppress QR code |
| `--daemon` | Background mode |
| `--token mkt_xxx` | API token |

### Python SDK

```python
import mekong_tunnel as mekong

# Start tunnel (blocking until stopped)
tunnel = mekong.expose(8000)
print(tunnel.url)     # https://happy-tiger-a1b2.proxy.angkorsearch.dev
tunnel.stop()

# Context manager (auto-stop)
with mekong.expose(8000) as t:
    print(t.url)

# With options
tunnel = mekong.expose(8000,
    token='mkt_xxx',
    expire='2h',
    no_qr=True,
)

# Auth
token = mekong.login()        # browser device flow
mekong.logout()
info = mekong.whoami()        # {'token': '...', 'email': '...'} or None
token = mekong.get_token()    # from env or config
```

### pytest fixture example

```python
import pytest
import mekong_tunnel as mekong

@pytest.fixture(scope='session')
def public_url():
    with mekong.expose(8000) as t:
        yield t.url

def test_home(public_url):
    import urllib.request
    res = urllib.request.urlopen(public_url)
    assert res.status == 200
```

### Run tests

```bash
cd mekong-python-sdk && python3 -m pytest     # 25 tests, 0 failed
```

---

## 12. VS Code Extension

**Location:** `mekong-vscode-extension/`
**Marketplace:** [KhmerStack.mekong-tunnel](https://marketplace.visualstudio.com/items?itemName=KhmerStack.mekong-tunnel)
**Version:** v1.5.0

### Files

```
mekong-vscode-extension/
├── package.json               ← extension manifest + commands + settings
├── tsconfig.json
├── src/
│   ├── extension.ts           ← main extension host code
│   └── liveServer.ts          ← built-in static file server
├── media/
│   ├── webview.html           ← sidebar panel UI
│   └── webview.js             ← sidebar panel logic
└── images/
    ├── icon.png
    └── mekong-icon.svg
```

### Build & package

```bash
cd mekong-vscode-extension
npm run compile                      # tsc → out/
npx vsce package --no-dependencies   # → mekong-tunnel-1.5.0.vsix
code --install-extension mekong-tunnel-1.5.0.vsix --force
```

### Publish to Marketplace

```bash
npx vsce publish                     # requires VSCE_PAT env var
# or via GitHub Actions (publish-vscode.yml) on tag vscode-v*
```

### Key features

- **Account panel** — login/logout via `mekong login` terminal, shows email + plan badge
- **Binary auto-detect** — searches `/usr/local/bin`, `~/.local/bin`, `~/bin`, PATH (macOS: `/usr/local/bin` first)
- **Auto port detection** — reads `package.json` for framework default port
- **Dev server check** — warns if nothing is listening on target port
- **Live Server** — built-in static file server (no binary needed)
- **Status bar** — shows active tunnel URL / live server state

---

## 13. CI/CD Pipelines

All workflows in `.github/workflows/`.

### ci.yml — Continuous Integration

Triggers: push to `main`, pull requests

```yaml
Steps:
  1. go build ./...                  # verify compiles
  2. go test (stable subset)         # domain, expiry, tunnel packages
  3. make build-client-all           # cross-compile all 6 CLI binaries
```

### release.yml — Binary Release

Triggers: tag push matching `v*` (e.g. `v1.5.6`)

```yaml
Steps:
  1. Cross-compile 6 binaries (darwin/linux/windows × amd64/arm64)
  2. Generate SHA-256 checksums
  3. Build release notes from CHANGELOG.md
  4. Create GitHub Release with all binaries + checksums
```

Local equivalent:

```bash
make release-cli-assets TAG=v1.5.7
make release-cli-publish TAG=v1.5.7
```

### publish-npm.yml — npm

Triggers: tag `npm-v*` OR manual dispatch

```yaml
Steps:
  1. Resolve version from package.json
  2. Verify tag matches package.json version
  3. Check version not already published
  4. npm test (11 tests)
  5. npm publish --access public
```

### publish-pypi.yml — PyPI

Triggers: tag `pypi-v*` OR manual dispatch

```yaml
Steps:
  1. Resolve version from pyproject.toml
  2. Verify tag matches toml version
  3. Check version not already published on PyPI
  4. python -m pytest (25 tests)
  5. python -m build → twine upload
  6. Upload dist as GitHub artifact (30-day retention)
```

### publish-vscode.yml — VS Code Marketplace

Triggers: tag `vscode-v*` OR manual dispatch

```yaml
Steps:
  1. npm install
  2. npm run compile
  3. npx vsce publish
```

---

## 14. Release Checklist

### Full release (all components)

```
Go CLI + Server:
[ ] Update VER constant in install-tabs.tsx to new version
[ ] Update version in install.sh and install.ps1
[ ] Bump version in internal/config/config.go
[ ] git tag v1.x.x && git push --tags
[ ] GitHub Actions release.yml runs automatically

npm:
[ ] cd mekong-node-sdk && npm test (11/11 pass)
[ ] Bump version in mekong-node-sdk/package.json
[ ] git tag npm-v2.x.x && git push --tags
[ ] GitHub Actions publish-npm.yml runs automatically

PyPI:
[ ] cd mekong-python-sdk && python3 -m pytest (25/25 pass)
[ ] Bump version in mekong-python-sdk/pyproject.toml
[ ] git tag pypi-v2.x.x && git push --tags
[ ] GitHub Actions publish-pypi.yml runs automatically

VS Code:
[ ] cd mekong-vscode-extension && npm run compile
[ ] Bump version in mekong-vscode-extension/package.json
[ ] npx vsce package → test .vsix locally
[ ] git tag vscode-v1.x.x && git push --tags
[ ] GitHub Actions publish-vscode.yml runs automatically

Frontend:
[ ] Update VER in components/install-tabs.tsx
[ ] Update version badge in components/hero.tsx
[ ] Update HANDBOOK.md last-updated line
[ ] npm run build && deploy
```

---

## 15. Deployment Guide

### Current production split

| Public hostname | Purpose |
|-----------------|---------|
| `angkorsearch.dev` | Frontend |
| `api.angkorsearch.dev` | API |
| `proxy.angkorsearch.dev` | Tunnel SSH + HTTPS edge |
| `*.proxy.angkorsearch.dev` | Generated public tunnel URLs |
| `*.mekongtunnel.dev` | Optional branded wildcard custom domains |

### Preferred deploy commands

Run from the repo on your local machine:

```bash
./scripts/deploy-api.sh
./scripts/deploy-tunnel.sh
WILDCARD_DOMAIN=mekongtunnel.dev ./scripts/deploy-tunnel.sh   # optional branded wildcard
```

What they do:

- `deploy-api.sh` builds `cmd/api`, uploads it to the API host on SSH `:2222`, restarts `mekong-api`, and checks `/api/health`, `/api/cli/subdomains`, and `/api/cli/domains`
- `deploy-tunnel.sh` builds `cmd/mekongtunnel`, uploads `bin/mekongtunnel` plus local `.env.prod`, installs `mekongtunnel.service`, verifies ports `22`, `8081`, `8443`, `9090`, and can install a branded wildcard nginx vhost

If the real servers still use `systemd`, GitHub Actions can run these same scripts now:

- push to `main` -> `Deploy Dev`
- publish a GitHub Release -> `Deploy Production`

Use [`docs/GITHUB_DEPLOY.md`](./docs/GITHUB_DEPLOY.md) for the required GitHub Environment secrets and variables.

Redis is optional in this VM workflow. Leave `REDIS_URL` unset if you are still running a single API instance and a single tunnel edge.

### Proxy host expectations

The proxy host should look like this after deploy:

```text
sshd           -> :2222
mekongtunnel   -> :22
mekongtunnel   -> 127.0.0.1:8081
mekongtunnel   -> 127.0.0.1:8443
mekongtunnel   -> 127.0.0.1:9090
nginx          -> :80 and :443
```

### Server-side git workflow (optional)

If `/opt/mekongtunnel` is a real git checkout on the proxy host, you can still use:

```bash
cd /opt/mekongtunnel
./update.sh
```

`update.sh` is not the primary production path anymore; it is for git-managed hosts only.

### TLS and nginx

- issue a wildcard cert for `proxy.angkorsearch.dev` and `*.proxy.angkorsearch.dev`
- optionally issue a second wildcard cert for `mekongtunnel.dev` and `*.mekongtunnel.dev`
- nginx should terminate public `:80/:443` and proxy to MekongTunnel on `127.0.0.1:8081` and `127.0.0.1:8443`

For the exact DNS, TLS, firewall, and verification checklist, use [`SETUP.md`](./SETUP.md).
