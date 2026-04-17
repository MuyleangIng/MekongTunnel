# MekongTunnel — Project Structure

---

## Current layout

Supporting docs:

- `docs/API_FLOW.md` — current handler-driven flow and target service-layer direction
- `docs/PERFORMANCE.md` — local API stress testing and benchmark limits
- `docs/TELEGRAM_BOT.md` — Telegram bot setup and account linking
- `docs/DISCORD_BOT.md` — Discord bot integration
- `HANDBOOK_v2.md` — deploy hosting architecture (SSH reverse tunnel serving)
- `docker-compose.yml` + `docker-compose.dev.yml` + `docker-compose.prod.yml` — supported stack files

```
mekongtunnel-ecosystem/
├── cmd/
│   ├── mekong/                        ← CLI client binary
│   │   ├── main.go                    (reconnect loop, QR, clipboard, expiry)
│   │   ├── auth.go                    (login, logout, whoami, token-info)
│   │   ├── deploy.go                  (mekong deploy — upload/list/stop/redeploy)
│   │   ├── domains.go                 (custom domains, doctor, connect, wait)
│   │   ├── localstack.go              (local virtual host helpers)
│   │   ├── selftest.go                (mekong test — self-diagnostic)
│   │   ├── subdomains.go              (reserve/list/delete reserved subdomains)
│   │   ├── platform_unix.go           (daemon via Setsid + isPIDAlive via signal)
│   │   └── platform_windows.go        (DETACHED_PROCESS + OpenProcess)
│   └── mekongtunnel/
│       └── main.go                    (reads env, starts 4 listeners)
│
├── internal/
│   ├── api/
│   │   ├── autobilling.go             (automatic billing renewal background job)
│   │   ├── handlers/
│   │   │   ├── admin.go               (admin: users, plans, abuse, server config)
│   │   │   ├── auth.go                (register, login, OAuth, 2FA, password reset)
│   │   │   ├── billing.go             (Stripe checkout, portal, Koma checkout, PayPal)
│   │   │   ├── billing_bakong.go      (Bakong KHQR subscription checkout flow)
│   │   │   ├── billing_koma.go        (Koma payment gateway helpers)
│   │   │   ├── cli_device.go          (CLI device authentication)
│   │   │   ├── deploy.go              (static/PHP/Next.js hosting via SSH tunnel)
│   │   │   ├── domains.go             (custom domain management + Telegram alerts)
│   │   │   ├── domains_test.go
│   │   │   ├── donations.go           (donation submit/list/approve)
│   │   │   ├── edge_auth.go           (internal edge API: token validate, subdomain lookup)
│   │   │   ├── monitor.go             (system monitoring snapshot + SSE stream)
│   │   │   ├── newsletter.go          (email subscription + unsubscribe by token)
│   │   │   ├── notifications.go       (user notifications + SSE stream)
│   │   │   ├── org.go                 (org creation, members, teams, approval workflow)
│   │   │   ├── partners.go            (partner directory)
│   │   │   ├── paypal.go              (PayPal IPN / receipt handling)
│   │   │   ├── resource_scope.go      (plan-scoped resource access helpers)
│   │   │   ├── sponsors.go            (sponsor listings)
│   │   │   ├── subdomain.go           (reserved subdomain management)
│   │   │   ├── team.go                (team CRUD, members, invitations)
│   │   │   ├── telegram.go            (Telegram account linking flow)
│   │   │   ├── telegram_alerts.go     (Telegram alert notifications for admin events)
│   │   │   ├── tokens.go              (API token CRUD)
│   │   │   ├── tunnels.go             (list/kill user tunnels, live tunnel view)
│   │   │   ├── upload.go              (file upload — reused for receipts)
│   │   │   ├── user.go                (profile, password, deletion, verify request)
│   │   │   └── wallet.go              (credit wallet: balance, Bakong top-up, history)
│   │   │   └── wallet_koma.go         (Koma payment helpers for wallet top-up)
│   │   ├── middleware/
│   │   │   ├── auth.go                (JWT auth, optional auth, admin auth, internal secret)
│   │   │   ├── cors.go                (CORS policy)
│   │   │   └── rate_limit.go          (Redis-backed API rate limiting)
│   │   ├── response/
│   │   │   └── response.go
│   │   └── server.go                  (all HTTP routes registered here)
│   │
│   ├── auth/
│   ├── billing/                       ← billing service layer
│   │   ├── autobilling.go
│   │   ├── client.go
│   │   ├── format.go
│   │   ├── redact.go
│   │   ├── service.go
│   │   └── types.go
│   ├── config/                        ← tunnel server constants + Config struct
│   ├── customdomain/                  ← custom domain lookup helpers
│   ├── db/                            ← PostgreSQL queries (flat, no interfaces yet)
│   ├── domain/                        ← subdomain Generate() / IsValid()
│   ├── expiry/                        ← tunnel lifetime + idle timeout
│   ├── hub/                           ← notification fan-out hub
│   ├── mailer/                        ← email delivery (Resend + SMTP fallback)
│   ├── models/                        ← shared structs, zero business logic
│   ├── notify/                        ← notification service helpers
│   ├── proxy/                         ← SSH server + HTTPS reverse proxy
│   ├── redisx/                        ← optional Redis cache, pub/sub, OTP, rate limit
│   ├── system/                        ← system metrics snapshot
│   ├── telegrambot/                   ← Telegram bot client + service
│   │   ├── client.go
│   │   ├── format.go
│   │   ├── service.go
│   │   └── types.go
│   └── tunnel/                        ← per-tunnel lifecycle, logger, rate limit
│
├── migrations/                        (031 PostgreSQL migration files, run in order)
│   ├── 001_init.sql … 025_telegram_bot.sql
│   ├── 026_deployments.sql
│   ├── 027_deploy_storage_quota.sql
│   ├── 028_credit_wallet.sql
│   ├── 029_payment_orders_koma.sql
│   ├── 030_payment_orders_billing_bakong.sql
│   └── 031_deploy_types_extended.sql
│
├── scripts/
│   ├── deploy-api.sh                  (rsync/systemd deploy — existing VMs)
│   ├── deploy-tunnel.sh               (rsync/systemd deploy — existing VMs)
│   ├── gcp-deploy-api.sh              (GCP SSH deploy — API server)
│   ├── gcp-deploy-frontend.sh         (GCP — frontend deploy)
│   ├── gcp-deploy-tunnel.sh           (GCP SSH deploy — tunnel server)
│   ├── gcp-init-app.sh                (GCP bootstrap — app server first-time setup)
│   ├── gcp-init-tunnel.sh             (GCP bootstrap — tunnel server first-time setup)
│   ├── gcp-setup.sh                   (GCP infrastructure setup)
│   ├── init-stack.sh                  (run migrations + seed + admin bootstrap)
│   ├── run-api.sh                     (local dev — run API with env file)
│   └── stress-local.sh                (local API stress test)
│
├── mekong-node-sdk/                   ← npm package source (mekong-cli)
├── mekong-python-sdk/                 ← PyPI package source (mekong-tunnel)
├── mekong-vscode-extension/           ← VS Code extension source
├── docs/
│   ├── API_FLOW.md
│   ├── CLI_CONTRACT.md
│   ├── DISCORD_BOT.md
│   ├── GITHUB_DEPLOY.md
│   ├── PERFORMANCE.md
│   └── TELEGRAM_BOT.md
├── HANDBOOK.md                        (architecture, API, data model, release context)
├── HANDBOOK_v2.md                     (deploy hosting architecture)
├── STRUCTURE.md                       (this file)
├── SETUP.md                           (DNS, TLS, nginx, production deploy)
├── CHANGELOG.md
├── Makefile
├── Dockerfile.api
├── docker-compose.yml
├── docker-compose.dev.yml
├── docker-compose.prod.yml
├── install.sh
├── install.ps1
├── go.mod
└── go.sum
```

---

## Architecture layers

| Layer | Package | Spring equivalent | Responsibility |
|---|---|---|---|
| Handler | `internal/api/handlers/` | `@RestController` | Parse HTTP, call service, write response |
| Service | `internal/service/` | `@Service` | All business logic and rules |
| Repository | `internal/db/` | `@Repository` | SQL queries only, returns domain models |
| Models | `internal/models/` | `@Entity` | Shared structs, zero business logic |
| Errors | `internal/apierr/` | — | Typed errors used by all layers |

Dependency direction is strict: **handler → service → repository → models**.
Never import upward. Never import sideways between services.

---

## What does NOT change

These packages are already well structured — leave them alone:

| Package | Role |
|---|---|
| `internal/proxy/` | SSH/HTTP tunnel engine |
| `internal/tunnel/` | Per-tunnel lifecycle, logger, rate limit |
| `internal/redisx/` | Redis client, cache, OTP, rate limit |
| `internal/auth/` | JWT, OAuth, TOTP, bcrypt |
| `internal/mailer/` | Email sending |
| `internal/expiry/` | Tunnel lifetime + idle timeout |
| `internal/system/` | System monitor |
| `internal/config/` | Constants, env loading |
