# tunnl.gg — Project Structure

---

## Before redesign (current)

Current supporting docs:

- `docs/API_FLOW.md` explains the current handler-driven flow and the target service-layer direction
- `docs/PERFORMANCE.md` covers local API stress testing and benchmark limits
- `docker-compose.yml` + `docker-compose.dev.yml` + `docker-compose.prod.yml` are the supported stack files

Problems with the current layout:

- No service layer — business logic scattered across handlers and db/ files
- `db/` is a flat bag of 15 files with no clear interface contracts
- Orphan packages (`customdomain/`, `hub/`, `notify/`) have no clear home
- No typed errors — each handler invents its own error strings
- Hard to unit test — no interfaces means no mocking

```
tunnl.gg/
├── cmd/
│   ├── api/
│   │   └── main.go
│   ├── mekong/                        ← CLI client binary
│   │   ├── auth.go
│   │   ├── domains.go
│   │   ├── localstack.go
│   │   ├── main.go
│   │   ├── platform_unix.go
│   │   ├── platform_windows.go
│   │   ├── selftest.go
│   │   └── subdomains.go
│   └── mekongtunnel/
│       └── main.go
│
├── internal/
│   ├── api/
│   │   ├── handlers/                  ← ⚠ too much logic here
│   │   │   ├── admin.go
│   │   │   ├── auth.go
│   │   │   ├── billing.go
│   │   │   ├── cli_device.go
│   │   │   ├── domains.go
│   │   │   ├── donations.go
│   │   │   ├── monitor.go
│   │   │   ├── newsletter.go
│   │   │   ├── notifications.go
│   │   │   ├── partners.go
│   │   │   ├── sponsors.go
│   │   │   ├── subdomain.go
│   │   │   ├── team.go
│   │   │   ├── tokens.go
│   │   │   ├── tunnels.go
│   │   │   ├── upload.go
│   │   │   └── user.go
│   │   ├── middleware/
│   │   │   ├── auth.go
│   │   │   ├── cors.go
│   │   │   └── rate_limit.go
│   │   ├── response/
│   │   │   └── response.go
│   │   └── server.go
│   │
│   ├── auth/
│   ├── config/
│   ├── customdomain/                  ← ⚠ orphan — no clear layer
│   ├── db/                            ← ⚠ flat, 15 files, no interfaces
│   │   ├── admin.go
│   │   ├── cli_device.go
│   │   ├── db.go
│   │   ├── domains.go
│   │   ├── donations.go
│   │   ├── migrate.go
│   │   ├── newsletter.go
│   │   ├── notifications.go
│   │   ├── partners.go
│   │   ├── server_config.go
│   │   ├── sponsors.go
│   │   ├── subdomains.go
│   │   ├── teams.go
│   │   ├── tokens.go
│   │   ├── tunnels.go
│   │   ├── users.go
│   │   └── verify.go
│   ├── domain/                        ← ⚠ orphan — merge into models/
│   ├── expiry/
│   ├── hub/                           ← ⚠ orphan — move into service/
│   ├── mailer/
│   ├── models/
│   ├── notify/                        ← ⚠ orphan — move into service/
│   ├── proxy/
│   ├── redisx/
│   ├── system/
│   └── tunnel/
│
├── migrations/
├── mekong-cli/
├── mekong-tunnel/
├── mekong-tunnel-vscode/
├── scripts/
├── docs/
├── Makefile
├── Dockerfile.api
├── docker-compose.yml
├── go.mod
└── go.sum
```

---

## After redesign (recommended)

Three changes — everything else stays the same:

1. **Create `internal/service/`** — all business logic lives here
2. **Rename `db/*.go` → `*_repo.go`** — makes role instantly clear, add interfaces
3. **Create `internal/apierr/`** — one typed error package for all layers

```
tunnl.gg/
├── cmd/
│   ├── api/
│   │   └── main.go
│   ├── mekong/                        ← CLI client binary (unchanged)
│   │   ├── auth.go
│   │   ├── domains.go
│   │   ├── localstack.go
│   │   ├── main.go
│   │   ├── platform_unix.go
│   │   ├── platform_windows.go
│   │   ├── selftest.go
│   │   └── subdomains.go
│   └── mekongtunnel/
│       └── main.go
│
├── internal/
│   ├── api/
│   │   ├── handlers/                  ← parse req → call service → write res
│   │   │   ├── admin_handler.go
│   │   │   ├── auth_handler.go
│   │   │   ├── billing_handler.go
│   │   │   ├── cli_device_handler.go
│   │   │   ├── domain_handler.go
│   │   │   ├── donation_handler.go
│   │   │   ├── monitor_handler.go
│   │   │   ├── newsletter_handler.go
│   │   │   ├── notification_handler.go
│   │   │   ├── partner_handler.go
│   │   │   ├── sponsor_handler.go
│   │   │   ├── subdomain_handler.go
│   │   │   ├── team_handler.go
│   │   │   ├── token_handler.go
│   │   │   ├── tunnel_handler.go
│   │   │   ├── upload_handler.go
│   │   │   └── user_handler.go
│   │   ├── middleware/                ← unchanged
│   │   │   ├── auth.go
│   │   │   ├── cors.go
│   │   │   └── rate_limit.go
│   │   ├── response/                  ← unchanged
│   │   │   └── response.go
│   │   └── server.go
│   │
│   ├── service/                       ← NEW — all business logic here
│   │   ├── user_service.go            (was: logic inside handlers/user.go)
│   │   ├── auth_service.go            (was: logic inside handlers/auth.go)
│   │   ├── tunnel_service.go          (was: logic inside handlers/tunnels.go)
│   │   ├── billing_service.go         (was: logic inside handlers/billing.go)
│   │   ├── domain_service.go          (was: customdomain/ + handlers/domains.go)
│   │   ├── team_service.go            (was: logic inside handlers/team.go)
│   │   └── notify_service.go          (was: notify/ + hub/)
│   │
│   ├── apierr/                        ← NEW — typed errors
│   │   └── errors.go                  (ErrNotFound, ErrUnauthorized, Wrap())
│   │
│   ├── db/                            ← repository layer — SQL only
│   │   ├── db.go                      ← connection pool setup ONLY
│   │   ├── migrate.go
│   │   ├── user_repo.go               (was: users.go + verify.go)
│   │   ├── token_repo.go              (was: tokens.go)
│   │   ├── tunnel_repo.go             (was: tunnels.go)
│   │   ├── domain_repo.go             (was: domains.go)
│   │   ├── subdomain_repo.go          (was: subdomains.go)
│   │   ├── team_repo.go               (was: teams.go)
│   │   ├── billing_repo.go            (was: server_config.go + stripe bits)
│   │   ├── notification_repo.go       (was: notifications.go)
│   │   ├── newsletter_repo.go         (was: newsletter.go)
│   │   ├── donation_repo.go           (was: donations.go)
│   │   ├── partner_repo.go            (was: partners.go)
│   │   ├── sponsor_repo.go            (was: sponsors.go)
│   │   ├── admin_repo.go              (was: admin.go)
│   │   └── cli_device_repo.go         (was: cli_device.go)
│   │
│   ├── auth/                          ← unchanged
│   │   ├── apitoken.go
│   │   ├── jwt.go
│   │   ├── oauth.go
│   │   ├── password.go
│   │   └── totp.go
│   │
│   ├── config/                        ← unchanged
│   │   └── config.go
│   │
│   ├── models/                        ← unchanged + absorb domain/ helpers
│   │   └── models.go
│   │
│   ├── expiry/                        ← unchanged
│   ├── mailer/                        ← unchanged
│   ├── proxy/                         ← unchanged
│   ├── redisx/                        ← unchanged
│   ├── system/                        ← unchanged
│   └── tunnel/                        ← unchanged
│
├── migrations/
│   ├── 001_init.sql
│   └── ... (017 files total, run in order)
│
├── mekong-cli/                        ← npm package wrapper
├── mekong-tunnel/                     ← Python package wrapper
├── mekong-tunnel-vscode/              ← VS Code extension
├── scripts/                           ← deploy + run scripts
├── docs/
│   └── CLI_CONTRACT.md
├── Makefile
├── Dockerfile.api
├── docker-compose.yml
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
