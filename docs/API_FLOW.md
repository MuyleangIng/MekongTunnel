# Mekong API Flow

This document records the current API request flow and the target layering from `STRUCTURE.md`.

## Current Runtime Flow

Today the API mostly follows this shape:

```text
HTTP request
  -> middleware
  -> handler
  -> db / notify / mailer / redisx
  -> models
  -> response
```

Current reality in the repo:

- handlers still contain some business logic
- handlers still call `internal/db` directly
- Redis is used as a supporting layer for cache, pub/sub, OTP, and rate limiting
- typed API errors are only partially introduced through `internal/apierr`

That is why the integration and load tooling in this repo targets the current handler-driven API surface instead of a not-yet-finished service layer.

## Target Flow

The target architecture remains:

```text
handler -> service -> repository -> models
```

Responsibilities:

- `handler`
  - parse HTTP request
  - validate shape and auth context
  - call one service method
  - translate service results into `response.*`
- `service`
  - business rules
  - orchestration across repository, mailer, notifications, Redis, and external APIs
  - map internal failures to typed `apierr` values
- `repository`
  - SQL only
  - return domain models
  - no HTTP, no mail, no notification fan-out
- `models`
  - shared structs and enums
  - no request parsing or SQL

## Current Package Notes

Current packages that already fit well:

- `internal/redisx`
- `internal/auth`
- `internal/proxy`
- `internal/tunnel`
- `internal/mailer`

Packages that still need refactor work:

- `internal/api/handlers`
- `internal/db`
- `internal/notify`
- `internal/hub`

## Refactor Rule Set

When moving code toward the target layering:

1. Do not put SQL in handlers.
2. Do not put route-specific response formatting in repositories.
3. Keep Redis coordination in services unless it is generic helper code that belongs in `redisx`.
4. Route all typed business errors through `internal/apierr`.
5. Keep the current external API contract stable while the internal layering changes.
