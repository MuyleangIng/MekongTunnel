# Mekong CLI Contract

This document defines the user-facing rules for the core `mekong` CLI.

## Source Of Truth

- The Go `mekong` binary is the canonical CLI.
- Other launchers and integrations should align to it rather than invent their own defaults.
- Future wrappers should prefer machine-readable output from the core CLI over reimplementing detection logic.

## Domain Model

- Marketing and installer URLs use `mekongtunnel.dev`.
- The web app uses `angkorsearch.dev`.
- The API uses `api.angkorsearch.dev`.
- Default generated tunnel URLs use `*.proxy.angkorsearch.dev`.
- Branded wildcard domains such as `*.mekongtunnel.dev` are optional and should be described as optional.

## Auth Precedence

Auth resolution order is:

1. `--token`
2. `MEKONG_TOKEN`
3. saved login in `~/.mekong/config.json`

Rules:

- `mekong 3000` should just work with saved login when available.
- `--token` is for CI, headless use, or explicit override.
- `--subdomain` is only for picking a specific reserved subdomain.
- If `--subdomain` is omitted, the tunnel should keep a random generated URL even when a saved login or token exists.

## Help Style

- Main help should stay short and grouped by task.
- Advanced flows belong in topic help such as `mekong help php`.
- Examples should show the common path first, then advanced overrides.
- Avoid repeating the same auth or domain explanation in multiple sections.

## Command Model

- Reserved names should use `mekong subdomain ...` as the preferred UI.
- Preferred reserved-subdomain commands are:
  - `mekong subdomain` to list
  - `mekong subdomain <name>` to reserve
  - `mekong subdomain delete <name>` to remove
- Compatibility aliases such as `mekong subdomains`, `mekong reserve`, and `mekong unreserve` may remain for existing users.
- Custom domains should stay under `mekong domain ...`.

## Local Project Config

The per-project config file is `.mekong.json` in the current working directory.

Supported fields:

- `port`
- `upstream_host`
- `start`
- `stack`

Rules:

- Unknown fields must be ignored.
- `mekong init` may create or update this file.
- Running `mekong` with no port argument may fall back to `port` from `.mekong.json`.
- `upstream_host` is for local virtual-host stacks such as Laragon, XAMPP, WAMP, or Apache vhosts.

## Runtime Separation

- The core `mekong` CLI tunnels an already-running local app.
- `mekong 3000` should not imply `npm run dev`, `vite`, `uvicorn`, or any other app-start command.
- Wrapper tools may provide boot helpers, but the base CLI contract is still: start the app first, then start the tunnel.

## Browser Tunnel Pages

- A browser visit to a generated tunnel URL should show a one-time shared-tunnel notice before opening the app.
- The warning-page CTA must work in one click.
- The Continue action should go through a server redirect that sets the warning cookie before returning to the shared URL.
- The warning page should stay simple, branded, and mobile-friendly.
- If the tunnel is offline, the browser should see a branded offline page instead of a raw 404.
- If a custom domain is pointed at MekongTunnel but not attached to a live target yet, the browser should see a branded pending page instead of a generic bad request.
- If the tunnel is live but the local app is unreachable, the browser should see a `Tunnel Status` page with a 4-step flow:
  `Internet -> Mekong Edge -> Mekong Agent -> Local Service`
- On that page, `Internet`, `Mekong Edge`, and `Mekong Agent` should show as active, while `Local Service` should show as failed.
- When the client reported its local port, the page should show the expected local target such as `localhost:3000`.
- When the client did not report its local port, for example with raw `ssh -R`, the page must not guess a fake local target.
- The upstream-unreachable page should retry automatically and recover back into the live app when the local service starts responding.

## Detect And Init

- `mekong detect --json` is the future integration point for wrappers.
- Detection should prefer stable project markers such as `package.json`, `pyproject.toml`, `requirements.txt`, `composer.json`, and `artisan`.
- Detection should report whether the chosen port is currently reachable.
- `mekong init` should write a minimal `.mekong.json` that the core CLI can use directly.

## PHP And Local Stack Rules

- Laravel detection should use `artisan` and `composer.json`.
- `php artisan serve` is the preferred Laravel default.
- Generic PHP stacks may use Apache on common ports such as `80`, `8080`, or `8081`.
- Port-only tunneling is not enough for local vhost setups like `myapp.test`.
- The CLI should support `--upstream-host myapp.test` so the local app receives the expected `Host` header.
