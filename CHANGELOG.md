# Changelog

Includes tags present in this repo on 2026-03-14.

## v1.4.7 - 2026-03-14

Highlights:

- Surfaced the server's real `tcpip-forward` rejection reason in `mekong` instead of a generic `server rejected port-forward request`
- Raised the default per-IP active tunnel limit from `3` to `10`
- Added configurable `MAX_TOTAL_TUNNELS` and `MAX_CONNECTIONS_PER_MINUTE` server env vars for higher-capacity deployments, including 300+ tunnels from one IP when explicitly configured
- Versioned Docker builds now embed `main.version`, publish OCI image version metadata, and support versioned Compose image tags
- Built fresh multi-platform client binaries with `main.version=v1.4.7`

## v1.4.6 - 2026-03-13

Highlights:

- Added `mekong logs` to print daemon logs from `~/.mekong/mekong.log`
- Added `mekong logs -f` / `mekong logs --follow` to stream daemon logs live like `docker logs -f`
- Added optional port filtering so `mekong logs 3000` and `mekong logs -f 3000` show only one local port
- Added `mekong stop 3000` to stop a single daemon tunnel by local port and `mekong stop --all` to stop every daemon tunnel
- Stopping a daemon tunnel now clears that port's old log lines from `~/.mekong/mekong.log`
- Updated daemon mode output and README examples to surface the new log commands
- Built fresh multi-platform client binaries with `main.version=v1.4.6`

## v1.4.5 - 2026-03-13

Highlights:

- Hardened `update.sh` so production deploys fetch tags, reset to a clean ref, clear Go caches, clean old build outputs, rebuild both binaries, and restart from the latest code
- Added `mekongtunnel version` for direct server binary verification after deploys
- Updated install docs to use `sudo xattr` for macOS binaries installed into `/usr/local/bin`
- Built fresh multi-platform client binaries with `main.version=v1.4.5`

## v1.4.4 - 2026-03-13

Highlights:

- Added tunnel expiry support to `mekong` via `-e` / `--expire`
- Added raw SSH expiry support via `--expire=...` and `MEKONG_EXPIRE`
- Added per-tunnel lifetime handling, expiry display, expiry-aware reconnect behavior, and idle timeout that follows the requested expiry
- Built fresh multi-platform client binaries with `main.version=v1.4.4`
- Clarified the client error when expiry is used against an older server that does not support the feature yet

## Tags

| Tag | Date |
| --- | --- |
| `v1.4.7` | 2026-03-14 |
| `v1.4.6` | 2026-03-13 |
| `v1.4.5` | 2026-03-13 |
| `v1.4.4` | 2026-03-13 |
| `v1.4.3` | 2026-03-03 |
| `v1.4.2` | 2026-02-28 |
| `v1.4.1` | 2026-02-28 |
| `v1.4.0` | 2026-02-28 |
| `v1.3.0` | 2026-02-28 |
| `v1.2.0` | 2026-02-28 |
| `v1.1.0` | 2026-02-28 |
| `v1.0.0` | 2026-02-27 |

## v1.4.3 - 2026-03-03

Tag commit: `chore: remove multi-port and --server from help text`

Changes since `v1.4.2`:

- `docs: remove unsupported features for v1.4.3`
- `chore: remove multi-port and --server from help text`

## v1.4.2 - 2026-02-28

Tag commit: `fix: write state file immediately when tunnel URL is received`

Changes since `v1.4.1`:

- `feat: remove custom subdomain feature`
- `fix: write state file immediately when tunnel URL is received`

## v1.4.1 - 2026-02-28

Tag commit: `chore: remove subdomain example from help text`

Changes since `v1.4.0`:

- `fix: split platform-specific daemon code for cross-compilation`
- `feat: make MaxTunnelsPerIP configurable via MAX_TUNNELS_PER_IP env var`
- `fix: allow flags after port args (mekong 3000 --subdomain myapp)`
- `feat: add -p/--port flag for local port, fix flag ordering issue`
- `docs: update install links to v1.4.1, add changelog entry`
- `chore: clean old binaries before rebuild in update.sh`
- `debug: log SSH User field and show requested subdomain in banner`
- `chore: clean up usage examples in help text`
- `chore: remove subdomain example from help text`

## v1.4.0 - 2026-02-28

Tag commit: `feat: v1.4.0 - custom subdomain, multi-port, daemon mode, status/stop, web dashboard`

Changes since `v1.3.0`:

- `docs: bump install links to v1.3.0`
- `readme update`
- `feat: v1.4.0 - custom subdomain, multi-port, daemon mode, status/stop, web dashboard`

## v1.3.0 - 2026-02-28

Tag commit: `feat(mekong): add self-update command and version embedding`

Changes since `v1.2.0`:

- `docs: bump install links to v1.2.0`
- `feat(mekong): add self-update command and version embedding`

## v1.2.0 - 2026-02-28

Tag commit: `chore: remove certs and mekong binary from repo, update .gitignore`

Changes since `v1.1.0`:

- `docs: bump install links to v1.1.0`
- `chore: add update.sh script for server deployment`
- `chore: also build mekong client binary in update.sh`
- `docs: add xattr quarantine fix for macOS Gatekeeper`
- `docs: remove xattr note, keep command in install steps`
- `fix(mekong): use half-block chars for smaller QR code in terminal`
- `fix(mekong): use GenerateHalfBlock for smaller QR code`
- `chore: rename module to github.com/MuyleangIng/MekongTunnel`
- `chore: remove certs and mekong binary from repo, update .gitignore`

## v1.1.0 - 2026-02-28

Tag commit: `docs: update README to reflect blocked IP auto-detection in mekong CLI`

Changes since `v1.0.0`:

- `docs: add sudo and test command to install instructions`
- `docs: update project structure and build commands to include mekong CLI`
- `feat: redirect root domain to mekongtunnel-dev.vercel.app`
- `fix: only redirect root domain to Vercel when not a warning page request`
- `fix: redirect to Vercel when warning page has no redirect param`
- `docs: add troubleshooting entry for IP blocked error`
- `docs: add auto-reconnect IP blocking warning to mekong CLI section`
- `config: relax rate limits to reduce accidental blocks`
- `feat(mekong): stop auto-reconnect when server reports IP is blocked`
- `docs: update README to reflect blocked IP auto-detection in mekong CLI`

## v1.0.0 - 2026-02-27

Tag commit: `fix: keep stdin pipe open to prevent immediate server disconnect`

Initial tagged release:

- `first commit`
- `feat: replace tunnel banner with ASCII art logo and author branding`
- `fix: serve warning interstitial page on root domain instead of Bad Request`
- `fix: fix warning cookie domain and redesign page with Khmer theme`
- `feat: add mekong CLI client with auto-reconnect, QR code, and clipboard`
- `docs: add mekong CLI install instructions and usage to README`
- `fix: keep stdin pipe open to prevent immediate server disconnect`
