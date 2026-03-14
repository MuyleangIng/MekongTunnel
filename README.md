# MekongTunnel

> Expose your local app to the internet in one command — no config, no signup.

**Open Source by [KhmerStack](https://github.com/KhmerStack)**

| | |
|---|---|
| Author (EN) | Ing Muyleang |
| Author (KH) | អុឹង មួយលៀង |
| Handle | Ing_Muyleang |
| Live Server | mekongtunnel.dev |
| License | MIT |

---

## Install mekong CLI (Recommended)

The `mekong` CLI is the easiest way to use MekongTunnel — no SSH flags, auto-reconnect, QR code, clipboard copy, daemon mode, and more.

### macOS (Apple Silicon — M1, M2, M3)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.4.7/mekong-darwin-arm64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
sudo xattr -d com.apple.quarantine /usr/local/bin/mekong
mekong 3000
```

### macOS (Intel)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.4.7/mekong-darwin-amd64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
sudo xattr -d com.apple.quarantine /usr/local/bin/mekong
mekong 3000
```

### Linux (amd64)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.4.7/mekong-linux-amd64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
mekong 3000
```

### Linux (arm64)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.4.7/mekong-linux-arm64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
mekong 3000
```

### Windows

Download [`mekong-windows-amd64.exe`](https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.4.7/mekong-windows-amd64.exe), rename it to `mekong.exe`, and add it to your PATH. Then run `mekong 3000`.

---

## Usage

```bash
# Expose localhost:3000
mekong 3000

# Keep the tunnel alive for up to 48 hours
mekong 3000 -e 48h

# Keep the tunnel alive for up to 1 week
mekong 3000 --expire 1w

# Run tunnel in background (daemon mode) — frees your terminal
mekong -d 3000

# Show your active tunnels
mekong status

# Show daemon logs
mekong logs

# Show daemon logs for one local port
mekong logs 3000

# Follow daemon logs live
mekong logs -f

# Follow daemon logs live for one local port
mekong logs -f 3000

# Show tunnel for a specific port
mekong status 3000

# Stop the background tunnel for one local port
mekong stop 3000

# Stop all background tunnels
mekong stop --all

# No QR code
mekong 3000 --no-qr

# No clipboard copy
mekong 3000 --no-clipboard

# Exit on disconnect instead of reconnecting
mekong 3000 --no-reconnect

# Update mekong to the latest version
mekong update
```

### mekong CLI Features

| Feature | Description |
|---------|-------------|
| Auto-reconnect | Reconnects automatically with exponential backoff (2s → 60s max) |
| QR code | Printed in terminal — scan with your phone instantly |
| Clipboard | Public URL copied to clipboard automatically |
| Daemon mode | `-d` runs in background; logs go to `~/.mekong/mekong.log` |
| Logs command | `mekong logs [port]` prints daemon logs; `mekong logs -f [port]` follows them live, optionally filtered to one local port |
| Custom expiry | `-e` / `--expire` sets tunnel lifetime up to 1 week |
| Status command | `mekong status` shows your active tunnels (yours only, not other users') |
| Stop command | `mekong stop <port>` stops one daemon tunnel; `mekong stop --all` stops every daemon tunnel |
| Self-update | `mekong update` downloads and replaces the binary in one step |
| Cross-platform | macOS, Linux, Windows |

Accepted expiry values: `30m`, `48h`, `2d`, `2day`, `1week`, or bare hours like `48`.
Idle timeout now follows the requested expiry. Example: `--expire 1w` gives a `1w` lifetime and `1w` idle timeout.

### Daemon mode

Run a tunnel in the background without keeping a terminal open:

```bash
mekong -d 3000
```

```
  ✔  mekong running in background
     PID     48291
     Logs    ~/.mekong/mekong.log
     View    mekong logs 3000
     Follow  mekong logs -f 3000
     Status  mekong status
     Stop    mekong stop 3000
     StopAll mekong stop --all
```

Check on it or stop it later:

```bash
mekong logs        # print daemon logs
mekong logs 3000   # print only logs for localhost:3000
mekong logs -f     # follow daemon logs live
mekong logs -f 3000 # follow only logs for localhost:3000
mekong status      # show URL, uptime, local port
mekong status 3000 # filter to a specific port
mekong stop 3000   # stop only localhost:3000
mekong stop --all  # stop all daemon tunnels
```

Logs are written to `~/.mekong/mekong.log` — each user has their own state under `~/.mekong/`.

> **Note — Auto-reconnect and IP blocking:**
> The `mekong` CLI reconnects automatically when the tunnel drops. If the server blocks your IP, the CLI detects it and exits instead of retrying:
> ```
> ✖  IP is blocked: ERROR: IP x.x.x.x is temporarily blocked. Try again in 14m0s
> ✖  Reconnect aborted — wait for the block to expire, then try again.
> ```
> See [Troubleshooting → "IP is temporarily blocked"](#ip-is-temporarily-blocked) for recovery steps.

---

## What Is This?

MekongTunnel is a self-hosted SSH tunnel server written in Go.
It works like ngrok or Cloudflare Tunnel but you run it yourself on your own domain.

When a client connects, the server:
1. Assigns a random public URL
2. Terminates TLS on port 443
3. Reverse-proxies every HTTPS request through the SSH connection to the client's local port

Use the `mekong` CLI above, or the raw `ssh` command:

---

## Quick Start (3 Steps)

### 1. Build

```bash
# Requires Go 1.24+
git clone https://github.com/klipitkas/MekongTunnel.git
cd MekongTunnel

make build-small        # → bin/mekongtunnel  (~6 MB optimized binary)
```

### 2. Run (development — no TLS)

```bash
SSH_ADDR=:2222 \
HTTP_ADDR=:8080 \
HTTPS_ADDR=:8443 \
DOMAIN=localhost \
./bin/mekongtunnel
```

### 3. Connect

```bash
# In another terminal — start a local app first
python3 -m http.server 9000

# Then open a tunnel to it
ssh -t -p 2222 -R 80:localhost:9000 localhost

# Or request a custom lifetime
ssh -t -p 2222 -R 80:localhost:9000 localhost --expire=1w
```

You will see your public URL printed in the terminal:

```
Connected to localhost.
Tunnel is live!
Public URL: https://happy-tiger-a1b2c3d4.localhost
Expires:    Feb 26, 2027 at 15:04 UTC (or 1d idle)
```

> **The `-t` flag is required.** It allocates a TTY so the server can display your tunnel URL and stream request logs.

---

## Port Forwarding Guide

### Expose a local port

```bash
# Expose localhost:8080 → https://happy-tiger-a1b2c3d4.yourdomain.com
ssh -t -R 80:localhost:8080 yourdomain.com
```

### Set a custom tunnel expiry

```bash
# CLI form
mekong 3000 --expire 1w

# Raw SSH one-word form
ssh -t -R 80:localhost:3000 yourdomain.com --expire=1w

# Raw SSH env form
ssh -o SetEnv=MEKONG_EXPIRE=48h -t -R 80:localhost:3000 yourdomain.com
```

Supported values: `30m`, `48h`, `2d`, `2day`, `1week`, or bare hours like `48`.
Maximum requested lifetime is 1 week. Idle timeout now follows the requested expiry.

### Expose a different local port

```bash
# Your app runs on :3000
ssh -t -R 80:localhost:3000 yourdomain.com

# Your app runs on :5173 (Vite dev server)
ssh -t -R 80:localhost:5173 yourdomain.com
```

### Expose a service on another machine on your network

```bash
# Forward traffic to 192.168.1.50:8080 (not localhost)
ssh -t -R 80:192.168.1.50:8080 yourdomain.com
```

### Keep the connection alive (recommended)

```bash
ssh -t -R 80:localhost:8080 \
    -o ServerAliveInterval=60 \
    -o ServerAliveCountMax=3 \
    yourdomain.com
```

### Skip the browser phishing warning (for API clients)

Browser requests get a one-time warning page on first visit. To bypass it programmatically:

```bash
# Header method
curl -H "mekongtunnel-skip-warning: 1" https://happy-tiger-a1b2c3d4.yourdomain.com

# Or just use curl — it's not a browser and skips the warning automatically
curl https://happy-tiger-a1b2c3d4.yourdomain.com
```

### WebSocket support

WebSocket connections are automatically detected and proxied. No special flags needed:

```bash
# Works transparently — your WS client just connects to the public URL
wscat -c wss://happy-tiger-a1b2c3d4.yourdomain.com/ws
```

### Server on a non-standard SSH port

If your server's SSH moved to 2222 (recommended — see Domain Setup below):

```bash
ssh -t -p 2222 -R 80:localhost:8080 yourdomain.com
```

---

## Domain Name Setup

To run MekongTunnel on your own domain, you need:

1. A VPS/server with a public IP
2. A domain name
3. DNS records pointing to your server
4. A wildcard TLS certificate

### Step 1 — DNS Records

In your DNS provider, add two A records:

```
A    yourdomain.com       →  YOUR_SERVER_IP
A    *.yourdomain.com     →  YOUR_SERVER_IP
```

The wildcard record (`*.yourdomain.com`) is what routes `happy-tiger-a1b2c3d4.yourdomain.com` to your server.

### Step 2 — TLS Certificate (Let's Encrypt)

```bash
sudo apt install certbot

# Wildcard cert requires DNS challenge (manual or with a DNS plugin)
sudo certbot certonly --manual --preferred-challenges dns \
  -d yourdomain.com \
  -d '*.yourdomain.com'

# Certs are saved to:
#   /etc/letsencrypt/live/yourdomain.com/fullchain.pem
#   /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

### Step 3 — Move Your Server SSH to Port 2222

Port 22 is needed by MekongTunnel. Move your server's own SSH first:

```bash
sudo nano /etc/ssh/sshd_config
# Change:  Port 22  →  Port 2222

sudo systemctl restart sshd

# IMPORTANT: open a new session on port 2222 before closing this one
ssh -p 2222 user@yourdomain.com
```

Also open the firewall:

```bash
sudo ufw allow 22/tcp      # MekongTunnel
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 2222/tcp    # your own SSH
```

### Step 4 — Deploy with Docker

```bash
git clone https://github.com/Ing-Muyleang/MekongTunnel.git
cd MekongTunnel

# 1. Create your .env from the template
cp .env.example .env
nano .env
# Set DOMAIN=yourdomain.com  (and check TLS paths)

# 2. Copy your certificates
mkdir -p data/certs
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem data/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem   data/certs/
sudo chown -R $USER:$USER data/certs

# 3. Start the service
docker compose up -d

# View logs
docker compose logs -f
```

### Step 5 — Connect!

```bash
ssh -t -R 80:localhost:8080 yourdomain.com
# → https://happy-tiger-a1b2c3d4.yourdomain.com
```

---

## Configuration

All configuration is done via environment variables loaded from a `.env` file.

### Setup `.env`

```bash
cp .env.example .env
nano .env          # fill in DOMAIN and TLS paths
```

Your `.env` file (gitignored — never commit it):

```env
# Your domain — tunnels become subdomains of this
DOMAIN=muyleanging.com

# Server ports (leave as-is unless something conflicts)
SSH_ADDR=:22
HTTP_ADDR=:80
HTTPS_ADDR=:443
STATS_ADDR=127.0.0.1:9090

# SSH host key (auto-generated on first run)
HOST_KEY_PATH=/host_key

# TLS certificates (copy from certbot output)
TLS_CERT=/certs/fullchain.pem
TLS_KEY=/certs/privkey.pem
```

### All Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `muyleanging.com` | Your domain name |
| `SSH_ADDR` | `:22` | SSH server listen address |
| `HTTP_ADDR` | `:80` | HTTP redirect server |
| `HTTPS_ADDR` | `:443` | HTTPS proxy server |
| `STATS_ADDR` | `127.0.0.1:9090` | Dashboard and metrics (localhost only) |
| `IMAGE_TAG` | `latest` | Docker Compose image tag for the production service build |
| `DEV_IMAGE_TAG` | `dev` | Docker Compose image tag for the dev service build |
| `MAX_TUNNELS_PER_IP` | `10` | Active tunnel limit per source IP |
| `MAX_TOTAL_TUNNELS` | `5000` | Total active tunnel capacity for the server |
| `MAX_CONNECTIONS_PER_MINUTE` | `600` | New SSH tunnel attempts allowed per IP each minute |
| `HOST_KEY_PATH` | `host_key` | SSH host key file (auto-generated if missing) |
| `TLS_CERT` | `/certs/fullchain.pem` | TLS certificate (inside container) |
| `TLS_KEY` | `/certs/privkey.pem` | TLS private key (inside container) |

### Example: run two instances on the same server

```bash
# Instance 1 — production on default ports
DOMAIN=yourdomain.com ./bin/mekongtunnel

# Instance 2 — dev on alternate ports
SSH_ADDR=:2223 HTTP_ADDR=:8080 HTTPS_ADDR=:8443 \
STATS_ADDR=127.0.0.1:9091 DOMAIN=yourdomain.com \
./bin/mekongtunnel
```

To allow one IP to open 300+ concurrent tunnels, start the server with higher limits:

```bash
MAX_TUNNELS_PER_IP=350 MAX_TOTAL_TUNNELS=5000 \
MAX_CONNECTIONS_PER_MINUTE=600 DOMAIN=yourdomain.com \
./bin/mekongtunnel
```

Build a versioned Docker image for release `v1.4.7`:

```bash
docker build --build-arg VERSION=v1.4.7 -t mekongtunnel:v1.4.7 -t mekongtunnel:latest .
```

Connect to the dev instance:

```bash
ssh -t -p 2223 -R 80:localhost:5173 yourdomain.com
```

---

## Project Structure

```
MekongTunnel/
├── cmd/
│   ├── mekongtunnel/
│   │   └── main.go              ← server entry point (starts all 4 servers)
│   └── mekong/
│       └── main.go              ← CLI client (reconnect, QR, daemon, status, stop)
├── internal/
│   ├── config/
│   │   └── config.go            ← constants, limits, and runtime config
│   ├── proxy/                   ← SSH + HTTP server components
│   │   ├── proxy.go             ← tunnel registry, ClaimSubdomain logic
│   │   ├── ssh.go               ← SSH connection and port-forwarding handler
│   │   ├── http.go              ← HTTPS reverse proxy, WebSocket, warning page
│   │   ├── stats.go             ← web dashboard (/) and JSON API (/api/stats)
│   │   └── abuse.go             ← rate limiting and IP blocking
│   ├── domain/                  ← subdomain generation and validation
│   │   └── domain.go            ← auto-generate random subdomains
│   └── tunnel/                  ← per-tunnel state and lifecycle
│       ├── tunnel.go            ← request counter, rate limiter, logger
│       ├── ratelimit.go         ← token-bucket rate limiter (10 req/s, burst 20)
│       └── logger.go            ← async SSH terminal request logger
├── Dockerfile                   ← multi-stage build → scratch image (~6 MB)
├── docker-compose.yml           ← production + dev services
└── Makefile                     ← build and test commands
```

---

## Build Commands

| Command | Output | Description |
|---------|--------|-------------|
| `make build` | `bin/mekongtunnel` + `bin/mekong` | Standard optimized build (server + client) |
| `make build-small` | `bin/mekongtunnel` + `bin/mekong` | Maximum size optimization (~6 MB server, ~4 MB client) |
| `make build-tiny` | `bin/mekongtunnel` | With UPX compression if available (~2 MB) |
| `make build-all` | `bin/mekongtunnel-*` | Cross-compile server for Linux + macOS (amd64 + arm64) |
| `make build-client` | `bin/mekong` | Build CLI client only |
| `make build-client-all` | `bin/mekong-*` | Cross-compile client for Mac + Linux + Windows |
| `make build-dev` | `bin/mekongtunnel` | Fast debug build with symbols |
| `make test` | — | Run all tests |
| `make clean` | — | Remove build artifacts |

---

## Running Tests

```bash
# Run all tests
make test

# Or directly with Go
go test ./...

# Verbose output
go test -v ./...

# Single package
go test -v ./internal/domain/...
go test -v ./internal/tunnel/...
go test -v ./internal/proxy/...
```

---

## Limits & Protection

| Limit | Value |
|-------|-------|
| Tunnels per IP | 3 |
| Total server tunnels | 1,000 |
| Requests per tunnel | 10/s (burst 20) |
| Request body size | 128 MB |
| Response body size | 128 MB |
| WebSocket transfer | 1 GB per direction |
| WebSocket idle timeout | 2 hours |
| SSH handshake timeout | 30 seconds |
| New connections per IP/min | 30 |
| Inactivity timeout | 2 hours |
| Max tunnel lifetime | 24 hours |
| Block duration | 15 minutes |
| Violations before block | 10 |

---

## Admin Dashboard & Stats

Available on localhost only (`127.0.0.1:9090`):

| Endpoint | Description |
|----------|-------------|
| `http://127.0.0.1:9090/` | Live HTML dashboard — auto-refreshes every 3 seconds |
| `http://127.0.0.1:9090/api/stats` | JSON metrics snapshot |

The dashboard shows active tunnel count, total requests, blocked IPs, and a per-tunnel table (subdomain, client IP, uptime, request count).

```bash
# Open dashboard in browser
open http://127.0.0.1:9090/

# JSON API
curl http://127.0.0.1:9090/api/stats
```

Example JSON response:

```json
{
  "active_tunnels": 3,
  "unique_ips": 2,
  "total_connections": 15,
  "total_requests": 1247,
  "blocked_ips": 1,
  "total_blocked": 5,
  "total_rate_limited": 23,
  "tunnels": [
    { "subdomain": "happy-tiger-a1b2", "client_ip": "1.2.3.4", "uptime_secs": 842, "request_count": 120 },
    { "subdomain": "myapp",            "client_ip": "5.6.7.8", "uptime_secs": 310, "request_count": 45  }
  ]
}
```

---

## How It Works

```
Your Browser
    │  HTTPS request to happy-tiger-a1b2c3d4.yourdomain.com
    ▼
┌────────────────────────────────────────────────────┐
│                  MekongTunnel Server               │
│                                                    │
│  SSH :22        HTTP :80        HTTPS :443         │
│  (port fwd)  →  (redirect) →   (TLS + proxy)       │
│      │                              │              │
│      ▼                              ▼              │
│  Tunnel Registry  ←──────────────────────────────  │
│  map[subdomain]*Tunnel                             │
└──────────────────────┬─────────────────────────────┘
                       │ forwarded-tcpip SSH channel
                       ▼
               Your SSH Client
                       │
                       ▼
               localhost:8080  (your app)
```

1. You run `mekong 8080` (or `ssh -t -R 80:localhost:8080 yourdomain.com`)
2. Server assigns a random subdomain and shows the public URL
3. A browser opens `https://happy-tiger-a1b2c3d4.yourdomain.com`
4. Server looks up the tunnel, dials the internal listener
5. Opens a `forwarded-tcpip` SSH channel back to your client
6. Your client forwards the connection to `localhost:8080`
7. Response flows back the same way
8. The request is logged to your SSH terminal in real time

---

## Systemd Service (Manual Deploy)

```bash
sudo nano /etc/systemd/system/mekongtunnel.service
```

```ini
[Unit]
Description=MekongTunnel SSH Tunnel Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mekongtunnel
ExecStart=/opt/mekongtunnel/mekongtunnel
Restart=always
RestartSec=5

Environment=SSH_ADDR=:22
Environment=HTTP_ADDR=:80
Environment=HTTPS_ADDR=:443
Environment=STATS_ADDR=127.0.0.1:9090
Environment=HOST_KEY_PATH=/opt/mekongtunnel/host_key
Environment=TLS_CERT=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
Environment=TLS_KEY=/etc/letsencrypt/live/yourdomain.com/privkey.pem
Environment=DOMAIN=yourdomain.com

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/mekongtunnel

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /opt/mekongtunnel
sudo cp bin/mekongtunnel /opt/mekongtunnel/
sudo chmod +x /opt/mekongtunnel/mekongtunnel
sudo systemctl daemon-reload
sudo systemctl enable --now mekongtunnel
sudo systemctl status mekongtunnel
```

---

## Troubleshooting

### "No output / connection hangs"

The `-t` flag is required — without it there is no TTY and the URL cannot be displayed:

```bash
# Wrong
ssh -R 80:localhost:8080 yourdomain.com

# Correct
ssh -t -R 80:localhost:8080 yourdomain.com
```

### "Host key verification failed"

Accept the host key on first connection:

```
Are you sure you want to continue connecting (yes/no)? yes
```

### "Connection refused on port 22"

Check that the service is running and ports are open:

```bash
docker compose ps
sudo ss -tlnp | grep -E ':(22|80|443)'
sudo ufw status
```

### "IP is temporarily blocked"

Your IP exceeded the connection rate limit too many times and was auto-blocked for 15 minutes.

**Why it happens:** The server allows a maximum of 30 new SSH connections per IP per minute. After 10 violations, the IP is blocked for 15 minutes. This commonly happens when an SSH client reconnects in a tight loop.

**If you are using the `mekong` CLI:** it detects this error automatically and exits instead of retrying:
```
✖  IP is blocked: ERROR: IP x.x.x.x is temporarily blocked. Try again in 14m0s
✖  Reconnect aborted — wait for the block to expire, then try again.
```

**How to recover:**

Option 1 — Wait it out (block expires automatically — check the remaining time in the error message).

Option 2 — Restart the server (if you have access):
```bash
# Docker
docker compose restart

# Systemd
sudo systemctl restart mekongtunnel
```
The block list is in-memory only — a restart clears all blocks instantly.

**How to prevent it:** Use `ServerAliveInterval` to keep the connection alive:

```bash
ssh -t -R 80:localhost:8080 \
    -o ServerAliveInterval=60 \
    -o ServerAliveCountMax=3 \
    yourdomain.com
```

---

### "Certificate issues"

```bash
# Renew
sudo certbot renew

# Copy new certs and restart
sudo cp /etc/letsencrypt/live/yourdomain.com/*.pem data/certs/
docker compose restart
```

---

## GitHub Actions

- `Go CI` — runs on pushes to `main` and on pull requests; builds the repo, runs the stable test suites, and cross-builds the client binaries
- `Release Mekong CLI` — runs on tag pushes like `v1.4.7` or manual dispatch; builds the release binaries, generates SHA-256 checksums, extracts the matching `CHANGELOG.md` section, and creates or updates the GitHub release

Release a new version:

```bash
git tag v1.4.7
git push origin main v1.4.7
```

---

## Changelog

### v1.4.7
- **Port-forward rejection details** — `mekong` now reads and prints the server’s actual `tcpip-forward` rejection reason instead of collapsing everything into a generic error
- **Higher-capacity defaults** — server defaults now allow `10` active tunnels per IP, `5000` total tunnels, and `600` new connections per IP per minute
- **Configurable server capacity** — `MAX_TOTAL_TUNNELS` and `MAX_CONNECTIONS_PER_MINUTE` are now first-class runtime env vars alongside `MAX_TUNNELS_PER_IP`
- **Versioned Docker builds** — Docker builds now embed `main.version`, expose OCI version metadata, and support versioned Compose image tags

### v1.4.6
- **Daemon logs command** — `mekong logs [port]` prints the background tunnel log file and `mekong logs -f [port]` follows it live like `docker logs -f`, optionally filtered to one local port
- **Specific stop command** — `mekong stop 3000` stops one daemon tunnel by local port, and `mekong stop --all` stops every daemon tunnel
- **Log cleanup on stop** — stopping a daemon tunnel now clears that port’s old log lines so the next `mekong logs 3000` starts clean
- **Daemon help text** — background mode now shows the `mekong logs [port]` and `mekong logs -f [port]` commands next to the log file path

### v1.4.5
- **Production deploy script** — `update.sh` now fetches tags, resets to a clean ref, clears Go caches, cleans old build outputs, rebuilds both binaries, prints installed versions, and restarts the service from the latest code
- **Server version command** — `mekongtunnel version` now prints the running server binary version for easier production verification
- **macOS install fix** — install docs now use `sudo xattr` so the quarantine removal step works after installing into `/usr/local/bin`

### v1.4.4
- **Expiry option** — `mekong` now supports `-e` / `--expire` with values like `30m`, `48h`, `2d`, `2day`, and `1w`
- **Raw SSH expiry** — raw SSH tunnels can request expiry with `--expire=1w` or `-o SetEnv=MEKONG_EXPIRE=48h`
- **Tunnel lifecycle** — tunnel banners and `mekong status` now show expiry, idle timeout follows the requested expiry, and `mekong` stops auto-reconnect when the requested lifetime is reached
- **Compatibility message** — if the server is older and does not support expiry yet, `mekong` now shows a clear upgrade message instead of looping on `ssh: setenv failed`

### v1.4.3
- **Docs** — removed custom subdomain, multi-port, and `--server` flag documentation (not yet supported)

### v1.4.2
- **Removed custom subdomain feature** — `--subdomain` flag and `ClaimSubdomain` logic removed entirely; all tunnels now get random names
- **Bug fix** — `mekong status` in daemon mode now writes the state file the moment the tunnel URL arrives instead of after disconnect

### v1.4.1
- **Bug fix** — `--subdomain` flag now works in any position (`mekong 3000 --subdomain myapp` no longer errors)
- **Server** — per-IP tunnel limit is now configurable via `MAX_TUNNELS_PER_IP` env var (default is now `10`), with `MAX_TOTAL_TUNNELS` and `MAX_CONNECTIONS_PER_MINUTE` available for higher-capacity deployments

### v1.4.0
- **Daemon mode** — `mekong -d 3000` runs in the background and frees the terminal; logs go to `~/.mekong/mekong.log`
- **Status command** — `mekong status` shows your active tunnels (URL, uptime, local port); `mekong status 3000` filters by port
- **Stop command** — `mekong stop` gracefully stops a background tunnel
- **Web dashboard** — live HTML dashboard at `http://127.0.0.1:9090/` (auto-refreshes every 3s); JSON API moved to `/api/stats`
- **Per-tunnel request counter** — dashboard and JSON API now show request counts per tunnel

### v1.3.0
- Self-update command (`mekong update`)
- Version embedding via ldflags

### v1.2.0
- Auto-reconnect with exponential backoff
- IP block detection — exits instead of retrying when blocked

### v1.1.0
- QR code in terminal
- Clipboard auto-copy

### v1.0.0
- Initial release

---

## Author

| | |
|---|---|
| Name (EN) | Ing Muyleang |
| Name (KH) | អុឹង មួយលៀង |
| Handle | Ing_Muyleang |

## License

MIT — Copyright (c) 2025 MekongTunnel, Copyright (c) 2026 Ing Muyleang (អុឹង មួយលៀង)
