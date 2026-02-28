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

The `mekong` CLI is the easiest way to use MekongTunnel — no SSH flags, auto-reconnect, QR code, and clipboard copy built in.

### macOS (Apple Silicon — M1, M2, M3)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.1.0/mekong-darwin-arm64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
xattr -d com.apple.quarantine /usr/local/bin/mekong
mekong 3000
```

### macOS (Intel)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.1.0/mekong-darwin-amd64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
xattr -d com.apple.quarantine /usr/local/bin/mekong
mekong 3000
```


### Linux (amd64)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.1.0/mekong-linux-amd64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
mekong 3000
```

### Linux (arm64)

```bash
sudo curl -L https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.1.0/mekong-linux-arm64 -o /usr/local/bin/mekong
sudo chmod +x /usr/local/bin/mekong
mekong 3000
```

### Windows

Download [`mekong-windows-amd64.exe`](https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.1.0/mekong-windows-amd64.exe), rename it to `mekong.exe`, and add it to your PATH. Then run `mekong 3000`.

---

## Usage

```bash
# Expose localhost:3000
mekong 3000

# Expose localhost:8080
mekong 8080

# Use a custom server
mekong 3000 --server mekongtunnel.dev

# No QR code
mekong 3000 --no-qr

# No clipboard copy
mekong 3000 --no-clipboard

# Exit on disconnect instead of reconnecting
mekong 3000 --no-reconnect
```

You will see the tunnel banner with your public URL, a QR code to scan with your phone, and the URL is automatically copied to your clipboard.

### mekong CLI Features

| Feature | Description |
|---------|-------------|
| Auto-reconnect | Reconnects automatically if the tunnel drops (stops immediately if IP is blocked) |
| QR code | Printed in terminal — scan with your phone instantly |
| Clipboard | Public URL copied to clipboard automatically |
| Cross-platform | macOS, Linux, Windows |

> **Note — Auto-reconnect and IP blocking:**
> The `mekong` CLI reconnects automatically when the tunnel drops, using exponential backoff (2s → 4s → 8s → … → 60s max). If the server blocks your IP due to too many rapid reconnects, the CLI now **detects the block and exits immediately** instead of retrying:
> ```
> ✖  IP is blocked: ERROR: IP x.x.x.x is temporarily blocked. Try again in 14m0s
> ✖  Reconnect aborted — wait for the block to expire, then try again.
> ```
> To prevent getting blocked in the first place, use `--no-reconnect` when debugging a flapping connection, or use the raw `ssh` command with `ServerAliveInterval` to keep the tunnel stable:
> ```bash
> ssh -t -R 80:localhost:8080 \
>     -o ServerAliveInterval=60 \
>     -o ServerAliveCountMax=3 \
>     mekongtunnel.dev
> ```
> See [Troubleshooting → "IP is temporarily blocked"](#ip-is-temporarily-blocked) for recovery steps.

---

## What Is This?

MekongTunnel is a self-hosted SSH tunnel server written in Go.
It works like ngrok or Cloudflare Tunnel but you run it yourself on your own domain.

When a client connects, the server:
1. Generates a unique public URL (e.g. `https://happy-tiger-a1b2c3d4.mekongtunnel.dev`)
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
ssh -t -R 80:localhost:9000 localhost -p 2222
```

You will see your public URL printed in the terminal:

```
Connected to localhost.
Tunnel is live!
Public URL: https://happy-tiger-a1b2c3d4.localhost
Expires:    Feb 26, 2027 at 15:04 UTC (or 2h idle)
```

> **The `-t` flag is required.** It allocates a TTY so the server can display your tunnel URL and stream request logs.

---

## Port Forwarding Guide

### Expose a local port

```bash
# Expose localhost:8080 → https://happy-tiger-a1b2c3d4.yourdomain.com
ssh -t -R 80:localhost:8080 yourdomain.com
```

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

### Run multiple tunnels at the same time

Each SSH connection gets its own subdomain. Just open multiple terminals:

```bash
# Terminal 1 — frontend
ssh -t -R 80:localhost:3000 yourdomain.com

# Terminal 2 — backend API
ssh -t -R 80:localhost:8080 yourdomain.com
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
ssh -t -R 80:localhost:8080 yourdomain.com -p 2222
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
| `STATS_ADDR` | `127.0.0.1:9090` | Metrics endpoint (localhost only) |
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

Connect to the dev instance:

```bash
ssh -t -R 80:localhost:5173 yourdomain.com -p 2223
```

---

## Project Structure

```
MekongTunnel/
├── cmd/
│   ├── mekongtunnel/
│   │   └── main.go              ← server entry point (starts all 4 servers)
│   └── mekong/
│       └── main.go              ← CLI client (auto-reconnect, QR code, clipboard)
├── internal/
│   ├── config/
│   │   └── config.go            ← constants, limits, and runtime config
│   ├── proxy/                   ← SSH + HTTP server components
│   │   ├── proxy.go             ← tunnel registry and server struct
│   │   ├── ssh.go               ← SSH connection and port-forwarding handler
│   │   ├── http.go              ← HTTPS reverse proxy, WebSocket, warning page
│   │   ├── stats.go             ← JSON metrics endpoint
│   │   └── abuse.go             ← rate limiting and IP blocking
│   ├── domain/                  ← subdomain generation and validation
│   │   └── domain.go
│   └── tunnel/                  ← per-tunnel state and lifecycle
│       ├── tunnel.go
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
/opt/homebrew/bin/go test ./...

# Verbose output
/opt/homebrew/bin/go test -v ./...

# Single package
/opt/homebrew/bin/go test -v ./internal/domain/...
/opt/homebrew/bin/go test -v ./internal/tunnel/...
/opt/homebrew/bin/go test -v ./internal/proxy/...
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

## Stats Endpoint

Available on localhost only (`127.0.0.1:9090`):

```bash
# Basic stats
curl http://127.0.0.1:9090/

# Include active subdomain names
curl "http://127.0.0.1:9090/?subdomains=true"
```

Example response:

```json
{
  "active_tunnels": 3,
  "unique_ips": 2,
  "total_connections": 15,
  "total_requests": 1247,
  "blocked_ips": 1,
  "total_blocked": 5,
  "total_rate_limited": 23,
  "subdomains": ["happy-tiger-a1b2c3d4", "calm-eagle-e5f6a7b8"]
}
```

---

## How It Works

```
Your Browser
    │  HTTPS request to happy-tiger-a1b2c3d4.yourdomain.com
    ▼
┌────────────────────────────────────────────────────┐
│                  MekongTunnel Server                   │
│                                                    │
│  SSH :22        HTTP :80        HTTPS :443         │
│  (port fwd)  →  (redirect) →   (TLS + proxy)      │
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

1. You run `ssh -t -R 80:localhost:8080 yourdomain.com`
2. Server assigns you a subdomain and shows the public URL
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

**Why it happens:** The server allows a maximum of 30 new SSH connections per IP per minute. After 10 violations of this limit, the IP is automatically blocked for 15 minutes. This commonly happens when an SSH client is set to auto-reconnect in a tight loop (e.g. reconnecting every few seconds after a disconnect).

**If you are using the `mekong` CLI:** it now detects this error automatically and exits instead of retrying. You will see:
```
✖  IP is blocked: ERROR: IP x.x.x.x is temporarily blocked. Try again in 14m0s
✖  Reconnect aborted — wait for the block to expire, then try again.
```

**How to recover:**

Option 1 — Wait it out:
```
ERROR: IP x.x.x.x is temporarily blocked. Try again in 58m0s
```
The block expires automatically. Check the remaining time in the error message.

Option 2 — Restart the server (if you have access):
```bash
# Docker
docker compose restart

# Systemd
sudo systemctl restart mekongtunnel
```
The block list is in-memory only — a restart clears all blocks instantly.

**How to prevent it:** Use `ServerAliveInterval` to keep the connection alive instead of letting it drop and reconnect:

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

## Author

| | |
|---|---|
| Name (EN) | Ing Muyleang |
| Name (KH) | អុឹង មួយលៀង |
| Handle | Ing_Muyleang |

## License

MIT — Copyright (c) 2025 MekongTunnel, Copyright (c) 2026 Ing Muyleang (អុឹង មួយលៀង)
