# MekongTunnel

> Expose your local app to the internet in one command — no config, no account required.

**Open Source by [KhmerStack](https://github.com/KhmerStack)**

| | |
|---|---|
| Author | Ing Muyleang (អុឹង មួយលៀង) |
| Live Server | [mekongtunnel.dev](https://mekongtunnel.dev) |
| License | MIT |
| Current Version | v1.5.0 |

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
mekong login       # get a reserved subdomain (optional)
mekong 3000        # expose localhost:3000 → public HTTPS URL
```

---

## CLI reference

```bash
# Expose ports
mekong 3000                    # single port
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
ssh -t -R 80:localhost:3000 mekongtunnel.dev

# With keep-alive
ssh -t -R 80:localhost:3000 -o ServerAliveInterval=60 -o ServerAliveCountMax=3 mekongtunnel.dev

# With expiry
ssh -o SetEnv=MEKONG_EXPIRE=48h -t -R 80:localhost:3000 mekongtunnel.dev
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
# Docker Compose (PostgreSQL + API + Tunnel server)
docker compose up -d

# Or build from source
make build          # server + CLI
make build-all      # cross-compile server (Linux + macOS, amd64 + arm64)
make build-client-all  # cross-compile CLI (all platforms)
```

See [HANDBOOK.md](./HANDBOOK.md) for the full architecture, API reference, DB setup, build system, and deployment guide.

---

## Architecture

```
Internet
   │ HTTPS :443
   ▼
┌─────────────────────────────────────────┐
│           mekongtunnel.dev              │
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

Every tunnel gets a random subdomain: `adjective-noun-8hexchars.mekongtunnel.dev`
Login for a **reserved** subdomain that stays the same across reconnects.

---

## Links

- Docs: [mekongtunnel.dev/docs](https://mekongtunnel.dev/docs)
- GitHub: [github.com/MuyleangIng/MekongTunnel](https://github.com/MuyleangIng/MekongTunnel)
- npm: [npmjs.com/package/mekong-cli](https://www.npmjs.com/package/mekong-cli)
- PyPI: [pypi.org/project/mekong-tunnel](https://pypi.org/project/mekong-tunnel/)
- VS Code: [marketplace.visualstudio.com — KhmerStack.mekong-tunnel](https://marketplace.visualstudio.com/items?itemName=KhmerStack.mekong-tunnel)
