# mekong-cli

> Expose your Node.js dev server to the internet in one command.
> Works with Next.js, Vite, Nuxt, Angular, Astro, Svelte, Express, and more.

[![npm version](https://img.shields.io/npm/v/mekong-cli)](https://www.npmjs.com/package/mekong-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Install

```bash
npm install -g mekong-cli
```

Or use without installing:

```bash
npx mekong-cli 3000
```

---

## Requirements

- **Node.js 14+**
- **mekong binary** — install separately (see below)

### Install the mekong binary

```bash
# macOS / Linux (auto-detect arch)
curl -fsSL https://github.com/MuyleangIng/MekongTunnel/releases/latest/download/mekong-$(uname -s | tr A-Z a-z)-$(uname -m) \
  -o ~/.local/bin/mekong && chmod +x ~/.local/bin/mekong

# macOS Intel
curl -fsSL https://github.com/MuyleangIng/MekongTunnel/releases/latest/download/mekong-darwin-amd64 \
  -o /usr/local/bin/mekong && chmod +x /usr/local/bin/mekong

# macOS Apple Silicon
curl -fsSL https://github.com/MuyleangIng/MekongTunnel/releases/latest/download/mekong-darwin-arm64 \
  -o /usr/local/bin/mekong && chmod +x /usr/local/bin/mekong

# Linux amd64
curl -fsSL https://github.com/MuyleangIng/MekongTunnel/releases/latest/download/mekong-linux-amd64 \
  -o /usr/local/bin/mekong && chmod +x /usr/local/bin/mekong

# Windows — download from:
# https://github.com/MuyleangIng/MekongTunnel/releases/latest
```

---

## Commands

### 1. `mekong-cli <port>` — Tunnel an already-running server

Your server is already running. Just pass the port:

```bash
mekong-cli 3000
mekong-cli 5173
mekong-cli 8080
```

> If nothing is listening on that port, mekong-cli will tell you clearly and exit — it will **not** start the tunnel.

---

### 2. `mekong-cli` — Auto-detect port from package.json

No port needed if your `package.json` uses a known framework:

```bash
mekong-cli
```

mekong-cli reads your `package.json` and detects the port automatically:

| Framework | Detected port |
|---|---|
| Next.js | 3000 |
| Nuxt | 3000 |
| React (CRA) | 3000 |
| Remix | 3000 |
| Express / Fastify / Koa | 3000 |
| Vite | 5173 |
| SvelteKit | 5173 |
| Angular | 4200 |
| Astro | 4321 |
| Gatsby | 8000 |

---

### 3. `mekong-cli --with "<cmd>" --port <n>` — Start server + tunnel together

Start your dev server AND the tunnel at the same time — no separate terminals:

```bash
# Next.js
mekong-cli --with "next dev" --port 3000

# Vite (React, Vue, Svelte, etc.)
mekong-cli --with "vite" --port 5173

# Nuxt
mekong-cli --with "nuxt dev" --port 3000

# Angular
mekong-cli --with "ng serve" --port 4200

# Astro
mekong-cli --with "astro dev" --port 4321

# SvelteKit
mekong-cli --with "vite dev" --port 5173

# Express / Node server
mekong-cli --with "node server.js" --port 3000

# Any custom command
mekong-cli --with "npm run dev" --port 3000
```

mekong-cli will:
1. Start your dev server
2. Wait for port to accept connections (up to 30s)
3. Start the mekong tunnel
4. Print the public URL banner
5. On Ctrl+C — stop both cleanly

---

### 4. `mekong-cli init` — Auto-setup in your project

Run this once in your project root:

```bash
mekong-cli init
```

mekong-cli init will:
- Detect your framework (Next.js, Vite, Nuxt, etc.)
- Ask which port your server runs on
- Inject a `dev:tunnel` script into your `package.json`

After running init, your `package.json` will have:

```json
{
  "scripts": {
    "dev": "next dev",
    "dev:tunnel": "mekong-cli --with \"next dev\" --port 3000"
  }
}
```

Then just run:

```bash
npm run dev:tunnel
```

---

## All options

```
mekong-cli [options] [port]

  <port>           Port of an already-running server to tunnel
  --with <cmd>     Start this dev server command first, then tunnel
  --port <n>       Explicit port (used with --with, or overrides auto-detect)
  --expire <val>   Tunnel expiry: 30m, 2h, 1d, 1w
  --daemon         Run mekong tunnel in background
  --no-qr          Suppress QR code in terminal
  --mekong <path>  Custom path to mekong binary
  --help, -h       Show help

  init             Auto-setup dev:tunnel script in your project
```

---

## Framework quick reference

| Framework | Command |
|---|---|
| **Next.js** | `mekong-cli --with "next dev" --port 3000` |
| **Vite** | `mekong-cli --with "vite" --port 5173` |
| **Nuxt** | `mekong-cli --with "nuxt dev" --port 3000` |
| **Angular** | `mekong-cli --with "ng serve" --port 4200` |
| **Astro** | `mekong-cli --with "astro dev" --port 4321` |
| **SvelteKit** | `mekong-cli --with "vite dev" --port 5173` |
| **Remix** | `mekong-cli --with "remix dev" --port 3000` |
| **Gatsby** | `mekong-cli --with "gatsby develop" --port 8000` |
| **Express** | `mekong-cli --with "node server.js" --port 3000` |
| **Fastify** | `mekong-cli --with "node server.js" --port 3000` |

---

## With expiry and options

```bash
# Expire tunnel after 2 hours
mekong-cli --with "next dev" --port 3000 --expire 2h

# Run tunnel in background (daemon mode)
mekong-cli --with "next dev" --port 3000 --daemon

# No QR code
mekong-cli --with "vite" --port 5173 --no-qr

# Custom mekong binary path
mekong-cli --with "next dev" --port 3000 --mekong ~/bin/mekong
```

---

## Add scripts to package.json manually

```json
{
  "scripts": {
    "dev": "next dev",
    "dev:tunnel": "mekong-cli --with \"next dev\" --port 3000",
    "dev:tunnel:share": "mekong-cli --with \"next dev\" --port 3000 --expire 2h"
  }
}
```

Or just run `mekong-cli init` and it does this for you automatically.

---

## How it works

```
mekong-cli --with "next dev" --port 3000

[server] ready - started server on 0.0.0.0:3000
[server] ...
✔  Port 3000 is ready. Starting tunnel...
[tunnel] ✔  Tunnel is live!
[tunnel]    URL  https://happy-tiger-a1b2c3d4.mekongtunnel.dev

╔══════════════════════════════════════════════════╗
║  Public URL: https://happy-tiger-a1b2c3d4.mekongtunnel.dev  ║
╚══════════════════════════════════════════════════╝
```

---

## License

MIT © [Ing Muyleang](https://github.com/MuyleangIng) — KhmerStack
