# Mekong Tunnel — VS Code Extension

Expose your local dev server to the internet with one click, directly from VS Code. Powered by the [Mekong Tunnel](https://github.com/MuyleangIng/MekongTunnel) CLI.

---

## Requirements

> **Live Server works without any install.** Only tunneling (public URL) requires the `mekong` binary.

Install `mekong` with one command:

**macOS / Linux**
```bash
curl -fsSL https://mekongtunnel.dev/install.sh | sh
```

**Windows (PowerShell)**
```powershell
irm https://mekongtunnel.dev/install.ps1 | iex
```

Both scripts auto-detect your OS and architecture, install the binary, and add it to your `PATH`. Once done, click **Re-check** in the extension panel — no VS Code reload needed.

---

## Features

- **Account panel** — login with one click, see your email and plan, use your reserved subdomain automatically
- **Start Tunnel** — expose any local port to a public `mekongtunnel.dev` URL
- **HTML Live Server** — built-in live reload server for HTML files, no binary needed
- **Auto port detection** — reads `package.json` to detect your framework's default port
- **Dev server check** — warns you if your dev server isn't running before starting a tunnel
- **Activity log** — real-time log of tunnel and live server events inside the panel
- **Right-click support** — open any HTML file directly with Live Server from the Explorer

---

## Login (reserved subdomain)

The sidebar panel shows your login status at the top:

- **Not logged in** — click **Login**. A terminal opens inside VS Code and runs `mekong login`, which opens the browser device flow. Once you approve, the panel updates automatically.
- **Logged in** — shows your email, plan badge, and a **Logout** button. Every tunnel you start uses your reserved subdomain from now on.

You can also run `mekong login` in any terminal — the extension picks it up automatically.

---

## Usage

### Sidebar Panel

Click the **Mekong Tunnel** icon in the Activity Bar (left sidebar). The panel lets you:

- See your login status and account info
- Set a port or click **⚡ Detect** to auto-detect from `package.json`
- Set an optional tunnel expiry
- Start / Stop the tunnel
- Copy or open the public URL
- Start / Stop the HTML Live Server
- View the activity log

### Command Palette

Open with `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Windows/Linux):

| Command | Description |
|---------|-------------|
| `Mekong: Start Tunnel` | Start tunnel on detected or configured port |
| `Mekong: Stop Tunnel` | Stop the running tunnel |
| `Mekong: Copy Public URL` | Copy tunnel URL to clipboard |
| `Mekong: Open Public URL in Browser` | Open tunnel URL in browser |
| `Mekong: Start Live Server` | Start the built-in HTML live server |
| `Mekong: Stop Live Server` | Stop the live server |

### Right-click in Explorer

Right-click any `.html` file or folder → **Open with Live Server (Mekong)**

Starts the live server rooted at that file's directory and opens it in your browser automatically.

---

## Auto Port Detection

The extension reads your `package.json` and maps known frameworks to their default ports:

| Framework | Default Port |
|-----------|-------------|
| Next.js, Nuxt, React (CRA), Remix, Express, Fastify, Hono | 3000 |
| Vite, SvelteKit, Svelte | 5173 |
| Angular | 4200 |
| Astro | 4321 |
| Gatsby | 8000 |

---

## Status Bar

| Item | State | Description |
|------|-------|-------------|
| `$(radio-tower) mekong` | Idle | Click to start tunnel |
| `$(sync~spin) mekong: connecting...` | Starting | Waiting for tunnel URL |
| `$(radio-tower) https://abc.mekongtunnel.dev` | Running | Click to copy URL |
| `$(error) mekong: error` | Error | Click to restart |
| `$(broadcast) Live Server` | Live idle | Click to start live server |
| `$(broadcast) Live :5500` | Live running | Click to open in browser |

---

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `mekong.apiToken` | — | API token (overrides saved login) |
| `mekong.port` | — | Fixed local port (overrides auto-detect) |
| `mekong.autoStart` | `false` | Auto-start tunnel when workspace opens |
| `mekong.expire` | — | Tunnel expiry: `1h`, `6h`, `24h`, `2d`, `1w` |
| `mekong.binaryPath` | — | Custom path to `mekong` binary (leave empty for auto-detect) |
| `mekong.showQr` | `false` | Show QR code in output panel |
| `mekong.liveServerPort` | `5500` | Base port for the built-in Live Server |

---

## Links

- Website: [mekongtunnel.dev](https://mekongtunnel.dev)
- GitHub: [github.com/MuyleangIng/MekongTunnel](https://github.com/MuyleangIng/MekongTunnel)
- Publisher: KhmerStack
