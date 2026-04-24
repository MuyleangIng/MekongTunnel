# Mekong Tunnel — VS Code Extension

Expose your local dev server to the internet with one click, directly from VS Code. Powered by the [Mekong Tunnel](https://github.com/MuyleangIng/MekongTunnel) CLI.

---

## Requirements

> **Live Server works without any install.** Only tunneling (public URL) requires the `mekong` binary.

If the extension says **`mekong CLI not installed`**, run one of these commands in a terminal on your own computer, then click **Re-check** in the extension panel:

**macOS / Linux**
```bash
curl -fsSL https://mekongtunnel.dev/install.sh | sh
```

**Windows (PowerShell)**
```powershell
irm https://mekongtunnel.dev/install.ps1 | iex
```

Both scripts auto-detect your OS and architecture, install the binary, and add it to your `PATH`. No VS Code reload is needed.

---

## Features

- **Account panel** — login with one click, see your email and plan, use your reserved subdomain automatically
- **Start Tunnel** — expose any local port to a public `proxy.mekongtunnel.dev` URL by default
- **HTML Live Server** — built-in live reload server for HTML and Markdown files, no binary needed
- **Markdown preview** — open any `.md` file with Live Server and see it rendered as styled HTML with live reload
- **Auto port detection** — reads `package.json` to detect your framework's default port
- **Dev server check** — warns you if your dev server isn't running before starting a tunnel
- **Activity log** — real-time log of tunnel and live server events inside the panel
- **Right-click support** — open any `.html` or `.md` file directly with Live Server from the Explorer

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

Right-click any `.html`, `.md` file, or folder → **Open with Live Server (Mekong)**

Starts the live server rooted at that file's directory and opens it in your browser automatically.

---

## Markdown Live Preview

Open any `.md` file with the Live Server and it renders as a clean, GitHub-dark styled HTML page — with live reload whenever you save.

**How to use:**
1. Right-click a `.md` file in the Explorer → **Open with Mekong Live Server**
2. Or open the **Live Server** tab in the sidebar panel and click **Open with Live Server**

**Markdown Preview Mode behavior:**
- Full markdown rendering: headings, bold/italic, code blocks with syntax highlighting classes, tables, blockquotes, lists, images, links
- File watcher triggers a re-render on every save
- Tunneling is **disabled** in Markdown mode — the panel hides the tunnel button and shows a note
- Trying to tunnel the same port from the Tunnel tab is blocked with an error message
- If a folder has no `index.html`, the live server falls back to `README.md` automatically

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
| `$(radio-tower) https://abc.proxy.mekongtunnel.dev` | Running | Click to copy URL |
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

## Changelog

### v1.5.10
- **Fix wrong domains** — replaced all `angkorsearch.dev` references with `mekongtunnel.dev` in API calls, settings description, and README

### v1.5.9
- **Fix wrong API domain** — token-info was fetching from wrong domain; corrected to `api.mekongtunnel.dev`

### v1.5.8
- **README update** — changelog and documentation refreshed

### v1.5.7
- **Fix "Open Live Server in Browser" command** — now starts the Live Server automatically if it isn't running yet, instead of showing "Live Server is not running"

### v1.5.6
- **README update** — documentation updated with full feature list, login flow, and changelog history

### v1.5.5
- **Markdown-only project detection** — Live Server automatically sets Markdown mode when the workspace root contains `.md` files but no `index.html`; no manual toggle needed
- **Markdown sidebar nav** — rendered `.md` pages now include a sidebar listing all sibling Markdown files in the same directory, with the active file highlighted; `README.md` and `index.md` are sorted to the top
- **Active editor auto-root** — starting Live Server from the command palette now roots to the active editor's directory when it's an `.html` or `.md` file, so the served URL matches the open file

### v1.5.4
- **Expiry options expanded** — tunnel expiry selector now includes 30 min, 12 h, 24 h, 7 days, 2 weeks, and 1 month options
- **Live Server file watcher extended** — watcher now covers `.ts`, `.json`, `.svg`, and image files in addition to `.html`, `.css`, and `.js`; changes to any tracked file trigger a reload
- **Markdown mode live-reload subtitle** — activity log sub-text and status pill update dynamically to reflect whether the server is in HTML or Markdown mode

### v1.5.3
- **Markdown tunnel guard** — tunneling is blocked when the Live Server is in Markdown mode; the tunnel button is hidden in the Live Server tab and the Tunnel tab shows an error if the same port is entered
- **Live Server tab badge** — a small green dot appears on the Live Server tab label when the server is active
- **Prominent Preview Panel button** — "Open Preview Panel" is now a full-width ghost button with a monitor icon in the running state, replacing the small sub-action link

### v1.5.2
- **Markdown Live Server** — `.md` files are now fully supported by the built-in Live Server; right-click any `.md` file or folder → Open with Mekong Live Server
- **Markdown renderer** — zero-dependency inline renderer supporting headings, bold/italic/strikethrough, fenced code blocks, tables, blockquotes, ordered/unordered lists, images, and links; rendered with a GitHub-dark theme
- **Directory fallback** — if a folder has no `index.html`, the Live Server serves `README.md` automatically
- **Live reload for `.md`** — file watcher now includes `.md` files so saving triggers an instant re-render in the browser
- **Right-click menus extended** — Explorer, Editor, and Editor title context menus now show Live Server options for `.md` files

---

## Links

- Website: [mekongtunnel.dev](https://mekongtunnel.dev)
- GitHub: [github.com/MuyleangIng/MekongTunnel](https://github.com/MuyleangIng/MekongTunnel)
- Publisher: KhmerStack
