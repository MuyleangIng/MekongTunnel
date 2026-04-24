# Mekong Tunnel — JetBrains Plugin

Expose your local dev server to the internet with one click, directly from WebStorm, IntelliJ IDEA, PyCharm, GoLand, PhpStorm, Rider, and all other JetBrains IDEs.

Powered by the [Mekong Tunnel](https://github.com/MuyleangIng/MekongTunnel) CLI and platform.

---

## Features

- **Start / Stop Tunnel** — expose any local port to a public URL instantly from the side panel
- **Login with your Mekong account** — browser-based device login flow, no terminal needed; login once and use your reserved subdomain on every tunnel
- **Reserved subdomain** — logged-in users get a consistent public URL tied to their account
- **Tunnel expiry** — set a time limit (30 min, 1 h, 7 days, 1 month…) on any tunnel
- **Built-in Live Server** — zero-config HTTP server for HTML and Markdown files with hot reload; no CLI needed
- **Markdown preview** — `.md` files are rendered as styled GitHub-dark HTML with live reload on save
- **Auto-detects project root** — Live Server roots to your open project directory automatically
- **Activity Log** — real-time terminal-style log showing server events, tunnel status, and errors
- **Status bar widget** — quick tunnel state visible at the bottom of any JetBrains IDE
- **Works in all JetBrains IDEs** — WebStorm, IntelliJ IDEA, PyCharm, GoLand, PhpStorm, Rider, CLion, and more

---

## Requirements

> **Live Server works without any install.** Only tunneling (public URL) requires the `mekong` binary.

If the plugin says **mekong not found**, install the CLI on your machine:

**macOS / Linux**
```bash
curl -fsSL https://mekongtunnel.dev/install.sh | sh
```

**Windows (PowerShell)**
```powershell
irm https://mekongtunnel.dev/install.ps1 | iex
```

---

## Installation

### From JetBrains Marketplace
1. Open your IDE → **Settings / Preferences** → **Plugins**
2. Search for **Mekong Tunnel**
3. Click **Install** → restart the IDE

### From disk (manual)
1. Download `mekong-tunnel-x.x.x.zip` from [Releases](https://github.com/MuyleangIng/mekong-jetbrains-plugin/releases)
2. **Settings** → **Plugins** → gear icon → **Install Plugin from Disk…**
3. Select the zip file → restart

---

## Usage

### Side Panel
Click the **Mekong Tunnel** icon in the right-side tool window strip. The panel has two tabs:

#### Tunnel tab
- Enter a local port or let the plugin detect it
- Set an optional expiry
- Click **Start tunnel** — a public URL is generated and shown
- Click **Copy** or **Open** to share the URL
- Click **Stop tunnel** when done

#### Live Server tab
- Click **Start Live Server** — your project folder is served on `localhost:5500`
- The browser opens automatically
- Save any `.html`, `.css`, `.js`, or `.md` file — the browser reloads instantly
- Click **Stop live server** when done

### Login (reserved subdomain)
1. Click **Log in** in the panel header
2. A browser window opens with the Mekong authorization page
3. Log in or create an account and click **Authorize**
4. The plugin automatically detects the login and shows your email
5. All future tunnels use your reserved subdomain

---

## Activity Log

The Activity Log at the bottom of the panel shows real-time events in a terminal-style view:
- `[OK]` — green — server started, tunnel live, login success
- `[WARN]` — blue — tunnel stopped, server stopped
- `[ERROR]` — red — errors and failures

---

## Links

- Website: [mekongtunnel.dev](https://mekongtunnel.dev)
- CLI repo: [github.com/MuyleangIng/MekongTunnel](https://github.com/MuyleangIng/MekongTunnel)
- VS Code extension: [Mekong Tunnel on Marketplace](https://marketplace.visualstudio.com/items?itemName=KhmerStack.mekong-tunnel)
- Publisher: KhmerStack

---

## License

[MIT](./LICENSE)
