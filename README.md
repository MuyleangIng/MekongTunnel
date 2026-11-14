# MekongTunnel

> Share your local app on a public HTTPS link with one command.

```bash
mekong 3000
# → https://happy-tiger-a1b2c3d4.proxy.mekongtunnel.dev
```

Made in Cambodia by [KhmerStack](https://github.com/KhmerStack) · Author: Ing Muyleang (អុឹង មួយលៀង) · MIT License

| | |
|---|---|
| Website & dashboard | [mekongtunnel.dev](https://mekongtunnel.dev) |
| Docs | [docs.mekongtunnel.dev](https://docs.mekongtunnel.dev) |
| Latest release | [Releases page](https://github.com/MuyleangIng/MekongTunnel/releases/latest) |
| VS Code extension | [Mekong Tunnel on the Marketplace](https://marketplace.visualstudio.com/items?itemName=KhmerStack.mekong-tunnel) |

---

## About this repository

**This public repository is where MekongTunnel is released.** Day-to-day development
happens in a private repository, so the `main` branch here is **not** the newest code.

What you get here:

- **Releases** — every version is published on the [Releases page](https://github.com/MuyleangIng/MekongTunnel/releases)
  with ready-to-run binaries for macOS, Linux and Windows (Intel and ARM) and a `SHA256SUMS` file.
- **Source of each release** — every release tag (for example `v1.6.16`) contains the full source code of
  that version. Browse it by switching to the tag, or download the source zip from the release.
- **Changelog** — what changed in each version is in the release notes.

So: to *use* MekongTunnel, install the latest release (below). To *read or build* the code,
check out the newest tag, not `main`.

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

**With Go** (builds the newest release tag)
```bash
go install github.com/MuyleangIng/MekongTunnel/cmd/mekong@latest
```

Already installed? Update with `mekong update`. Check your version with `mekong -v`.

---

## Quick start

```bash
mekong 3000                       # random public URL for localhost:3000
mekong login                      # sign in once (opens your browser)
mekong 3000 --subdomain myapp     # use a name you reserved in the dashboard
mekong 3000 --skip-browser-warning  # visitors open your app directly
```

Logged-in tunnels show up in your [dashboard](https://mekongtunnel.dev/dashboard/tunnels) with request logs.
Plans: Free (4 active tunnels), Student (6 active tunnels, reserved subdomains) — see [pricing](https://mekongtunnel.dev/pricing).

No install? Plain SSH works too:

```bash
ssh -t -R 80:localhost:3000 proxy.mekongtunnel.dev
```

---

## Build from source

```bash
git clone https://github.com/MuyleangIng/MekongTunnel.git
cd MekongTunnel
git checkout "$(git tag --sort=-v:refname | head -1)"   # newest release, not main
make build-small          # → bin/mekong (CLI) and bin/mekongtunnel (server)
```

Want to run your own server? Follow the [self-hosting guide](https://docs.mekongtunnel.dev/docs/v1.0.0/advanced/self-hosting).

---

## Support

- Questions and bugs: [open an issue](https://github.com/MuyleangIng/MekongTunnel/issues)
- Email: support.mekongtunnel@gmail.com
- Support the project: [mekongtunnel.dev/sponsor](https://mekongtunnel.dev/sponsor) — 100% of donations go to Kantha Bopha Children's Hospital

MIT © Ing Muyleang / KhmerStack
