## v1.5.7 - 2026-03-27

Highlights:

- Added optional Redis integration for the Go API and tunnel edge
- Cached `server_config` reads and verified custom-domain target lookups in Redis
- Added Redis pub/sub fan-out for notifications so multiple API instances can serve SSE correctly
- Added Redis-backed distributed API rate limiting for public auth and CLI device endpoints
- Moved email login OTP codes to Redis when configured, with PostgreSQL fallback kept for single-node or Redis-disabled setups
- Added GitHub Actions workflows for systemd-based dev and production deploys, plus deployment docs for environment secrets, variables, and optional Redis setup
- Added compose base/dev/prod stack files for Postgres + Redis + API + optional tunnel edge
- Added bootstrap-only API mode plus `api-init` workflow for migrations, `server_config`, and admin creation/promotion
- Added `.env.compose.dev.example` and `.env.compose.prod.example` templates
- Added `cmd/apibench` and `scripts/stress-local.sh` for local API stress runs such as 1000 users and 5000 tunnel reports
- Redesigned the shared-tunnel warning page into a simpler one-click flow so the first Continue click sets the warning cookie and opens the site correctly
- Added a cleaner branded Tunnel Status page for unreachable local apps with a 4-step connection flow, active/failed state colors, mobile-safe text wrapping, and automatic retry/reopen when the local app starts responding again
- Improved tunnel browser error pages so they show the real client-reported local port when available and never fake `localhost:80` for raw `ssh -R` sessions
- Expanded the random generated tunnel-name word pool while keeping the stable `word-word-8hex` format
- Added `docs/API_FLOW.md` and `docs/PERFORMANCE.md`
- Replaced the old local `.env` / `.env.api` workflow with explicit `.env.dev` / `.env.prod` templates, cleaned the compose env templates, and updated scripts/docs to match
- Updated the README, CLI contract, and handbook to document the normal `npm run dev` + `mekong 3000` workflow and the new browser tunnel UX
- Built fresh multi-platform client binaries with `main.version=v1.5.7`


## Release Assets

| Asset | SHA-256 |
| --- | --- |
| `mekong-darwin-amd64` | `198d2f674ae8bc5d234c1849ae6552269744bd3d7f36d30875cd0e918e5bff53` |
| `mekong-darwin-arm64` | `5b11cf46f78f7b17097c05bd4293f81504910840c81428175843ff654b0106e3` |
| `mekong-linux-amd64` | `e5e820f147fee8a049474552baaca90a514c2d57dd946c3bd245114f1e95176e` |
| `mekong-linux-arm64` | `d2a4fc78e59a7df6c092d770fb85ac1a99b0aa249210c5c87eb73816aa1ee3b6` |
| `mekong-windows-amd64.exe` | `a1018c29565ce9cd22211b17637ef4d3f3ebd7b1497fd18e7b0958d75fb5f6df` |
| `mekong-windows-arm64.exe` | `a78c30992b1e3fc29e11d3b4f317a6e9e84156744acb2bea94f1b757038b8db0` |
