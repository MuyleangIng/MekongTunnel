# MekongTunnel Startup Cloud Plan

Last updated: March 24, 2026

This document turns the current repo architecture into a practical startup deployment plan.

It focuses on:

- where to run the Next.js frontend
- where to run the Go API
- where to run the SSH/HTTPS tunnel server
- rough sizing for 100, 500, and 1000 active tunnels
- cloud provider cost comparisons for an early production setup

## Short Answer

For the current codebase, the best startup setup is:

- Next.js frontend on Vercel
- Go API on a small dedicated VM
- tunnel server on a separate, larger VM
- managed Postgres

Recommended domains:

- `www.yourdomain.com` or apex: Next.js frontend
- `api.yourdomain.com`: Go API
- `tunnel.yourdomain.com:22`: SSH entrypoint
- `*.tunnel.yourdomain.com`: public tunnel traffic

This is better than putting the frontend and the tunnel wildcard on the same host.

## Why This Split

Your product has two very different workloads:

| Plane | What it does | Main bottleneck |
| --- | --- | --- |
| Control plane | Next.js, auth, dashboard, billing, API, admin | app CPU, DB, auth, API latency |
| Data plane | SSH tunnels, HTTPS proxying, WebSocket forwarding | bandwidth, open connections, TLS, socket pressure |

The control plane and data plane should not compete for the same machine.

## Important Current Code Constraints

The current repo is good for a startup launch, but it has clear scaling limits.

| Constraint | Current state in repo | Why it matters |
| --- | --- | --- |
| Tunnel lifetime | default 24h, max 7 days | long-lived single tunnels for months are not supported |
| Tunnel registry | in-memory map in the tunnel server | public traffic must hit the same node that owns the SSH tunnel |
| Horizontal tunnel scale | not implemented | multiple tunnel nodes need sharding or shared routing logic |
| Reserved subdomain continuity | supported via reconnect + API token | stable domain is fine, but not one raw tunnel session for months |

Relevant code:

- `cmd/mekongtunnel/main.go`
- `internal/proxy/proxy.go`
- `internal/proxy/ssh.go`
- `internal/proxy/http.go`
- `internal/tunnel/tunnel.go`
- `internal/config/config.go`

## Recommended Startup Architecture

```text
Users
  |
  +--> www.yourdomain.com ----------------> Next.js frontend
  |
  +--> api.yourdomain.com ----------------> Go API
  |
  +--> tunnel.yourdomain.com:22 ----------> tunnel server (SSH)
  |
  +--> *.tunnel.yourdomain.com -----------> same tunnel server (HTTPS proxy)
                                               |
                                               +--> user's local app via SSH reverse tunnel

Go API <------------------------------------> Managed Postgres
```

## First Production Shape

This is the setup I would launch first.

| Component | Recommendation | Notes |
| --- | --- | --- |
| Frontend | Vercel Pro | easiest for Next.js, previews, CI/CD, TLS |
| API | 1 small VM | keep API isolated from tunnel traffic |
| Tunnel server | 1 larger VM | run only the SSH/HTTPS proxy here |
| Database | managed Postgres | avoid self-hosting Postgres on day 1 |
| Monitoring | basic metrics + logs | at minimum CPU, RAM, disk, bandwidth, process restarts |

## Capacity Tiers

These are practical startup estimates, not guarantees.

They assume:

- normal web-app style traffic
- no heavy video streaming
- no huge file transfer abuse
- one tunnel node for now

| Stage | Active tunnels | Tunnel server | API layer | DB |
| --- | --- | --- | --- | --- |
| Beta | up to 100 | 8 vCPU / 16 GB RAM | 1 node, 2-4 vCPU / 4-8 GB | managed Postgres small/pro |
| Early growth | up to 500 | 16 vCPU / 32 GB RAM | 2 API nodes or 1 stronger node | managed Postgres medium |
| Before redesign | around 1000 | 16-32 vCPU / 32-64 GB RAM | 2 API nodes behind LB | managed Postgres medium/large |

## Tunnel Scaling Advice

Do not jump to multiple tunnel nodes too early.

With the current design, one tunnel lives in one process on one node. If SSH lands on node A but HTTPS lands on node B, the tunnel lookup fails.

That means:

- one strong tunnel node is the simplest startup path
- add more API/frontend capacity first
- redesign tunnel routing before adding multiple tunnel nodes

When you later scale the tunnel layer, choose one of these:

| Approach | Fit | Tradeoff |
| --- | --- | --- |
| Single large tunnel node | best startup choice | simplest, but one scaling ceiling |
| Shard by hostname | good next step | more DNS and routing complexity |
| Shared registry + smart routing | best long-term | highest engineering cost |

## Frontend Hosting Choices

For the Next.js app, I would choose Vercel first.

| Option | Best for | Pros | Cons |
| --- | --- | --- | --- |
| Vercel Pro | fastest startup | best Next.js workflow, previews, CDN, low ops | another provider in the stack |
| Self-hosted Next.js on your API VM | lowest provider count | simple infra on paper | mixes concerns, harder ops, weaker rollout model |
| Self-hosted Next.js on separate VM | full control | avoids Vercel lock-in | more maintenance than Vercel |

Recommended startup answer:

- use Vercel for frontend
- do not host Next.js on the same box as the tunnel server

## Managed Database Advice

For startup speed, use managed Postgres.

| Option | Startup fit | Notes |
| --- | --- | --- |
| Supabase Pro | very good | simple Postgres + auth-adjacent ecosystem, easy start |
| Neon | good | good Postgres experience, especially for app backends |
| Self-hosted Postgres | not recommended on day 1 | more backup, failover, tuning, and ops work |

## Provider Comparison For The Core VM Layer

The table below compares the VM side of the stack for a practical early-production shape:

- one API VM around the 4 GB class
- one tunnel VM around the 16 GB class
- frontend on Vercel Pro
- database on Supabase Pro

This is not perfectly apples-to-apples. CPU models and network policies differ by provider.

The Hetzner rows below use their shared regular-performance cloud plans. That is the budget-efficient startup choice. If your tunnel node starts showing sustained CPU pressure, move that node to a stronger dedicated/general-purpose tier before you redesign for multi-node tunnel routing.

Note: Hetzner published a price-adjustment notice effective April 1, 2026. Recheck the final invoice numbers before ordering.

| Provider | API VM | Tunnel VM | Frontend | DB | Rough monthly total |
| --- | --- | --- | --- | --- | --- |
| Hetzner | CX23: 2 vCPU / 4 GB / 40 GB at $4.09 | CX43: 8 vCPU / 16 GB / 160 GB at $10.59 | Vercel Pro $20 | Supabase Pro $25 | about $59.68, plus Hetzner IPv4 if needed |
| DigitalOcean | Basic Droplet: 2 vCPU / 4 GB / 80 GB at $24 | Basic Droplet: 8 vCPU / 16 GB / 320 GB at $96 | Vercel Pro $20 | Supabase Pro $25 | about $165 |
| AWS Lightsail | 2 vCPU / 4 GB / 80 GB at $24 | 4 vCPU / 16 GB / 320 GB at $84 | Vercel Pro $20 | Supabase Pro $25 | about $153 |

## Budget Recommendation

If the goal is startup efficiency, this is the best order:

1. Vercel for Next.js
2. Hetzner for API VM and tunnel VM
3. Supabase Pro for Postgres

Why:

- lowest monthly cost of the compared stacks
- good enough for early production
- easy to separate API and tunnel workloads
- generous traffic policy compared with hyperscalers
- you can still move the tunnel VM to a larger dedicated tier later if needed

## Setup Bundles

### Option A: Lean Launch

Best when you want to ship quickly and keep monthly cost low.

| Layer | Choice | Estimated monthly |
| --- | --- | --- |
| Frontend | Vercel Pro | $20 |
| API VM | Hetzner CX23 | $4.09 |
| Tunnel VM | Hetzner CX43 | $10.59 |
| Database | Supabase Pro | $25 |
| Total |  | about $59.68, plus Hetzner IPv4 if needed |

Fit:

- first real production launch
- up to around 100 active tunnels
- small team

### Option B: Safer Early Production

Best when you want more room for API growth and smoother deploys.

| Layer | Choice | Estimated monthly |
| --- | --- | --- |
| Frontend | Vercel Pro | $20 |
| API VMs | 2 x Hetzner CX23 | $8.18 |
| Tunnel VM | Hetzner CX43 | $10.59 |
| Small load balancer | Hetzner LB11 | $8.49 |
| Database | Supabase Pro | $25 |
| Total |  | about $72.26, plus Hetzner IPv4 if needed |

Fit:

- more reliable API rollouts
- admin/dashboard traffic is growing
- still single tunnel node

### Option C: Hyperscaler Simplicity

Best when you strongly prefer AWS branding and one-vendor familiarity.

| Layer | Choice | Estimated monthly |
| --- | --- | --- |
| Frontend | Vercel Pro | $20 |
| API VM | AWS Lightsail 4 GB | $24 |
| Tunnel VM | AWS Lightsail 16 GB | $84 |
| Database | Supabase Pro | $25 |
| Total |  | about $153 |

Fit:

- easier executive comfort with AWS name
- not the cheapest option
- bandwidth economics are usually worse for a tunnel product

## Recommendation By Business Stage

| Stage | What to do |
| --- | --- |
| 0 to first customers | Option A |
| some paying teams, stable growth | Option B |
| after proving demand for hundreds of active tunnels | redesign tunnel routing before multi-node tunnel expansion |

## What I Would Do Next In This Repo

Before serious scale, I would add these items:

| Priority | Change | Reason |
| --- | --- | --- |
| High | explicit tunnel-node architecture doc | avoid mixing API and tunnel assumptions |
| High | tunnel routing strategy for multi-node future | current in-memory model is single-node oriented |
| High | real observability for tunnel node | you need connection, bandwidth, and error visibility |
| High | abuse controls and traffic accounting | tunnel products attract misuse |
| Medium | stronger tunnel state persistence/reporting | better admin and analytics visibility |
| Medium | HA path for API only | much easier than tunnel HA |

## Final Recommendation

If you want the most practical startup answer:

- keep frontend on Vercel
- keep API and tunnel on separate machines
- start with one strong tunnel node
- use managed Postgres
- use Hetzner first unless you have a strong reason to pay AWS prices early

Do not design for one tunnel session staying up for months.

Design for:

- stable reserved subdomains
- automatic reconnect
- clean tunnel replacement

That matches the current codebase much better.

## Pricing Sources

These prices were checked on March 24, 2026 and can change.

- Hetzner Cloud pricing page: https://www.hetzner.com/cloud
- Hetzner load balancer pricing page: https://www.hetzner.com/cloud/load-balancer
- Hetzner Cloud price adjustment notice effective April 1, 2026: https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/
- Hetzner Cloud servers docs: https://docs.hetzner.com/cloud/servers/
- DigitalOcean Droplet pricing: https://www.digitalocean.com/pricing/droplets
- DigitalOcean Droplet pricing docs: https://docs.digitalocean.com/products/droplets/details/pricing/
- AWS Lightsail pricing: https://aws.amazon.com/lightsail/pricing/
- Vercel pricing: https://vercel.com/pricing
- Vercel plans docs: https://vercel.com/docs/plans
- Supabase billing examples and Pro plan docs: https://supabase.com/docs/guides/platform/manage-your-usage/disk-size
- Supabase spend cap docs: https://supabase.com/docs/guides/platform/spend-cap
