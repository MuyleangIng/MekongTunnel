# Mekong Performance And Stress Testing

This repo now includes a local API benchmark command:

```bash
go run ./cmd/apibench -base-url http://127.0.0.1:8080 -users 1000 -tunnels 5000 -concurrency 100
```

Or with the helper script:

```bash
USERS=1000 TUNNELS=5000 CONCURRENCY=100 ./scripts/stress-local.sh
```

## What It Measures

The local benchmark exercises the API control plane:

- user registration throughput
- synthetic tunnel-report throughput via `POST /api/tunnels`
- request latency
- request/response byte volume at the API layer

It is useful for:

- Postgres pool tuning
- Redis cache/rate-limit overhead checks
- API handler and middleware throughput
- localhost regression testing after API changes

## What It Does Not Measure

The API benchmark does not measure:

- real SSH tunnel creation overhead
- HTTPS proxy throughput
- WebSocket forwarding bandwidth
- public internet latency
- total egress cost

Those belong to the tunnel data plane, not the API control plane.

## Local Stack

Bring up the local stack first:

```bash
cp .env.compose.dev.example .env.compose.dev
docker compose --env-file .env.compose.dev -f docker-compose.yml -f docker-compose.dev.yml up -d
./scripts/init-stack.sh dev
```

Then run:

```bash
./scripts/stress-local.sh
```

## Reading The Output

The benchmark prints, per phase:

- success / failure counts
- elapsed duration
- throughput in requests per second
- p50 / p95 / max latency
- request and response bytes

Suggested first tuning knobs:

- `DB_MAX_CONNS`
- `DB_MIN_CONNS`
- `REDIS_CACHE_TTL`
- `REDIS_DOMAIN_CACHE_TTL`
- benchmark `CONCURRENCY`

## Real Tunnel Throughput

To measure real exposed-app performance, you need a live tunnel:

1. Run the tunnel edge locally or on a staging host.
2. Start a real app behind `mekong`.
3. Send traffic to the public URL, not just the API.
4. Measure both the app-side latency and the public-side latency.

Example flow:

```bash
mekong 3000
curl -I https://your-generated-url
```

For real tunnel data-plane benchmarking, use external HTTP or WebSocket traffic generators against the public tunnel URL and compare:

- app-side latency
- proxy-side latency
- bytes transferred
- CPU / RAM on the tunnel edge
- open file descriptors and socket counts

## Capacity Reminder

`1000 users` and `5000 tunnel reports` through the API is a useful local stress test, but it is still not the same as `5000 real active SSH tunnels`. The current tunnel edge keeps the live registry in memory on one node, so true tunnel scale testing must include the `mekongtunnel` process and public request traffic.
