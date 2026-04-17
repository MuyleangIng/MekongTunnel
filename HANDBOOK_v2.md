# MekongTunnel Handbook v2

This handbook documents the current deploy-hosting path after the switch from `rsync + Caddy` to `app-server file serving + SSH reverse tunnel`.

## 1. What Changed

Old deploy flow:

1. Upload zip to API
2. Extract files on app server
3. Sync files to proxy host with `rsync`
4. Serve with Caddy on the proxy host

New deploy flow:

1. Upload zip to API
2. Extract files on the app server into `DEPLOY_DIR/<subdomain>`
3. Start a local static file server on the app server
4. Open an SSH reverse tunnel from the app server to the tunnel server
5. Claim the deployment subdomain on the tunnel server using the shared `TUNNEL_EDGE_SECRET`
6. Serve traffic through the normal Mekong proxy path

Result:

- No `rsync`
- No deploy-time Caddy route creation
- Files stay on the app server
- The proxy host only forwards traffic

## 2. Deploy Architecture

Public request path:

```text
Browser
  -> https://<subdomain>.proxy.mekongtunnel.dev
  -> mekongtunnel proxy host
  -> SSH forwarded channel
  -> app-server local file server
  -> extracted deployment files
```

Control path:

```text
Dashboard / CLI
  -> API POST /api/deploy
  -> extract archive on app server
  -> app server opens SSH session to tunnel server
  -> tunnel server binds deployment subdomain
```

## 3. Required Environment

### API server

- `DEPLOY_DIR`
- `DEPLOY_DOMAIN`
- `TUNNEL_EDGE_SECRET`
- Optional: `DEPLOY_TUNNEL_ADDR`
- Optional fallback: `DEPLOY_TUNNEL_HOST` + `DEPLOY_TUNNEL_SSH_PORT`

Recommended:

```env
DEPLOY_DIR=/opt/mekong/deployments
DEPLOY_DOMAIN=proxy.mekongtunnel.dev
TUNNEL_EDGE_SECRET=<same-secret-on-api-and-proxy>
DEPLOY_TUNNEL_ADDR=34.158.38.176:2222
```

### Tunnel server

- `DOMAIN`
- `SSH_ADDR`
- `TUNNEL_EDGE_SECRET`

The API and tunnel server must use the same `TUNNEL_EDGE_SECRET`.

## 4. Service Behavior

### Upload

`POST /api/deploy` now:

1. validates plan and archive
2. extracts files locally
3. creates the deployment DB row
4. starts the local file server
5. waits for the first SSH tunnel handshake to succeed
6. returns success only after the tunnel is actually up

If the tunnel startup fails, the API returns an error and removes the just-created deployment row and extracted files.

### Restore on restart

When the API starts, it restores active deployments from the `deployments` table and re-opens their SSH tunnels automatically.

### Stop vs delete

- `stop`: marks deployment stopped, stops tunnel, removes extracted files
- `delete`: also removes the deployment row

## 5. Logs

There are now three useful log layers.

### A. Per-deployment session logs

Stored on the API/app server at:

```text
$DEPLOY_DIR/.deploy-logs/<subdomain>.log
```

These logs include:

- deploy tunnel startup events
- SSH session output
- live request lines streamed by the tunnel server
- disconnect / reconnect events

Dashboard `Logs` for a deployment reads the recent tail of this file through:

```text
GET /api/deploy/{subdomain}/logs
```

### B. API service logs

Use this when the deploy upload itself fails:

```bash
ssh -p 22 muyleanging@34.21.139.140 "journalctl -u mekong-api -n 120 --no-pager"
```

Common things you will see there:

- archive/extract errors
- deployment tunnel startup failure
- restore failure on boot

### C. Tunnel server logs

Use this when the public hostname is not routing correctly:

```bash
ssh -p 2222 muyleanging@34.158.38.176 "journalctl -u mekongtunnel -n 120 --no-pager"
```

Common things you will see there:

- SSH connection accepted/rejected
- deployment subdomain claim rejection
- proxy runtime issues

## 6. Normal Deploy Order

When backend deploy code changes:

1. deploy tunnel server
2. deploy API server
3. only deploy frontend if dashboard UI also changed

Commands:

```bash
LOCAL_ENV_FILE=.env.prod bash ./scripts/gcp-deploy-tunnel.sh
LOCAL_ENV_FILE=.env.prod bash ./scripts/gcp-deploy-api.sh
```

Frontend is separate:

```bash
bash ./scripts/gcp-deploy-frontend.sh
```

## 7. Troubleshooting

### Upload returns `internal server error`

Check:

```bash
ssh -p 22 muyleanging@34.21.139.140 "journalctl -u mekong-api -n 120 --no-pager"
```

Likely causes:

- `TUNNEL_EDGE_SECRET` mismatch
- missing `DEPLOY_TUNNEL_ADDR`
- SSH tunnel session exits immediately
- filesystem permission issue under `DEPLOY_DIR`

### Deploy URL does not open

Check both:

```bash
ssh -p 22 muyleanging@34.21.139.140 "journalctl -u mekong-api -n 120 --no-pager"
ssh -p 2222 muyleanging@34.158.38.176 "journalctl -u mekongtunnel -n 120 --no-pager"
```

Then inspect the per-deployment log:

```bash
ssh -p 22 muyleanging@34.21.139.140 "tail -n 80 /opt/mekong/deployments/.deploy-logs/<subdomain>.log"
```

### Deployment disappears after API restart

Check:

- deployment row still exists in `deployments`
- extracted files still exist in `DEPLOY_DIR/<subdomain>`
- API boot logs show restore success

### Logs button shows no request logs yet

That means the deployment tunnel exists, but no request/session output has been written for that deployment yet.

## 8. Current Limits

- Static hosting only through the local file server
- One active deployment per user in the current handler logic
- Deployment logs are session-based text logs, not structured analytics
- Dashboard UI may still show older wording in some places until the frontend is updated

## 9. Quick Ops Commands

App server:

```bash
ssh -p 22 muyleanging@34.21.139.140
systemctl status mekong-api
journalctl -u mekong-api -n 120 --no-pager
```

Tunnel server:

```bash
ssh -p 2222 muyleanging@34.158.38.176
systemctl status mekongtunnel
journalctl -u mekongtunnel -n 120 --no-pager
```

Inspect one deployment log:

```bash
tail -n 120 /opt/mekong/deployments/.deploy-logs/<subdomain>.log
```
