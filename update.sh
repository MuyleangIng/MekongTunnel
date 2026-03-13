#!/usr/bin/env bash
# update.sh — fetch the latest code, reset to a clean ref, rebuild, and restart MekongTunnel
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/mekongtunnel}"
SERVICE_NAME="${SERVICE_NAME:-mekongtunnel.service}"
TARGET_REF="${1:-origin/main}"
SERVER_BIN="${SERVER_BIN:-/usr/local/bin/mekongtunnel}"
CLIENT_BIN="${CLIENT_BIN:-/usr/local/bin/mekong}"

cd "${APP_DIR}"

echo "→ Stopping service..."
systemctl stop "${SERVICE_NAME}"

echo "→ Fetching latest code and tags..."
git fetch --force --prune --tags origin
git rev-parse --verify "${TARGET_REF}^{commit}" >/dev/null

echo "→ Resetting repository to ${TARGET_REF}..."
if [[ "${TARGET_REF}" == origin/* ]]; then
  branch="${TARGET_REF#origin/}"
  git checkout -B "${branch}" "${TARGET_REF}"
else
  git checkout --detach "${TARGET_REF}"
fi
git reset --hard "${TARGET_REF}"
git clean -fdx -e host_key -e data/ -e data-dev/ -e certs/ -e .env -e .env.* -e logs/

echo "→ Cleaning old binaries and Go caches..."
rm -f mekongtunnel "${SERVER_BIN}" "${CLIENT_BIN}"
go clean -cache -testcache -modcache

VERSION="$(git describe --tags --always)"
LDFLAGS="-s -w -X main.version=${VERSION}"

echo "→ Building server binary (${VERSION})..."
CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -trimpath -o mekongtunnel ./cmd/mekongtunnel
install -m 0755 mekongtunnel "${SERVER_BIN}"

echo "→ Building mekong client binary (${VERSION})..."
CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -trimpath -o "${CLIENT_BIN}" ./cmd/mekong
chmod +x "${CLIENT_BIN}"

echo "→ Installed versions:"
./mekongtunnel version
"${SERVER_BIN}" version
"${CLIENT_BIN}" version

echo "→ Starting service..."
systemctl start "${SERVICE_NAME}"

echo "→ Status:"
systemctl status "${SERVICE_NAME}" --no-pager
