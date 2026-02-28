#!/bin/bash
# update.sh — pull latest code, clean, rebuild, and restart mekongtunnel
set -e

cd /opt/mekongtunnel

echo "→ Stopping service..."
systemctl stop mekongtunnel.service

echo "→ Pulling latest code..."
git pull

echo "→ Cleaning old binaries..."
rm -f mekongtunnel /usr/local/bin/mekong

echo "→ Building server binary..."
go build -ldflags="-s -w -X main.version=$(git describe --tags --always)" -trimpath -o mekongtunnel ./cmd/mekongtunnel

echo "→ Building mekong client binary..."
go build -ldflags="-s -w -X main.version=$(git describe --tags --always)" -trimpath -o /usr/local/bin/mekong ./cmd/mekong
chmod +x /usr/local/bin/mekong

echo "→ Starting service..."
systemctl start mekongtunnel.service

echo "→ Status:"
systemctl status mekongtunnel.service --no-pager
