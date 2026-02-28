#!/bin/bash
# update.sh — pull latest code, rebuild, and restart mekongtunnel
set -e

cd /opt/mekongtunnel

echo "→ Stopping service..."
systemctl stop mekongtunnel.service

echo "→ Pulling latest code..."
git pull

echo "→ Building server binary..."
go build -ldflags="-s -w" -trimpath -o mekongtunnel ./cmd/mekongtunnel

echo "→ Building mekong client binary..."
go build -ldflags="-s -w" -trimpath -o /usr/local/bin/mekong ./cmd/mekong
chmod +x /usr/local/bin/mekong

echo "→ Starting service..."
systemctl start mekongtunnel.service

echo "→ Status:"
systemctl status mekongtunnel.service --no-pager
