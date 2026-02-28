#!/bin/bash
# update.sh — pull latest code, rebuild, and restart mekongtunnel
set -e

cd /opt/mekongtunnel

echo "→ Stopping service..."
systemctl stop mekongtunnel.service

echo "→ Pulling latest code..."
git pull

echo "→ Building binary..."
go build -ldflags="-s -w" -trimpath -o mekongtunnel ./cmd/mekongtunnel

echo "→ Starting service..."
systemctl start mekongtunnel.service

echo "→ Status:"
systemctl status mekongtunnel.service --no-pager
