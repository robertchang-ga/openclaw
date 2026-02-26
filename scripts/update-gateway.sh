#!/usr/bin/env bash
# update-gateway.sh — Pull latest, rebuild, and restart the openclaw-gateway service.
# Usage: ./scripts/update-gateway.sh [branch]
#   branch defaults to feat/security-proxy

set -euo pipefail

BRANCH="${1:-feat/security-proxy}"

echo "==> Pulling $BRANCH..."
git pull origin "$BRANCH"

echo "==> Installing dependencies..."
pnpm install

echo "==> Building TypeScript..."
pnpm build

echo "==> Building Docker image..."
docker build --no-cache -t openclaw-gateway .

echo "==> Installing CLI globally..."
npm install -g .

echo "==> Restarting openclaw-gateway service..."
sudo systemctl restart openclaw-gateway

echo "==> Done! Gateway restarted (sidecars auto-started by gateway)."
