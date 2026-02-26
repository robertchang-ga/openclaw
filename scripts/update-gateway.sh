#!/usr/bin/env bash
# update-gateway.sh — Pull latest, rebuild, and restart the openclaw-gateway service.
# Usage: ./scripts/update-gateway.sh [branch] [--full]
#   branch defaults to feat/security-proxy
#   --full: run full rebuild (pnpm install, npm install -g)

set -euo pipefail

BRANCH="${1:-feat/security-proxy}"
FULL=false
for arg in "$@"; do
  [ "$arg" = "--full" ] && FULL=true
done

echo "==> Pulling $BRANCH..."
git pull origin "$BRANCH"

if $FULL; then
  echo "==> Installing dependencies..."
  pnpm install
fi

echo "==> Building TypeScript..."
pnpm build

echo "==> Building Docker image (cached)..."
docker build -t openclaw-gateway .

if $FULL; then
  echo "==> Installing CLI globally..."
  npm install -g .
fi

echo "==> Restarting openclaw-gateway service..."
sudo systemctl restart openclaw-gateway

echo "==> Done! Gateway restarted (sidecars auto-started by gateway)."
