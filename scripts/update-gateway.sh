#!/usr/bin/env bash
# update-gateway.sh — Rebuild and restart the openclaw-gateway service from the current working tree.
# Usage: ./scripts/update-gateway.sh [--full]
#   --full: force full rebuild (pnpm install, npm install -g)

set -euo pipefail

FULL=false
for arg in "$@"; do
  case "$arg" in
    --full) FULL=true ;;
    -*) echo "Unknown flag: $arg"; exit 1 ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

if $FULL; then
  echo "==> Installing dependencies..."
  pnpm install
fi

echo "==> Building TypeScript..."
pnpm build

echo "==> Deploying memory-cognee plugin..."
PLUGIN_DIR="$HOME/.openclaw/extensions/memory-cognee/dist"
mkdir -p "$PLUGIN_DIR"
cp cognee-plugin-source.js "$PLUGIN_DIR/index.js"
cp transcript-cleaner.js "$PLUGIN_DIR/transcript-cleaner.js"

echo "==> Building Docker images (cached)..."
docker build -t openclaw-gateway .
docker build -f Dockerfile.voice-sidecar -t openclaw-voice-sidecar:latest .
docker compose build kroko
docker compose build cognee

if $FULL; then
  echo "==> Installing CLI globally..."
  npm install -g .
fi

echo "==> Restarting services..."
sudo systemctl restart openclaw-gateway
docker compose up -d kroko cognee

echo "==> Done! Gateway restarted, Cognee rebuilt (sidecars auto-started by gateway)."
