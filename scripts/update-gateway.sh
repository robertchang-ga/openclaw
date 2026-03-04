#!/usr/bin/env bash
# update-gateway.sh — Pull latest, rebuild, and restart the openclaw-gateway service.
# Usage: ./scripts/update-gateway.sh [branch] [--full]
#   branch defaults to feat/security-proxy
#   --full: force full rebuild (pnpm install, npm install -g)

set -euo pipefail

BRANCH=""
FULL=false
for arg in "$@"; do
  case "$arg" in
    --full) FULL=true ;;
    -*) echo "Unknown flag: $arg"; exit 1 ;;
    *) BRANCH="$arg" ;;
  esac
done
BRANCH="${BRANCH:-feat/security-proxy}"

# Guard against infinite re-exec loop (set by the re-exec block below).
RERAN="${_OPENCLAW_UPDATE_RERAN:-}"

if [ -z "$RERAN" ]; then
  # Record lockfile hash before pull to detect dep changes.
  LOCK_BEFORE=$(md5sum pnpm-lock.yaml 2>/dev/null | cut -d' ' -f1 || echo "none")
  # Record this script's hash before pull so we can detect if it changed.
  SCRIPT_BEFORE=$(md5sum "$0" 2>/dev/null | cut -d' ' -f1 || echo "none")

  echo "==> Pulling $BRANCH..."
  git pull origin "$BRANCH"

  SCRIPT_AFTER=$(md5sum "$0" 2>/dev/null | cut -d' ' -f1 || echo "none")
  # Bash buffers the script before executing, so any lines added by git pull
  # (e.g. a new docker build step) are not seen by the running instance.
  # Re-exec with the updated script to pick up those changes.
  if [ "$SCRIPT_BEFORE" != "$SCRIPT_AFTER" ]; then
    echo "==> Script updated by git pull — re-running with new version..."
    export _OPENCLAW_UPDATE_RERAN=1
    exec bash "$0" "$@"
  fi

  LOCK_AFTER=$(md5sum pnpm-lock.yaml 2>/dev/null | cut -d' ' -f1 || echo "none")
  # Auto-detect dependency changes.
  if [ "$LOCK_BEFORE" != "$LOCK_AFTER" ]; then
    echo "==> pnpm-lock.yaml changed — installing dependencies..."
    FULL=true
  fi
else
  echo "==> (Re-ran after script self-update)"
fi

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
docker build -f Dockerfile.kroko -t kroko:local .
docker compose build cognee

if $FULL; then
  echo "==> Installing CLI globally..."
  npm install -g .
fi

echo "==> Restarting services..."
sudo systemctl restart openclaw-gateway
docker compose up -d cognee

echo "==> Done! Gateway restarted, Cognee rebuilt (sidecars auto-started by gateway)."
