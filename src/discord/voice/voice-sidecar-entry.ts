#!/usr/bin/env node
/**
 * Voice Sidecar Entrypoint
 *
 * Starts the voice bridge server that manages Discord voice connections.
 * This process runs in a separate container with bridge network access,
 * isolating Discord voice I/O from the main gateway container.
 *
 * Environment variables:
 *   DISCORD_BOT_TOKEN     - Discord bot token (placeholder in secure mode)
 *   SPEACHES_URL          - Speaches WebSocket URL (default: ws://speaches:8000/v1/realtime)
 *   WHISPER_MODEL         - STT model name (default: Systran/faster-distil-whisper-large-v3)
 *   VOICE_BRIDGE_PORT     - HTTP/WS port (default: 18791)
 *   VOICE_LANGUAGE        - Language hint for STT
 *   DAVE_ENCRYPTION       - "false" to disable DAVE encryption
 */

import { VoiceBridgeServer } from "./voice-bridge-server.js";
import { VOICE_BRIDGE_DEFAULT_PORT } from "./voice-bridge-types.js";

const config = {
  port: parseInt(process.env.VOICE_BRIDGE_PORT ?? String(VOICE_BRIDGE_DEFAULT_PORT), 10),
  discordToken: process.env.DISCORD_BOT_TOKEN ?? "",
  speachesUrl: process.env.SPEACHES_URL ?? "ws://speaches:8000/v1/realtime",
  whisperModel:
    process.env.WHISPER_MODEL ?? "Systran/faster-distil-whisper-large-v3",
  language: process.env.VOICE_LANGUAGE || undefined,
  daveEncryption: process.env.DAVE_ENCRYPTION === "false" ? false : undefined,
  decryptionFailureTolerance:
    process.env.DECRYPTION_FAILURE_TOLERANCE === "0" ? 0 : undefined,
};

if (!config.discordToken) {
  console.error("[voice-sidecar] DISCORD_BOT_TOKEN is required");
  process.exit(1);
}

console.log(`[voice-sidecar] Starting voice bridge server on port ${config.port}`);
console.log(`[voice-sidecar] Speaches URL: ${config.speachesUrl}`);
console.log(`[voice-sidecar] Whisper model: ${config.whisperModel}`);

const server = new VoiceBridgeServer(config);

// Graceful shutdown
const shutdown = async () => {
  console.log("[voice-sidecar] Shutting down...");
  await server.stop();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await server.start();
