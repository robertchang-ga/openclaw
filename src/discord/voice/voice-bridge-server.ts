/**
 * Voice Bridge Server — runs inside the voice sidecar container.
 *
 * Responsibilities:
 * - Manages Discord voice connections (WSS signaling + UDP audio)
 * - Opus decodes incoming audio and pipes it to Speaches STT (via WebSocket)
 * - Sends transcripts to the gateway via WebSocket events
 * - Receives TTS audio from the gateway and plays it back via Discord
 *
 * Network: bridge (for Discord) + openclaw-secure-net (for gateway + Speaches)
 */

import { createRequire } from "node:module";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import {
  AudioPlayerStatus,
  EndBehaviorType,
  VoiceConnectionStatus,
  createAudioPlayer,
  createAudioResource,
  entersState,
  joinVoiceChannel,
  type AudioPlayer,
  type VoiceConnection,
  type DiscordGatewayAdapterCreator,
  type DiscordGatewayAdapterLibraryMethods,
} from "@discordjs/voice";
import { WebSocketServer, WebSocket } from "ws";
import { RealtimeSTT, resample48kStereoTo24kMono } from "./realtime-stt.js";
import type {
  VoiceBridgeConfig,
  VoiceBridgeEvent,
  VoiceBridgeJoinRequest,
  VoiceBridgeLeaveRequest,
  VoiceBridgePlayRequest,
  VoiceBridgeOperationResult,
  VoiceBridgeStatusEntry,
} from "./voice-bridge-types.js";

const require = createRequire(import.meta.url);

const SAMPLE_RATE = 48_000;
const CHANNELS = 2;
const PLAYBACK_READY_TIMEOUT_MS = 15_000;
const SPEAKING_READY_TIMEOUT_MS = 60_000;
const DECRYPT_FAILURE_WINDOW_MS = 30_000;
const DECRYPT_FAILURE_RECONNECT_THRESHOLD = 3;
const DECRYPT_FAILURE_PATTERN = /DecryptionFailed\(/;

// Simple logger that works without OpenClaw subsystem infrastructure
const log = {
  info: (msg: string) => console.log(`[voice-sidecar] ${msg}`),
  warn: (msg: string) => console.warn(`[voice-sidecar] ${msg}`),
  error: (msg: string) => console.error(`[voice-sidecar] ${msg}`),
};

// ---------------------------------------------------------------------------
// Opus decoder (same as manager.ts)
// ---------------------------------------------------------------------------

type OpusDecoder = { decode: (buffer: Buffer) => Buffer };

let warnedOpusFallback = false;

function createOpusDecoder(): { decoder: OpusDecoder; name: string } | null {
  try {
    const { OpusEncoder } = require("@discordjs/opus") as {
      OpusEncoder: new (sampleRate: number, channels: number) => OpusDecoder;
    };
    const decoder = new OpusEncoder(SAMPLE_RATE, CHANNELS);
    return { decoder, name: "@discordjs/opus" };
  } catch (nativeErr) {
    try {
      const OpusScript = require("opusscript") as {
        new (sampleRate: number, channels: number, application: number): OpusDecoder;
        Application: { AUDIO: number };
      };
      const decoder = new OpusScript(SAMPLE_RATE, CHANNELS, OpusScript.Application.AUDIO);
      if (!warnedOpusFallback) {
        warnedOpusFallback = true;
        log.warn(
          `@discordjs/opus unavailable (${String(nativeErr)}); using opusscript fallback`,
        );
      }
      return { decoder, name: "opusscript" };
    } catch (jsErr) {
      log.warn(`opus decoder init failed: ${String(nativeErr)}`);
      log.warn(`opusscript init failed: ${String(jsErr)}`);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Voice session state
// ---------------------------------------------------------------------------

type VoiceSession = {
  guildId: string;
  channelId: string;
  connection: VoiceConnection;
  player: AudioPlayer;
  playbackQueue: Promise<void>;
  activeSpeakers: Set<string>;
  realtimeSTT: RealtimeSTT | null;
  decryptFailureCount: number;
  lastDecryptFailureAt: number;
  decryptRecoveryInFlight: boolean;
  lastSpeakerId?: string;
  pendingTranscripts?: Array<{ text: string; speakerId?: string }>;
  transcriptDebounceTimer?: ReturnType<typeof setTimeout> | null;
  stop: () => void;
};

// ---------------------------------------------------------------------------
// Voice Bridge Server
// ---------------------------------------------------------------------------

export class VoiceBridgeServer {
  private sessions = new Map<string, VoiceSession>();
  private wss: WebSocketServer | null = null;
  private httpServer: http.Server | null = null;
  private gatewayWs: WebSocket | null = null;
  private botUserId?: string;
  private config: VoiceBridgeConfig;
  /** Adapters for relaying voice state events from the main gateway. */
  private adapters = new Map<string, DiscordGatewayAdapterLibraryMethods>();

  constructor(config: VoiceBridgeConfig) {
    this.config = config;
  }

  // ─── Lifecycle ───────────────────────────────────────────────

  async start(): Promise<void> {
    // Fetch bot identity via REST (no gateway connection needed).
    await this.initBotIdentity();

    // Start HTTP + WebSocket server for gateway communication
    this.startServer();

    log.info(`Voice bridge server started on port ${this.config.port}`);
  }

  async stop(): Promise<void> {
    // Destroy all voice sessions
    for (const session of this.sessions.values()) {
      session.stop();
    }
    this.sessions.clear();

    // Close WebSocket connections
    if (this.gatewayWs) {
      this.gatewayWs.close();
      this.gatewayWs = null;
    }
    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }

    // Close HTTP server
    if (this.httpServer) {
      this.httpServer.close();
      this.httpServer = null;
    }

    log.info("Voice bridge server stopped");
  }

  // ─── Bot Identity (REST only — NO gateway connection) ──────

  private async initBotIdentity(): Promise<void> {
    const token = this.config.discordToken;
    if (!token) {
      throw new Error("Discord bot token is required for voice sidecar");
    }

    // Fetch bot user ID via REST API — the sidecar has bridge network access.
    try {
      const res = await fetch("https://discord.com/api/v10/users/@me", {
        headers: { Authorization: `Bot ${token}` },
      });
      if (res.ok) {
        const data = (await res.json()) as { id: string };
        this.botUserId = data.id;
        log.info(`Discord client ready as ${this.botUserId}`);
      } else {
        log.warn(`Failed to fetch bot identity: HTTP ${res.status}`);
      }
    } catch (err) {
      log.warn(`Failed to fetch bot identity: ${String(err)}`);
    }
  }

  // ─── Relay Adapter Creator ────────────────────────────────

  /**
   * Creates a DiscordGatewayAdapterCreator that relays voice state events
   * through the bridge WebSocket instead of using a direct Discord gateway.
   *
   * - sendPayload → sends "send_voice_payload" to the main gateway via WS
   * - onVoiceStateUpdate/onVoiceServerUpdate ← received from main gateway via WS
   */
  private createRelayAdapterCreator(guildId: string): DiscordGatewayAdapterCreator {
    return (methods: DiscordGatewayAdapterLibraryMethods) => {
      this.adapters.set(guildId, methods);
      return {
        sendPayload: (payload: { op: number; d: unknown }) => {
          if (!this.gatewayWs || this.gatewayWs.readyState !== WebSocket.OPEN) {
            log.warn(`Cannot send voice payload for guild ${guildId}: no gateway WS`);
            return false;
          }
          this.gatewayWs.send(
            JSON.stringify({ type: "send_voice_payload", payload }),
          );
          return true;
        },
        destroy: () => {
          this.adapters.delete(guildId);
        },
      };
    };
  }

  /**
   * Handle an incoming bridge WS message that relays a voice state event
   * from the main gateway.
   */
  private handleRelayEvent(event: VoiceBridgeEvent): void {
    if (event.type === "voice_state_update") {
      const data = event.data as Record<string, unknown>;
      const guildId = data.guild_id as string | undefined;
      if (guildId) {
        this.adapters.get(guildId)?.onVoiceStateUpdate(data as never);
      }
    } else if (event.type === "voice_server_update") {
      const data = event.data as Record<string, unknown>;
      const guildId = data.guild_id as string | undefined;
      if (guildId) {
        this.adapters.get(guildId)?.onVoiceServerUpdate(data as never);
      }
    }
  }

  // ─── HTTP/WS Server ────────────────────────────────────────

  private startServer(): void {
    this.httpServer = http.createServer(async (req, res) => {
      try {
        await this.handleHttpRequest(req, res);
      } catch (err) {
        log.error(`HTTP error: ${String(err)}`);
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end(JSON.stringify({ ok: false, message: String(err) }));
        }
      }
    });

    this.wss = new WebSocketServer({ server: this.httpServer, path: "/ws" });
    this.wss.on("connection", (ws) => {
      log.info("Gateway WebSocket connected");
      this.gatewayWs = ws;
      ws.on("message", (data) => {
        try {
          const event: VoiceBridgeEvent = JSON.parse(data.toString());
          this.handleRelayEvent(event);
        } catch (err) {
          log.warn(`Invalid relay event: ${String(err)}`);
        }
      });
      ws.on("close", () => {
        log.info("Gateway WebSocket disconnected");
        if (this.gatewayWs === ws) {
          this.gatewayWs = null;
        }
      });
      ws.on("error", (err) => {
        log.warn(`Gateway WebSocket error: ${String(err)}`);
      });
    });

    this.httpServer.listen(this.config.port, "0.0.0.0", () => {
      log.info(`Listening on 0.0.0.0:${this.config.port}`);
    });
  }

  private async handleHttpRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const method = req.method?.toUpperCase() ?? "GET";

    if (method === "POST" && url.pathname === "/voice/join") {
      const body = await readJsonBody<VoiceBridgeJoinRequest>(req);
      const result = await this.handleJoin(body);
      sendJson(res, result);
      return;
    }

    if (method === "POST" && url.pathname === "/voice/leave") {
      const body = await readJsonBody<VoiceBridgeLeaveRequest>(req);
      const result = await this.handleLeave(body);
      sendJson(res, result);
      return;
    }

    if (method === "POST" && url.pathname === "/voice/play") {
      const guildId = url.searchParams.get("guildId");
      const index = url.searchParams.get("index");
      if (!guildId) {
        sendJson(res, { ok: false, message: "Missing guildId" }, 400);
        return;
      }
      const audioData = await readBinaryBody(req);
      const result = await this.handlePlay({
        guildId,
        audioData,
        index: index ? parseInt(index, 10) : undefined,
      });
      sendJson(res, result);
      return;
    }

    if (method === "POST" && url.pathname === "/voice/stop-playback") {
      const body = await readJsonBody<{ guildId: string }>(req);
      const session = this.sessions.get(body.guildId);
      if (session) {
        session.player.stop(true);
        sendJson(res, { ok: true, message: "Playback stopped" });
      } else {
        sendJson(res, { ok: false, message: "No active session" }, 404);
      }
      return;
    }

    if (method === "GET" && url.pathname === "/voice/status") {
      const entries: VoiceBridgeStatusEntry[] = Array.from(this.sessions.values()).map((s) => ({
        guildId: s.guildId,
        channelId: s.channelId,
        connected: true,
      }));
      sendJson(res, entries);
      return;
    }

    if (method === "GET" && url.pathname === "/health") {
      sendJson(res, { ok: true, sessions: this.sessions.size });
      return;
    }

    res.statusCode = 404;
    res.end("Not found");
  }

  // ─── Voice Operations ──────────────────────────────────────

  private async handleJoin(
    params: VoiceBridgeJoinRequest,
  ): Promise<VoiceBridgeOperationResult> {
    if (!this.gatewayWs || this.gatewayWs.readyState !== WebSocket.OPEN) {
      return { ok: false, message: "Gateway WebSocket not connected" };
    }

    const { guildId, channelId } = params;
    if (!guildId?.trim() || !channelId?.trim()) {
      return { ok: false, message: "Missing guildId or channelId" };
    }

    const existing = this.sessions.get(guildId);
    if (existing && existing.channelId === channelId) {
      return { ok: true, message: `Already connected to <#${channelId}>.`, guildId, channelId };
    }
    if (existing) {
      await this.handleLeave({ guildId });
    }

    const adapterCreator = this.createRelayAdapterCreator(guildId);
    const connection = joinVoiceChannel({
      channelId,
      guildId,
      adapterCreator,
      selfDeaf: false,
      selfMute: false,
      // Work around @discordjs/voice 0.19.x DAVE E2E bug — same as manager.ts
      // commit ef25cfbc. Disabling DAVE falls back to XSalsa20 transport
      // encryption (still encrypted, just not E2E).
      daveEncryption: false,
    });

    try {
      await entersState(connection, VoiceConnectionStatus.Ready, PLAYBACK_READY_TIMEOUT_MS);
      log.info(`Connected to voice: guild ${guildId} channel ${channelId}`);
    } catch (err) {
      connection.destroy();
      return { ok: false, message: `Failed to join: ${String(err)}` };
    }

    const player = createAudioPlayer();
    connection.subscribe(player);

    const session: VoiceSession = {
      guildId,
      channelId,
      connection,
      player,
      playbackQueue: Promise.resolve(),
      activeSpeakers: new Set(),
      realtimeSTT: null,
      decryptFailureCount: 0,
      lastDecryptFailureAt: 0,
      decryptRecoveryInFlight: false,
      stop: () => {
        session.realtimeSTT?.destroy();
        player.stop();
        connection.destroy();
      },
    };

    // Set up realtime STT
    const stt = new RealtimeSTT({
      url: this.config.speachesUrl,
      model: this.config.whisperModel,
      language: this.config.language,
      onTranscript: (text: string) => {
        const speakerId = session.lastSpeakerId;
        log.info(
          `transcript (${text.length} chars): guild ${guildId} user ${speakerId ?? "unknown"}`,
        );

        // Debounce transcripts (same logic as manager.ts)
        session.pendingTranscripts = session.pendingTranscripts ?? [];
        session.pendingTranscripts.push({ text, speakerId });
        if (session.transcriptDebounceTimer) {
          clearTimeout(session.transcriptDebounceTimer);
        }
        session.transcriptDebounceTimer = setTimeout(() => {
          const pending = session.pendingTranscripts ?? [];
          session.pendingTranscripts = [];
          session.transcriptDebounceTimer = null;
          if (pending.length === 0) return;

          const mergedText = pending.map((p) => p.text).join(" ");
          const lastSpeaker = pending[pending.length - 1].speakerId;
          log.info(
            `debounced transcript (${mergedText.length} chars, ${pending.length} segments)`,
          );

          this.emitEvent({
            type: "transcript",
            guildId,
            channelId,
            text: mergedText,
            userId: lastSpeaker,
          });
        }, 1500);
      },
      onSpeechStart: () => {
        // Interrupt playback when user starts speaking
        if (session.player.state.status === AudioPlayerStatus.Playing) {
          session.player.stop(true);
        }
        this.emitEvent({ type: "speech_start", guildId, channelId });
      },
    });
    session.realtimeSTT = stt;

    stt.connect().catch((err) => {
      log.warn(`STT connect failed: ${String(err)}`);
    });

    // Set up audio capture (same as manager.ts)
    const opusDecoder = createOpusDecoder();
    if (opusDecoder) {
      log.info(`opus decoder: ${opusDecoder.name}`);
    }

    const speakingHandler = (userId: string) => {
      if (this.botUserId && userId === this.botUserId) return;
      if (session.activeSpeakers.has(userId)) return;
      session.activeSpeakers.add(userId);
      session.lastSpeakerId = userId;

      const stream = connection.receiver.subscribe(userId, {
        end: { behavior: EndBehaviorType.AfterSilence, duration: 500 },
      });

      stream.on("data", (chunk: Buffer) => {
        if (!chunk || chunk.length === 0 || !opusDecoder || !stt.isConnected) return;
        try {
          const pcm48k = opusDecoder.decoder.decode(chunk);
          if (pcm48k && pcm48k.length > 0) {
            const pcm24k = resample48kStereoTo24kMono(Buffer.from(pcm48k));
            stt.feedAudio(pcm24k);
          }
        } catch {
          // Decode errors on individual packets are normal
        }
      });

      stream.on("end", () => {
        session.activeSpeakers.delete(userId);
        stt.flushSilence();
      });

      stream.on("error", (err) => {
        session.activeSpeakers.delete(userId);
        log.warn(`receive error for user ${userId}: ${String(err)}`);
      });
    };

    connection.receiver.speaking.on("start", speakingHandler);

    connection.on(VoiceConnectionStatus.Disconnected, async () => {
      try {
        await Promise.race([
          entersState(connection, VoiceConnectionStatus.Signalling, 5_000),
          entersState(connection, VoiceConnectionStatus.Connecting, 5_000),
        ]);
      } catch {
        this.sessions.delete(guildId);
        session.realtimeSTT?.destroy();
        connection.destroy();
        this.emitEvent({
          type: "session_disconnected",
          guildId,
          channelId,
          reason: "disconnected",
        });
      }
    });

    connection.on(VoiceConnectionStatus.Destroyed, () => {
      this.sessions.delete(guildId);
      session.realtimeSTT?.destroy();
      this.emitEvent({
        type: "session_disconnected",
        guildId,
        channelId,
        reason: "destroyed",
      });
    });

    player.on("error", (err) => {
      log.warn(`playback error: ${String(err)}`);
    });

    // DAVE decrypt failure tracking
    if (this.config.decryptionFailureTolerance !== 0) {
      connection.on("error" as never, (err: Error) => {
        const msg = err?.message ?? String(err);
        if (!DECRYPT_FAILURE_PATTERN.test(msg)) return;
        const now = Date.now();
        if (now - session.lastDecryptFailureAt > DECRYPT_FAILURE_WINDOW_MS) {
          session.decryptFailureCount = 0;
        }
        session.lastDecryptFailureAt = now;
        session.decryptFailureCount += 1;
        if (
          session.decryptFailureCount >= DECRYPT_FAILURE_RECONNECT_THRESHOLD &&
          !session.decryptRecoveryInFlight
        ) {
          this.recoverFromDecryptFailures(session);
        }
      });
    }

    this.sessions.set(guildId, session);
    this.emitEvent({ type: "session_connected", guildId, channelId });

    return { ok: true, message: `Joined <#${channelId}>.`, guildId, channelId };
  }

  private async handleLeave(
    params: VoiceBridgeLeaveRequest,
  ): Promise<VoiceBridgeOperationResult> {
    const { guildId } = params;
    const session = this.sessions.get(guildId);
    if (!session) {
      return { ok: false, message: "Not connected to a voice channel." };
    }
    if (params.channelId && params.channelId !== session.channelId) {
      return { ok: false, message: "Not connected to that voice channel." };
    }
    session.stop();
    this.sessions.delete(guildId);
    return { ok: true, message: `Left <#${session.channelId}>.`, guildId, channelId: session.channelId };
  }

  private async handlePlay(params: {
    guildId: string;
    audioData: Buffer;
    index?: number;
  }): Promise<VoiceBridgeOperationResult> {
    const session = this.sessions.get(params.guildId);
    if (!session) {
      return { ok: false, message: "No active voice session" };
    }

    const { audioData, index } = params;
    log.info(
      `play: guild ${params.guildId} chunk${index != null ? ` #${index}` : ""} (${audioData.length} bytes)`,
    );

    // Enqueue playback
    session.playbackQueue = session.playbackQueue
      .then(async () => {
        const tmpDir = mkdtempSync(path.join("/tmp", "voice-play-"));
        const audioPath = path.join(tmpDir, `chunk${index ?? 0}.wav`);
        writeFileSync(audioPath, audioData);

        const resource = createAudioResource(audioPath);
        session.player.play(resource);
        await entersState(session.player, AudioPlayerStatus.Playing, PLAYBACK_READY_TIMEOUT_MS).catch(
          () => undefined,
        );
        await entersState(session.player, AudioPlayerStatus.Idle, SPEAKING_READY_TIMEOUT_MS).catch(
          () => undefined,
        );
        await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
      })
      .catch((err) => log.warn(`playback failed: ${String(err)}`));

    return { ok: true, message: "Enqueued for playback" };
  }

  private async recoverFromDecryptFailures(session: VoiceSession): Promise<void> {
    session.decryptRecoveryInFlight = true;
    log.warn(`Attempting rejoin for guild ${session.guildId} due to decrypt failures`);
    try {
      await this.handleLeave({ guildId: session.guildId });
      await this.handleJoin({ guildId: session.guildId, channelId: session.channelId });
      log.info(`Rejoin succeeded for guild ${session.guildId}`);
    } catch (err) {
      log.warn(`Rejoin recovery error: ${String(err)}`);
    }
  }

  // ─── Event Emission ────────────────────────────────────────

  private emitEvent(event: VoiceBridgeEvent): void {
    if (this.gatewayWs?.readyState === WebSocket.OPEN) {
      this.gatewayWs.send(JSON.stringify(event));
    } else {
      log.warn(`Cannot send event (no gateway connection): ${event.type}`);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function readJsonBody<T>(req: http.IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as T);
      } catch (err) {
        reject(new Error(`Invalid JSON body: ${String(err)}`));
      }
    });
    req.on("error", reject);
  });
}

function readBinaryBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJson(res: http.ServerResponse, data: unknown, status = 200): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(data));
}
