import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import {
  ChannelType,
  type Client,
  ReadyListener,
  VoiceStateUpdateListener,
  VoiceServerUpdateListener,
} from "@buape/carbon";
import { type GatewayPlugin } from "@buape/carbon/gateway";
import type { VoicePlugin } from "@buape/carbon/voice";
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
} from "@discordjs/voice";
import { agentCommand } from "../../commands/agent.js";
import type { OpenClawConfig } from "../../config/config.js";
import type { DiscordVoiceConfig } from "../../config/types.discord.js";
import type { DiscordAccountConfig, TtsConfig } from "../../config/types.js";
import { logVerbose } from "../../globals.js";
import { onAgentEvent } from "../../infra/agent-events.js";
import { formatErrorMessage } from "../../infra/errors.js";
import { resolvePreferredOpenClawTmpDir } from "../../infra/tmp-openclaw-dir.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { resolveAgentRoute } from "../../routing/resolve-route.js";
import type { RuntimeEnv } from "../../runtime.js";
import { parseTtsDirectives } from "../../tts/tts-core.js";
import { kokoroTTSBuffer, resolveKokoroConfig, warmUpKokoro } from "../../tts/tts-kokoro.js";
import { resolveTtsConfig, textToSpeech, type ResolvedTtsConfig } from "../../tts/tts.js";
import { KrokoSTT, resample48kStereoTo16kMonoFloat32 } from "./kroko-stt.js";
import { RealtimeSTT, resample48kStereoTo24kMono } from "./realtime-stt.js";
import { VoiceBridgeClient } from "./voice-bridge-client.js";

const require = createRequire(import.meta.url);

const SAMPLE_RATE = 48_000;
const CHANNELS = 2;
const PLAYBACK_READY_TIMEOUT_MS = 15_000;
const SPEAKING_READY_TIMEOUT_MS = 60_000;
const DECRYPT_FAILURE_WINDOW_MS = 30_000;
const DECRYPT_FAILURE_RECONNECT_THRESHOLD = 3;
const DECRYPT_FAILURE_PATTERN = /DecryptionFailed\(/;

/** Resolve the Speaches WebSocket URL for realtime STT. */
function resolveSpeachesRealtimeUrl(cfg: OpenClawConfig): string {
  // In Docker secure mode, use the Docker-internal hostname
  if (process.env.OPENCLAW_SECURE_MODE) {
    return "ws://speaches:8000/v1/realtime";
  }
  // Try to derive from the audio provider baseUrl config
  const audioBaseUrl = cfg.tools?.media?.audio?.baseUrl?.trim();
  if (audioBaseUrl) {
    try {
      const parsed = new URL(audioBaseUrl);
      parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
      // Replace /v1 suffix with /v1/realtime
      parsed.pathname = parsed.pathname.replace(/\/v1\/?$/, "/v1/realtime");
      if (!parsed.pathname.includes("/v1/realtime")) {
        parsed.pathname = "/v1/realtime";
      }
      return parsed.toString().replace(/\/$/, "");
    } catch {
      /* fall through */
    }
  }
  // Default: local Speaches on host port
  return "ws://localhost:8090/v1/realtime";
}

/** Resolve the Whisper model name from config. */
function resolveWhisperModel(cfg: OpenClawConfig): string {
  // Check audio models config
  const audioModels = cfg.tools?.media?.audio?.models;
  if (audioModels && audioModels.length > 0) {
    const first = audioModels[0];
    if (typeof first === "object" && first.model) {
      return first.model;
    }
    if (typeof first === "string") {
      return first;
    }
  }
  return process.env.SPEACHES_MODEL || "Systran/faster-distil-whisper-large-v3";
}

const logger = createSubsystemLogger("discord/voice");

const logVoiceVerbose = (message: string) => {
  logVerbose(`discord voice: ${message}`);
};

type VoiceOperationResult = {
  ok: boolean;
  message: string;
  channelId?: string;
  guildId?: string;
};

type VoiceSessionEntry = {
  guildId: string;
  channelId: string;
  sessionChannelId: string;
  route: ReturnType<typeof resolveAgentRoute>;
  connection: VoiceConnection;
  player: AudioPlayer;
  playbackQueue: Promise<void>;
  processingQueue: Promise<void>;
  activeSpeakers: Set<string>;
  realtimeSTT: RealtimeSTT | KrokoSTT | null;
  decryptFailureCount: number;
  lastDecryptFailureAt: number;
  decryptRecoveryInFlight: boolean;
  lastSpeakerId?: string;
  pendingTranscripts?: Array<{ text: string; speakerId?: string }>;
  transcriptDebounceTimer?: ReturnType<typeof setTimeout> | null;
  stop: () => void;
};

function mergeTtsConfig(base: TtsConfig, override?: TtsConfig): TtsConfig {
  if (!override) {
    return base;
  }
  return {
    ...base,
    ...override,
    modelOverrides: {
      ...base.modelOverrides,
      ...override.modelOverrides,
    },
    elevenlabs: {
      ...base.elevenlabs,
      ...override.elevenlabs,
      voiceSettings: {
        ...base.elevenlabs?.voiceSettings,
        ...override.elevenlabs?.voiceSettings,
      },
    },
    openai: {
      ...base.openai,
      ...override.openai,
    },
    edge: {
      ...base.edge,
      ...override.edge,
    },
  };
}

function resolveVoiceTtsConfig(params: { cfg: OpenClawConfig; override?: TtsConfig }): {
  cfg: OpenClawConfig;
  resolved: ResolvedTtsConfig;
} {
  if (!params.override) {
    return { cfg: params.cfg, resolved: resolveTtsConfig(params.cfg) };
  }
  const base = params.cfg.messages?.tts ?? {};
  const merged = mergeTtsConfig(base, params.override);
  const messages = params.cfg.messages ?? {};
  const cfg = {
    ...params.cfg,
    messages: {
      ...messages,
      tts: merged,
    },
  };
  return { cfg, resolved: resolveTtsConfig(cfg) };
}

function resolveVoiceSttConfig(voice?: DiscordVoiceConfig): {
  provider: "speaches" | "kroko";
  kroko: { url: string; language?: string; apiKey?: string };
} {
  return {
    provider: voice?.stt?.provider ?? "speaches",
    kroko: {
      url: voice?.stt?.kroko?.url ?? "ws://localhost:8080",
      language: voice?.stt?.kroko?.language,
      apiKey: voice?.stt?.kroko?.apiKey,
    },
  };
}

type OpusDecoder = {
  decode: (buffer: Buffer) => Buffer;
};

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
        logger.warn(
          `discord voice: @discordjs/opus unavailable (${formatErrorMessage(nativeErr)}); using opusscript fallback`,
        );
      }
      return { decoder, name: "opusscript" };
    } catch (jsErr) {
      logger.warn(`discord voice: opus decoder init failed: ${formatErrorMessage(nativeErr)}`);
      logger.warn(`discord voice: opusscript init failed: ${formatErrorMessage(jsErr)}`);
    }
  }
  return null;
}

export class DiscordVoiceManager {
  private sessions = new Map<string, VoiceSessionEntry>();
  private botUserId?: string;
  private readonly voiceEnabled: boolean;
  private autoJoinTask: Promise<void> | null = null;
  /** Bridge client for secure mode — delegates voice I/O to the sidecar */
  private bridgeClient: VoiceBridgeClient | null = null;

  constructor(
    private params: {
      client: Client;
      cfg: OpenClawConfig;
      discordConfig: DiscordAccountConfig;
      accountId: string;
      runtime: RuntimeEnv;
      botUserId?: string;
    },
  ) {
    this.botUserId = params.botUserId;
    this.voiceEnabled = params.discordConfig.voice?.enabled !== false;

    // In secure mode, use the voice bridge client to delegate voice I/O
    // to the sidecar container (which has bridge network access).
    const sidecarUrl = process.env.VOICE_SIDECAR_URL;
    if (sidecarUrl) {
      logger.info(`Secure mode: voice bridge client → ${sidecarUrl}`);
      this.bridgeClient = new VoiceBridgeClient({
        baseUrl: sidecarUrl,
        onTranscript: (event) => {
          // Find or create a virtual session entry for agent processing
          const route = resolveAgentRoute({
            cfg: params.cfg,
            channel: "discord",
            accountId: params.accountId,
            guildId: event.guildId,
            peer: { kind: "channel", id: event.channelId },
          });
          const virtualEntry: VoiceSessionEntry = {
            guildId: event.guildId,
            channelId: event.channelId,
            sessionChannelId: event.channelId,
            route,
            connection: null as never, // Not used in bridge mode
            player: null as never, // Not used in bridge mode
            playbackQueue: Promise.resolve(),
            processingQueue: Promise.resolve(),
            activeSpeakers: new Set(),
            realtimeSTT: null,
            decryptFailureCount: 0,
            lastDecryptFailureAt: 0,
            decryptRecoveryInFlight: false,
            stop: () => {},
          };
          this.enqueueProcessing(virtualEntry, async () => {
            await this.processTranscript({
              entry: virtualEntry,
              transcript: event.text,
              userId: event.userId,
            });
          });
        },
        onSpeechStart: (_event) => {
          // The sidecar handles playback interruption directly
        },
        onSessionDisconnected: (event) => {
          logger.info(
            `Voice session disconnected (bridge): guild ${event.guildId} reason ${event.reason ?? "unknown"}`,
          );
          this.sessions.delete(event.guildId);
        },
      });
      this.bridgeClient.connect();

      // ── Voice state relay: forward VoicePlugin events to the sidecar ──
      // The main gateway has the sole Discord gateway connection.  We hook
      // into VoicePlugin's adapter map so that VOICE_STATE_UPDATE and
      // VOICE_SERVER_UPDATE events are forwarded to the sidecar via the
      // bridge WebSocket.  The sidecar never opens its own Discord gateway.
      this.setupVoiceRelay();
    }
  }

  /**
   * Wire the voice state relay between the main gateway's Discord connection
   * and the sidecar via the bridge WebSocket.
   *
   * - VOICE_STATE_UPDATE / VOICE_SERVER_UPDATE → sidecar (via bridge WS)
   * - send_voice_payload (opcode 4) from sidecar → Discord gateway
   */
  private setupVoiceRelay(): void {
    const gateway = this.params.client.getPlugin<GatewayPlugin>("gateway");
    if (!gateway) {
      logger.warn("Voice relay: GatewayPlugin not available");
      return;
    }

    const bridge = this.bridgeClient!;

    // Handle opcode 4 relay from sidecar → Discord gateway.
    // When the sidecar's @discordjs/voice calls sendPayload(), the sidecar
    // sends a "send_voice_payload" message via the bridge WS.  We receive
    // it here and send it through the main gateway's Discord connection.
    bridge.onSendVoicePayload = (payload) => {
      try {
        (gateway as unknown as { send(p: unknown, skipRL?: boolean): void }).send(payload, true);
      } catch (err) {
        logger.warn(`Voice relay: failed to send opcode 4: ${String(err)}`);
      }
    };

    // Register listeners that forward voice state events to the sidecar.
    // @buape/carbon's VoicePlugin already registers its own listeners for
    // local adapters; our additional listeners also relay the raw data to
    // the sidecar via the bridge WS.
    //
    // IMPORTANT: Carbon's listener `data` objects are rich objects with
    // circular references (Client, Guild, etc.).  We must extract only the
    // raw Discord fields that @discordjs/voice needs; serialising the whole
    // object would throw "Converting circular structure to JSON".
    class RelayVoiceStateUpdate extends VoiceStateUpdateListener {
      async handle(data: Record<string, unknown>): Promise<void> {
        const guildId = data.guild_id as string | undefined;
        if (guildId) {
          bridge.sendVoiceStateUpdate({
            guild_id: guildId,
            channel_id: data.channel_id ?? null,
            session_id: data.session_id,
            user_id: data.user_id,
            deaf: data.deaf,
            mute: data.mute,
            self_deaf: data.self_deaf,
            self_mute: data.self_mute,
            suppress: data.suppress,
          } as Record<string, unknown>);
        }
      }
    }

    class RelayVoiceServerUpdate extends VoiceServerUpdateListener {
      async handle(data: Record<string, unknown>): Promise<void> {
        const guildId = data.guild_id as string | undefined;
        if (guildId) {
          bridge.sendVoiceServerUpdate({
            guild_id: guildId,
            token: data.token,
            endpoint: data.endpoint,
          } as Record<string, unknown>);
        }
      }
    }

    this.params.client.registerListener(new RelayVoiceStateUpdate());
    this.params.client.registerListener(new RelayVoiceServerUpdate());

    logger.info("Voice state relay wired: main gateway ↔ sidecar");
  }

  setBotUserId(id?: string) {
    if (id) {
      this.botUserId = id;
    }
  }

  isEnabled() {
    return this.voiceEnabled;
  }

  async autoJoin(): Promise<void> {
    if (!this.voiceEnabled) {
      return;
    }
    if (this.autoJoinTask) {
      return this.autoJoinTask;
    }
    this.autoJoinTask = (async () => {
      const entries = this.params.discordConfig.voice?.autoJoin ?? [];
      logVoiceVerbose(`autoJoin: ${entries.length} entries`);
      const seenGuilds = new Set<string>();
      for (const entry of entries) {
        const guildId = entry.guildId.trim();
        if (!guildId) {
          continue;
        }
        if (seenGuilds.has(guildId)) {
          logger.warn(
            `discord voice: autoJoin has multiple entries for guild ${guildId}; skipping`,
          );
          continue;
        }
        seenGuilds.add(guildId);
        logVoiceVerbose(`autoJoin: joining guild ${guildId} channel ${entry.channelId}`);
        await this.join({
          guildId: entry.guildId,
          channelId: entry.channelId,
        });
      }
    })().finally(() => {
      this.autoJoinTask = null;
    });
    return this.autoJoinTask;
  }

  status(): VoiceOperationResult[] {
    return Array.from(this.sessions.values()).map((session) => ({
      ok: true,
      message: `connected: guild ${session.guildId} channel ${session.channelId}`,
      guildId: session.guildId,
      channelId: session.channelId,
    }));
  }

  async join(params: { guildId: string; channelId: string }): Promise<VoiceOperationResult> {
    if (!this.voiceEnabled) {
      return {
        ok: false,
        message: "Discord voice is disabled (channels.discord.voice.enabled).",
      };
    }
    const guildId = params.guildId.trim();
    const channelId = params.channelId.trim();
    if (!guildId || !channelId) {
      return { ok: false, message: "Missing guildId or channelId." };
    }
    logVoiceVerbose(`join requested: guild ${guildId} channel ${channelId}`);

    // In secure mode, delegate to the voice sidecar
    if (this.bridgeClient) {
      // Guard: skip forwarding to sidecar if already connected to the same channel.
      // Without this, autoJoin (re-fired on Discord gateway reconnect) would forward
      // a join to the sidecar while the voice connection is mid-DAVE-renegotiation
      // (signalling), causing the sidecar to force-rejoin → kill STT → loop.
      const existingBridge = this.sessions.get(guildId);
      if (existingBridge && existingBridge.channelId === channelId) {
        logVoiceVerbose(
          `join: already connected to guild ${guildId} channel ${channelId} (bridge)`,
        );
        return { ok: true, message: `Already connected to <#${channelId}>.`, guildId, channelId };
      }
      const result = await this.bridgeClient.join({
        guildId,
        channelId,
        botUserId: this.botUserId,
      });
      if (result.ok) {
        // Pre-warm Kokoro so the first TTS call doesn't hit cold-start latency.
        const kokoroDtype = this.params.discordConfig.voice?.tts?.kokoro?.dtype;
        logger.info(`kokoro pre-warm: starting (dtype=${kokoroDtype ?? "default"})`);
        warmUpKokoro(kokoroDtype ?? undefined)
          .then(() => logger.info("kokoro pre-warm: model ready"))
          .catch((err) => logger.warn(`kokoro pre-warm failed: ${err}`));

        // Track a lightweight session entry for the bridge
        const sessionChannelId = channelId;
        const route = resolveAgentRoute({
          cfg: this.params.cfg,
          channel: "discord",
          accountId: this.params.accountId,
          guildId,
          peer: { kind: "channel", id: sessionChannelId },
        });
        this.sessions.set(guildId, {
          guildId,
          channelId,
          sessionChannelId,
          route,
          connection: null as never,
          player: null as never,
          playbackQueue: Promise.resolve(),
          processingQueue: Promise.resolve(),
          activeSpeakers: new Set(),
          realtimeSTT: null,
          decryptFailureCount: 0,
          lastDecryptFailureAt: 0,
          decryptRecoveryInFlight: false,
          stop: () => {
            this.bridgeClient?.leave({ guildId }).catch(() => {});
          },
        });
      }
      return result;
    }

    const existing = this.sessions.get(guildId);
    if (existing && existing.channelId === channelId) {
      if (existing.connection.state.status === VoiceConnectionStatus.Ready) {
        logVoiceVerbose(`join: already connected to guild ${guildId} channel ${channelId}`);
        return { ok: true, message: `Already connected to <#${channelId}>.`, guildId, channelId };
      }
      // Session exists but connection is not Ready (disconnected/reconnecting) — force rejoin
      logVoiceVerbose(
        `join: session for guild ${guildId} channel ${channelId} not ready (${existing.connection.state.status}); rejoining`,
      );
      await this.leave({ guildId });
    } else if (existing) {
      logVoiceVerbose(`join: replacing existing session for guild ${guildId}`);
      await this.leave({ guildId });
    }

    const channelInfo = await this.params.client.fetchChannel(channelId).catch(() => null);
    if (!channelInfo || ("type" in channelInfo && !isVoiceChannel(channelInfo.type))) {
      return { ok: false, message: `Channel ${channelId} is not a voice channel.` };
    }
    const channelGuildId = "guildId" in channelInfo ? channelInfo.guildId : undefined;
    if (channelGuildId && channelGuildId !== guildId) {
      return { ok: false, message: "Voice channel is not in this guild." };
    }

    const voicePlugin = this.params.client.getPlugin<VoicePlugin>("voice");
    if (!voicePlugin) {
      return { ok: false, message: "Discord voice plugin is not available." };
    }

    const adapterCreator = voicePlugin.getGatewayAdapterCreator(guildId);
    const daveEncryption = this.params.discordConfig.voice?.daveEncryption;
    const decryptionFailureTolerance = this.params.discordConfig.voice?.decryptionFailureTolerance;
    const connection = joinVoiceChannel({
      channelId,
      guildId,
      adapterCreator,
      selfDeaf: false,
      selfMute: false,
      // DAVE encryption: configurable via channels.discord.voice.daveEncryption.
      // Defaults to enabled (undefined = library default). Set to false to disable.
      ...(daveEncryption === false ? { daveEncryption: false } : {}),
    });
    logVoiceVerbose(
      `join: settings encryption=${daveEncryption === false ? "off" : "on"} tolerance=${decryptionFailureTolerance ?? "default"}`,
    );

    try {
      await entersState(connection, VoiceConnectionStatus.Ready, PLAYBACK_READY_TIMEOUT_MS);
      logVoiceVerbose(`join: connected to guild ${guildId} channel ${channelId}`);
    } catch (err) {
      connection.destroy();
      return { ok: false, message: `Failed to join voice channel: ${formatErrorMessage(err)}` };
    }

    const sessionChannelId = channelInfo?.id ?? channelId;
    // Use the voice channel id as the session channel so text chat in the voice channel
    // shares the same session as spoken audio.
    if (sessionChannelId !== channelId) {
      logVoiceVerbose(
        `join: using session channel ${sessionChannelId} for voice channel ${channelId}`,
      );
    }
    const route = resolveAgentRoute({
      cfg: this.params.cfg,
      channel: "discord",
      accountId: this.params.accountId,
      guildId,
      peer: { kind: "channel", id: sessionChannelId },
    });

    const player = createAudioPlayer();
    connection.subscribe(player);

    // Pre-warm Kokoro ONNX model so first TTS call is fast.
    const voiceTtsOverride = this.params.discordConfig.voice?.tts;
    const kokoroDtype = voiceTtsOverride?.kokoro?.dtype;
    logger.info(`kokoro pre-warm: starting (dtype=${kokoroDtype ?? "default"})`);
    warmUpKokoro(kokoroDtype ?? undefined)
      .then(() => logger.info("kokoro pre-warm: model ready"))
      .catch((err) => logger.warn(`kokoro pre-warm failed: ${err}`));

    const entry: VoiceSessionEntry = {
      guildId,
      channelId,
      sessionChannelId,
      route,
      connection,
      player,
      playbackQueue: Promise.resolve(),
      processingQueue: Promise.resolve(),
      activeSpeakers: new Set(),
      realtimeSTT: null,
      decryptFailureCount: 0,
      lastDecryptFailureAt: 0,
      decryptRecoveryInFlight: false,
      stop: () => {
        entry.realtimeSTT?.destroy();
        player.stop();
        connection.destroy();
      },
    };

    // ─── Realtime STT setup ──────────────────────────────────────
    const sttConfig = resolveVoiceSttConfig(this.params.discordConfig.voice);

    // Shared callbacks — identical for both providers.
    const sttCallbacks = {
      onTranscript: (text: string) => {
        const speakerId = entry.lastSpeakerId;
        logger.info(
          `realtime transcript (${text.length} chars): guild ${guildId} channel ${channelId} user ${speakerId ?? "unknown"}`,
        );

        entry.pendingTranscripts = entry.pendingTranscripts ?? [];
        entry.pendingTranscripts.push({ text, speakerId });
        if (entry.transcriptDebounceTimer) {
          clearTimeout(entry.transcriptDebounceTimer);
        }
        entry.transcriptDebounceTimer = setTimeout(() => {
          const pending = entry.pendingTranscripts ?? [];
          entry.pendingTranscripts = [];
          entry.transcriptDebounceTimer = null;
          if (pending.length === 0) {
            return;
          }

          const mergedText = pending.map((p) => p.text).join(" ");
          const lastSpeaker = pending[pending.length - 1].speakerId;
          logger.info(
            `debounced transcript (${mergedText.length} chars, ${pending.length} segments): guild ${guildId}`,
          );
          this.enqueueProcessing(entry, async () => {
            await this.processTranscript({ entry, transcript: mergedText, userId: lastSpeaker });
          });
        }, 1000);
      },
      onSpeechStart: () => {
        if (entry.player.state.status === AudioPlayerStatus.Playing) {
          entry.player.stop(true);
        }
      },
    };

    let stt: RealtimeSTT | KrokoSTT;
    if (sttConfig.provider === "kroko") {
      stt = new KrokoSTT({
        url: sttConfig.kroko.url,
        language: sttConfig.kroko.language,
        apiKey: sttConfig.kroko.apiKey,
        ...sttCallbacks,
      });
    } else {
      const wsUrl = resolveSpeachesRealtimeUrl(this.params.cfg);
      const whisperModel = resolveWhisperModel(this.params.cfg);
      stt = new RealtimeSTT({
        url: wsUrl,
        model: whisperModel,
        language: this.params.cfg.tools?.media?.audio?.language,
        ...sttCallbacks,
      });
    }
    entry.realtimeSTT = stt;

    stt.connect().catch((err) => {
      logger.warn(
        `discord voice: STT connect failed: ${formatErrorMessage(err)}, falling back to batch mode`,
      );
    });

    // Pipe all incoming audio to the realtime STT
    const opusDecoder = createOpusDecoder();
    if (opusDecoder) {
      logger.info(`voice: opus decoder for realtime: ${opusDecoder.name}`);
    } else {
      logger.warn(`voice: no opus decoder available — audio capture disabled for guild ${guildId}`);
    }

    const speakingHandler = (userId: string) => {
      if (this.botUserId && userId === this.botUserId) {
        return;
      }
      if (entry.activeSpeakers.has(userId)) {
        return;
      }
      entry.activeSpeakers.add(userId);
      entry.lastSpeakerId = userId;

      logger.info(`capture start: guild ${guildId} channel ${channelId} user ${userId}`);

      // Subscribe to this user's audio stream
      const stream = connection.receiver.subscribe(userId, {
        end: {
          behavior: EndBehaviorType.AfterSilence,
          duration: 500,
        },
      });

      let firstChunkLogged = false;
      let sttDropWarnedAt = 0;
      stream.on("data", (chunk: Buffer) => {
        if (!chunk || chunk.length === 0) {
          return;
        }
        if (!opusDecoder) {
          // Already warned at join time; no need to repeat per-chunk
          return;
        }
        if (!stt.isConnected) {
          // Throttle to one warning per 5s so logs don't flood
          const now = Date.now();
          if (now - sttDropWarnedAt > 5_000) {
            sttDropWarnedAt = now;
            logger.warn(
              `voice: STT not connected — dropping audio for user ${userId} guild ${guildId} (Speaches unreachable?)`,
            );
          }
          return;
        }
        if (!firstChunkLogged) {
          firstChunkLogged = true;
          logger.info(
            `voice: first audio chunk received for user ${userId} guild ${guildId} (${chunk.length} bytes opus)`,
          );
        }
        try {
          const pcm48k = opusDecoder.decoder.decode(chunk);
          if (pcm48k && pcm48k.length > 0) {
            const pcm =
              sttConfig.provider === "kroko"
                ? resample48kStereoTo16kMonoFloat32(Buffer.from(pcm48k))
                : resample48kStereoTo24kMono(Buffer.from(pcm48k));
            stt.feedAudio(pcm);
          }
        } catch {
          // Decode errors on individual packets are normal (silence frames, etc.)
        }
      });

      stream.on("end", () => {
        entry.activeSpeakers.delete(userId);
        logger.info(`capture end: guild ${guildId} channel ${channelId} user ${userId}`);
        // Flush short silence so server VAD detects end-of-speech
        stt.flushSilence();
      });

      stream.on("error", (err) => {
        entry.activeSpeakers.delete(userId);
        logger.warn(`discord voice: receive error for user ${userId}: ${formatErrorMessage(err)}`);
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
        entry.realtimeSTT?.destroy();
        connection.destroy();
      }
    });
    connection.on(VoiceConnectionStatus.Destroyed, () => {
      this.sessions.delete(guildId);
      entry.realtimeSTT?.destroy();
    });

    player.on("error", (err) => {
      logger.warn(`discord voice: playback error: ${formatErrorMessage(err)}`);
    });

    // ─── DAVE decrypt failure tracking ─────────────────────────────
    if (decryptionFailureTolerance !== 0) {
      connection.on("error" as never, (err: Error) => {
        const msg = err?.message ?? String(err);
        if (!DECRYPT_FAILURE_PATTERN.test(msg)) {
          return;
        }
        const now = Date.now();
        if (now - entry.lastDecryptFailureAt > DECRYPT_FAILURE_WINDOW_MS) {
          entry.decryptFailureCount = 0;
        }
        entry.lastDecryptFailureAt = now;
        entry.decryptFailureCount += 1;
        if (entry.decryptFailureCount === 1) {
          logger.warn(
            "discord voice: DAVE decrypt failures detected; voice receive may be unstable (upstream: discordjs/discord.js#11419)",
          );
        }
        if (
          entry.decryptFailureCount >= DECRYPT_FAILURE_RECONNECT_THRESHOLD &&
          !entry.decryptRecoveryInFlight
        ) {
          void this.recoverFromDecryptFailures(entry);
        }
      });
    }

    this.sessions.set(guildId, entry);
    return {
      ok: true,
      message: `Joined <#${channelId}>.`,
      guildId,
      channelId,
    };
  }

  async leave(params: { guildId: string; channelId?: string }): Promise<VoiceOperationResult> {
    const guildId = params.guildId.trim();
    logVoiceVerbose(`leave requested: guild ${guildId} channel ${params.channelId ?? "current"}`);

    // In secure mode, delegate to the voice sidecar
    if (this.bridgeClient) {
      const result = await this.bridgeClient.leave({ guildId, channelId: params.channelId });
      this.sessions.delete(guildId);
      return result;
    }

    const entry = this.sessions.get(guildId);
    if (!entry) {
      return { ok: false, message: "Not connected to a voice channel." };
    }
    if (params.channelId && params.channelId !== entry.channelId) {
      return { ok: false, message: "Not connected to that voice channel." };
    }
    entry.stop();
    this.sessions.delete(guildId);
    logVoiceVerbose(`leave: disconnected from guild ${guildId} channel ${entry.channelId}`);
    return {
      ok: true,
      message: `Left <#${entry.channelId}>.`,
      guildId,
      channelId: entry.channelId,
    };
  }

  async destroy(): Promise<void> {
    // Destroy bridge client in secure mode
    if (this.bridgeClient) {
      this.bridgeClient.destroy();
      this.bridgeClient = null;
    }
    for (const entry of this.sessions.values()) {
      entry.stop();
    }
    this.sessions.clear();
  }

  private async recoverFromDecryptFailures(entry: VoiceSessionEntry) {
    const active = this.sessions.get(entry.guildId);
    if (!active || active.connection !== entry.connection) {
      return;
    }
    entry.decryptRecoveryInFlight = true;
    logger.warn(
      `discord voice: repeated decrypt failures; attempting rejoin for guild ${entry.guildId} channel ${entry.channelId}`,
    );
    try {
      const leaveResult = await this.leave({ guildId: entry.guildId });
      if (!leaveResult.ok) {
        logger.warn(`discord voice: rejoin leave step failed: ${leaveResult.message}`);
        return;
      }
      const joinResult = await this.join({ guildId: entry.guildId, channelId: entry.channelId });
      if (!joinResult.ok) {
        logger.warn(`discord voice: rejoin after decrypt failures failed: ${joinResult.message}`);
      } else {
        logger.info(
          `discord voice: rejoin after decrypt failures succeeded for guild ${entry.guildId}`,
        );
      }
    } catch (err) {
      logger.warn(`discord voice: rejoin recovery error: ${formatErrorMessage(err)}`);
    }
  }

  private async resolveSpeakerLabel(guildId: string, userId: string): Promise<string | undefined> {
    try {
      const member = await this.params.client.fetchMember(guildId, userId);
      return member.nickname ?? member.user?.globalName ?? member.user?.username ?? userId;
    } catch {
      try {
        const user = await this.params.client.fetchUser(userId);
        return user.globalName ?? user.username ?? userId;
      } catch {
        return userId;
      }
    }
  }

  private enqueueProcessing(entry: VoiceSessionEntry, task: () => Promise<void>) {
    entry.processingQueue = entry.processingQueue
      .then(task)
      .catch((err) => logger.warn(`discord voice: processing failed: ${formatErrorMessage(err)}`));
  }

  private enqueuePlayback(entry: VoiceSessionEntry, task: () => Promise<void>) {
    entry.playbackQueue = entry.playbackQueue
      .then(task)
      .catch((err) => logger.warn(`discord voice: playback failed: ${formatErrorMessage(err)}`));
  }

  /**
   * Process a transcript received from the realtime STT WebSocket.
   */
  private async processTranscript(params: {
    entry: VoiceSessionEntry;
    transcript: string;
    userId?: string;
  }) {
    const { entry, transcript, userId } = params;
    if (!transcript || transcript.length < 2) {
      logger.info(
        `processTranscript: dropped (too short: ${transcript?.length ?? 0} chars) guild ${entry.guildId}`,
      );
      return;
    }

    // Resolve speaker label (Discord nickname > global name > username > userId)
    let prompt = transcript;
    if (userId) {
      const speakerLabel = await this.resolveSpeakerLabel(entry.guildId, userId);
      if (speakerLabel) {
        prompt = `${speakerLabel}: ${transcript}`;
      }
    }
    logger.info(`prompt: "${prompt.slice(0, 80)}${prompt.length > 80 ? "..." : ""}"`);

    // Resolve TTS config upfront to determine streaming path.
    const { cfg: ttsCfg, resolved: ttsConfig } = resolveVoiceTtsConfig({
      cfg: this.params.cfg,
      override: this.params.discordConfig.voice?.tts,
    });
    const isKokoro = ttsConfig.provider === "kokoro";
    logger.info(`tts path: ${isKokoro ? "kokoro (streaming)" : (ttsConfig.provider ?? "default")}`);

    if (isKokoro) {
      // ─── Streaming TTS path (kokoro) ──────────────────────────────────
      // Subscribe to agent event bus BEFORE calling agentCommand so we
      // receive per-token text deltas as the LLM streams its response.
      // We accumulate text and split at sentence boundaries, generating
      // audio for each sentence and enqueuing it for playback immediately.
      const kokoroConfig = resolveKokoroConfig(this.params.cfg.messages?.tts?.kokoro);
      const runId = randomUUID();
      let sentenceBuffer = "";
      let sentenceCount = 0;

      const speakChunk = (sentence: string) => {
        sentenceCount++;
        const sentenceNum = sentenceCount;
        logger.info(
          `kokoro sentence #${sentenceNum} (${sentence.length} chars): guild ${entry.guildId}`,
        );

        // Start TTS generation immediately (parallel with prior playback).
        const audioPromise = kokoroTTSBuffer(sentence, kokoroConfig);

        if (this.bridgeClient) {
          // Bridge mode: send WAV to sidecar for playback
          const bridge = this.bridgeClient;
          const guildId = entry.guildId;
          audioPromise
            .then((wavBuf) => {
              logger.info(
                `kokoro bridge #${sentenceNum}: guild ${guildId} (${wavBuf.length} bytes)`,
              );
              return bridge.play(guildId, wavBuf, sentenceNum);
            })
            .catch((err) =>
              logger.warn(`kokoro bridge playback failed: ${formatErrorMessage(err)}`),
            );
        } else {
          // Direct mode: play locally via AudioPlayer
          this.enqueuePlayback(entry, async () => {
            const wavBuf = await audioPromise;
            const tempRoot = resolvePreferredOpenClawTmpDir();
            mkdirSync(tempRoot, { recursive: true, mode: 0o700 });
            const tempDir = mkdtempSync(path.join(tempRoot, "tts-stream-"));
            const audioPath = path.join(tempDir, `s${sentenceNum}.wav`);
            writeFileSync(audioPath, wavBuf);
            logger.info(
              `kokoro playback #${sentenceNum}: guild ${entry.guildId} file ${path.basename(audioPath)} (${wavBuf.length} bytes)`,
            );
            const resource = createAudioResource(audioPath);
            entry.player.play(resource);
            await entersState(
              entry.player,
              AudioPlayerStatus.Playing,
              PLAYBACK_READY_TIMEOUT_MS,
            ).catch(() => undefined);
            await entersState(
              entry.player,
              AudioPlayerStatus.Idle,
              SPEAKING_READY_TIMEOUT_MS,
            ).catch(() => undefined);
            // Clean up temp file.
            fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
          });
        }
      };

      const splitAndSpeak = (flush: boolean) => {
        // Split only at sentence boundaries — NOT commas. Splitting on commas
        // causes acknowledgment clauses like "Sure," to play as a separate chunk
        // that runs straight into the next sentence with no natural pause.
        const boundary = flush ? /([.!?:;])\s*/ : /([.!?:;])\s+/;

        let match: RegExpExecArray | null;
        while ((match = boundary.exec(sentenceBuffer)) !== null) {
          const sentenceEnd = match.index + match[0].length;
          const sentence = sentenceBuffer.slice(0, sentenceEnd).trim();
          sentenceBuffer = sentenceBuffer.slice(sentenceEnd);
          if (sentence.length < 2) {
            continue;
          }

          speakChunk(sentence);
        }

        // On flush, speak whatever remains even if no sentence boundary.
        if (flush && sentenceBuffer.trim().length >= 2) {
          const remaining = sentenceBuffer.trim();
          sentenceBuffer = "";
          speakChunk(remaining);
        }
      };

      // Subscribe to agent events for this run.
      const unsubscribe = onAgentEvent((evt) => {
        if (evt.runId !== runId || evt.stream !== "assistant") {
          return;
        }
        const delta = typeof evt.data.delta === "string" ? evt.data.delta : "";
        if (!delta) {
          return;
        }
        sentenceBuffer += delta;
        splitAndSpeak(false);
      });

      try {
        logger.info(
          `agent command: sending prompt to agent ${entry.route.agentId} session=${entry.route.sessionKey}`,
        );
        const result = await agentCommand(
          {
            message: prompt,
            sessionKey: entry.route.sessionKey,
            agentId: entry.route.agentId,
            messageChannel: "discord",
            deliver: false,
            runId,
            extraSystemPrompt:
              "You are in a live voice conversation. Reply with plain spoken text ONLY. " +
              "Do NOT use the tts tool — your text response will be converted to speech automatically. " +
              "Keep responses VERY short — 1 to 2 sentences max. Do NOT use markdown, asterisks, emojis, or any special characters — this is spoken audio. " +
              "Always begin your reply with a short spoken acknowledgment clause ending in a comma or period " +
              "(e.g. 'Sure,' or 'Got it.') so the listener hears something immediately. " +
              "Before any tool call, search, or long operation, say what you are about to do in natural spoken language " +
              "(e.g. 'Sure, let me look that up.' or 'Let me check your calendar.').",
            // thinking: "off" — explicitly disable reasoning tokens so they don't
            // consume the output budget (Gemini 3 Flash defaults to dynamic thinking
            // which can eat 140+ tokens, leaving almost nothing for the response).
            // maxTokens raised to 500: the system prompt enforces short responses;
            // the hard limit was causing fragments like "Got it, I" or "Sure, no".
            thinking: "off",
            streamParams: { maxTokens: 500 },
          },
          this.params.runtime,
        );
        logger.info(
          `agent result: payloads=${(result?.payloads ?? []).length} meta=${JSON.stringify(result?.meta ?? {}).slice(0, 200)}`,
        );

        // Flush any remaining buffered text after the LLM completes.
        // If the event listener didn't capture anything (non-streaming model),
        // fall back to the full reply text.
        const replyText = (result.payloads ?? [])
          .map((payload) => payload.text)
          .filter((text) => typeof text === "string" && text.trim())
          .join("\n")
          .trim();

        if (sentenceCount === 0 && replyText) {
          // Non-streaming model fallback: generate TTS for the full reply.
          sentenceBuffer = replyText;
        }
        splitAndSpeak(true);

        if (sentenceCount === 0) {
          logger.info(`reply empty: guild ${entry.guildId} channel ${entry.channelId}`);
        } else {
          logger.info(`kokoro done (${sentenceCount} sentences): guild ${entry.guildId}`);
        }
      } finally {
        unsubscribe();
      }
    } else {
      // ─── Standard TTS path (non-kokoro) ─────────────────────────────
      const result = await agentCommand(
        {
          message: prompt,
          sessionKey: entry.route.sessionKey,
          agentId: entry.route.agentId,
          messageChannel: "discord",
          deliver: false,
          extraSystemPrompt:
            "You are in a live voice conversation. Reply with plain spoken text ONLY. " +
            "Do NOT use the tts tool — your text response will be converted to speech automatically. " +
            "Keep responses VERY short — 1 to 2 sentences max. Do NOT use markdown, asterisks, emojis, or any special characters — this is spoken audio. " +
            "Always begin your reply with a short spoken acknowledgment clause ending in a comma or period " +
            "(e.g. 'Sure,' or 'Got it.') so the listener hears something immediately. " +
            "Before any tool call, search, or long operation, say what you are about to do in natural spoken language " +
            "(e.g. 'Sure, let me look that up.' or 'Let me check your calendar.').",
          streamParams: { maxTokens: 150 },
        },
        this.params.runtime,
      );

      const replyText = (result.payloads ?? [])
        .map((payload) => payload.text)
        .filter((text) => typeof text === "string" && text.trim())
        .join("\n")
        .trim();

      if (!replyText) {
        logger.info(`reply empty: guild ${entry.guildId} channel ${entry.channelId}`);
        return;
      }
      logger.info(
        `reply ok (${replyText.length} chars): guild ${entry.guildId} channel ${entry.channelId}`,
      );

      const directive = parseTtsDirectives(replyText, ttsConfig.modelOverrides);
      const speakText = directive.overrides.ttsText ?? directive.cleanedText.trim();
      if (!speakText) {
        logger.info(`tts skipped (empty): guild ${entry.guildId} channel ${entry.channelId}`);
        return;
      }

      const ttsResult = await textToSpeech({
        text: speakText,
        cfg: ttsCfg,
        channel: "discord",
        overrides: directive.overrides,
      });
      if (!ttsResult.success || !ttsResult.audioPath) {
        logger.warn(`discord voice: TTS failed: ${ttsResult.error ?? "unknown error"}`);
        return;
      }
      const audioPath = ttsResult.audioPath;
      logger.info(
        `tts ok (${speakText.length} chars): guild ${entry.guildId} channel ${entry.channelId} file ${path.basename(audioPath)}`,
      );

      if (this.bridgeClient) {
        // Bridge mode: read the audio file and send to sidecar
        const audioData = readFileSync(audioPath);
        logger.info(`tts bridge: guild ${entry.guildId} (${audioData.length} bytes)`);
        await this.bridgeClient.play(entry.guildId, audioData);
      } else {
        this.enqueuePlayback(entry, async () => {
          logger.info(
            `playback start: guild ${entry.guildId} channel ${entry.channelId} file ${path.basename(audioPath)}`,
          );
          const resource = createAudioResource(audioPath);
          entry.player.play(resource);
          await entersState(
            entry.player,
            AudioPlayerStatus.Playing,
            PLAYBACK_READY_TIMEOUT_MS,
          ).catch(() => undefined);
          await entersState(entry.player, AudioPlayerStatus.Idle, SPEAKING_READY_TIMEOUT_MS).catch(
            () => undefined,
          );
          logger.info(`playback done: guild ${entry.guildId} channel ${entry.channelId}`);
        });
      }
    }
  }
}

export class DiscordVoiceReadyListener extends ReadyListener {
  constructor(private manager: DiscordVoiceManager) {
    super();
  }

  async handle() {
    await this.manager.autoJoin();
  }
}

function isVoiceChannel(type: ChannelType) {
  return type === ChannelType.GuildVoice || type === ChannelType.GuildStageVoice;
}
