import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import type { Readable } from "node:stream";
import { RealtimeSTT, resample48kStereoTo24kMono } from "./realtime-stt.js";
import { ChannelType, type Client, ReadyListener } from "@buape/carbon";
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
import { resolveAgentDir } from "../../agents/agent-scope.js";
import type { MsgContext } from "../../auto-reply/templating.js";
import { agentCommand } from "../../commands/agent.js";
import type { OpenClawConfig } from "../../config/config.js";
import type { DiscordAccountConfig, TtsConfig } from "../../config/types.js";
import { logVerbose, shouldLogVerbose } from "../../globals.js";
import { onAgentEvent } from "../../infra/agent-events.js";
import { formatErrorMessage } from "../../infra/errors.js";
import { resolvePreferredOpenClawTmpDir } from "../../infra/tmp-openclaw-dir.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import {
  buildProviderRegistry,
  createMediaAttachmentCache,
  normalizeMediaAttachments,
  runCapability,
} from "../../media-understanding/runner.js";
import { resolveAgentRoute } from "../../routing/resolve-route.js";
import type { RuntimeEnv } from "../../runtime.js";
import { parseTtsDirectives } from "../../tts/tts-core.js";
import { kokoroTTSBuffer, resolveKokoroConfig } from "../../tts/tts-kokoro.js";
import { resolveTtsConfig, textToSpeech, type ResolvedTtsConfig } from "../../tts/tts.js";

const require = createRequire(import.meta.url);

const SAMPLE_RATE = 48_000;
const CHANNELS = 2;
const BIT_DEPTH = 16;
const MIN_SEGMENT_SECONDS = 0.35;
const PLAYBACK_READY_TIMEOUT_MS = 15_000;
const SPEAKING_READY_TIMEOUT_MS = 60_000;

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
    } catch { /* fall through */ }
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
    if (typeof first === "object" && first.model) return first.model;
    if (typeof first === "string") return first;
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
  realtimeSTT: RealtimeSTT | null;
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

function buildWavBuffer(pcm: Buffer): Buffer {
  const blockAlign = (CHANNELS * BIT_DEPTH) / 8;
  const byteRate = SAMPLE_RATE * blockAlign;
  const header = Buffer.alloc(44);
  header.write("RIFF", 0);
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write("WAVE", 8);
  header.write("fmt ", 12);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(CHANNELS, 22);
  header.writeUInt32LE(SAMPLE_RATE, 24);
  header.writeUInt32LE(byteRate, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(BIT_DEPTH, 34);
  header.write("data", 36);
  header.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([header, pcm]);
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

async function decodeOpusStream(stream: Readable): Promise<Buffer> {
  const selected = createOpusDecoder();
  if (!selected) {
    logger.info("opus decode: no decoder available");
    return Buffer.alloc(0);
  }
  logger.info(`opus decode: using ${selected.name}`);
  const chunks: Buffer[] = [];
  try {
    for await (const chunk of stream) {
      if (!chunk || !(chunk instanceof Buffer) || chunk.length === 0) {
        continue;
      }
      const decoded = selected.decoder.decode(chunk);
      if (decoded && decoded.length > 0) {
        chunks.push(Buffer.from(decoded));
      }
    }
  } catch (err) {
    logger.info(`opus decode: error: ${formatErrorMessage(err)}`);
  }
  const result = chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
  logger.info(`opus decode: ${chunks.length} chunks, ${result.length} bytes PCM`);
  return result;
}

function estimateDurationSeconds(pcm: Buffer): number {
  const bytesPerSample = (BIT_DEPTH / 8) * CHANNELS;
  if (bytesPerSample <= 0) {
    return 0;
  }
  return pcm.length / (bytesPerSample * SAMPLE_RATE);
}

async function writeWavFile(pcm: Buffer): Promise<{ path: string; durationSeconds: number }> {
  const tempDir = await fs.mkdtemp(path.join(resolvePreferredOpenClawTmpDir(), "discord-voice-"));
  const filePath = path.join(tempDir, `segment-${randomUUID()}.wav`);
  const wav = buildWavBuffer(pcm);
  await fs.writeFile(filePath, wav);
  scheduleTempCleanup(tempDir);
  const durationSeconds = estimateDurationSeconds(pcm);
  logger.info(`wav write: ${filePath} (${wav.length} bytes, ${durationSeconds.toFixed(2)}s)`);
  return { path: filePath, durationSeconds };
}

function scheduleTempCleanup(tempDir: string, delayMs: number = 30 * 60 * 1000): void {
  const timer = setTimeout(() => {
    fs.rm(tempDir, { recursive: true, force: true }).catch((err) => {
      if (shouldLogVerbose()) {
        logVerbose(`discord voice: temp cleanup failed for ${tempDir}: ${formatErrorMessage(err)}`);
      }
    });
  }, delayMs);
  timer.unref();
}

async function transcribeAudio(params: {
  cfg: OpenClawConfig;
  agentId: string;
  filePath: string;
}): Promise<string | undefined> {
  const ctx: MsgContext = {
    MediaPath: params.filePath,
    MediaType: "audio/wav",
  };
  const attachments = normalizeMediaAttachments(ctx);
  if (attachments.length === 0) {
    logger.info(`transcribe: no attachments for ${params.filePath}`);
    return undefined;
  }
  const audioConfig = params.cfg.tools?.media?.audio;
  logger.info(
    `transcribe: ${attachments.length} attachment(s), audio enabled=${audioConfig?.enabled}, models=${JSON.stringify(audioConfig?.models?.length ?? 0)}`,
  );
  const cache = createMediaAttachmentCache(attachments);
  const providerRegistry = buildProviderRegistry();
  try {
    const result = await runCapability({
      capability: "audio",
      cfg: params.cfg,
      ctx,
      attachments: cache,
      media: attachments,
      agentDir: resolveAgentDir(params.cfg, params.agentId),
      providerRegistry,
      config: audioConfig,
    });
    const attempts = result.decision.attachments?.flatMap((a) =>
      a.attempts.map((t) => `${t.provider ?? t.type ?? "?"}:${t.outcome}${t.reason ? `(${t.reason})` : ""}`),
    );
    logger.info(
      `transcribe: decision=${result.decision.outcome}, outputs=${result.outputs.length}, attempts=[${attempts?.join(", ") ?? "none"}]`,
    );
    const output = result.outputs.find((entry) => entry.kind === "audio.transcription");
    const text = output?.text?.trim();
    return text || undefined;
  } finally {
    await cache.cleanup();
  }
}

export class DiscordVoiceManager {
  private sessions = new Map<string, VoiceSessionEntry>();
  private botUserId?: string;
  private readonly voiceEnabled: boolean;
  private autoJoinTask: Promise<void> | null = null;

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

    const existing = this.sessions.get(guildId);
    if (existing && existing.channelId === channelId) {
      logVoiceVerbose(`join: already connected to guild ${guildId} channel ${channelId}`);
      return { ok: true, message: `Already connected to <#${channelId}>.`, guildId, channelId };
    }
    if (existing) {
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
    const connection = joinVoiceChannel({
      channelId,
      guildId,
      adapterCreator,
      selfDeaf: false,
      selfMute: false,
      // @discordjs/voice 0.19.x DAVE receive decryption is broken (GitHub #11419).
      // All packets fail with DecryptionFailed(UnencryptedWhenPassthroughDisabled).
      // Falls back to standard XSalsa20 transport encryption (still encrypted).
      // TODO: re-enable when @discordjs/voice ships a fix (DAVE enforced March 2 2026).
      daveEncryption: false,
    });

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
      stop: () => {
        entry.realtimeSTT?.destroy();
        player.stop();
        connection.destroy();
      },
    };

    // ─── Realtime STT setup ──────────────────────────────────────
    const wsUrl = resolveSpeachesRealtimeUrl(this.params.cfg);
    const whisperModel = resolveWhisperModel(this.params.cfg);
    const stt = new RealtimeSTT({
      url: wsUrl,
      model: whisperModel,
      language: this.params.cfg.tools?.media?.audio?.language,
      onTranscript: (text: string) => {
        logger.info(
          `realtime transcript (${text.length} chars): guild ${guildId} channel ${channelId}`,
        );
        this.enqueueProcessing(entry, async () => {
          await this.processTranscript({ entry, transcript: text });
        });
      },
      onSpeechStart: () => {
        // Interrupt current playback when user starts speaking
        if (entry.player.state.status === AudioPlayerStatus.Playing) {
          entry.player.stop(true);
        }
      },
    });
    entry.realtimeSTT = stt;

    // Connect the realtime STT WebSocket
    stt.connect().catch((err) => {
      logger.warn(`discord voice: realtime STT connect failed: ${formatErrorMessage(err)}, falling back to batch mode`);
    });

    // Pipe all incoming audio to the realtime STT
    const opusDecoder = createOpusDecoder();
    if (opusDecoder) {
      logger.info(`voice: opus decoder for realtime: ${opusDecoder.name}`);
    }

    const speakingHandler = (userId: string) => {
      if (this.botUserId && userId === this.botUserId) return;
      if (entry.activeSpeakers.has(userId)) return;
      entry.activeSpeakers.add(userId);

      logger.info(`capture start: guild ${guildId} channel ${channelId} user ${userId}`);

      // Subscribe to this user's audio stream
      const stream = connection.receiver.subscribe(userId, {
        end: {
          behavior: EndBehaviorType.AfterSilence,
          duration: 2_000, // Keep stream alive longer; VAD handles segmentation
        },
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
    for (const entry of this.sessions.values()) {
      entry.stop();
    }
    this.sessions.clear();
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
  }) {
    const { entry, transcript } = params;
    if (!transcript || transcript.length < 2) return;

    const prompt = transcript;
    logger.info(
      `prompt: "${prompt.slice(0, 80)}${prompt.length > 80 ? "..." : ""}"`,
    );

    // Resolve TTS config upfront to determine streaming path.
    const { cfg: ttsCfg, resolved: ttsConfig } = resolveVoiceTtsConfig({
      cfg: this.params.cfg,
      override: this.params.discordConfig.voice?.tts,
    });
    const isKokoro = ttsConfig.provider === "kokoro";
    logger.info(`tts path: ${isKokoro ? "kokoro (streaming)" : ttsConfig.provider ?? "default"}`);

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

      const splitAndSpeak = (flush: boolean) => {
        // Sentence boundary: period, exclamation, question mark, or colon
        // followed by whitespace (or end of string if flushing).
        const boundary = flush ? /([.!?:;])\s*/ : /([.!?:;])\s+/;

        let match: RegExpExecArray | null;
        while ((match = boundary.exec(sentenceBuffer)) !== null) {
          const sentenceEnd = match.index + match[0].length;
          const sentence = sentenceBuffer.slice(0, sentenceEnd).trim();
          sentenceBuffer = sentenceBuffer.slice(sentenceEnd);
          if (sentence.length < 2) {
            continue;
          }

          sentenceCount++;
          const sentenceNum = sentenceCount;
          logger.info(
            `kokoro sentence #${sentenceNum} (${sentence.length} chars): guild ${entry.guildId}`,
          );

          // Enqueue TTS generation + playback for this sentence.
          this.enqueuePlayback(entry, async () => {
            const wavBuf = await kokoroTTSBuffer(sentence, kokoroConfig);
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

        // On flush, speak whatever remains even if no sentence boundary.
        if (flush && sentenceBuffer.trim().length >= 2) {
          const remaining = sentenceBuffer.trim();
          sentenceBuffer = "";
          sentenceCount++;
          const sentenceNum = sentenceCount;
          logger.info(
            `kokoro flush #${sentenceNum} (${remaining.length} chars): guild ${entry.guildId}`,
          );
          this.enqueuePlayback(entry, async () => {
            const wavBuf = await kokoroTTSBuffer(remaining, kokoroConfig);
            const tempRoot = resolvePreferredOpenClawTmpDir();
            mkdirSync(tempRoot, { recursive: true, mode: 0o700 });
            const tempDir = mkdtempSync(path.join(tempRoot, "tts-stream-"));
            const audioPath = path.join(tempDir, `s${sentenceNum}.wav`);
            writeFileSync(audioPath, wavBuf);
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
            fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
          });
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
        logger.info(`agent command: sending prompt to agent ${entry.route.agentId}`);
        const result = await agentCommand(
          {
            message: prompt,
            sessionKey: entry.route.sessionKey,
            agentId: entry.route.agentId,
            messageChannel: "discord",
            deliver: false,
            runId,
          },
          this.params.runtime,
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
          logger.info(
            `reply empty: guild ${entry.guildId} channel ${entry.channelId}`,
          );
        } else {
          logger.info(
            `kokoro done (${sentenceCount} sentences): guild ${entry.guildId}`,
          );
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
        },
        this.params.runtime,
      );

      const replyText = (result.payloads ?? [])
        .map((payload) => payload.text)
        .filter((text) => typeof text === "string" && text.trim())
        .join("\n")
        .trim();

      if (!replyText) {
        logger.info(
          `reply empty: guild ${entry.guildId} channel ${entry.channelId}`,
        );
        return;
      }
      logger.info(
        `reply ok (${replyText.length} chars): guild ${entry.guildId} channel ${entry.channelId}`,
      );

      const directive = parseTtsDirectives(replyText, ttsConfig.modelOverrides);
      const speakText = directive.overrides.ttsText ?? directive.cleanedText.trim();
      if (!speakText) {
        logger.info(
          `tts skipped (empty): guild ${entry.guildId} channel ${entry.channelId}`,
        );
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

      this.enqueuePlayback(entry, async () => {
        logger.info(
          `playback start: guild ${entry.guildId} channel ${entry.channelId} file ${path.basename(audioPath)}`,
        );
        const resource = createAudioResource(audioPath);
        entry.player.play(resource);
        await entersState(entry.player, AudioPlayerStatus.Playing, PLAYBACK_READY_TIMEOUT_MS).catch(
          () => undefined,
        );
        await entersState(entry.player, AudioPlayerStatus.Idle, SPEAKING_READY_TIMEOUT_MS).catch(
          () => undefined,
        );
        logger.info(`playback done: guild ${entry.guildId} channel ${entry.channelId}`);
      });
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
