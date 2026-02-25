/**
 * Realtime STT via Speaches WebSocket
 *
 * Opens a persistent WebSocket to Speaches /v1/realtime in transcription-only
 * mode. Audio is streamed as PCM chunks; Speaches handles VAD and returns
 * transcriptions when speech ends.
 *
 * Protocol: OpenAI Realtime API compatible.
 * Uses Node.js native WebSocket (available since Node 22).
 */

import { createSubsystemLogger } from "../../logging/subsystem.js";

const logger = createSubsystemLogger("discord/voice");

// ---------------------------------------------------------------------------
// Audio helpers
// ---------------------------------------------------------------------------

/**
 * Resample 48kHz stereo S16LE PCM → 16kHz mono S16LE PCM.
 * Simple decimation: average L+R channels, take every 3rd sample.
 */
export function resample48kStereoTo16kMono(input: Buffer): Buffer {
  const samples = input.length / 2; // 16-bit = 2 bytes per sample
  const stereoSamples = samples / 2; // 2 channels per frame
  // Output: one channel, every 3rd frame → stereoSamples / 3
  const outFrames = Math.floor(stereoSamples / 3);
  const output = Buffer.alloc(outFrames * 2); // 16-bit mono

  for (let i = 0; i < outFrames; i++) {
    const srcFrame = i * 3; // source frame index (in stereo frames)
    const srcOffset = srcFrame * 4; // 4 bytes per stereo frame (2ch × 2bytes)

    const left = input.readInt16LE(srcOffset);
    const right = input.readInt16LE(srcOffset + 2);
    const mono = Math.round((left + right) / 2);

    output.writeInt16LE(Math.max(-32768, Math.min(32767, mono)), i * 2);
  }

  return output;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RealtimeSTTConfig = {
  /** WebSocket URL, e.g. ws://speaches:8000/v1/realtime */
  url: string;
  /** Whisper model ID */
  model: string;
  /** Language hint (optional) */
  language?: string;
  /** Callback when a transcription is completed */
  onTranscript: (text: string) => void;
  /** Callback when speech starts (for interruption detection) */
  onSpeechStart?: () => void;
  /** Callback when speech ends */
  onSpeechEnd?: () => void;
};

type RealtimeEvent = {
  type: string;
  [key: string]: unknown;
};

// ---------------------------------------------------------------------------
// RealtimeSTT
// ---------------------------------------------------------------------------

export class RealtimeSTT {
  private ws: WebSocket | null = null;
  private config: RealtimeSTTConfig;
  private connected = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private destroyed = false;

  constructor(config: RealtimeSTTConfig) {
    this.config = config;
  }

  /**
   * Open the WebSocket connection and configure the session.
   */
  async connect(): Promise<void> {
    if (this.destroyed) return;

    const wsUrl = `${this.config.url}?model=${encodeURIComponent(this.config.model)}`;
    logger.info(`realtime-stt: connecting to ${wsUrl}`);

    return new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      this.ws = ws;

      const connectTimeout = setTimeout(() => {
        if (!this.connected) {
          ws.close();
          reject(new Error("realtime-stt: connection timeout"));
        }
      }, 10_000);

      ws.addEventListener("open", () => {
        logger.info("realtime-stt: websocket connected");
        this.connected = true;
        clearTimeout(connectTimeout);

        // Configure session for transcription-only mode with server-side VAD.
        // type: "transcription" prevents Speaches from trying to generate
        // an LLM response after transcription (which causes "Not Found" errors).
        this.sendEvent({
          type: "session.update",
          session: {
            type: "transcription",
            input_audio_transcription: {
              model: this.config.model,
              language: this.config.language,
            },
            turn_detection: {
              type: "server_vad",
              threshold: 0.5,
              prefix_padding_ms: 300,
              silence_duration_ms: 500,
            },
          },
        });

        resolve();
      });

      ws.addEventListener("message", (evt: MessageEvent) => {
        try {
          const data = typeof evt.data === "string" ? evt.data : String(evt.data);
          const event = JSON.parse(data) as RealtimeEvent;
          this.handleEvent(event);
        } catch (err) {
          logger.warn(`realtime-stt: failed to parse message: ${String(err)}`);
        }
      });

      ws.addEventListener("close", (evt: CloseEvent) => {
        this.connected = false;
        logger.info(`realtime-stt: disconnected (code=${evt.code}, reason=${evt.reason})`);
        if (!this.destroyed) {
          this.scheduleReconnect();
        }
      });

      ws.addEventListener("error", () => {
        logger.warn("realtime-stt: websocket error");
        if (!this.connected) {
          clearTimeout(connectTimeout);
          reject(new Error("realtime-stt: websocket connection error"));
        }
      });
    });
  }

  /**
   * Feed raw PCM audio (16kHz mono S16LE) to Speaches.
   * Call resample48kStereoTo16kMono() before this if coming from Discord.
   */
  feedAudio(pcm16kMono: Buffer): void {
    if (!this.ws || !this.connected) return;

    this.sendEvent({
      type: "input_audio_buffer.append",
      audio: pcm16kMono.toString("base64"),
    });
  }

  /**
   * Disconnect and clean up.
   */
  destroy(): void {
    this.destroyed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connected = false;
  }

  get isConnected(): boolean {
    return this.connected;
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  private sendEvent(event: RealtimeEvent): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    this.ws.send(JSON.stringify(event));
  }

  private handleEvent(event: RealtimeEvent): void {
    switch (event.type) {
      case "session.created":
        logger.info("realtime-stt: session created");
        break;

      case "session.updated":
        logger.info("realtime-stt: session configured");
        break;

      case "input_audio_buffer.speech_started":
        logger.info("realtime-stt: speech started");
        this.config.onSpeechStart?.();
        break;

      case "input_audio_buffer.speech_stopped":
        logger.info("realtime-stt: speech stopped");
        this.config.onSpeechEnd?.();
        break;

      case "conversation.item.input_audio_transcription.completed": {
        const transcript = (event as { transcript?: string }).transcript?.trim();
        if (transcript && transcript.length > 0) {
          logger.info(`realtime-stt: transcript (${transcript.length} chars): "${transcript.slice(0, 80)}"`);
          this.config.onTranscript(transcript);
        } else {
          logger.info("realtime-stt: empty transcript, skipping");
        }
        break;
      }

      case "conversation.item.input_audio_transcription.delta": {
        // Partial transcription — log at verbose level
        const delta = (event as { delta?: string }).delta;
        if (delta) {
          logger.info(`realtime-stt: partial: "${delta.slice(0, 40)}"`);
        }
        break;
      }

      case "conversation.item.input_audio_transcription.failed": {
        const error = (event as { error?: { message?: string } }).error;
        logger.warn(`realtime-stt: transcription failed: ${error?.message ?? "unknown"}`);
        break;
      }

      case "error": {
        const error = (event as { error?: { message?: string } }).error;
        logger.warn(`realtime-stt: server error: ${error?.message ?? JSON.stringify(event)}`);
        break;
      }

      default:
        if (event.type && !event.type.startsWith("response.")) {
          logger.info(`realtime-stt: unhandled event: ${event.type}`);
        }
        break;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer || this.destroyed) return;
    logger.info("realtime-stt: reconnecting in 3s...");
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect().catch((err) => {
        logger.warn(`realtime-stt: reconnect failed: ${String(err)}`);
        this.scheduleReconnect();
      });
    }, 3_000);
  }
}
