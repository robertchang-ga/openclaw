/**
 * Kroko STT Provider
 *
 * Local streaming speech-to-text via the Kroko on-premise WebSocket server.
 * https://kroko.ai / https://docs.kroko.ai/on-premise/
 *
 * Protocol:
 *   Connect: ws://<host>:<port>/?language=<lang>&apiKey=<key>
 *   Send:    binary frames of PCM float32 at 16kHz mono (max 4s per frame)
 *   Receive: JSON — { type: "partial"|"final", text: string, ... }
 *
 * Only type==="final" messages are forwarded as transcripts.
 */
import { createSubsystemLogger } from "../../logging/subsystem.js";

const logger = createSubsystemLogger("discord/voice");

// 16kHz mono float32: 16000 samples/sec × 4 bytes/sample = 64000 bytes/sec
const SILENCE_DURATION_MS = 300;
const FLUSH_BYTES = Math.ceil((16000 * 4 * SILENCE_DURATION_MS) / 1000); // 19200 bytes

// ─── Audio helper ─────────────────────────────────────────────────────────────

/**
 * Resample 48kHz stereo S16LE PCM → 16kHz mono PCM float32.
 * Simple 3:1 decimation: average L+R channels, take every 3rd stereo frame,
 * normalize int16 → float32 in [-1.0, 1.0].
 * Kroko on-premise server expects 16kHz float32 mono input.
 */
export function resample48kStereoTo16kMonoFloat32(input: Buffer): Buffer {
  const stereoFrames = Math.floor(input.length / 4); // 4 bytes per stereo frame (2ch × 2bytes)
  const outFrames = Math.floor(stereoFrames / 3); // 3:1 decimation: 48k → 16k
  const output = Buffer.alloc(outFrames * 4); // float32 = 4 bytes per sample

  for (let i = 0; i < outFrames; i++) {
    const srcOffset = i * 3 * 4; // every 3rd stereo frame
    const left = input.readInt16LE(srcOffset);
    const right = input.readInt16LE(srcOffset + 2);
    const mono = (left + right) / 2;
    output.writeFloatLE(mono / 32768.0, i * 4); // normalize to [-1.0, 1.0]
  }

  return output;
}

// ─── Types ───────────────────────────────────────────────────────────────────

export type KrokoSTTConfig = {
  url: string; // e.g. "ws://localhost:8080"
  language?: string;
  apiKey?: string;
  onTranscript: (text: string) => void;
  onSpeechStart?: () => void;
  onSpeechEnd?: () => void;
};

type KrokoMessage = {
  type: "partial" | "final";
  text: string;
  segment?: number;
  startedAt?: number;
};

// ─── KrokoSTT ────────────────────────────────────────────────────────────────

export class KrokoSTT {
  private ws: WebSocket | null = null;
  private config: KrokoSTTConfig;
  private connected = false;
  private destroyed = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config: KrokoSTTConfig) {
    this.config = config;
  }

  /**
   * Open the WebSocket connection to the Kroko server.
   */
  async connect(): Promise<void> {
    if (this.destroyed) {
      return;
    }

    const params = new URLSearchParams();
    if (this.config.language) {
      params.set("language", this.config.language);
    }
    if (this.config.apiKey) {
      params.set("apiKey", this.config.apiKey);
    }
    const query = params.toString();
    const wsUrl = query ? `${this.config.url}/?${query}` : `${this.config.url}/`;
    logger.info(`kroko-stt: connecting to ${wsUrl}`);

    return new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      this.ws = ws;

      const connectTimeout = setTimeout(() => {
        if (!this.connected) {
          ws.close();
          reject(new Error("kroko-stt: connection timeout"));
        }
      }, 10_000);

      ws.addEventListener("open", () => {
        logger.info("kroko-stt: connected");
        this.connected = true;
        clearTimeout(connectTimeout);
        resolve();
      });

      ws.addEventListener("message", (evt: MessageEvent) => {
        try {
          const data = typeof evt.data === "string" ? evt.data : String(evt.data);
          const msg = JSON.parse(data) as KrokoMessage;
          this.handleMessage(msg);
        } catch (err) {
          logger.warn(`kroko-stt: failed to parse message: ${String(err)}`);
        }
      });

      ws.addEventListener("close", (evt: CloseEvent) => {
        this.connected = false;
        logger.info(`kroko-stt: disconnected (code=${evt.code})`);
        if (!this.destroyed) {
          this.scheduleReconnect();
        }
      });

      ws.addEventListener("error", () => {
        logger.warn("kroko-stt: websocket error");
        if (!this.connected) {
          clearTimeout(connectTimeout);
          reject(new Error("kroko-stt: websocket connection error"));
        }
      });
    });
  }

  /**
   * Feed raw PCM audio (float32 16kHz mono) to Kroko as a binary WebSocket frame.
   * Call resample48kStereoTo16kMonoFloat32() on Discord audio before this.
   */
  feedAudio(pcmFloat32: Buffer): void {
    if (!this.ws || !this.connected) {
      return;
    }
    // Buffer extends Uint8Array; cast needed because TS types Buffer as ArrayBufferLike not ArrayBuffer
    this.ws.send(pcmFloat32 as unknown as Uint8Array<ArrayBuffer>);
  }

  /**
   * Send 300ms of float32 silence to trigger server-side VAD end-of-speech detection.
   */
  flushSilence(): void {
    if (!this.ws || !this.connected) {
      return;
    }
    const silence = Buffer.alloc(FLUSH_BYTES); // all-zero float32 = silence
    this.ws.send(silence as unknown as Uint8Array<ArrayBuffer>);
    logger.info(`kroko-stt: flushed ${SILENCE_DURATION_MS}ms silence (${FLUSH_BYTES} bytes)`);
  }

  /**
   * Close the WebSocket. Safe to call multiple times.
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

  // ─── Private ─────────────────────────────────────────────────────────────

  private handleMessage(msg: KrokoMessage): void {
    if (msg.type === "partial") {
      logger.info(`kroko-stt: partial: "${(msg.text ?? "").slice(0, 40)}"`);
      return;
    }
    if (msg.type === "final") {
      const text = (msg.text ?? "").trim();
      if (text.length > 0) {
        logger.info(`kroko-stt: transcript (${text.length} chars): "${text.slice(0, 80)}"`);
        this.config.onTranscript(text);
      } else {
        logger.info("kroko-stt: empty transcript, skipping");
      }
      return;
    }
    logger.info(`kroko-stt: unhandled message type: ${String(msg.type)}`);
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer || this.destroyed) {
      return;
    }
    logger.info("kroko-stt: reconnecting in 3s...");
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect().catch((err) => {
        logger.warn(`kroko-stt: reconnect failed: ${String(err)}`);
        this.scheduleReconnect();
      });
    }, 3_000);
  }
}
