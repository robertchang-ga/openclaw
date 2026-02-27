/**
 * Voice Bridge Client — runs inside the gateway container.
 *
 * Connects to the voice sidecar's HTTP/WS API on the internal network.
 * Receives transcript events and sends TTS audio for playback.
 * Used by DiscordVoiceManager in secure mode instead of direct @discordjs/voice.
 */

import { WebSocket } from "ws";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import type {
  VoiceBridgeEvent,
  VoiceBridgeJoinRequest,
  VoiceBridgeLeaveRequest,
  VoiceBridgeOperationResult,
  VoiceBridgeStatusEntry,
} from "./voice-bridge-types.js";

const logger = createSubsystemLogger("discord/voice-bridge");

export type VoiceBridgeClientOptions = {
  /** Base URL of the voice sidecar HTTP API (e.g. http://openclaw-voice-sidecar:18791) */
  baseUrl: string;
  /** Called when a debounced transcript is received */
  onTranscript?: (event: {
    guildId: string;
    channelId: string;
    text: string;
    userId?: string;
  }) => void;
  /** Called when a user starts speaking (for playback interruption) */
  onSpeechStart?: (event: { guildId: string; channelId: string }) => void;
  /** Called when a voice session is disconnected */
  onSessionDisconnected?: (event: {
    guildId: string;
    channelId: string;
    reason?: string;
  }) => void;
};

export class VoiceBridgeClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private destroyed = false;
  private readonly baseUrl: string;
  private readonly wsUrl: string;
  private readonly options: VoiceBridgeClientOptions;
  /** Settable callback for opcode 4 relay from sidecar → main gateway. */
  onSendVoicePayload: ((payload: Record<string, unknown>) => void) | null = null;

  constructor(options: VoiceBridgeClientOptions) {
    this.options = options;
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    // Convert http:// to ws:// for WebSocket
    this.wsUrl = this.baseUrl.replace(/^http/, "ws") + "/ws";
  }

  // ─── Connection Management ─────────────────────────────────

  connect(): void {
    if (this.destroyed) return;
    this.connectWs();
  }

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
  }

  private connectWs(): void {
    if (this.destroyed) return;

    logger.info(`Connecting to voice sidecar: ${this.wsUrl}`);
    const ws = new WebSocket(this.wsUrl);

    ws.on("open", () => {
      logger.info("Connected to voice sidecar WebSocket");
      this.ws = ws;
    });

    ws.on("message", (data) => {
      try {
        const event: VoiceBridgeEvent = JSON.parse(data.toString());
        this.handleEvent(event);
      } catch (err) {
        logger.warn(`Invalid sidecar event: ${String(err)}`);
      }
    });

    ws.on("close", () => {
      logger.info("Voice sidecar WebSocket disconnected");
      if (this.ws === ws) {
        this.ws = null;
      }
      this.scheduleReconnect();
    });

    ws.on("error", (err) => {
      logger.warn(`Voice sidecar WebSocket error: ${String(err)}`);
    });
  }

  private scheduleReconnect(): void {
    if (this.destroyed || this.reconnectTimer) return;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connectWs();
    }, 3000);
  }

  private handleEvent(event: VoiceBridgeEvent): void {
    switch (event.type) {
      case "transcript":
        this.options.onTranscript?.(event);
        break;
      case "speech_start":
        this.options.onSpeechStart?.(event);
        break;
      case "session_disconnected":
        this.options.onSessionDisconnected?.(event);
        break;
      case "session_connected":
        logger.info(
          `Voice session connected: guild ${event.guildId} channel ${event.channelId}`,
        );
        break;
      case "send_voice_payload":
        this.onSendVoicePayload?.(event.payload);
        break;
      case "error":
        logger.warn(`Voice sidecar error: ${event.message}`);
        break;
      default:
        break;
    }
  }

  // ─── Voice Relay (Gateway → Sidecar) ───────────────────────

  /** Forward a VOICE_STATE_UPDATE event from the main gateway to the sidecar. */
  sendVoiceStateUpdate(data: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "voice_state_update", data }));
    }
  }

  /** Forward a VOICE_SERVER_UPDATE event from the main gateway to the sidecar. */
  sendVoiceServerUpdate(data: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "voice_server_update", data }));
    }
  }

  // ─── Voice Operations (HTTP) ───────────────────────────────

  async join(params: VoiceBridgeJoinRequest): Promise<VoiceBridgeOperationResult> {
    return this.postJson<VoiceBridgeOperationResult>("/voice/join", params);
  }

  async leave(params: VoiceBridgeLeaveRequest): Promise<VoiceBridgeOperationResult> {
    return this.postJson<VoiceBridgeOperationResult>("/voice/leave", params);
  }

  async status(): Promise<VoiceBridgeStatusEntry[]> {
    const res = await fetch(`${this.baseUrl}/voice/status`);
    return (await res.json()) as VoiceBridgeStatusEntry[];
  }

  /**
   * Send TTS audio to the sidecar for playback.
   * @param guildId Target guild
   * @param audioData WAV audio buffer
   * @param index Sentence index for ordering
   */
  async play(
    guildId: string,
    audioData: Buffer,
    index?: number,
  ): Promise<VoiceBridgeOperationResult> {
    const url = new URL(`${this.baseUrl}/voice/play`);
    url.searchParams.set("guildId", guildId);
    if (index != null) {
      url.searchParams.set("index", String(index));
    }
    const res = await fetch(url.toString(), {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: new Uint8Array(audioData),
    });
    return (await res.json()) as VoiceBridgeOperationResult;
  }

  async stopPlayback(guildId: string): Promise<VoiceBridgeOperationResult> {
    return this.postJson<VoiceBridgeOperationResult>("/voice/stop-playback", { guildId });
  }

  // ─── Helpers ───────────────────────────────────────────────

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return (await res.json()) as T;
  }
}
