/**
 * Voice Bridge Protocol Types
 *
 * Shared types for communication between the gateway container (internal-only
 * network) and the voice sidecar container (bridge + internal network).
 *
 * Transport: HTTP REST for commands (gateway → sidecar), WebSocket for events
 * (sidecar → gateway). TTS audio is sent as binary WebSocket frames.
 */

// ---------------------------------------------------------------------------
// Gateway → Sidecar (HTTP REST)
// ---------------------------------------------------------------------------

export type VoiceBridgeJoinRequest = {
  guildId: string;
  channelId: string;
};

export type VoiceBridgeLeaveRequest = {
  guildId: string;
  channelId?: string;
};

export type VoiceBridgePlayRequest = {
  guildId: string;
  /** Sentence index for logging/ordering */
  index?: number;
};
// Audio data follows as the request body (WAV binary).

export type VoiceBridgeOperationResult = {
  ok: boolean;
  message: string;
  guildId?: string;
  channelId?: string;
};

export type VoiceBridgeStatusEntry = {
  guildId: string;
  channelId: string;
  connected: boolean;
};

// ---------------------------------------------------------------------------
// Sidecar → Gateway (WebSocket events)
// ---------------------------------------------------------------------------

export type VoiceBridgeEventType =
  | "transcript"
  | "speech_start"
  | "speech_end"
  | "session_connected"
  | "session_disconnected"
  | "error";

export type VoiceBridgeTranscriptEvent = {
  type: "transcript";
  guildId: string;
  channelId: string;
  text: string;
  userId?: string;
};

export type VoiceBridgeSpeechStartEvent = {
  type: "speech_start";
  guildId: string;
  channelId: string;
};

export type VoiceBridgeSpeechEndEvent = {
  type: "speech_end";
  guildId: string;
  channelId: string;
};

export type VoiceBridgeSessionConnectedEvent = {
  type: "session_connected";
  guildId: string;
  channelId: string;
};

export type VoiceBridgeSessionDisconnectedEvent = {
  type: "session_disconnected";
  guildId: string;
  channelId: string;
  reason?: string;
};

export type VoiceBridgeErrorEvent = {
  type: "error";
  guildId?: string;
  channelId?: string;
  message: string;
};

export type VoiceBridgeEvent =
  | VoiceBridgeTranscriptEvent
  | VoiceBridgeSpeechStartEvent
  | VoiceBridgeSpeechEndEvent
  | VoiceBridgeSessionConnectedEvent
  | VoiceBridgeSessionDisconnectedEvent
  | VoiceBridgeErrorEvent;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export type VoiceBridgeConfig = {
  /** Port the sidecar's HTTP/WS server listens on (default: 18791) */
  port: number;
  /** Discord bot token (placeholder in secure mode) */
  discordToken: string;
  /** Speaches WebSocket URL for realtime STT */
  speachesUrl: string;
  /** Whisper model name */
  whisperModel: string;
  /** Language hint for STT */
  language?: string;
  /** DAVE encryption toggle */
  daveEncryption?: boolean;
  /** Decryption failure tolerance */
  decryptionFailureTolerance?: number;
};

/** Default port for the voice bridge sidecar */
export const VOICE_BRIDGE_DEFAULT_PORT = 18791;

/** Container name for the voice sidecar */
export const VOICE_SIDECAR_CONTAINER_NAME = "openclaw-voice-sidecar";
