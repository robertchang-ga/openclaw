/**
 * Tests for the bridge-mode stale session rejoin bug:
 * When session_disconnected was lost during a sidecar WS outage, the manager's
 * local sessions map retains a stale entry. A subsequent join() call must verify
 * with the sidecar (via status()) rather than blindly returning "Already connected".
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockBridgeConnect, mockBridgeJoin, mockBridgeLeave, mockBridgeStatus, mockBridgeDestroy } =
  vi.hoisted(() => {
    return {
      mockBridgeConnect: vi.fn(),
      mockBridgeJoin: vi.fn(),
      mockBridgeLeave: vi.fn(),
      mockBridgeStatus: vi.fn(),
      mockBridgeDestroy: vi.fn(),
    };
  });

vi.mock("./voice-bridge-client.js", () => ({
  // Regular function (not arrow) so it can be called with `new`
  VoiceBridgeClient: function VoiceBridgeClient(this: Record<string, unknown>, _options: unknown) {
    this.connect = mockBridgeConnect;
    this.join = mockBridgeJoin;
    this.leave = mockBridgeLeave;
    this.status = mockBridgeStatus;
    this.destroy = mockBridgeDestroy;
    this.onSendVoicePayload = null;
  },
}));

vi.mock("../../routing/resolve-route.js", () => ({
  resolveAgentRoute: vi.fn(() => ({ agentId: "agent-1", sessionKey: "discord:g1:c1" })),
}));

vi.mock("@discordjs/voice", () => ({
  AudioPlayerStatus: { Playing: "playing", Idle: "idle" },
  EndBehaviorType: { AfterSilence: "AfterSilence" },
  VoiceConnectionStatus: {
    Ready: "ready",
    Disconnected: "disconnected",
    Destroyed: "destroyed",
    Signalling: "signalling",
    Connecting: "connecting",
  },
  createAudioPlayer: vi.fn(() => ({ on: vi.fn(), off: vi.fn(), stop: vi.fn(), play: vi.fn() })),
  createAudioResource: vi.fn(),
  entersState: vi.fn(async () => undefined),
  joinVoiceChannel: vi.fn(() => ({
    destroy: vi.fn(),
    subscribe: vi.fn(),
    on: vi.fn(),
    off: vi.fn(),
    receiver: {
      speaking: { on: vi.fn(), off: vi.fn() },
      subscribe: vi.fn(() => ({ on: vi.fn(), [Symbol.asyncIterator]: async function* () {} })),
    },
    handlers: new Map(),
  })),
}));

vi.mock("../../tts/tts-kokoro.js", () => ({
  warmUpKokoro: vi.fn().mockResolvedValue(undefined),
  kokoroTTSBuffer: vi.fn(),
  resolveKokoroConfig: vi.fn(),
}));

let managerModule: typeof import("./manager.js");

function createBridgeManager() {
  return new managerModule.DiscordVoiceManager({
    client: {
      fetchChannel: vi.fn(async (channelId: string) => ({
        id: channelId,
        guildId: "g1",
        type: 2, // GuildVoice
      })),
      getPlugin: vi.fn(() => null), // no GatewayPlugin — setupVoiceRelay exits early
      fetchMember: vi.fn(),
      fetchUser: vi.fn(),
    } as never,
    cfg: {},
    discordConfig: { voice: { enabled: true } },
    accountId: "default",
    runtime: { log: vi.fn(), error: vi.fn(), exit: vi.fn() } as never,
  });
}

describe("DiscordVoiceManager bridge mode — stale session rejoin", () => {
  afterEach(() => {
    delete process.env.VOICE_SIDECAR_URL;
  });

  beforeEach(async () => {
    process.env.VOICE_SIDECAR_URL = "http://sidecar:18791";
    mockBridgeConnect.mockReset();
    mockBridgeJoin.mockReset();
    mockBridgeLeave.mockReset();
    mockBridgeStatus.mockReset();
    mockBridgeDestroy.mockReset();
    managerModule = await import("./manager.js");
  });

  it("forwards join to sidecar when local bridge session is stale (sidecar reports no active session)", async () => {
    mockBridgeStatus.mockResolvedValue([]);
    mockBridgeJoin.mockResolvedValue({
      ok: true,
      message: "Joined <#c1>.",
      guildId: "g1",
      channelId: "c1",
    });

    const manager = createBridgeManager();
    // Inject a stale local session entry (as if session_disconnected was lost during WS outage)
    const sessions = (manager as unknown as { sessions: Map<string, unknown> }).sessions;
    sessions.set("g1", { guildId: "g1", channelId: "c1", connection: null });

    const result = await manager.join({ guildId: "g1", channelId: "c1" });

    expect(mockBridgeJoin).toHaveBeenCalledWith(
      expect.objectContaining({ guildId: "g1", channelId: "c1" }),
    );
    expect(result.ok).toBe(true);
  });

  it("skips sidecar join and returns already-connected when sidecar confirms active session", async () => {
    mockBridgeStatus.mockResolvedValue([{ guildId: "g1", channelId: "c1", connected: true }]);

    const manager = createBridgeManager();
    const sessions = (manager as unknown as { sessions: Map<string, unknown> }).sessions;
    sessions.set("g1", { guildId: "g1", channelId: "c1", connection: null });

    const result = await manager.join({ guildId: "g1", channelId: "c1" });

    expect(mockBridgeJoin).not.toHaveBeenCalled();
    expect(result.ok).toBe(true);
    expect(result.message).toContain("Already connected");
  });
});
