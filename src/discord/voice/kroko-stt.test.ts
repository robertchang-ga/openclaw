import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KrokoSTT, resample48kStereoTo16kMonoFloat32 } from "./kroko-stt.js";

// Shared mock objects — re-stubbed in beforeEach because vitest config has unstubGlobals: true.
const mockWs = {
  send: vi.fn(),
  close: vi.fn(),
  addEventListener: vi.fn(),
};
// Must use a regular function (not arrow) so it can be called with `new`.
const MockWebSocket = vi.fn(function () {
  return mockWs;
});

// Helper: retrieve a specific event handler registered on mockWs.
function getHandler(name: string): ((...args: unknown[]) => void) | undefined {
  const calls = (mockWs.addEventListener as ReturnType<typeof vi.fn>).mock.calls as [
    string,
    (...args: unknown[]) => void,
  ][];
  return calls.find(([event]) => event === name)?.[1];
}

// Helper: simulate a JSON message from the server.
function sendMessage(data: unknown): void {
  const handler = getHandler("message") as ((evt: { data: string }) => void) | undefined;
  handler?.({ data: JSON.stringify(data) });
}

describe("resample48kStereoTo16kMonoFloat32", () => {
  it("produces correct float32 value for known int16 stereo input", () => {
    // 3 stereo frames (12 bytes) → 1 output float32 (4 bytes)
    const input = Buffer.alloc(12);
    input.writeInt16LE(16384, 0); // L frame 0
    input.writeInt16LE(16384, 2); // R frame 0 → mono = 16384 → float = 0.5
    // frames 1 and 2 are all zeros (discarded by decimation anyway)
    const output = resample48kStereoTo16kMonoFloat32(input);
    expect(output.length).toBe(4);
    expect(output.readFloatLE(0)).toBeCloseTo(0.5, 2);
  });

  it("returns empty buffer for empty input", () => {
    expect(resample48kStereoTo16kMonoFloat32(Buffer.alloc(0)).length).toBe(0);
  });

  it("output length is floor(stereoFrames / 3) × 4 bytes", () => {
    // 9 stereo frames × 4 bytes = 36 bytes input → 3 output samples × 4 bytes = 12 bytes
    const output = resample48kStereoTo16kMonoFloat32(Buffer.alloc(36));
    expect(output.length).toBe(12);
  });
});

describe("KrokoSTT", () => {
  let stt: KrokoSTT;
  const onTranscript = vi.fn();
  const onSpeechStart = vi.fn();

  beforeEach(() => {
    // Re-stub WebSocket each test because unstubGlobals:true in vitest.config.ts resets it.
    vi.stubGlobal("WebSocket", MockWebSocket);
    vi.clearAllMocks();
    mockWs.addEventListener.mockClear();
    mockWs.send.mockClear();
    mockWs.close.mockClear();
    (MockWebSocket as ReturnType<typeof vi.fn>).mockClear();
    stt = new KrokoSTT({
      url: "ws://localhost:8080",
      language: "en",
      onTranscript,
      onSpeechStart,
    });
  });

  afterEach(() => {
    stt.destroy();
  });

  // Helper to connect stt and fire the open event.
  async function connectStt(): Promise<void> {
    const p = stt.connect();
    getHandler("open")?.({});
    await p;
  }

  describe("connect()", () => {
    it("connects with language query param in URL", async () => {
      await connectStt();
      expect(MockWebSocket).toHaveBeenCalledWith("ws://localhost:8080/?language=en");
    });

    it("includes apiKey in URL when provided", async () => {
      stt = new KrokoSTT({ url: "ws://localhost:8080", apiKey: "secret", onTranscript });
      const p = stt.connect();
      getHandler("open")?.({});
      await p;
      expect(MockWebSocket).toHaveBeenCalledWith(expect.stringContaining("apiKey=secret"));
    });

    it("connects with no query params when language and apiKey are omitted", async () => {
      stt = new KrokoSTT({ url: "ws://localhost:8080", onTranscript });
      const p = stt.connect();
      getHandler("open")?.({});
      await p;
      expect(MockWebSocket).toHaveBeenCalledWith("ws://localhost:8080/");
    });

    it("rejects on WebSocket error before open", async () => {
      const p = stt.connect();
      getHandler("error")?.({});
      await expect(p).rejects.toThrow("kroko-stt: websocket connection error");
    });

    it("sets isConnected to true after open", async () => {
      await connectStt();
      expect(stt.isConnected).toBe(true);
    });
  });

  describe("feedAudio()", () => {
    it("sends buffer as binary WebSocket frame", async () => {
      await connectStt();
      const buf = Buffer.alloc(64, 0x42);
      stt.feedAudio(buf);
      expect(mockWs.send).toHaveBeenCalledWith(buf);
    });

    it("does nothing when not connected", () => {
      stt.feedAudio(Buffer.alloc(64));
      expect(mockWs.send).not.toHaveBeenCalled();
    });
  });

  describe("flushSilence()", () => {
    it("sends 19200 bytes of zeros when connected", async () => {
      await connectStt();
      stt.flushSilence();
      expect(mockWs.send).toHaveBeenCalledWith(Buffer.alloc(19200));
    });

    it("does nothing when not connected", () => {
      stt.flushSilence();
      expect(mockWs.send).not.toHaveBeenCalled();
    });
  });

  describe("transcript handling", () => {
    it("fires onTranscript for type=final with non-empty text", async () => {
      await connectStt();
      sendMessage({ type: "final", text: "hello world" });
      expect(onTranscript).toHaveBeenCalledWith("hello world");
    });

    it("does NOT fire onTranscript for type=partial", async () => {
      await connectStt();
      sendMessage({ type: "partial", text: "hell" });
      expect(onTranscript).not.toHaveBeenCalled();
    });

    it("does NOT fire onTranscript for empty final text", async () => {
      await connectStt();
      sendMessage({ type: "final", text: "   " });
      expect(onTranscript).not.toHaveBeenCalled();
    });
  });

  describe("destroy()", () => {
    it("closes the WebSocket", async () => {
      await connectStt();
      stt.destroy();
      expect(mockWs.close).toHaveBeenCalled();
    });

    it("sets isConnected to false", async () => {
      await connectStt();
      stt.destroy();
      expect(stt.isConnected).toBe(false);
    });

    it("is idempotent — no throw on double destroy", () => {
      stt.destroy();
      expect(() => stt.destroy()).not.toThrow();
    });

    it("connect() is a no-op after destroy", async () => {
      stt.destroy();
      await stt.connect(); // should return immediately without throwing
      expect(MockWebSocket).not.toHaveBeenCalled();
    });
  });
});
