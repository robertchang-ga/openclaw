/**
 * Kokoro TTS Provider
 *
 * Local ONNX-based text-to-speech using kokoro-js.
 * Supports both single-shot synthesis and sentence-level streaming via TextSplitterStream.
 *
 * The KokoroTTS instance is lazy-loaded and cached as a singleton.
 * First call downloads the model (~500MB) and initializes ONNX runtime.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import path from "node:path";
import { logVerbose } from "../globals.js";
import { resolvePreferredOpenClawTmpDir } from "../infra/tmp-openclaw-dir.js";
import { scheduleCleanup } from "./tts-core.js";

// ─── Defaults ────────────────────────────────────────────────────────────────
const DEFAULT_KOKORO_VOICE = "af_heart";
const DEFAULT_KOKORO_SPEED = 1.0;
const DEFAULT_KOKORO_DTYPE = "q8";

// ─── Types ───────────────────────────────────────────────────────────────────
export type KokoroConfig = {
  voice: string;
  speed: number;
  dtype: string;
};

export type KokoroTtsResult = {
  audioPath: string;
  outputFormat: string;
};

// ─── Lazy singleton ──────────────────────────────────────────────────────────
let kokoroInstance: unknown;
let kokoroInitPromise: Promise<unknown> | undefined;

async function getKokoroInstance(dtype: string): Promise<unknown> {
  if (kokoroInstance) {
    return kokoroInstance;
  }
  if (kokoroInitPromise) {
    return kokoroInitPromise;
  }
  kokoroInitPromise = (async () => {
    logVerbose("Kokoro TTS: initializing ONNX model (first call may download ~500MB)...");
    // Dynamic import to avoid bundling kokoro-js when not used.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { KokoroTTS: KokoroTTSClass } = await import("kokoro-js");
    const instance = await KokoroTTSClass.from_pretrained("onnx-community/Kokoro-82M-v1.0-ONNX", {
      dtype,
    });
    kokoroInstance = instance;
    logVerbose("Kokoro TTS: model loaded successfully.");
    return instance;
  })();
  return kokoroInitPromise;
}

// ─── WAV helpers ─────────────────────────────────────────────────────────────

/**
 * Encode Float32 PCM samples at a given sample rate into a WAV buffer.
 */
function encodeWav(samples: Float32Array, sampleRate: number): Buffer {
  const numChannels = 1;
  const bitsPerSample = 16;
  const byteRate = sampleRate * numChannels * (bitsPerSample / 8);
  const blockAlign = numChannels * (bitsPerSample / 8);
  const dataLength = samples.length * (bitsPerSample / 8);
  const headerLength = 44;
  const buffer = Buffer.alloc(headerLength + dataLength);

  // RIFF header
  buffer.write("RIFF", 0);
  buffer.writeUInt32LE(headerLength - 8 + dataLength, 4);
  buffer.write("WAVE", 8);

  // fmt subchunk
  buffer.write("fmt ", 12);
  buffer.writeUInt32LE(16, 16); // subchunk size
  buffer.writeUInt16LE(1, 20); // PCM
  buffer.writeUInt16LE(numChannels, 22);
  buffer.writeUInt32LE(sampleRate, 24);
  buffer.writeUInt32LE(byteRate, 28);
  buffer.writeUInt16LE(blockAlign, 32);
  buffer.writeUInt16LE(bitsPerSample, 34);

  // data subchunk
  buffer.write("data", 36);
  buffer.writeUInt32LE(dataLength, 40);

  // Convert float32 → int16
  let offset = headerLength;
  for (let i = 0; i < samples.length; i++) {
    const clamped = Math.max(-1, Math.min(1, samples[i]));
    const int16 = clamped < 0 ? clamped * 0x8000 : clamped * 0x7fff;
    buffer.writeInt16LE(Math.round(int16), offset);
    offset += 2;
  }

  return buffer;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function resolveKokoroConfig(raw?: {
  voice?: string;
  speed?: number;
  dtype?: string;
}): KokoroConfig {
  return {
    voice: raw?.voice?.trim() || DEFAULT_KOKORO_VOICE,
    speed: raw?.speed ?? DEFAULT_KOKORO_SPEED,
    dtype: raw?.dtype?.trim() || DEFAULT_KOKORO_DTYPE,
  };
}

/**
 * Generate TTS audio for the given text using Kokoro and save to a temp WAV file.
 * Returns the path to the generated file.
 */
export async function kokoroTTS(text: string, config: KokoroConfig): Promise<KokoroTtsResult> {
  const tts = (await getKokoroInstance(config.dtype)) as {
    generate: (
      text: string,
      options: { voice: string; speed: number },
    ) => Promise<{ audio: Float32Array; sampling_rate: number }>;
  };

  const result = await tts.generate(text, {
    voice: config.voice,
    speed: config.speed,
  });

  const wavBuffer = encodeWav(result.audio, result.sampling_rate);

  const tempRoot = resolvePreferredOpenClawTmpDir();
  mkdirSync(tempRoot, { recursive: true, mode: 0o700 });
  const tempDir = mkdtempSync(path.join(tempRoot, "tts-kokoro-"));
  const audioPath = path.join(tempDir, `voice-${Date.now()}.wav`);
  writeFileSync(audioPath, wavBuffer);
  scheduleCleanup(tempDir);

  return { audioPath, outputFormat: "wav" };
}

/**
 * Generate TTS audio for a single sentence and return the WAV buffer directly.
 * Used by the streaming TTS pipeline in the voice manager.
 */
export async function kokoroTTSBuffer(text: string, config: KokoroConfig): Promise<Buffer> {
  const tts = (await getKokoroInstance(config.dtype)) as {
    generate: (
      text: string,
      options: { voice: string; speed: number },
    ) => Promise<{ audio: Float32Array; sampling_rate: number }>;
  };

  const result = await tts.generate(text, {
    voice: config.voice,
    speed: config.speed,
  });

  return encodeWav(result.audio, result.sampling_rate);
}

/**
 * Reset the singleton (for testing or to force model re-initialization).
 */
export function resetKokoroInstance(): void {
  kokoroInstance = undefined;
  kokoroInitPromise = undefined;
}
