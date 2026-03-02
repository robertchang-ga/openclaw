# Kroko STT Integration Design

**Date:** 2026-03-02
**Status:** Approved

## Problem

OpenClaw's Discord voice STT is hard-wired to Speaches (an OpenAI Realtime API-compatible
server running Whisper). Kroko is a streaming STT engine with smaller on-premise ONNX models
(~70MB), CPU-efficient, and claims lower WER than Whisper in most languages. We want to add it
as a selectable alternative without disturbing the existing Speaches path.

## Goal

Add Kroko as a first-class STT provider alongside Speaches, selectable via config, with
identical behavioral surface: same callbacks, same session lifecycle, same silent-drop error
handling.

## Chosen Approach: Thin parallel class (Option A)

A `KrokoSTT` class in `src/discord/voice/kroko-stt.ts` mirrors `RealtimeSTT`'s public shape.
No interface layer introduced (YAGNI — two concrete classes with matching shapes is sufficient).
The voice manager instantiates one or the other based on `voice.stt.provider`.

## Architecture

### New file: `src/discord/voice/kroko-stt.ts`

**`KrokoSTT` class** — mirrors `RealtimeSTT`'s public API:

- Constructor: `KrokoSTTConfig` + callbacks (`onTranscript`, `onSpeechStart?`, `onSpeechEnd?`)
- `connect()` — opens a WebSocket to the on-premise Kroko server
- `feedAudio(pcm: Buffer)` — accepts **float32 16kHz mono** PCM; sends as binary WebSocket frames
- `flushSilence()` — sends a short buffer of float32 zeros to trigger server-side VAD end-of-speech
- `destroy()` — closes WebSocket; safe to call multiple times

**Transcript delivery** — Kroko sends `{ type: "partial" | "final", text: string, ... }` JSON.
`KrokoSTT` fires `onTranscript(text)` only on `type === "final"`, matching Speaches behavior.

**`KrokoSTTConfig` type:**

```ts
type KrokoSTTConfig = {
  url: string; // default: "ws://localhost:8080"
  language?: string; // optional ISO-639-1 hint (e.g. "en")
  apiKey?: string; // optional; required for commercial Kroko model license
};
```

### New helper: `resample48kStereoTo16kMonoFloat32`

Lives in `src/discord/voice/realtime-stt.ts` (alongside existing `resample48kStereoTo24kMono`)
or in a shared `audio-utils.ts`.

- Input: 48kHz stereo S16LE `Buffer` (4 bytes per frame)
- Output: 16kHz mono PCM float32 `Buffer` (4 bytes per sample)
- Algorithm: for each output sample, average L+R int16 values, decimate 3:1 (48k→16k),
  normalize to `[-1.0, 1.0]` as float32

The existing `resample48kStereoTo24kMono` is left untouched for Speaches.

### Config schema (`src/config/types.discord.ts`)

Add `stt` to `DiscordVoiceConfig` (alongside the existing `tts` override):

```ts
type DiscordVoiceSttConfig = {
  provider?: "speaches" | "kroko"; // default: "speaches"
  kroko?: {
    url?: string; // default: "ws://localhost:8080"
    language?: string;
    apiKey?: string;
  };
};
```

Example `~/.openclaw/config.yaml`:

```yaml
discord:
  voice:
    stt:
      provider: kroko
      kroko:
        url: ws://localhost:8080
        language: en
```

### Changes to `src/discord/voice/manager.ts`

- Import `KrokoSTT`, `resolveSttConfig` (new helper), `resample48kStereoTo16kMonoFloat32`
- Read `discordConfig.voice?.stt` to determine provider
- Instantiate `KrokoSTT` or `RealtimeSTT` and store on `VoiceSessionEntry` (same field, typed as
  a union or kept as `RealtimeSTT` with duck-typed usage — both have identical method names)
- Route audio through `resample48kStereoTo16kMonoFloat32` for Kroko,
  `resample48kStereoTo24kMono` for Speaches

## Kroko on-premise subprocess protocol detail

The on-premise server is started by the user:

```bash
./kroko-onnx-online-websocket-server --model=<downloaded-model>
```

Default port: 8080. No auth required for community ONNX models; `--key=LICENSE_KEY` required
for commercial models (passed as query param `?apiKey=<key>` in the WebSocket URL).

**WebSocket URL format:**

```
ws://<host>:<port>/?language=<lang>&apiKey=<key>
```

**Audio format:** binary frames containing raw PCM float32 at 16kHz, 1 channel, max 4s per frame.

**Response JSON:**

```json
{ "type": "partial" | "final", "text": "...", "segment": 0, "startedAt": 0.0 }
```

Only `type === "final"` messages are forwarded as transcripts.

## Error handling

- WebSocket connection failure or mid-session disconnect: log warning, stop delivering
  transcripts. No crash, no retry. Same silent-drop behavior as `RealtimeSTT`.
- `provider === "kroko"` with no `url` configured: default to `ws://localhost:8080`.

## Testing

Unit tests in `src/discord/voice/kroko-stt.test.ts`:

- Mock `WebSocket`; verify binary frames sent as float32
- Verify `onTranscript` fires only on `type === "final"`, not `"partial"`
- Verify `destroy()` closes WebSocket cleanly
- Unit test `resample48kStereoTo16kMonoFloat32`: known S16LE stereo input → expected float32
  mono output values

No e2e test (requires Kroko binary + model on disk).

## Out of scope

- Kroko model download/management (user installs Kroko and downloads a model manually)
- Fallback from Kroko to Speaches on error (can add later if needed)
- `language` auto-detection (pass through only)
