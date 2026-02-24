# Voice Transcription Pipeline — Status

**Date**: 2026-02-24

## Goal
Enable end-to-end voice transcription in Discord: **User speaks → Opus decode → WAV → Whisper STT (Speaches) → Agent → Kokoro TTS → Playback**

## Architecture
- **STT**: Speaches container running Whisper (`Systran/faster-distil-whisper-large-v3`) via OpenAI-compatible API
- **TTS**: Kokoro (via Speaches) for streaming sentence-level audio playback
- **VAD**: Discord's built-in `speaking` events + `EndBehaviorType.AfterSilence` (1000ms silence timeout)
- **Opus decode**: `@discordjs/opus` (native, preferred) or `opusscript` (WASM fallback)
- **Networking**: Container → Secrets Proxy (host) → `localhost:8090` → Speaches container

## Fixes Applied

### 1. ✅ DAVE Encryption Disabled
- **File**: `src/discord/voice/manager.ts`
- `@discordjs/voice@0.19.x` has a bug in DAVE E2E receive decryption
- Set `daveEncryption: false` in `joinVoiceChannel` — falls back to XSalsa20 transport encryption
- TODO: Re-enable when `@discordjs/voice` 0.20.x ships a fix (DAVE enforced March 2, 2026)

### 2. ✅ API Key Requirement
- `resolveProviderExecutionAuth` calls `requireApiKey()` for the `openai` provider
- Speaches doesn't need a real key, but the pipeline requires one
- **Fix**: Added `models.providers.openai` with dummy `apiKey: "sk-dummy-speaches-local"` to config

### 3. ✅ Secrets Proxy Allowlist
- The domain `speaches` was blocked by the secrets proxy allowlist
- **Fix**: Added `speaches` and `localhost` to the allowlist via `openclaw allowlist add`

### 4. ✅ BaseUrl Updated
- Original: `http://speaches:8000/v1` (Docker-internal hostname, unreachable from host-side proxy)
- **Fix**: Changed to `http://localhost:8090/v1` (Speaches port is published as `127.0.0.1:8090` on host)

### 5. ✅ End-to-End Logging
- **All** `logVoiceVerbose` calls promoted to `logger.info` throughout the entire pipeline
- Every stage now logs: opus decode, WAV write, subscribe, capture, transcription (with per-attempt reasons), speaker label, TTS path, agent command, Kokoro sentence splitting, playback start/done

### 6. ✅ Native Opus Dependencies in Dockerfile
- Added `libopus-dev`, `python3`, `make`, `g++` to `Dockerfile` before `pnpm install`

## Remaining Blockers

### 🔴 `TypeError: fetch failed` — STT request fails
- **Current error**: `attempts=[openai:failed(TypeError: fetch failed)]`
- Speaches IS running and reachable from host: `curl http://localhost:8090/v1/models` returns `{"data":[],"object":"list"}`
- The secrets proxy accepts the request but the underlying `fetch` to `localhost:8090` fails
- **Possible causes**:
  - The secrets proxy may not properly handle multipart/form-data (audio transcription uploads a WAV file)
  - The proxy may have issues forwarding to `localhost` specifically
  - Need to check secrets proxy logs for the actual TCP/connection error
- **Next steps**:
  - Add more error detail logging in the OpenAI transcription provider to capture the full error (cause chain)
  - Test if the secrets proxy can successfully proxy a simple `curl` to `localhost:8090/v1/models`
  - Check if `http://127.0.0.1:8090/v1` works differently than `localhost`
  - Potentially bypass the secrets proxy for local-only requests

### 🟡 `@discordjs/opus` native addon not loading
- **Current error**: `Cannot find module '.../@discordjs/opus/prebuild/node-v127-napi-v3-linux-x64-glibc-2.36/opus.node'`
- **A full Docker image rebuild WAS performed** with `libopus-dev` + build tools installed in Dockerfile
- The native addon still fails to load — likely `@discordjs/opus@0.10.0` uses prebuilt binaries via `@discordjs/node-pre-gyp` and doesn't compile from source even with build tools present
- `opusscript` WASM fallback works most of the time but intermittently crashes with `memory access out of bounds`
- **Next steps**:
  - Check build logs for `@discordjs/opus` compilation errors during `pnpm install`
  - May need to add `node-addon-api` or run `npm rebuild @discordjs/opus` explicitly in Dockerfile
  - Or pin a different opus package version that supports Node 22

### 🟡 Speaches models list is empty
- `GET /v1/models` returns `{"data":[],"object":"list"}`
- Models may load lazily on first use, but this needs verification
- If Speaches has no Whisper model loaded, transcription will fail even after fixing the fetch issue

## Config State (inside container)

```json
// tools.media.audio
{
  "enabled": true,
  "models": [{
    "provider": "openai",
    "model": "Systran/faster-distil-whisper-large-v3",
    "type": "provider",
    "baseUrl": "http://localhost:8090/v1"
  }]
}

// models.providers.openai
{
  "baseUrl": "https://api.openai.com/v1",
  "apiKey": "sk-dummy-speaches-local",
  "models": []
}
```

## Files Modified
| File | Changes |
|------|---------|
| `src/discord/voice/manager.ts` | DAVE disabled, end-to-end info logging, per-attempt transcription details |
| `Dockerfile` | Added native opus dependencies (libopus-dev, python3, make, g++) |
| Host config (`openclaw.json`) | Added `models.providers.openai`, changed audio baseUrl, allowlist entries |
