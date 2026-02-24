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

### ~~🔴 `TypeError: fetch failed` — STT request fails~~ ✅ FIXED
- **Root cause**: `baseUrl: http://localhost:8090/v1` is unreachable from inside the Docker container
  - `secure-fetch.ts` bypasses the proxy for `localhost` (correct behavior)
  - But inside the container, `localhost` resolves to the **container itself**, not the host
  - Port 8090 is not bound inside the container → `ECONNREFUSED`
- **Fix**: Added `resolveSecureModeBaseUrl()` in `runner.entries.ts`
  - When `OPENCLAW_SECURE_MODE=1`, rewrites `localhost:8090` → `speaches:8000`
  - Both gateway and Speaches containers share the `openclaw-secure-net` network
  - Host-mode (`localhost:8090`) is unchanged

### ~~🟡 `@discordjs/opus` native addon not loading~~ ✅ FIXED
- **Root cause**: `@discordjs/opus@0.10.0` uses `node-pre-gyp` which tries prebuilt binaries but none exist for Node 22
- Compilation from source requires an explicit rebuild step
- **Fix**: Added `RUN cd node_modules/@discordjs/opus && npx node-gyp rebuild` to `Dockerfile` after `pnpm install`
- Soft-failed (`|| echo ...`) so Docker build still succeeds if opus compilation fails (opusscript fallback available)

### ~~🟡 Speaches models list is empty~~ ✅ NOT A BUG
- `GET /v1/models` returns `{"data":[],"object":"list"}` — this is **expected** before first inference
- Speaches lazily downloads and loads models on the first transcription request
- The `WHISPER__MODEL` env var in docker-compose.yml is set correctly
- Once Blocker 1 is fixed, the first STT request will trigger model download + load

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
| `src/media-understanding/runner.entries.ts` | Added `resolveSecureModeBaseUrl()` — rewrites `localhost:8090` → `speaches:8000` in secure mode |
| `Dockerfile` | Added native opus dependencies + explicit `npx node-gyp rebuild` for `@discordjs/opus` |
| Host config (`openclaw.json`) | Added `models.providers.openai`, changed audio baseUrl, allowlist entries |
