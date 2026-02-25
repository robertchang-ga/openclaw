# Voice Transcription Pipeline — Status

**Date**: 2026-02-25  
**Branch**: `feat/security-proxy`

## Goal
Enable end-to-end voice transcription in Discord: **User speaks → Opus decode → Resample → Realtime STT WebSocket (Speaches) → Agent → Kokoro TTS → Playback**

## Architecture

### Current: Realtime Streaming STT
- **STT**: Speaches container (`v0.9.0-rc.3-cuda-12.6.3`) with Whisper (`Systran/faster-distil-whisper-large-v3`) via OpenAI-compatible Realtime WebSocket API
- **Mode**: `intent=transcription` — transcription-only, no LLM response generation
- **VAD**: Server-side (Speaches Silero VAD) with `create_response: false`
- **Audio Pipeline**: Discord Opus → `@discordjs/opus` decode → `resample48kStereoTo16kMono()` → WebSocket stream → Speaches
- **TTS**: Kokoro (via Speaches) for streaming sentence-level audio playback
- **Networking**: Gateway container → `ws://speaches:8000/v1/realtime` via `openclaw-secure-net` Docker network
- **Memory**: Cognee plugin (`http://cognee:8000`) for semantic recall

### Key Modules
| Module | Role |
|--------|------|
| `src/discord/voice/realtime-stt.ts` | `RealtimeSTT` class — WebSocket connection, audio streaming, VAD events, transcription callbacks |
| `src/discord/voice/manager.ts` | `DiscordVoiceManager` — integrates `RealtimeSTT`, pipes Discord audio, triggers agent processing |
| `src/config/sanitize-secrets.ts` | Rewrites plugin `baseUrl` from `localhost` → Docker-internal hostnames in secure mode |

## Fixes Applied (Original Pipeline)

### 1. ✅ DAVE Encryption Disabled
- `@discordjs/voice@0.19.x` DAVE E2E receive decryption bug
- Set `daveEncryption: false` — falls back to XSalsa20 transport encryption
- TODO: Re-enable when `@discordjs/voice` 0.20.x ships a fix (DAVE enforced March 2, 2026)

### 2. ✅ API Key Requirement
- Added `models.providers.openai` with dummy `apiKey: "sk-dummy-speaches-local"` to config

### 3. ✅ Secrets Proxy Allowlist
- Added `speaches` and `localhost` to the allowlist via `openclaw allowlist add`

### 4. ✅ BaseUrl Updated
- Changed to `http://localhost:8090/v1` (Speaches port published as `127.0.0.1:8090` on host)

### 5. ✅ End-to-End Logging
- All `logVoiceVerbose` calls promoted to `logger.info` throughout the entire pipeline

### 6. ✅ Native Opus Dependencies in Dockerfile
- Added `libopus-dev`, `python3`, `make`, `g++` to `Dockerfile` before `pnpm install`

## Realtime STT Migration

### 7. ✅ Replaced Batch Pipeline with Streaming WebSocket
- **Old**: Capture → silence wait → WAV file → HTTP upload → transcription
- **New**: Stream audio directly to `ws://speaches:8000/v1/realtime` via `RealtimeSTT` class
- Implemented `resample48kStereoTo16kMono()` for audio format conversion
- Uses Node.js native `WebSocket` (Node 22+)

### 8. ✅ Cognee Plugin Config (`sanitize-secrets.ts`)
- **Problem**: Plugin loaded from `.openclaw/extensions/cognee-openclaw/dist/index.js` (installed extension), NOT `cognee-plugin-source.js` in repo root
- **Problem**: Config had `baseUrl: "http://localhost:8000"` which doesn't work inside Docker container
- **Fix**: `sanitize-secrets.ts` now rewrites `localhost`/`127.0.0.1` plugin URLs to Docker-internal hostnames
- **Result**: Cognee sync and recall now working ✅ (`cognify completed`, `auto-sync complete`)

### 9. ✅ Speaches Upgraded to v0.9.0-rc.3
- **Problem**: `latest-cuda` tag = v0.8.x, which lacks `intent=transcription` (added in PR #522, v0.9.0-rc.1)
- **Fix**: Pinned to `0.9.0-rc.3-cuda-12.6.3` in `docker-compose.yml`
- Speaches now recognizes `intent=transcription` and sets `create_response: false` ✅

### 10. 🟡 Speaches Internal Transcription Self-Call (IN PROGRESS)
- **Problem**: Speaches' realtime handler uses the OpenAI Python SDK to call its own `/v1/audio/transcriptions` endpoint. Without `OPENAI_BASE_URL`, the SDK defaults to `https://api.openai.com` → `APIConnectionError`
- **Fix**: Added `OPENAI_BASE_URL=http://localhost:8000/v1` and `OPENAI_API_KEY=not-needed` to Speaches container environment
- **Status**: Deployed, awaiting verification

## Remaining Issues

### 🟡 Silence Flush After Discord Stream Ends
- When Discord's `AfterSilence` timer ends the audio stream, `flushSilence(1000)` sends 1s of zero-sample PCM
- This lets Speaches' VAD detect the speech→silence transition and trigger transcription
- May need tuning depending on how well the new `intent=transcription` mode handles it

### 🟡 Plugin ID Mismatch Warning
- `plugin memory-cognee: plugin id mismatch (manifest uses "memory-cognee", entry hints "cognee-openclaw")`
- Non-blocking warning, plugin still loads and works

## Files Modified
| File | Changes |
|------|---------|
| `src/discord/voice/realtime-stt.ts` | NEW — `RealtimeSTT` class with WebSocket, VAD, `flushSilence()` |
| `src/discord/voice/manager.ts` | Replaced batch STT with streaming `RealtimeSTT` integration |
| `src/config/sanitize-secrets.ts` | Plugin baseUrl injection (localhost → Docker hostname) |
| `docker-compose.yml` | Speaches `0.9.0-rc.3-cuda-12.6.3`, `OPENAI_BASE_URL`, `OPENAI_API_KEY` |
| `cognee-plugin-source.js` | `COGNEE_BASE_URL` env var fallback (repo root, not used by installed extension) |
| `src/security/gateway-container.ts` | `COGNEE_BASE_URL` env var for container |
| `Dockerfile` | Native opus dependencies + rebuild step |
