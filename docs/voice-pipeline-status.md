# Voice Transcription Pipeline — Status

**Date**: 2026-02-25  
**Branch**: `feat/security-proxy`

## Goal
Enable end-to-end voice transcription in Discord: **User speaks → Opus decode → Resample → Realtime STT WebSocket (Speaches) → Agent → Kokoro TTS → Playback**

## Architecture

### Current: Realtime Streaming STT
- **STT**: Locally patched Speaches (based on `v0.9.0-rc.3`) with Whisper (`Systran/faster-distil-whisper-large-v3`) via OpenAI-compatible Realtime WebSocket API
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
| `scripts/build-speaches-patched.sh` | Builds patched Speaches Docker image with ASGI middleware fix |

## Speaches Local Patch

### Problem
Speaches v0.9.0-rc.3 has a bug where the realtime WebSocket handler crashes after speech ends:
```
AssertionError: fastapi_middleware_astack not found in request scope
```

**Root cause**: In `dependencies.py`, `get_transcription_client()` creates an internal ASGI transport using `ASGITransport(stt_router)` where `stt_router` is a bare `APIRouter`. FastAPI's `AsyncExitStackMiddleware` (which sets `fastapi_middleware_astack` in the request scope) only exists on full `FastAPI()` app instances, not bare routers.

### Fix
Wrap bare routers in `FastAPI()` sub-apps before passing to `ASGITransport`:
```diff
-transport=ASGITransport(stt_router)
+sub_app = FastAPI()
+sub_app.include_router(stt_router)
+transport=ASGITransport(sub_app)
```

### Build & Deploy
```bash
# Build the patched image (requires CUDA GPU host, ~5 min)
bash scripts/build-speaches-patched.sh

# Deploy
docker compose down speaches && docker compose up -d speaches
sudo systemctl restart openclaw-gateway
```

The `docker-compose.yml` references `image: speaches:patched` (local image). If the image is lost (server rebuild, `docker system prune`), re-run the build script.

## Fixes Applied (Original Pipeline)

### 1. ✅ DAVE Encryption Disabled
- Set `daveEncryption: false` — falls back to XSalsa20 transport encryption
- TODO: Re-enable when `@discordjs/voice` 0.20.x ships a fix (DAVE enforced March 2, 2026)

### 2. ✅ API Key Requirement
- Added `models.providers.openai` with dummy `apiKey: "sk-dummy-speaches-local"` to config

### 3. ✅ Secrets Proxy Allowlist
- Added `speaches` and `localhost` to the allowlist

### 4. ✅ BaseUrl Updated
- Changed to `http://localhost:8090/v1` (Speaches port published as `127.0.0.1:8090` on host)

### 5. ✅ End-to-End Logging
- All `logVoiceVerbose` calls promoted to `logger.info`

### 6. ✅ Native Opus Dependencies in Dockerfile
- Added `libopus-dev`, `python3`, `make`, `g++` + explicit rebuild step

## Realtime STT Migration

### 7. ✅ Replaced Batch Pipeline with Streaming WebSocket
- Stream audio directly to `ws://speaches:8000/v1/realtime` via `RealtimeSTT` class
- Implemented `resample48kStereoTo16kMono()` for audio format conversion

### 8. ✅ Cognee Plugin Config
- `sanitize-secrets.ts` rewrites `localhost`/`127.0.0.1` plugin URLs to Docker-internal hostnames
- Cognee sync and recall working ✅

### 9. ✅ Speaches Upgraded to v0.9.0-rc.3
- `latest-cuda` = v0.8.x, which lacks `intent=transcription` (added in PR #522, v0.9.0-rc.1)

### 10. ✅ OPENAI_BASE_URL for Internal Self-Call
- Added `OPENAI_BASE_URL=http://localhost:8000/v1` to Speaches container environment

### 11. 🟡 ASGI Middleware Fix (IN PROGRESS)
- Local patch applied via `scripts/build-speaches-patched.sh`
- Awaiting build and testing

## Remaining Issues

### 🟡 Silence Flush Tuning
- `flushSilence(1000)` sends 1s of zero-sample PCM when Discord stream ends
- May need tuning for optimal VAD behavior

### 🟡 Plugin ID Mismatch Warning
- Non-blocking: `plugin memory-cognee: plugin id mismatch`

## Files Modified
| File | Changes |
|------|---------|
| `src/discord/voice/realtime-stt.ts` | NEW — `RealtimeSTT` class with WebSocket, VAD, `flushSilence()` |
| `src/discord/voice/manager.ts` | Replaced batch STT with streaming `RealtimeSTT` integration |
| `src/config/sanitize-secrets.ts` | Plugin baseUrl injection (localhost → Docker hostname) |
| `docker-compose.yml` | `speaches:patched` local image, `OPENAI_BASE_URL`, `OPENAI_API_KEY` |
| `scripts/build-speaches-patched.sh` | NEW — clones, patches, and builds Speaches Docker image |
| `cognee-plugin-source.js` | `COGNEE_BASE_URL` env var fallback |
| `src/security/gateway-container.ts` | `COGNEE_BASE_URL` env var for container |
| `Dockerfile` | Native opus dependencies + rebuild step |
