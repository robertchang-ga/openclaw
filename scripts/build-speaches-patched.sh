#!/bin/bash
# Build a patched Speaches Docker image that fixes the ASGI middleware bug
# in the realtime transcription handler.
#
# Bug: ASGITransport(stt_router) uses bare APIRouter without FastAPI middleware
# Fix: Wrap in FastAPI() sub-app so AsyncExitStackMiddleware initializes properly
set -euo pipefail

TAG="speaches:patched"
BUILD_DIR="/tmp/speaches-build"

echo "=== Cloning speaches v0.9.0-rc.3 ==="
rm -rf "$BUILD_DIR"
git clone --depth 1 --branch v0.9.0-rc.3 https://github.com/speaches-ai/speaches.git "$BUILD_DIR"
cd "$BUILD_DIR"

echo "=== Applying ASGI middleware fix to dependencies.py ==="
python3 - <<'PATCH_SCRIPT'
filepath = "src/speaches/dependencies.py"
with open(filepath, "r") as f:
    content = f.read()

# Fix get_transcription_client: wrap stt_router in FastAPI sub-app
old_transcription = '''    if config.loopback_host_url is None:
        # this might not work as expected if `stt_router` won't have shared state (access to the same `model_manager`) with the main FastAPI `app`. TODO: verify
        from speaches.routers.stt import (
            router as stt_router,
        )

        http_client = AsyncClient(
            transport=ASGITransport(stt_router),
            base_url="http://test/v1",
        )  # NOTE: "test" can be replaced with any other value'''

new_transcription = '''    if config.loopback_host_url is None:
        from speaches.routers.stt import (
            router as stt_router,
        )

        # Wrap bare router in a FastAPI sub-app so that AsyncExitStackMiddleware
        # is present. Without this, internal ASGI transport calls fail with:
        # AssertionError: fastapi_middleware_astack not found in request scope
        from fastapi import FastAPI as _FastAPI
        _stt_app = _FastAPI()
        _stt_app.include_router(stt_router)
        http_client = AsyncClient(
            transport=ASGITransport(_stt_app),
            base_url="http://test/v1",
        )'''

if old_transcription not in content:
    print("ERROR: Could not find transcription client pattern to patch")
    exit(1)

content = content.replace(old_transcription, new_transcription)

# Fix get_speech_client: same issue, wrap speech_router in FastAPI sub-app
old_speech = '''    if config.loopback_host_url is None:
        # this might not work as expected if `speech_router` won't have shared state (access to the same `model_manager`) with the main FastAPI `app`. TODO: verify
        from speaches.routers.speech import (
            router as speech_router,
        )

        http_client = AsyncClient(
            transport=ASGITransport(speech_router),
            base_url="http://test/v1",
        )  # NOTE: "test" can be replaced with any other value'''

new_speech = '''    if config.loopback_host_url is None:
        from speaches.routers.speech import (
            router as speech_router,
        )

        from fastapi import FastAPI as _FastAPI
        _speech_app = _FastAPI()
        _speech_app.include_router(speech_router)
        http_client = AsyncClient(
            transport=ASGITransport(_speech_app),
            base_url="http://test/v1",
        )'''

if old_speech not in content:
    print("WARNING: Could not find speech client pattern to patch (non-critical)")
else:
    content = content.replace(old_speech, new_speech)

with open(filepath, "w") as f:
    f.write(content)

print("OK: Patched dependencies.py successfully")
PATCH_SCRIPT

echo "=== Patching Dockerfile to remove BuildKit --mount syntax ==="
python3 - <<'PATCH_DOCKERFILE'
with open("Dockerfile", "r") as f:
    content = f.read()

# Replace the --mount=type=cache,type=bind uv sync steps with standard COPY+RUN
old_uv_install = '''RUN --mount=type=cache,target=/root/.cache/uv \\
    --mount=type=bind,source=uv.lock,target=uv.lock \\
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \\
    uv sync --frozen --compile-bytecode --no-install-project --no-dev
COPY --chown=ubuntu . .
RUN --mount=type=cache,target=/root/.cache/uv \\
    uv sync --frozen --compile-bytecode --no-dev'''

new_uv_install = '''COPY --chown=ubuntu pyproject.toml uv.lock ./
RUN uv sync --frozen --compile-bytecode --no-install-project --no-dev
COPY --chown=ubuntu . .
RUN uv sync --frozen --compile-bytecode --no-dev'''

if old_uv_install not in content:
    print("ERROR: Could not find Dockerfile uv sync pattern to patch")
    exit(1)

content = content.replace(old_uv_install, new_uv_install)

with open("Dockerfile", "w") as f:
    f.write(content)

print("OK: Patched Dockerfile successfully")
PATCH_DOCKERFILE

echo "=== Building Docker image ($TAG) ==="
echo "This will take several minutes..."
docker build \
  --build-arg BASE_IMAGE=nvidia/cuda:12.6.3-cudnn-runtime-ubuntu24.04 \
  -t "$TAG" \
  .

echo ""
echo "=== Done! Image built: $TAG ==="
echo "Update docker-compose.yml to use: image: $TAG"
