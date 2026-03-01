FROM cognee/cognee:latest

# Install graphiti-core into the app virtualenv's site-packages
# (system pip is at /usr/local/bin, venv has no pip — use --target)
RUN VENV_SITE=$(find /app/.venv/lib -name site-packages -type d | head -1) && \
    pip install --no-cache-dir --target="$VENV_SITE" "graphiti-core"

# Add custom Graphiti router module
COPY graphiti_router.py /app/cognee/api/v1/graphiti_router.py

# Patch client.py to mount the Graphiti router alongside existing routers.
# Append to the end of the module — no anchor dependency on upstream code.
RUN printf '\n# --- OpenClaw: Graphiti temporal awareness router ---\ntry:\n    from cognee.api.v1.graphiti_router import get_graphiti_router\n    app.include_router(get_graphiti_router(), prefix="/api/v1/graphiti", tags=["graphiti"])\nexcept Exception as _e:\n    import logging; logging.getLogger("graphiti").warning(f"Graphiti router not mounted: {_e}")\n# --- End OpenClaw patch ---\n' >> /app/cognee/api/client.py
