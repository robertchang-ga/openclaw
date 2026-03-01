FROM cognee/cognee:latest

# Install graphiti-core (optional extra not included in base image)
# Point system pip at the app virtualenv so packages are visible to the Cognee runtime
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"
RUN pip install --no-cache-dir "graphiti-core>=0.7.0,<0.8"

# Add custom Graphiti router module
COPY graphiti_router.py /app/cognee/api/v1/graphiti_router.py

# Patch client.py to mount the Graphiti router alongside existing routers.
# Append to the end of the module — no anchor dependency on upstream code.
RUN printf '\n# --- OpenClaw: Graphiti temporal awareness router ---\ntry:\n    from cognee.api.v1.graphiti_router import get_graphiti_router\n    app.include_router(get_graphiti_router(), prefix="/api/v1/graphiti", tags=["graphiti"])\nexcept Exception as _e:\n    import logging; logging.getLogger("graphiti").warning(f"Graphiti router not mounted: {_e}")\n# --- End OpenClaw patch ---\n' >> /app/cognee/api/client.py
