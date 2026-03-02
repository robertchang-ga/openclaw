"""
Custom Graphiti router for Cognee.

Exposes build_graph_with_temporal_awareness and index_and_transform_graphiti_nodes_and_edges
via a REST endpoint so the OpenClaw plugin can trigger the Graphiti pipeline after cognify.
"""
import logging
import os
import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger("graphiti_router")

# Strip YAML frontmatter (---...---) from text before feeding to Graphiti.
# Frontmatter contains metadata (type, date, participants) intended for Cognee,
# not temporal event extraction. Including it creates noisy temporal nodes.
_FRONTMATTER_RE = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.DOTALL)

def strip_frontmatter(text: str) -> str:
    """Remove YAML frontmatter block from the beginning of text."""
    return _FRONTMATTER_RE.sub("", text)


class GraphitiCognifyRequest(BaseModel):
    """Request body for the Graphiti cognify endpoint."""
    dataset_ids: Optional[list[str]] = Field(
        None, description="Dataset IDs to process. If None, processes all datasets."
    )


class GraphitiCognifyResponse(BaseModel):
    """Response from the Graphiti cognify endpoint."""
    success: bool
    message: str
    episodes_added: int = 0


def _resolve_graphiti_llm_config():
    """
    Build a Graphiti LLMConfig based on environment variables.

    Supports:
      - LLM_PROVIDER=gemini  -> uses GOOGLE_API_KEY or GEMINI_API_KEY or LLM_API_KEY
      - LLM_PROVIDER=openai  -> uses OPENAI_API_KEY or LLM_API_KEY
      - Other providers       -> uses OPENAI_API_KEY or LLM_API_KEY (OpenAI-compatible)
    """
    from graphiti_core.llm_client import LLMConfig

    provider = os.getenv("LLM_PROVIDER", "openai").lower().strip()
    llm_model = os.getenv("LLM_MODEL", "")

    if provider == "gemini":
        api_key = (
            os.getenv("GOOGLE_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("LLM_API_KEY", "")
        )
        # Strip litellm prefix (e.g., "gemini/gemini-3-flash-preview" → "gemini-3-flash-preview")
        gemini_model = llm_model or "gemini-2.0-flash"
        if gemini_model.startswith("gemini/"):
            gemini_model = gemini_model[len("gemini/"):]
        # Use Gemini's OpenAI-compatible endpoint
        return "gemini", LLMConfig(
            api_key=api_key,
            model=gemini_model,
            small_model=gemini_model,
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        )
    else:
        api_key = (
            os.getenv("OPENAI_API_KEY")
            or os.getenv("LLM_API_KEY", "")
        )
        return "openai", LLMConfig(
            api_key=api_key,
            model=llm_model or "gpt-4o-mini",
            small_model=llm_model or "gpt-4o-mini",
        )


def get_graphiti_router() -> APIRouter:
    router = APIRouter()

    @router.post("/cognify", response_model=GraphitiCognifyResponse)
    async def graphiti_cognify(payload: GraphitiCognifyRequest):
        """
        Run Graphiti's temporal awareness pipeline on previously added data.

        This endpoint:
        1. Retrieves text data from Cognee's data store
        2. Creates a Graphiti instance with the correct LLM provider
        3. Feeds data through Graphiti's add_episode() for temporal extraction
        4. Bridges the resulting nodes into Cognee's vector store
        """
        try:
            from cognee.modules.users.methods import get_default_user
            from cognee.modules.data.methods import get_datasets, get_datasets_by_name
            from cognee.modules.data.methods.get_dataset_data import get_dataset_data
            from cognee.tasks.temporal_awareness.index_graphiti_objects import (
                index_and_transform_graphiti_nodes_and_edges,
            )
            from graphiti_core import Graphiti
            from graphiti_core.llm_client import OpenAIClient
            from graphiti_core.nodes import EpisodeType

            user = await get_default_user()

            # Get datasets to process
            if payload.dataset_ids:
                datasets = await get_datasets_by_name(payload.dataset_ids, user.id)
            else:
                datasets = await get_datasets(user.id)

            if not datasets:
                return GraphitiCognifyResponse(
                    success=True,
                    message="No datasets found to process",
                    episodes_added=0,
                )

            # Collect all text content from datasets
            all_texts = []
            for dataset in datasets:
                try:
                    data_documents = await get_dataset_data(dataset_id=dataset.id)
                    for doc in data_documents:
                        # Extract text content from document
                        if hasattr(doc, 'raw_data') and doc.raw_data:
                            all_texts.append(strip_frontmatter(str(doc.raw_data)))
                        elif hasattr(doc, 'content') and doc.content:
                            all_texts.append(strip_frontmatter(str(doc.content)))
                        elif hasattr(doc, 'name') and doc.name:
                            all_texts.append(doc.name)
                except Exception as e:
                    logger.warning(f"Failed to get data for dataset {dataset.name}: {e}")
                    continue

            if not all_texts:
                return GraphitiCognifyResponse(
                    success=True,
                    message="No text content found in datasets",
                    episodes_added=0,
                )

            logger.info(f"Building Graphiti graph with {len(all_texts)} text segments")

            # Build Graphiti with provider-aware LLM config
            url = os.getenv("GRAPH_DATABASE_URL", "bolt://neo4j:7687")
            username = os.getenv("GRAPH_DATABASE_USERNAME", "neo4j")
            password = os.getenv("GRAPH_DATABASE_PASSWORD", "")

            provider_type, llm_config = _resolve_graphiti_llm_config()
            logger.info(
                f"Graphiti LLM config: provider={provider_type}, model={llm_config.model}, "
                f"base_url={llm_config.base_url}, "
                f"api_key={'set' if llm_config.api_key else 'MISSING'}"
            )
            # Use OpenAIGenericClient for non-OpenAI providers (uses /chat/completions
            # instead of /responses which Google's API doesn't support)
            if provider_type == "gemini":
                from graphiti_core.llm_client.openai_generic_client import OpenAIGenericClient
                from graphiti_core.embedder import OpenAIEmbedder, OpenAIEmbedderConfig
                llm_client = OpenAIGenericClient(llm_config)
                # Configure embedder — use same EMBEDDING_* env vars as Cognee
                embedding_provider = os.getenv("EMBEDDING_PROVIDER", "openai").lower().strip()
                embedding_model = os.getenv("EMBEDDING_MODEL", "text-embedding-004")
                # Strip litellm prefix (e.g., "gemini/gemini-embedding-001" → "gemini-embedding-001")
                if embedding_model.startswith("gemini/"):
                    embedding_model = embedding_model[len("gemini/"):]
                if embedding_provider in ("gemini", "google"):
                    embedder = OpenAIEmbedder(OpenAIEmbedderConfig(
                        api_key=llm_config.api_key,
                        embedding_model=embedding_model,
                        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                    ))
                    logger.info(f"Using Gemini embedder ({embedding_model})")
                else:
                    # Embedding provider is OpenAI — use separate OPENAI_API_KEY if available
                    embed_api_key = os.getenv("OPENAI_API_KEY", llm_config.api_key)
                    embedder = OpenAIEmbedder(OpenAIEmbedderConfig(
                        api_key=embed_api_key,
                        embedding_model=embedding_model,
                    ))
                    logger.info(f"Using OpenAI embedder ({embedding_model})")
            else:
                llm_client = OpenAIClient(llm_config)
                embedder = None  # Use default OpenAI embedder
            graphiti = Graphiti(
                url, username, password,
                llm_client=llm_client,
                **({"embedder": embedder} if embedder else {}),
            )

            await graphiti.build_indices_and_constraints()
            logger.info("Graph database initialized")

            # Temporarily hide cognee's Entity nodes from graphiti's full-text
            # index by removing their Entity label. Cognee and graphiti share
            # Neo4j; graphiti's node_fulltext_search returns all :Entity nodes
            # and fails constructing EntityNode when uuid/summary are null
            # (cognee nodes never have these fields).
            await graphiti.driver.execute_query(
                """MATCH (n:Entity) WHERE n.uuid IS NULL
                   REMOVE n:Entity SET n:_CogneeEntity""",
                database_="neo4j",
            )
            logger.info("Temporarily hidden cognee Entity nodes from graphiti index")

            # Add episodes — restore cognee nodes even if this fails
            try:
                for i, text in enumerate(all_texts):
                    await graphiti.add_episode(
                        name=f"episode_{i}",
                        episode_body=text,
                        source=EpisodeType.text,
                        source_description="openclaw-memory",
                        reference_time=datetime.now(),
                    )
                    logger.info(f"Added episode {i}: {text[:50]}...")
            finally:
                await graphiti.driver.execute_query(
                    """MATCH (n:_CogneeEntity)
                       REMOVE n:_CogneeEntity SET n:Entity""",
                    database_="neo4j",
                )
                logger.info("Restored cognee Entity nodes")

            # Bridge Graphiti nodes into Cognee's vector store
            logger.info("Indexing Graphiti objects into Cognee vector store")
            await index_and_transform_graphiti_nodes_and_edges()

            # Close the Graphiti connection after indexing is complete
            await graphiti.close()

            return GraphitiCognifyResponse(
                success=True,
                message=f"Graphiti pipeline completed: {len(all_texts)} episodes processed",
                episodes_added=len(all_texts),
            )

        except ImportError as e:
            logger.error(f"Graphiti dependencies not available: {e}")
            return GraphitiCognifyResponse(
                success=False,
                message=f"Graphiti dependencies not installed: {str(e)}",
            )
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            # Extract detailed error info for OpenAI/LLM API errors
            error_details = str(e)
            if hasattr(e, 'response'):
                try:
                    resp = e.response
                    error_details += f" | status={resp.status_code}"
                    error_details += f" | body={resp.text[:500]}"
                    error_details += f" | url={resp.url}"
                except Exception:
                    pass
            if hasattr(e, 'body'):
                error_details += f" | body={e.body}"
            logger.error(f"Graphiti cognify failed: {error_details}\n{tb}")
            return GraphitiCognifyResponse(
                success=False,
                message=f"Graphiti cognify failed: {error_details}\nTraceback:\n{tb[-1000:]}",
            )

    @router.get("/status")
    async def graphiti_status():
        """Check if Graphiti dependencies are available."""
        try:
            import graphiti_core

            graph_url = os.getenv("GRAPH_DATABASE_URL", "not set")
            has_password = bool(os.getenv("GRAPH_DATABASE_PASSWORD"))
            llm_provider = os.getenv("LLM_PROVIDER", "openai")
            llm_model = os.getenv("LLM_MODEL", "")

            # Show resolved config
            try:
                _, resolved = _resolve_graphiti_llm_config()
                resolved_info = {
                    "model": resolved.model,
                    "base_url": resolved.base_url,
                    "api_key_set": bool(resolved.api_key),
                }
            except Exception as cfg_err:
                resolved_info = {"error": str(cfg_err)}

            return {
                "available": True,
                "graphiti_core_version": getattr(graphiti_core, "__version__", "unknown"),
                "graph_database_url": graph_url,
                "graph_database_password_set": has_password,
                "llm_provider": llm_provider,
                "llm_model": llm_model,
                "resolved_config": resolved_info,
            }
        except ImportError:
            return {
                "available": False,
                "message": "graphiti-core is not installed",
            }

    return router
