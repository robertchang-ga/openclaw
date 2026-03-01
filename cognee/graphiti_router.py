"""
Custom Graphiti router for Cognee.

Exposes build_graph_with_temporal_awareness and index_and_transform_graphiti_nodes_and_edges
via a REST endpoint so the OpenClaw plugin can trigger the Graphiti pipeline after cognify.
"""
import logging
import re
from typing import Optional
from uuid import UUID

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


def get_graphiti_router() -> APIRouter:
    router = APIRouter()

    @router.post("/cognify", response_model=GraphitiCognifyResponse)
    async def graphiti_cognify(payload: GraphitiCognifyRequest):
        """
        Run Graphiti's temporal awareness pipeline on previously added data.

        This endpoint:
        1. Retrieves text data from Cognee's data store
        2. Feeds it through Graphiti's build_graph_with_temporal_awareness()
        3. Bridges the resulting nodes into Cognee's vector store via
           index_and_transform_graphiti_nodes_and_edges()
        """
        try:
            from cognee.modules.users.methods import get_default_user
            from cognee.modules.data.methods import get_datasets, get_datasets_by_name
            from cognee.modules.data.methods.get_dataset_data import get_dataset_data
            from cognee.tasks.temporal_awareness.build_graph_with_temporal_awareness import (
                build_graph_with_temporal_awareness,
            )
            from cognee.tasks.temporal_awareness.index_graphiti_objects import (
                index_and_transform_graphiti_nodes_and_edges,
            )
            from cognee.tasks.documents import classify_documents, extract_chunks_from_documents

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

            # Step 1: Build the Graphiti temporal graph
            graphiti = await build_graph_with_temporal_awareness(all_texts)

            # Step 2: Bridge Graphiti nodes into Cognee's vector store
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
            logger.error(f"Graphiti cognify failed: {e}", exc_info=True)
            return GraphitiCognifyResponse(
                success=False,
                message=f"Graphiti cognify failed: {str(e)}",
            )

    @router.get("/status")
    async def graphiti_status():
        """Check if Graphiti dependencies are available."""
        try:
            import graphiti_core
            import os

            graph_url = os.getenv("GRAPH_DATABASE_URL", "not set")
            has_password = bool(os.getenv("GRAPH_DATABASE_PASSWORD"))

            return {
                "available": True,
                "graphiti_core_version": getattr(graphiti_core, "__version__", "unknown"),
                "graph_database_url": graph_url,
                "graph_database_password_set": has_password,
            }
        except ImportError:
            return {
                "available": False,
                "message": "graphiti-core is not installed",
            }

    return router
