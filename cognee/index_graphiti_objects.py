"""
Patched version of cognee's index_graphiti_objects.py.

Fixes: cognee and graphiti share the same Neo4j database. Cognee's knowledge
graph nodes (DocumentChunk, Entity, etc.) have no 'uuid' property, so the
original `MATCH (n) SET n.id = n.uuid` silently sets id=null for those nodes,
causing get_graph_data() to raise KeyError: 'id'.

Fix: add WHERE n.uuid IS NOT NULL guards so only graphiti nodes are touched,
and replace get_graph_data() with filtered queries that skip non-graphiti nodes.
"""

from collections import Counter

from cognee.infrastructure.databases.graph import get_graph_engine
from cognee.infrastructure.databases.vector import get_vector_engine
from cognee.modules.graph.models.EdgeType import EdgeType
from cognee.shared.logging_utils import ERROR, get_logger
from cognee.tasks.temporal_awareness.graphiti_model import GraphitiNode

logger = get_logger(level=ERROR)

# Gemini embedding-001 supports up to 2048 tokens (~6000 chars of typical text).
# Truncate to stay safely within the limit and avoid 422 errors.
_MAX_EMBED_CHARS = 5000

# Gemini's BatchEmbedContents API allows at most 100 items per call.
_EMBED_BATCH_SIZE = 100


def _clean_embed_text(val) -> str:
    """Strip whitespace and truncate to the embedding model's safe character limit.

    Returns None if the result would be empty — callers should skip those values
    since Gemini's embedding API rejects empty-string inputs with 422.
    """
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    return s[:_MAX_EMBED_CHARS]


async def index_and_transform_graphiti_nodes_and_edges():
    try:
        created_indexes = {}
        index_points = {}

        vector_engine = get_vector_engine()
        graph_engine = await get_graph_engine()
    except Exception as e:
        logger.error("Failed to initialize engines: %s", e)
        raise RuntimeError("Initialization error") from e

    # Only touch graphiti nodes (those that have uuid). Cognee's knowledge-graph
    # nodes (DocumentChunk, Entity, etc.) have no uuid and must be left alone.
    await graph_engine.query(
        """MATCH (n) WHERE n.uuid IS NOT NULL SET n.id = n.uuid RETURN n""",
        params={},
    )
    await graph_engine.query(
        """MATCH (source)-[r]->(target)
           WHERE source.id IS NOT NULL AND target.id IS NOT NULL
           SET r.source_node_id = source.id,
               r.target_node_id = target.id,
               r.relationship_name = type(r) RETURN r""",
        params={},
    )
    await graph_engine.query(
        """MATCH (n) WHERE n.uuid IS NOT NULL
           SET n.text = COALESCE(n.summary, n.content) RETURN n""",
        params={},
    )

    # Replace get_graph_data() with filtered queries so we skip cognee nodes
    # that have no 'id' property (which would cause KeyError in the adapter).
    raw_nodes = await graph_engine.query(
        "MATCH (n) WHERE n.id IS NOT NULL RETURN n.id AS node_id, properties(n) AS props",
        params={},
    )
    nodes_data = [(r["node_id"], r["props"]) for r in raw_nodes]

    raw_edges = await graph_engine.query(
        """MATCH (source)-[r]->(target)
           WHERE r.source_node_id IS NOT NULL AND r.target_node_id IS NOT NULL
           RETURN r.source_node_id AS src, r.target_node_id AS tgt,
                  type(r) AS rel_type, properties(r) AS props""",
        params={},
    )
    edges_data = [(r["src"], r["tgt"], r["rel_type"], r["props"]) for r in raw_edges]

    for node_id, node_data in nodes_data:
        graphiti_node = GraphitiNode(
            **{key: node_data[key] for key in ("content", "name", "summary") if key in node_data},
            id=node_id,
        )

        data_point_type = type(graphiti_node)

        for field_name in graphiti_node.metadata["index_fields"]:
            index_name = f"{data_point_type.__name__}.{field_name}"

            if index_name not in created_indexes:
                await vector_engine.create_vector_index(data_point_type.__name__, field_name)
                created_indexes[index_name] = True

            if index_name not in index_points:
                index_points[index_name] = []

            # Clean and truncate — Gemini rejects empty strings (422) and texts
            # exceeding its ~2048-token limit. Whitespace-only strings are also
            # rejected despite being truthy in Python.
            clean_val = _clean_embed_text(getattr(graphiti_node, field_name, None))
            if clean_val:
                indexed_data_point = graphiti_node.model_copy()
                setattr(indexed_data_point, field_name, clean_val)
                indexed_data_point.metadata["index_fields"] = [field_name]
                index_points[index_name].append(indexed_data_point)

    for index_name, indexable_points in index_points.items():
        if not indexable_points:
            continue
        index_name, field_name = index_name.split(".")
        for i in range(0, len(indexable_points), _EMBED_BATCH_SIZE):
            await vector_engine.index_data_points(index_name, field_name, indexable_points[i:i + _EMBED_BATCH_SIZE])

    edge_types = Counter(
        edge[2]  # relationship type is at index 2
        for edge in edges_data
    )

    for text, count in edge_types.items():
        edge = EdgeType(relationship_name=text, number_of_edges=count)
        data_point_type = type(edge)

        for field_name in edge.metadata["index_fields"]:
            index_name = f"{data_point_type.__name__}.{field_name}"

            if index_name not in created_indexes:
                await vector_engine.create_vector_index(data_point_type.__name__, field_name)
                created_indexes[index_name] = True

            if index_name not in index_points:
                index_points[index_name] = []

            clean_val = _clean_embed_text(getattr(edge, field_name, None))
            if clean_val:
                indexed_data_point = edge.model_copy()
                setattr(indexed_data_point, field_name, clean_val)
                indexed_data_point.metadata["index_fields"] = [field_name]
                index_points[index_name].append(indexed_data_point)

    for index_name, indexable_points in index_points.items():
        if not indexable_points:
            continue
        index_name, field_name = index_name.split(".")
        for i in range(0, len(indexable_points), _EMBED_BATCH_SIZE):
            await vector_engine.index_data_points(index_name, field_name, indexable_points[i:i + _EMBED_BATCH_SIZE])

    return None
