"""
TestAI Agent - Brain Module

Vector-based knowledge storage using ChromaDB.
Stores and retrieves QA knowledge using semantic search.
"""

from .vector_store import QABrain, KnowledgeChunk, SearchResult, create_brain
from .smart_ingest import (
    SmartBrainIngestor,
    BrainSection,
    BrainChunk,
    IngestResult,
    ContentType,
    ingest_brain,
    ingest_brain_content,
)

__all__ = [
    'QABrain',
    'KnowledgeChunk',
    'SearchResult',
    'create_brain',
    # Smart Ingest
    'SmartBrainIngestor',
    'BrainSection',
    'BrainChunk',
    'IngestResult',
    'ContentType',
    'ingest_brain',
    'ingest_brain_content',
]
