"""
TestAI Agent - Brain Module

The Brain provides:
- Knowledge ingestion from markdown
- Section-level tagging for citations
- Vector-based semantic retrieval
- ChromaDB storage
"""

from .vector_store import QABrain, create_brain, CitedKnowledge, RetrievalResult
from .ingestion import KnowledgeParser, ParsedSection, parse_knowledge_base

__all__ = [
    'QABrain',
    'create_brain',
    'CitedKnowledge',
    'RetrievalResult',
    'KnowledgeParser',
    'ParsedSection',
    'parse_knowledge_base',
]
