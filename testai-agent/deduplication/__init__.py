"""
TestAI Agent - Deduplication Module

Intelligent test case deduplication using semantic similarity
to identify and merge functionally equivalent tests.
"""

from .deduplicator import (
    TestDeduplicator,
    DuplicateGroup,
    DeduplicationResult,
    SimilarityMethod,
    create_deduplicator,
)

from .merger import (
    TestMerger,
    MergeStrategy,
    MergeResult,
    create_merger,
)

__all__ = [
    # Deduplicator
    "TestDeduplicator",
    "DuplicateGroup",
    "DeduplicationResult",
    "SimilarityMethod",
    "create_deduplicator",
    # Merger
    "TestMerger",
    "MergeStrategy",
    "MergeResult",
    "create_merger",
]
