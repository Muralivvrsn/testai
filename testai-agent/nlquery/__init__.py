"""
TestAI Agent - Natural Language Query Module

Enables natural language queries against test suites
with semantic parsing and fuzzy matching.
"""

from .parser import (
    QueryParser,
    ParsedQuery,
    QueryIntent,
    QueryFilter,
    create_query_parser,
)

from .executor import (
    QueryExecutor,
    QueryResult,
    TestMatch,
    create_query_executor,
)

from .nlp import (
    NLProcessor,
    TokenizedQuery,
    Entity,
    EntityType,
    create_nl_processor,
)

__all__ = [
    # Parser
    "QueryParser",
    "ParsedQuery",
    "QueryIntent",
    "QueryFilter",
    "create_query_parser",
    # Executor
    "QueryExecutor",
    "QueryResult",
    "TestMatch",
    "create_query_executor",
    # NLP
    "NLProcessor",
    "TokenizedQuery",
    "Entity",
    "EntityType",
    "create_nl_processor",
]
