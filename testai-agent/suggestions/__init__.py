"""
TestAI Agent - Suggestions Module

Intelligent test suggestion engine that proactively identifies
missing tests, coverage gaps, and improvement opportunities.
"""

from .suggestion_engine import (
    SuggestionEngine,
    Suggestion,
    SuggestionType,
    SuggestionPriority,
    SuggestionCategory,
    create_suggestion_engine,
)

from .test_improver import (
    TestImprover,
    ImprovementType,
    TestImprovement,
    create_test_improver,
)

__all__ = [
    # Suggestion Engine
    "SuggestionEngine",
    "Suggestion",
    "SuggestionType",
    "SuggestionPriority",
    "SuggestionCategory",
    "create_suggestion_engine",
    # Test Improver
    "TestImprover",
    "ImprovementType",
    "TestImprovement",
    "create_test_improver",
]
