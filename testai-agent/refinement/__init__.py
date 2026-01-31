"""
TestAI Agent - Refinement Module

Allows users to refine, modify, and enhance test cases using natural language.
This makes the agent truly interactive - it can understand feedback and improve.
"""

from .nl_refiner import (
    NaturalLanguageRefiner,
    RefinementCommand,
    RefinementType,
    RefinementResult,
    create_refiner,
)

from .test_modifier import (
    TestModifier,
    ModificationAction,
    ModificationResult,
    create_modifier,
)

__all__ = [
    # NL Refiner
    "NaturalLanguageRefiner",
    "RefinementCommand",
    "RefinementType",
    "RefinementResult",
    "create_refiner",
    # Test Modifier
    "TestModifier",
    "ModificationAction",
    "ModificationResult",
    "create_modifier",
]
