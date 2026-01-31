"""
TestAI Agent - Understanding Module

Understands what the user wants to test.
Extracts intent, identifies features, suggests focus areas.
Detects edge cases that humans miss.
"""

from .feature_analyzer import FeatureAnalyzer, FeatureContext, UserIntent
from .edge_cases import (
    EdgeCaseDetector,
    EdgeCase,
    EdgeCaseCategory,
    EdgeCaseAnalysis,
    detect_edge_cases,
    get_edge_case_tests,
)

__all__ = [
    'FeatureAnalyzer',
    'FeatureContext',
    'UserIntent',
    'EdgeCaseDetector',
    'EdgeCase',
    'EdgeCaseCategory',
    'EdgeCaseAnalysis',
    'detect_edge_cases',
    'get_edge_case_tests',
]
