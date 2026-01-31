"""
TestAI Agent - Root Cause Analysis Module

AI-powered test failure analysis with pattern recognition,
code correlation, and intelligent debugging suggestions.
"""

from .root_cause import (
    RootCauseAnalyzer,
    FailurePattern,
    FailureCategory,
    RootCause,
    create_root_cause_analyzer,
)

from .correlator import (
    CodeCorrelator,
    ChangeCorrelation,
    CodeChange,
    create_code_correlator,
)

from .debugger import (
    DebugAssistant,
    DebugSuggestion,
    DebugStrategy,
    create_debug_assistant,
)

__all__ = [
    # Root Cause
    "RootCauseAnalyzer",
    "FailurePattern",
    "FailureCategory",
    "RootCause",
    "create_root_cause_analyzer",
    # Correlator
    "CodeCorrelator",
    "ChangeCorrelation",
    "CodeChange",
    "create_code_correlator",
    # Debugger
    "DebugAssistant",
    "DebugSuggestion",
    "DebugStrategy",
    "create_debug_assistant",
]
