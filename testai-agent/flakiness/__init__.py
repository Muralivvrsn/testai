"""
TestAI Agent - Flakiness Detection

Test flakiness detection, analysis, and mitigation
with pattern recognition and automated fixes.
"""

from .detector import (
    FlakinessDetector,
    FlakinessPattern,
    FlakinessLevel,
    TestExecution,
    create_flakiness_detector,
)

from .analyzer import (
    FlakinessAnalyzer,
    FlakeAnalysis,
    FlakeRootCause,
    create_flakiness_analyzer,
)

from .mitigator import (
    FlakinessMitigator,
    MitigationStrategy,
    MitigationStatus,
    MitigationResult,
    create_flakiness_mitigator,
)

__all__ = [
    # Detector
    "FlakinessDetector",
    "FlakinessPattern",
    "FlakinessLevel",
    "TestExecution",
    "create_flakiness_detector",
    # Analyzer
    "FlakinessAnalyzer",
    "FlakeAnalysis",
    "FlakeRootCause",
    "create_flakiness_analyzer",
    # Mitigator
    "FlakinessMitigator",
    "MitigationStrategy",
    "MitigationStatus",
    "MitigationResult",
    "create_flakiness_mitigator",
]
