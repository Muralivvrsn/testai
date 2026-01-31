"""
TestAI Agent - Test Coverage Tracking

Code coverage tracking, test-to-code mapping,
and gap analysis for comprehensive test coverage.
"""

from .tracker import (
    CoverageTracker,
    CoverageReport,
    CoverageMetrics,
    CoverageType,
    create_coverage_tracker,
)

from .mapper import (
    TestCoverageMapper,
    CoverageMapping,
    TestCoverageInfo,
    create_coverage_mapper,
)

from .gaps import (
    GapAnalyzer,
    CoverageGap,
    GapSeverity,
    GapReport,
    create_gap_analyzer,
)

__all__ = [
    # Tracker
    "CoverageTracker",
    "CoverageReport",
    "CoverageMetrics",
    "CoverageType",
    "create_coverage_tracker",
    # Mapper
    "TestCoverageMapper",
    "CoverageMapping",
    "TestCoverageInfo",
    "create_coverage_mapper",
    # Gaps
    "GapAnalyzer",
    "CoverageGap",
    "GapSeverity",
    "GapReport",
    "create_gap_analyzer",
]
