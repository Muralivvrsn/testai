"""
TestAI Agent - Impact Analysis Module

Analyzes code changes to determine which tests should be
re-run based on dependency mapping and change detection.
"""

from .analyzer import (
    ImpactAnalyzer,
    ImpactResult,
    AffectedTest,
    ImpactLevel,
    create_impact_analyzer,
)

from .dependency_mapper import (
    DependencyMapper,
    DependencyGraph,
    TestDependency,
    DependencyType,
    create_dependency_mapper,
)

from .change_detector import (
    ChangeDetector,
    CodeChange,
    ChangeType,
    ChangeSet,
    create_change_detector,
)

__all__ = [
    # Analyzer
    "ImpactAnalyzer",
    "ImpactResult",
    "AffectedTest",
    "ImpactLevel",
    "create_impact_analyzer",
    # Dependency Mapper
    "DependencyMapper",
    "DependencyGraph",
    "TestDependency",
    "DependencyType",
    "create_dependency_mapper",
    # Change Detector
    "ChangeDetector",
    "CodeChange",
    "ChangeType",
    "ChangeSet",
    "create_change_detector",
]
