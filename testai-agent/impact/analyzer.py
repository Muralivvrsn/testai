"""
TestAI Agent - Impact Analyzer

Analyzes code changes to determine which tests should be
re-run, with prioritization based on change risk.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set

from .change_detector import ChangeDetector, ChangeSet, CodeChange, ChangeType
from .dependency_mapper import DependencyMapper, DependencyGraph, DependencyType


class ImpactLevel(Enum):
    """Level of impact from a change."""
    CRITICAL = "critical"  # Must re-run immediately
    HIGH = "high"  # Should re-run in CI
    MEDIUM = "medium"  # Should re-run eventually
    LOW = "low"  # Optional re-run
    NONE = "none"  # No impact detected


@dataclass
class AffectedTest:
    """A test affected by code changes."""
    test_id: str
    impact_level: ImpactLevel
    affected_by: List[str]  # File paths that caused the impact
    risk_score: float  # 0-1 score
    priority: int  # Execution priority (lower = run first)
    reason: str
    confidence: float = 1.0  # How confident we are in this assessment


@dataclass
class ImpactResult:
    """Result of impact analysis."""
    changeset_id: str
    analyzed_at: datetime
    affected_tests: List[AffectedTest]
    total_tests_affected: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    estimated_run_time_ms: int = 0
    recommendations: List[str] = field(default_factory=list)


class ImpactAnalyzer:
    """
    Analyzes code changes to determine test impact.

    Combines change detection with dependency mapping to:
    - Identify affected tests
    - Prioritize test execution
    - Estimate risk levels
    - Provide recommendations
    """

    # Impact scoring weights
    IMPACT_WEIGHTS = {
        DependencyType.DIRECT: 1.0,
        DependencyType.COVERS: 0.9,
        DependencyType.INDIRECT: 0.5,
        DependencyType.FIXTURE: 0.8,
        DependencyType.MOCK: 0.6,
    }

    # Change type risk multipliers
    CHANGE_RISK = {
        ChangeType.ADDED: 0.6,
        ChangeType.MODIFIED: 0.8,
        ChangeType.DELETED: 1.0,
        ChangeType.RENAMED: 0.7,
        ChangeType.MOVED: 0.5,
    }

    def __init__(
        self,
        dependency_mapper: Optional[DependencyMapper] = None,
        change_detector: Optional[ChangeDetector] = None,
        default_test_duration_ms: int = 5000,
    ):
        """Initialize the impact analyzer."""
        self.mapper = dependency_mapper or DependencyMapper()
        self.detector = change_detector or ChangeDetector()
        self.default_test_duration_ms = default_test_duration_ms

    def analyze(
        self,
        changeset: ChangeSet,
        all_tests: Optional[List[Dict[str, Any]]] = None,
    ) -> ImpactResult:
        """Analyze a changeset for test impact."""
        affected: Dict[str, AffectedTest] = {}

        for change in changeset.changes:
            # Skip test files for production impact
            if change.is_test_file:
                continue

            # Get tests affected by this file
            tests = self.mapper.get_tests_for_file(change.file_path)

            # Calculate impact for each test
            change_risk = self.detector.calculate_change_risk(change)

            for test_id in tests:
                if test_id in affected:
                    # Update existing impact
                    existing = affected[test_id]
                    existing.affected_by.append(change.file_path)
                    existing.risk_score = max(existing.risk_score, change_risk)
                else:
                    # Create new impact
                    impact_level = self._calculate_impact_level(change, change_risk)
                    affected[test_id] = AffectedTest(
                        test_id=test_id,
                        impact_level=impact_level,
                        affected_by=[change.file_path],
                        risk_score=change_risk,
                        priority=self._calculate_priority(impact_level, change_risk),
                        reason=self._generate_reason(change),
                        confidence=0.8,
                    )

        # Sort by priority
        affected_list = sorted(affected.values(), key=lambda x: x.priority)

        # Count by level
        critical = sum(1 for t in affected_list if t.impact_level == ImpactLevel.CRITICAL)
        high = sum(1 for t in affected_list if t.impact_level == ImpactLevel.HIGH)
        medium = sum(1 for t in affected_list if t.impact_level == ImpactLevel.MEDIUM)
        low = sum(1 for t in affected_list if t.impact_level == ImpactLevel.LOW)

        # Estimate run time
        estimated_time = len(affected_list) * self.default_test_duration_ms

        # Generate recommendations
        recommendations = self._generate_recommendations(
            changeset, affected_list, critical, high
        )

        return ImpactResult(
            changeset_id=changeset.id,
            analyzed_at=datetime.now(),
            affected_tests=affected_list,
            total_tests_affected=len(affected_list),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            estimated_run_time_ms=estimated_time,
            recommendations=recommendations,
        )

    def analyze_git_diff(
        self,
        diff_content: str,
        description: str = "",
    ) -> ImpactResult:
        """Analyze a git diff for test impact."""
        changeset = self.detector.parse_git_diff(diff_content, description=description)
        return self.analyze(changeset)

    def get_tests_to_run(
        self,
        result: ImpactResult,
        max_tests: Optional[int] = None,
        min_impact_level: ImpactLevel = ImpactLevel.LOW,
    ) -> List[str]:
        """Get ordered list of tests to run."""
        level_values = {
            ImpactLevel.CRITICAL: 4,
            ImpactLevel.HIGH: 3,
            ImpactLevel.MEDIUM: 2,
            ImpactLevel.LOW: 1,
            ImpactLevel.NONE: 0,
        }

        min_value = level_values.get(min_impact_level, 1)

        filtered = [
            t for t in result.affected_tests
            if level_values.get(t.impact_level, 0) >= min_value
        ]

        if max_tests:
            filtered = filtered[:max_tests]

        return [t.test_id for t in filtered]

    def suggest_test_order(
        self,
        result: ImpactResult,
    ) -> List[List[str]]:
        """Suggest test execution order in batches."""
        batches = []

        # Critical tests first
        critical = [t.test_id for t in result.affected_tests if t.impact_level == ImpactLevel.CRITICAL]
        if critical:
            batches.append(critical)

        # High priority tests
        high = [t.test_id for t in result.affected_tests if t.impact_level == ImpactLevel.HIGH]
        if high:
            batches.append(high)

        # Medium priority tests
        medium = [t.test_id for t in result.affected_tests if t.impact_level == ImpactLevel.MEDIUM]
        if medium:
            batches.append(medium)

        # Low priority tests
        low = [t.test_id for t in result.affected_tests if t.impact_level == ImpactLevel.LOW]
        if low:
            batches.append(low)

        return batches

    def estimate_savings(
        self,
        result: ImpactResult,
        total_tests: int,
        avg_test_duration_ms: int,
    ) -> Dict[str, Any]:
        """Estimate time savings from selective testing."""
        full_run_time = total_tests * avg_test_duration_ms
        selective_run_time = result.total_tests_affected * avg_test_duration_ms

        savings_ms = full_run_time - selective_run_time
        savings_pct = (savings_ms / full_run_time * 100) if full_run_time > 0 else 0

        return {
            "full_run_time_ms": full_run_time,
            "selective_run_time_ms": selective_run_time,
            "savings_ms": savings_ms,
            "savings_pct": savings_pct,
            "tests_skipped": total_tests - result.total_tests_affected,
            "tests_to_run": result.total_tests_affected,
        }

    def _calculate_impact_level(
        self,
        change: CodeChange,
        risk_score: float,
    ) -> ImpactLevel:
        """Calculate impact level from change and risk."""
        # Critical: deletions of significant code
        if change.change_type == ChangeType.DELETED:
            return ImpactLevel.CRITICAL

        # High: many changes or function modifications
        if risk_score > 0.6 or len(change.modified_functions) > 3:
            return ImpactLevel.HIGH

        # Medium: moderate changes
        if risk_score > 0.3 or change.modified_functions:
            return ImpactLevel.MEDIUM

        # Low: minor changes
        return ImpactLevel.LOW

    def _calculate_priority(
        self,
        impact_level: ImpactLevel,
        risk_score: float,
    ) -> int:
        """Calculate execution priority (lower = higher priority)."""
        base_priority = {
            ImpactLevel.CRITICAL: 0,
            ImpactLevel.HIGH: 100,
            ImpactLevel.MEDIUM: 200,
            ImpactLevel.LOW: 300,
            ImpactLevel.NONE: 400,
        }.get(impact_level, 400)

        # Adjust by risk within level
        risk_adjustment = int((1 - risk_score) * 50)

        return base_priority + risk_adjustment

    def _generate_reason(self, change: CodeChange) -> str:
        """Generate a human-readable reason for impact."""
        parts = []

        if change.change_type == ChangeType.DELETED:
            parts.append(f"File '{change.file_path}' was deleted")
        elif change.change_type == ChangeType.ADDED:
            parts.append(f"New file '{change.file_path}' was added")
        else:
            parts.append(f"File '{change.file_path}' was modified")

        if change.modified_functions:
            funcs = ", ".join(change.modified_functions[:3])
            if len(change.modified_functions) > 3:
                funcs += f" (+{len(change.modified_functions) - 3} more)"
            parts.append(f"Changed functions: {funcs}")

        if change.modified_classes:
            classes = ", ".join(change.modified_classes[:2])
            parts.append(f"Changed classes: {classes}")

        return "; ".join(parts)

    def _generate_recommendations(
        self,
        changeset: ChangeSet,
        affected: List[AffectedTest],
        critical: int,
        high: int,
    ) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        if critical > 0:
            recommendations.append(
                f"🔴 {critical} critical tests should be run immediately before merging"
            )

        if high > 5:
            recommendations.append(
                f"🟡 Consider running the {high} high-priority tests in parallel"
            )

        if len(affected) > 50:
            recommendations.append(
                "Consider breaking this change into smaller commits for easier testing"
            )

        if changeset.total_deletions > changeset.total_additions:
            recommendations.append(
                "Deletion-heavy change - verify no functionality is broken"
            )

        categories = self.detector.categorize_changes(changeset)
        if len(categories["source_code"]) > 10:
            recommendations.append(
                f"Large change touching {len(categories['source_code'])} source files"
            )

        if not affected:
            recommendations.append(
                "No affected tests found - consider adding test coverage"
            )

        return recommendations

    def format_result(self, result: ImpactResult) -> str:
        """Format impact result as readable text."""
        lines = [
            "=" * 60,
            "  IMPACT ANALYSIS RESULT",
            "=" * 60,
            "",
            f"  Changeset: {result.changeset_id}",
            f"  Analyzed: {result.analyzed_at.strftime('%Y-%m-%d %H:%M')}",
            "",
            f"  Total Tests Affected: {result.total_tests_affected}",
            "",
            "-" * 60,
            "  IMPACT BREAKDOWN",
            "-" * 60,
            "",
            f"  🔴 Critical: {result.critical_count}",
            f"  🟠 High:     {result.high_count}",
            f"  🟡 Medium:   {result.medium_count}",
            f"  🟢 Low:      {result.low_count}",
            "",
            f"  Estimated Run Time: {result.estimated_run_time_ms // 1000}s",
            "",
        ]

        if result.affected_tests:
            lines.extend([
                "-" * 60,
                "  AFFECTED TESTS (Top 10)",
                "-" * 60,
            ])

            level_icons = {
                ImpactLevel.CRITICAL: "🔴",
                ImpactLevel.HIGH: "🟠",
                ImpactLevel.MEDIUM: "🟡",
                ImpactLevel.LOW: "🟢",
            }

            for test in result.affected_tests[:10]:
                icon = level_icons.get(test.impact_level, "⚪")
                lines.append(f"\n  {icon} {test.test_id}")
                lines.append(f"     Risk: {test.risk_score:.1%} | Priority: {test.priority}")
                lines.append(f"     Reason: {test.reason[:60]}...")

        if result.recommendations:
            lines.extend([
                "",
                "-" * 60,
                "  RECOMMENDATIONS",
                "-" * 60,
            ])

            for rec in result.recommendations:
                lines.append(f"  • {rec}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_impact_analyzer(
    dependency_mapper: Optional[DependencyMapper] = None,
    change_detector: Optional[ChangeDetector] = None,
) -> ImpactAnalyzer:
    """Create an impact analyzer instance."""
    return ImpactAnalyzer(dependency_mapper, change_detector)
