"""
TestAI Agent - Coverage Report Generator

Generates test coverage reports with feature tracking,
gap analysis, and improvement recommendations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class CoverageLevel(Enum):
    """Coverage level indicators."""
    FULL = "full"
    PARTIAL = "partial"
    MINIMAL = "minimal"
    NONE = "none"


class CoverageType(Enum):
    """Types of coverage being tracked."""
    FEATURE = "feature"
    REQUIREMENT = "requirement"
    USER_STORY = "user_story"
    API_ENDPOINT = "api_endpoint"
    UI_COMPONENT = "ui_component"


@dataclass
class FeatureCoverage:
    """Coverage data for a feature."""
    feature_id: str
    name: str
    description: str
    coverage_type: CoverageType
    level: CoverageLevel
    test_count: int
    passing_tests: int
    failing_tests: int
    skipped_tests: int
    test_ids: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    notes: str = ""

    @property
    def coverage_percent(self) -> float:
        """Calculate coverage percentage based on passing tests."""
        if self.test_count == 0:
            return 0.0
        return (self.passing_tests / self.test_count) * 100


@dataclass
class CoverageReport:
    """A complete coverage report."""
    report_id: str
    title: str
    project: str
    version: str
    features: List[FeatureCoverage]
    overall_coverage: float
    total_tests: int
    passing_tests: int
    failing_tests: int
    skipped_tests: int
    gaps: List[str]
    recommendations: List[str]
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = "TestAI Agent"


class CoverageReportGenerator:
    """
    Generates test coverage reports.

    Features:
    - Feature-level coverage tracking
    - Gap analysis
    - Trend comparison
    - Recommendations
    """

    def __init__(self):
        """Initialize the coverage report generator."""
        self._report_counter = 0
        self._feature_counter = 0
        self._reports: Dict[str, CoverageReport] = {}

    def create_report(
        self,
        title: str,
        project: str,
        version: str = "1.0",
    ) -> CoverageReport:
        """Create a new coverage report."""
        self._report_counter += 1

        report = CoverageReport(
            report_id=f"CR-{self._report_counter:04d}",
            title=title,
            project=project,
            version=version,
            features=[],
            overall_coverage=0.0,
            total_tests=0,
            passing_tests=0,
            failing_tests=0,
            skipped_tests=0,
            gaps=[],
            recommendations=[],
        )

        self._reports[report.report_id] = report
        return report

    def add_feature(
        self,
        report: CoverageReport,
        name: str,
        description: str,
        coverage_type: CoverageType = CoverageType.FEATURE,
        test_count: int = 0,
        passing_tests: int = 0,
        failing_tests: int = 0,
        skipped_tests: int = 0,
        test_ids: Optional[List[str]] = None,
        gaps: Optional[List[str]] = None,
    ) -> FeatureCoverage:
        """Add a feature to the coverage report."""
        self._feature_counter += 1

        # Determine coverage level
        if test_count == 0:
            level = CoverageLevel.NONE
        elif passing_tests == test_count:
            level = CoverageLevel.FULL
        elif passing_tests >= test_count * 0.7:
            level = CoverageLevel.PARTIAL
        elif passing_tests > 0:
            level = CoverageLevel.MINIMAL
        else:
            level = CoverageLevel.NONE

        feature = FeatureCoverage(
            feature_id=f"FC-{self._feature_counter:04d}",
            name=name,
            description=description,
            coverage_type=coverage_type,
            level=level,
            test_count=test_count,
            passing_tests=passing_tests,
            failing_tests=failing_tests,
            skipped_tests=skipped_tests,
            test_ids=test_ids or [],
            gaps=gaps or [],
        )

        report.features.append(feature)
        self._update_report_totals(report)
        return feature

    def _update_report_totals(self, report: CoverageReport):
        """Update report totals from features."""
        report.total_tests = sum(f.test_count for f in report.features)
        report.passing_tests = sum(f.passing_tests for f in report.features)
        report.failing_tests = sum(f.failing_tests for f in report.features)
        report.skipped_tests = sum(f.skipped_tests for f in report.features)

        if report.total_tests > 0:
            report.overall_coverage = (report.passing_tests / report.total_tests) * 100
        else:
            report.overall_coverage = 0.0

    def analyze_gaps(self, report: CoverageReport) -> List[str]:
        """Analyze and identify coverage gaps."""
        gaps = []

        for feature in report.features:
            if feature.level == CoverageLevel.NONE:
                gaps.append(f"No tests for '{feature.name}'")
            elif feature.level == CoverageLevel.MINIMAL:
                gaps.append(f"Minimal coverage for '{feature.name}' ({feature.coverage_percent:.1f}%)")

            # Add feature-specific gaps
            gaps.extend(feature.gaps)

            # Check for failing tests
            if feature.failing_tests > 0:
                gaps.append(f"'{feature.name}' has {feature.failing_tests} failing test(s)")

        report.gaps = gaps
        return gaps

    def generate_recommendations(self, report: CoverageReport) -> List[str]:
        """Generate recommendations for improving coverage."""
        recommendations = []

        # Overall coverage recommendations
        if report.overall_coverage < 50:
            recommendations.append(
                f"CRITICAL: Overall coverage is {report.overall_coverage:.1f}%. "
                "Aim for at least 80% coverage."
            )
        elif report.overall_coverage < 80:
            recommendations.append(
                f"Coverage at {report.overall_coverage:.1f}%. "
                "Consider adding more tests to reach 80%."
            )

        # Feature-specific recommendations
        uncovered = [f for f in report.features if f.level == CoverageLevel.NONE]
        if uncovered:
            names = ", ".join(f.name for f in uncovered[:3])
            recommendations.append(
                f"Add tests for uncovered features: {names}"
                + (f" (+{len(uncovered)-3} more)" if len(uncovered) > 3 else "")
            )

        minimal = [f for f in report.features if f.level == CoverageLevel.MINIMAL]
        if minimal:
            names = ", ".join(f.name for f in minimal[:3])
            recommendations.append(
                f"Improve coverage for: {names}"
            )

        # Failing tests recommendation
        if report.failing_tests > 0:
            recommendations.append(
                f"Fix {report.failing_tests} failing test(s) before adding new coverage"
            )

        # Skipped tests recommendation
        if report.skipped_tests > 5:
            recommendations.append(
                f"Review {report.skipped_tests} skipped tests - consider removing or fixing"
            )

        report.recommendations = recommendations
        return recommendations

    def compare_reports(
        self,
        current: CoverageReport,
        previous: CoverageReport,
    ) -> Dict[str, Any]:
        """Compare two coverage reports."""
        coverage_change = current.overall_coverage - previous.overall_coverage
        test_change = current.total_tests - previous.total_tests
        passing_change = current.passing_tests - previous.passing_tests

        # Find new and removed features
        current_features = {f.name for f in current.features}
        previous_features = {f.name for f in previous.features}

        new_features = current_features - previous_features
        removed_features = previous_features - current_features

        # Calculate feature-level changes
        feature_changes = []
        for feature in current.features:
            prev_feature = next(
                (f for f in previous.features if f.name == feature.name),
                None
            )
            if prev_feature:
                change = feature.coverage_percent - prev_feature.coverage_percent
                if abs(change) > 0.1:  # Only report significant changes
                    feature_changes.append({
                        "name": feature.name,
                        "previous": prev_feature.coverage_percent,
                        "current": feature.coverage_percent,
                        "change": change,
                    })

        return {
            "coverage_change": coverage_change,
            "coverage_improved": coverage_change > 0,
            "test_count_change": test_change,
            "passing_change": passing_change,
            "new_features": list(new_features),
            "removed_features": list(removed_features),
            "feature_changes": feature_changes,
            "summary": self._generate_comparison_summary(
                coverage_change, test_change, passing_change
            ),
        }

    def _generate_comparison_summary(
        self,
        coverage_change: float,
        test_change: int,
        passing_change: int,
    ) -> str:
        """Generate a summary of the comparison."""
        parts = []

        if coverage_change > 0:
            parts.append(f"Coverage improved by {coverage_change:.1f}%")
        elif coverage_change < 0:
            parts.append(f"Coverage decreased by {abs(coverage_change):.1f}%")
        else:
            parts.append("Coverage unchanged")

        if test_change > 0:
            parts.append(f"{test_change} new tests added")
        elif test_change < 0:
            parts.append(f"{abs(test_change)} tests removed")

        if passing_change > 0:
            parts.append(f"{passing_change} more tests passing")
        elif passing_change < 0:
            parts.append(f"{abs(passing_change)} fewer tests passing")

        return ". ".join(parts) + "."

    def format_report(
        self,
        report: CoverageReport,
        format: str = "markdown",
    ) -> str:
        """Format coverage report as text."""
        if format == "markdown":
            return self._format_markdown(report)
        return str(report)

    def _format_markdown(self, report: CoverageReport) -> str:
        """Format report as Markdown."""
        lines = [
            f"# {report.title}",
            "",
            f"**Project:** {report.project}",
            f"**Version:** {report.version}",
            f"**Generated:** {report.created_at.strftime('%Y-%m-%d %H:%M')}",
            f"**Author:** {report.created_by}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Overall Coverage | {report.overall_coverage:.1f}% |",
            f"| Total Tests | {report.total_tests} |",
            f"| Passing | {report.passing_tests} |",
            f"| Failing | {report.failing_tests} |",
            f"| Skipped | {report.skipped_tests} |",
            "",
            "## Feature Coverage",
            "",
        ]

        # Coverage level icons
        level_icons = {
            CoverageLevel.FULL: "🟢",
            CoverageLevel.PARTIAL: "🟡",
            CoverageLevel.MINIMAL: "🟠",
            CoverageLevel.NONE: "🔴",
        }

        for feature in report.features:
            icon = level_icons.get(feature.level, "⚪")
            lines.extend([
                f"### {icon} {feature.name}",
                "",
                f"**Coverage:** {feature.coverage_percent:.1f}% ({feature.level.value})",
                f"**Tests:** {feature.test_count} total, "
                f"{feature.passing_tests} passing, "
                f"{feature.failing_tests} failing",
                "",
                feature.description,
                "",
            ])

            if feature.gaps:
                lines.append("**Gaps:**")
                for gap in feature.gaps:
                    lines.append(f"- {gap}")
                lines.append("")

        # Gaps section
        if report.gaps:
            lines.extend([
                "## Coverage Gaps",
                "",
            ])
            for gap in report.gaps:
                lines.append(f"- {gap}")
            lines.append("")

        # Recommendations section
        if report.recommendations:
            lines.extend([
                "## Recommendations",
                "",
            ])
            for rec in report.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        return "\n".join(lines)

    def get_report(self, report_id: str) -> Optional[CoverageReport]:
        """Get a report by ID."""
        return self._reports.get(report_id)

    def get_feature_by_type(
        self,
        report: CoverageReport,
        coverage_type: CoverageType,
    ) -> List[FeatureCoverage]:
        """Get features filtered by type."""
        return [f for f in report.features if f.coverage_type == coverage_type]

    def get_low_coverage_features(
        self,
        report: CoverageReport,
        threshold: float = 70.0,
    ) -> List[FeatureCoverage]:
        """Get features below coverage threshold."""
        return [
            f for f in report.features
            if f.coverage_percent < threshold
        ]


def create_coverage_report_generator() -> CoverageReportGenerator:
    """Create a coverage report generator instance."""
    return CoverageReportGenerator()
