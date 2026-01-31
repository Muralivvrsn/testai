"""
TestAI Agent - Coverage Gap Analyzer

Identifies coverage gaps, prioritizes them by risk,
and generates recommendations for improving coverage.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set


class GapSeverity(Enum):
    """Severity of coverage gaps."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GapType(Enum):
    """Types of coverage gaps."""
    UNTESTED_FILE = "untested_file"
    UNTESTED_FUNCTION = "untested_function"
    LOW_BRANCH_COVERAGE = "low_branch_coverage"
    MISSING_EDGE_CASES = "missing_edge_cases"
    UNTESTED_ERROR_PATHS = "untested_error_paths"
    INTEGRATION_GAP = "integration_gap"
    DEPRECATED_TESTS = "deprecated_tests"


@dataclass
class CoverageGap:
    """A coverage gap that needs attention."""
    gap_id: str
    gap_type: GapType
    severity: GapSeverity
    location: str
    description: str
    impact_score: float
    recommended_tests: List[str]
    estimated_effort: str  # low, medium, high
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GapRecommendation:
    """Recommendation for closing a coverage gap."""
    recommendation_id: str
    gap_id: str
    priority: int
    title: str
    description: str
    test_scenarios: List[str]
    code_changes: Optional[str] = None


@dataclass
class GapReport:
    """Complete gap analysis report."""
    report_id: str
    timestamp: datetime
    total_gaps: int
    gaps_by_severity: Dict[str, int]
    gaps_by_type: Dict[str, int]
    gaps: List[CoverageGap]
    recommendations: List[GapRecommendation]
    overall_risk_score: float
    coverage_health: str  # healthy, at_risk, critical
    metadata: Dict[str, Any] = field(default_factory=dict)


class GapAnalyzer:
    """
    Analyze and identify coverage gaps.

    Features:
    - Gap identification
    - Risk scoring
    - Recommendation generation
    - Priority ranking
    """

    def __init__(
        self,
        min_coverage_threshold: float = 80.0,
        critical_paths: Optional[List[str]] = None,
        risk_weights: Optional[Dict[str, float]] = None,
    ):
        """Initialize the analyzer."""
        self._threshold = min_coverage_threshold
        self._critical_paths = set(critical_paths or [])
        self._risk_weights = risk_weights or {
            "authentication": 2.0,
            "payment": 2.5,
            "security": 2.5,
            "data": 1.5,
            "api": 1.5,
            "core": 1.8,
        }

        self._gaps: List[CoverageGap] = []
        self._reports: List[GapReport] = []
        self._gap_counter = 0
        self._report_counter = 0
        self._rec_counter = 0

    def analyze_coverage(
        self,
        coverage_data: Dict[str, Any],
        code_inventory: Optional[List[str]] = None,
    ) -> List[CoverageGap]:
        """Analyze coverage data for gaps."""
        gaps = []

        # Check for untested files
        tested_files = set(coverage_data.get("files", {}).keys())
        all_files = set(code_inventory or [])

        untested = all_files - tested_files
        for file_path in untested:
            gap = self._create_gap(
                gap_type=GapType.UNTESTED_FILE,
                location=file_path,
                description=f"File has no test coverage: {file_path}",
            )
            gaps.append(gap)

        # Check for low coverage files
        for file_path, file_data in coverage_data.get("files", {}).items():
            line_pct = file_data.get("line_coverage", 100)
            branch_pct = file_data.get("branch_coverage", 100)
            func_pct = file_data.get("function_coverage", 100)

            if line_pct < self._threshold:
                gap = self._create_gap(
                    gap_type=GapType.UNTESTED_FILE,
                    location=file_path,
                    description=f"Low line coverage ({line_pct:.1f}%): {file_path}",
                    metadata={"line_coverage": line_pct},
                )
                gaps.append(gap)

            if branch_pct < self._threshold:
                gap = self._create_gap(
                    gap_type=GapType.LOW_BRANCH_COVERAGE,
                    location=file_path,
                    description=f"Low branch coverage ({branch_pct:.1f}%): {file_path}",
                    metadata={"branch_coverage": branch_pct},
                )
                gaps.append(gap)

            # Check uncovered functions
            uncovered_funcs = file_data.get("uncovered_functions", [])
            for func_name in uncovered_funcs:
                gap = self._create_gap(
                    gap_type=GapType.UNTESTED_FUNCTION,
                    location=f"{file_path}::{func_name}",
                    description=f"Function not tested: {func_name}",
                )
                gaps.append(gap)

        # Check for missing error path coverage
        error_paths = coverage_data.get("error_paths", {})
        for path, covered in error_paths.items():
            if not covered:
                gap = self._create_gap(
                    gap_type=GapType.UNTESTED_ERROR_PATHS,
                    location=path,
                    description=f"Error handling path not tested: {path}",
                )
                gaps.append(gap)

        self._gaps.extend(gaps)
        return gaps

    def _create_gap(
        self,
        gap_type: GapType,
        location: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CoverageGap:
        """Create a coverage gap."""
        self._gap_counter += 1
        gap_id = f"GAP-{self._gap_counter:05d}"

        # Determine severity
        severity = self._calculate_severity(gap_type, location)

        # Calculate impact score
        impact = self._calculate_impact(gap_type, location)

        # Generate recommended tests
        recommended = self._generate_test_recommendations(gap_type, location)

        # Estimate effort
        effort = self._estimate_effort(gap_type)

        return CoverageGap(
            gap_id=gap_id,
            gap_type=gap_type,
            severity=severity,
            location=location,
            description=description,
            impact_score=impact,
            recommended_tests=recommended,
            estimated_effort=effort,
            metadata=metadata or {},
        )

    def _calculate_severity(
        self,
        gap_type: GapType,
        location: str,
    ) -> GapSeverity:
        """Calculate severity of a gap."""
        # Critical paths are always high severity
        for critical in self._critical_paths:
            if critical in location:
                return GapSeverity.CRITICAL

        # Check risk weights
        for keyword, weight in self._risk_weights.items():
            if keyword.lower() in location.lower():
                if weight >= 2.0:
                    return GapSeverity.CRITICAL if weight >= 2.5 else GapSeverity.HIGH
                elif weight >= 1.5:
                    return GapSeverity.MEDIUM

        # Default by gap type
        type_severity = {
            GapType.UNTESTED_FILE: GapSeverity.HIGH,
            GapType.UNTESTED_FUNCTION: GapSeverity.MEDIUM,
            GapType.LOW_BRANCH_COVERAGE: GapSeverity.MEDIUM,
            GapType.MISSING_EDGE_CASES: GapSeverity.LOW,
            GapType.UNTESTED_ERROR_PATHS: GapSeverity.HIGH,
            GapType.INTEGRATION_GAP: GapSeverity.HIGH,
            GapType.DEPRECATED_TESTS: GapSeverity.LOW,
        }

        return type_severity.get(gap_type, GapSeverity.MEDIUM)

    def _calculate_impact(
        self,
        gap_type: GapType,
        location: str,
    ) -> float:
        """Calculate impact score (0-1)."""
        base_impact = {
            GapType.UNTESTED_FILE: 0.8,
            GapType.UNTESTED_FUNCTION: 0.6,
            GapType.LOW_BRANCH_COVERAGE: 0.5,
            GapType.MISSING_EDGE_CASES: 0.3,
            GapType.UNTESTED_ERROR_PATHS: 0.7,
            GapType.INTEGRATION_GAP: 0.75,
            GapType.DEPRECATED_TESTS: 0.2,
        }.get(gap_type, 0.5)

        # Apply risk weight multiplier
        multiplier = 1.0
        for keyword, weight in self._risk_weights.items():
            if keyword.lower() in location.lower():
                multiplier = max(multiplier, weight / 2.0)

        return min(1.0, base_impact * multiplier)

    def _generate_test_recommendations(
        self,
        gap_type: GapType,
        location: str,
    ) -> List[str]:
        """Generate recommended test scenarios."""
        recommendations = []

        if gap_type == GapType.UNTESTED_FILE:
            recommendations.extend([
                f"Add unit tests for {location}",
                f"Add integration tests covering {location}",
                "Test happy path scenarios",
                "Test error handling",
            ])

        elif gap_type == GapType.UNTESTED_FUNCTION:
            func_name = location.split("::")[-1] if "::" in location else location
            recommendations.extend([
                f"Test {func_name} with valid inputs",
                f"Test {func_name} with edge cases",
                f"Test {func_name} with invalid inputs",
            ])

        elif gap_type == GapType.LOW_BRANCH_COVERAGE:
            recommendations.extend([
                "Add tests for uncovered branches",
                "Test conditional logic paths",
                "Test boundary conditions",
            ])

        elif gap_type == GapType.UNTESTED_ERROR_PATHS:
            recommendations.extend([
                "Test error handling code",
                "Verify error messages",
                "Test recovery scenarios",
            ])

        elif gap_type == GapType.INTEGRATION_GAP:
            recommendations.extend([
                "Add end-to-end test coverage",
                "Test component interactions",
                "Verify data flow between modules",
            ])

        return recommendations

    def _estimate_effort(self, gap_type: GapType) -> str:
        """Estimate effort to fix gap."""
        effort_map = {
            GapType.UNTESTED_FILE: "high",
            GapType.UNTESTED_FUNCTION: "medium",
            GapType.LOW_BRANCH_COVERAGE: "medium",
            GapType.MISSING_EDGE_CASES: "low",
            GapType.UNTESTED_ERROR_PATHS: "medium",
            GapType.INTEGRATION_GAP: "high",
            GapType.DEPRECATED_TESTS: "low",
        }
        return effort_map.get(gap_type, "medium")

    def add_gap(
        self,
        gap_type: GapType,
        location: str,
        description: str,
        severity: Optional[GapSeverity] = None,
    ) -> CoverageGap:
        """Manually add a coverage gap."""
        gap = self._create_gap(gap_type, location, description)
        if severity:
            gap.severity = severity
        self._gaps.append(gap)
        return gap

    def prioritize_gaps(
        self,
        gaps: Optional[List[CoverageGap]] = None,
    ) -> List[CoverageGap]:
        """Prioritize gaps by severity and impact."""
        gaps = gaps or self._gaps

        severity_order = {
            GapSeverity.CRITICAL: 0,
            GapSeverity.HIGH: 1,
            GapSeverity.MEDIUM: 2,
            GapSeverity.LOW: 3,
        }

        return sorted(
            gaps,
            key=lambda g: (severity_order[g.severity], -g.impact_score)
        )

    def generate_recommendations(
        self,
        gaps: Optional[List[CoverageGap]] = None,
        max_recommendations: int = 10,
    ) -> List[GapRecommendation]:
        """Generate recommendations for closing gaps."""
        gaps = gaps or self._gaps
        prioritized = self.prioritize_gaps(gaps)[:max_recommendations]

        recommendations = []
        for i, gap in enumerate(prioritized):
            self._rec_counter += 1
            rec_id = f"REC-{self._rec_counter:05d}"

            rec = GapRecommendation(
                recommendation_id=rec_id,
                gap_id=gap.gap_id,
                priority=i + 1,
                title=f"Address {gap.gap_type.value.replace('_', ' ').title()}",
                description=gap.description,
                test_scenarios=gap.recommended_tests,
            )
            recommendations.append(rec)

        return recommendations

    def generate_report(
        self,
        name: str = "Gap Analysis Report",
    ) -> GapReport:
        """Generate a complete gap analysis report."""
        self._report_counter += 1
        report_id = f"GAPRPT-{self._report_counter:05d}"

        # Count by severity
        severity_counts = {s.value: 0 for s in GapSeverity}
        for gap in self._gaps:
            severity_counts[gap.severity.value] += 1

        # Count by type
        type_counts = {t.value: 0 for t in GapType}
        for gap in self._gaps:
            type_counts[gap.gap_type.value] += 1

        # Calculate overall risk
        if not self._gaps:
            risk_score = 0.0
        else:
            risk_score = sum(g.impact_score for g in self._gaps) / len(self._gaps)

        # Determine health
        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)

        if critical_count > 0:
            health = "critical"
        elif high_count > 2:
            health = "at_risk"
        else:
            health = "healthy"

        # Generate recommendations
        recommendations = self.generate_recommendations()

        report = GapReport(
            report_id=report_id,
            timestamp=datetime.now(),
            total_gaps=len(self._gaps),
            gaps_by_severity=severity_counts,
            gaps_by_type=type_counts,
            gaps=self.prioritize_gaps(),
            recommendations=recommendations,
            overall_risk_score=risk_score,
            coverage_health=health,
            metadata={"name": name},
        )

        self._reports.append(report)
        return report

    def get_gaps_by_severity(
        self,
        severity: GapSeverity,
    ) -> List[CoverageGap]:
        """Get gaps of a specific severity."""
        return [g for g in self._gaps if g.severity == severity]

    def get_gaps_by_type(
        self,
        gap_type: GapType,
    ) -> List[CoverageGap]:
        """Get gaps of a specific type."""
        return [g for g in self._gaps if g.gap_type == gap_type]

    def get_critical_gaps(self) -> List[CoverageGap]:
        """Get all critical gaps."""
        return self.get_gaps_by_severity(GapSeverity.CRITICAL)

    def clear(self):
        """Clear all gaps."""
        self._gaps.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "total_gaps": len(self._gaps),
            "critical_gaps": len(self.get_gaps_by_severity(GapSeverity.CRITICAL)),
            "high_gaps": len(self.get_gaps_by_severity(GapSeverity.HIGH)),
            "total_reports": len(self._reports),
            "coverage_threshold": self._threshold,
        }

    def format_report(self, report: GapReport) -> str:
        """Format a gap report for display."""
        health_icons = {
            "healthy": "✅",
            "at_risk": "⚠️",
            "critical": "🚨",
        }

        lines = [
            "=" * 60,
            f"  GAP ANALYSIS REPORT",
            "=" * 60,
            "",
            f"  Report ID: {report.report_id}",
            f"  Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"  Coverage Health: {health_icons.get(report.coverage_health, '')} {report.coverage_health.upper()}",
            f"  Risk Score: {report.overall_risk_score:.2f}",
            "",
            "-" * 60,
            "  GAPS BY SEVERITY",
            "-" * 60,
            "",
        ]

        severity_icons = {
            "critical": "🚨",
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
        }

        for sev, count in report.gaps_by_severity.items():
            icon = severity_icons.get(sev, "")
            lines.append(f"  {icon} {sev.capitalize()}: {count}")

        lines.append("")

        # Top gaps
        if report.gaps:
            lines.append("-" * 60)
            lines.append("  TOP PRIORITY GAPS")
            lines.append("-" * 60)
            lines.append("")
            for gap in report.gaps[:5]:
                sev_icon = severity_icons.get(gap.severity.value, "")
                lines.append(f"  {sev_icon} [{gap.gap_id}] {gap.description[:50]}")
            if len(report.gaps) > 5:
                lines.append(f"  ... and {len(report.gaps) - 5} more")
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("-" * 60)
            lines.append("  RECOMMENDATIONS")
            lines.append("-" * 60)
            lines.append("")
            for rec in report.recommendations[:3]:
                lines.append(f"  {rec.priority}. {rec.title}")
                lines.append(f"     → {rec.description[:50]}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


def create_gap_analyzer(
    min_coverage_threshold: float = 80.0,
    critical_paths: Optional[List[str]] = None,
) -> GapAnalyzer:
    """Create a gap analyzer instance."""
    return GapAnalyzer(
        min_coverage_threshold=min_coverage_threshold,
        critical_paths=critical_paths,
    )
