"""
TestAI Agent - Test Reporter

Generates comprehensive test reports in multiple formats.
Provides actionable insights from test execution results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import json

from .simulator import SimulationResult, ExecutionStatus


class ReportFormat(Enum):
    """Available report formats."""
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


@dataclass
class TestReport:
    """Report for a single test execution."""
    test_id: str
    test_title: str
    status: str
    duration_ms: int
    error_message: Optional[str]
    step_count: int
    steps_passed: int
    steps_failed: int
    category: str
    priority: str


@dataclass
class CategoryStats:
    """Statistics for a test category."""
    category: str
    total: int
    passed: int
    failed: int
    pass_rate: float
    avg_duration_ms: int


@dataclass
class SuiteReport:
    """Comprehensive report for a test suite execution."""
    suite_name: str
    started_at: datetime
    finished_at: datetime
    total_duration_ms: int
    total_tests: int
    passed: int
    failed: int
    skipped: int
    flaky: int
    timeout: int
    error: int
    pass_rate: float
    test_reports: List[TestReport] = field(default_factory=list)
    category_stats: List[CategoryStats] = field(default_factory=list)
    failures: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class TestReporter:
    """
    Generates comprehensive test reports from execution results.

    Provides multiple output formats and actionable recommendations.
    """

    def __init__(self):
        """Initialize the reporter."""
        self._reports: List[SuiteReport] = []

    def generate_suite_report(
        self,
        results: List[SimulationResult],
        suite_name: str = "Test Suite",
    ) -> SuiteReport:
        """Generate a comprehensive report from simulation results."""
        if not results:
            return SuiteReport(
                suite_name=suite_name,
                started_at=datetime.now(),
                finished_at=datetime.now(),
                total_duration_ms=0,
                total_tests=0,
                passed=0,
                failed=0,
                skipped=0,
                flaky=0,
                timeout=0,
                error=0,
                pass_rate=0.0,
            )

        # Calculate timing
        started_at = min(r.started_at for r in results)
        finished_at = max(r.finished_at for r in results)
        total_duration_ms = sum(r.duration_ms for r in results)

        # Calculate status counts
        passed = sum(1 for r in results if r.status == ExecutionStatus.PASSED)
        failed = sum(1 for r in results if r.status == ExecutionStatus.FAILED)
        skipped = sum(1 for r in results if r.status == ExecutionStatus.SKIPPED)
        flaky = sum(1 for r in results if r.status == ExecutionStatus.FLAKY)
        timeout = sum(1 for r in results if r.status == ExecutionStatus.TIMEOUT)
        error = sum(1 for r in results if r.status == ExecutionStatus.ERROR)

        total_tests = len(results)
        pass_rate = passed / total_tests if total_tests > 0 else 0.0

        # Generate individual test reports
        test_reports = []
        for r in results:
            steps_passed = sum(1 for s in r.step_results if s.status == ExecutionStatus.PASSED)
            steps_failed = len(r.step_results) - steps_passed

            test_reports.append(TestReport(
                test_id=r.test_id,
                test_title=r.test_title,
                status=r.status.value,
                duration_ms=r.duration_ms,
                error_message=r.error_message,
                step_count=len(r.step_results),
                steps_passed=steps_passed,
                steps_failed=steps_failed,
                category=r.metadata.get("category", "functional"),
                priority=r.metadata.get("priority", "medium"),
            ))

        # Calculate category statistics
        category_stats = self._calculate_category_stats(results)

        # Collect failures
        failures = []
        for r in results:
            if r.status not in [ExecutionStatus.PASSED, ExecutionStatus.SKIPPED]:
                failures.append({
                    "test_id": r.test_id,
                    "test_title": r.test_title,
                    "status": r.status.value,
                    "error_type": r.error_type,
                    "error_message": r.error_message,
                    "category": r.metadata.get("category"),
                    "priority": r.metadata.get("priority"),
                })

        # Generate recommendations
        recommendations = self._generate_recommendations(results, category_stats)

        report = SuiteReport(
            suite_name=suite_name,
            started_at=started_at,
            finished_at=finished_at,
            total_duration_ms=total_duration_ms,
            total_tests=total_tests,
            passed=passed,
            failed=failed,
            skipped=skipped,
            flaky=flaky,
            timeout=timeout,
            error=error,
            pass_rate=pass_rate,
            test_reports=test_reports,
            category_stats=category_stats,
            failures=failures,
            recommendations=recommendations,
        )

        self._reports.append(report)
        return report

    def _calculate_category_stats(
        self,
        results: List[SimulationResult],
    ) -> List[CategoryStats]:
        """Calculate statistics per test category."""
        categories: Dict[str, List[SimulationResult]] = {}

        for r in results:
            category = r.metadata.get("category", "functional")
            if category not in categories:
                categories[category] = []
            categories[category].append(r)

        stats = []
        for category, cat_results in categories.items():
            total = len(cat_results)
            passed = sum(1 for r in cat_results if r.status == ExecutionStatus.PASSED)
            failed = total - passed
            pass_rate = passed / total if total > 0 else 0.0
            avg_duration = sum(r.duration_ms for r in cat_results) // total if total > 0 else 0

            stats.append(CategoryStats(
                category=category,
                total=total,
                passed=passed,
                failed=failed,
                pass_rate=pass_rate,
                avg_duration_ms=avg_duration,
            ))

        return sorted(stats, key=lambda s: s.pass_rate)

    def _generate_recommendations(
        self,
        results: List[SimulationResult],
        category_stats: List[CategoryStats],
    ) -> List[str]:
        """Generate actionable recommendations based on results."""
        recommendations = []

        # Check overall pass rate
        total = len(results)
        passed = sum(1 for r in results if r.status == ExecutionStatus.PASSED)
        pass_rate = passed / total if total > 0 else 0.0

        if pass_rate < 0.8:
            recommendations.append(
                f"Pass rate is {pass_rate:.1%}, below the 80% threshold. "
                "Consider reviewing failing tests for common patterns."
            )

        # Check for flaky tests
        flaky = sum(1 for r in results if r.status == ExecutionStatus.FLAKY)
        if flaky > 0:
            recommendations.append(
                f"Found {flaky} flaky test(s). Add retry logic or increase wait times "
                "for intermittently failing tests."
            )

        # Check for timeouts
        timeout = sum(1 for r in results if r.status == ExecutionStatus.TIMEOUT)
        if timeout > 0:
            recommendations.append(
                f"Found {timeout} timeout(s). Consider increasing timeout thresholds "
                "or optimizing slow operations."
            )

        # Check category-specific issues
        for stat in category_stats:
            if stat.pass_rate < 0.7 and stat.total >= 3:
                recommendations.append(
                    f"Category '{stat.category}' has {stat.pass_rate:.1%} pass rate. "
                    f"Review the {stat.failed} failing tests in this category."
                )

        # Check for high-priority failures
        high_priority_failures = [
            r for r in results
            if r.status not in [ExecutionStatus.PASSED, ExecutionStatus.SKIPPED]
            and r.metadata.get("priority") in ["critical", "high"]
        ]
        if high_priority_failures:
            recommendations.append(
                f"Found {len(high_priority_failures)} high-priority test failure(s). "
                "These should be addressed before deployment."
            )

        # Check for error patterns
        error_types = {}
        for r in results:
            if r.error_type:
                error_types[r.error_type] = error_types.get(r.error_type, 0) + 1

        for error_type, count in error_types.items():
            if count >= 3:
                recommendations.append(
                    f"Found {count} '{error_type}' errors. "
                    "This pattern suggests a systemic issue worth investigating."
                )

        if not recommendations:
            recommendations.append("All tests performing well. No immediate actions required.")

        return recommendations

    def format_report(
        self,
        report: SuiteReport,
        format: ReportFormat = ReportFormat.TEXT,
    ) -> str:
        """Format a report in the specified format."""
        if format == ReportFormat.TEXT:
            return self._format_text(report)
        elif format == ReportFormat.JSON:
            return self._format_json(report)
        elif format == ReportFormat.HTML:
            return self._format_html(report)
        elif format == ReportFormat.MARKDOWN:
            return self._format_markdown(report)
        else:
            return self._format_text(report)

    def _format_text(self, report: SuiteReport) -> str:
        """Format report as plain text."""
        lines = [
            "=" * 60,
            f"  TEST EXECUTION REPORT: {report.suite_name}",
            "=" * 60,
            "",
            f"  Started:  {report.started_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Finished: {report.finished_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Duration: {report.total_duration_ms}ms",
            "",
            "-" * 60,
            "  SUMMARY",
            "-" * 60,
            f"  Total Tests: {report.total_tests}",
            f"  Passed:      {report.passed} ({report.pass_rate:.1%})",
            f"  Failed:      {report.failed}",
            f"  Skipped:     {report.skipped}",
            f"  Flaky:       {report.flaky}",
            f"  Timeout:     {report.timeout}",
            f"  Error:       {report.error}",
            "",
        ]

        # Category breakdown
        if report.category_stats:
            lines.extend([
                "-" * 60,
                "  RESULTS BY CATEGORY",
                "-" * 60,
            ])
            for stat in report.category_stats:
                status_bar = self._create_status_bar(stat.pass_rate)
                lines.append(
                    f"  {stat.category:15} {status_bar} "
                    f"{stat.passed}/{stat.total} ({stat.pass_rate:.1%})"
                )
            lines.append("")

        # Failures
        if report.failures:
            lines.extend([
                "-" * 60,
                "  FAILURES",
                "-" * 60,
            ])
            for failure in report.failures[:10]:  # Limit to 10
                lines.append(f"  [{failure['status'].upper()}] {failure['test_title']}")
                if failure['error_message']:
                    lines.append(f"    > {failure['error_message'][:80]}")
            if len(report.failures) > 10:
                lines.append(f"  ... and {len(report.failures) - 10} more failures")
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.extend([
                "-" * 60,
                "  RECOMMENDATIONS",
                "-" * 60,
            ])
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def _format_json(self, report: SuiteReport) -> str:
        """Format report as JSON."""
        data = {
            "suite_name": report.suite_name,
            "started_at": report.started_at.isoformat(),
            "finished_at": report.finished_at.isoformat(),
            "total_duration_ms": report.total_duration_ms,
            "summary": {
                "total_tests": report.total_tests,
                "passed": report.passed,
                "failed": report.failed,
                "skipped": report.skipped,
                "flaky": report.flaky,
                "timeout": report.timeout,
                "error": report.error,
                "pass_rate": report.pass_rate,
            },
            "category_stats": [
                {
                    "category": s.category,
                    "total": s.total,
                    "passed": s.passed,
                    "failed": s.failed,
                    "pass_rate": s.pass_rate,
                    "avg_duration_ms": s.avg_duration_ms,
                }
                for s in report.category_stats
            ],
            "failures": report.failures,
            "recommendations": report.recommendations,
            "test_reports": [
                {
                    "test_id": t.test_id,
                    "test_title": t.test_title,
                    "status": t.status,
                    "duration_ms": t.duration_ms,
                    "category": t.category,
                    "priority": t.priority,
                }
                for t in report.test_reports
            ],
        }
        return json.dumps(data, indent=2)

    def _format_html(self, report: SuiteReport) -> str:
        """Format report as HTML."""
        status_color = "#4caf50" if report.pass_rate >= 0.8 else "#f44336"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Test Report: {report.suite_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 24px; }}
        h1 {{ color: #333; border-bottom: 2px solid {status_color}; padding-bottom: 12px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
        .stat {{ background: #f9f9f9; padding: 16px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #333; }}
        .stat-label {{ color: #666; font-size: 14px; }}
        .passed {{ color: #4caf50; }}
        .failed {{ color: #f44336; }}
        .section {{ margin: 24px 0; }}
        .section h2 {{ color: #555; font-size: 18px; border-bottom: 1px solid #eee; padding-bottom: 8px; }}
        .failure {{ background: #fff3f3; padding: 12px; border-left: 4px solid #f44336; margin: 8px 0; border-radius: 4px; }}
        .recommendation {{ background: #fff8e1; padding: 12px; border-left: 4px solid #ff9800; margin: 8px 0; border-radius: 4px; }}
        .progress {{ height: 8px; background: #eee; border-radius: 4px; overflow: hidden; }}
        .progress-bar {{ height: 100%; background: {status_color}; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Test Report: {report.suite_name}</h1>

        <div class="summary">
            <div class="stat">
                <div class="stat-value">{report.total_tests}</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat">
                <div class="stat-value passed">{report.passed}</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat">
                <div class="stat-value failed">{report.failed}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat">
                <div class="stat-value">{report.pass_rate:.1%}</div>
                <div class="stat-label">Pass Rate</div>
            </div>
        </div>

        <div class="progress">
            <div class="progress-bar" style="width: {report.pass_rate * 100}%;"></div>
        </div>

        <div class="section">
            <h2>Failures ({len(report.failures)})</h2>
"""

        for failure in report.failures[:10]:
            html += f"""            <div class="failure">
                <strong>[{failure['status'].upper()}]</strong> {failure['test_title']}<br>
                <small>{failure.get('error_message', 'No error message')}</small>
            </div>
"""

        html += """        </div>

        <div class="section">
            <h2>Recommendations</h2>
"""

        for rec in report.recommendations:
            html += f"""            <div class="recommendation">{rec}</div>
"""

        html += """        </div>
    </div>
</body>
</html>"""
        return html

    def _format_markdown(self, report: SuiteReport) -> str:
        """Format report as Markdown."""
        lines = [
            f"# Test Report: {report.suite_name}",
            "",
            f"**Duration:** {report.total_duration_ms}ms  ",
            f"**Started:** {report.started_at.strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Finished:** {report.finished_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Tests | {report.total_tests} |",
            f"| Passed | {report.passed} |",
            f"| Failed | {report.failed} |",
            f"| Skipped | {report.skipped} |",
            f"| Pass Rate | {report.pass_rate:.1%} |",
            "",
        ]

        # Category stats
        if report.category_stats:
            lines.extend([
                "## Results by Category",
                "",
                "| Category | Passed | Failed | Pass Rate |",
                "|----------|--------|--------|-----------|",
            ])
            for stat in report.category_stats:
                lines.append(
                    f"| {stat.category} | {stat.passed} | {stat.failed} | {stat.pass_rate:.1%} |"
                )
            lines.append("")

        # Failures
        if report.failures:
            lines.extend([
                "## Failures",
                "",
            ])
            for failure in report.failures[:10]:
                lines.append(f"### {failure['test_title']}")
                lines.append(f"- **Status:** {failure['status']}")
                if failure.get('error_message'):
                    lines.append(f"- **Error:** {failure['error_message']}")
                lines.append("")

        # Recommendations
        if report.recommendations:
            lines.extend([
                "## Recommendations",
                "",
            ])
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        return "\n".join(lines)

    def _create_status_bar(self, pass_rate: float, width: int = 20) -> str:
        """Create a text-based status bar."""
        filled = int(pass_rate * width)
        empty = width - filled
        return f"[{'=' * filled}{' ' * empty}]"

    def get_all_reports(self) -> List[SuiteReport]:
        """Get all generated reports."""
        return self._reports


def create_reporter() -> TestReporter:
    """Create a test reporter instance."""
    return TestReporter()
