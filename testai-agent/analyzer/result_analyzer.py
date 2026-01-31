"""
TestAI Agent - Test Result Analyzer

Analyzes test execution results to identify patterns, learn from failures,
and provide actionable recommendations for improving test quality.

Features:
- Failure pattern detection
- Flaky test identification
- Coverage gap analysis
- Trend tracking over time
- AI-powered recommendations
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from datetime import datetime, timedelta
from collections import Counter
import json
import re


class TestStatus(Enum):
    """Status of a test execution."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    FLAKY = "flaky"


class FailureType(Enum):
    """Type of test failure."""
    ASSERTION = "assertion"       # Expected vs actual mismatch
    TIMEOUT = "timeout"           # Test took too long
    ELEMENT_NOT_FOUND = "element_not_found"  # Selector failed
    NETWORK_ERROR = "network_error"  # API/request failed
    CRASH = "crash"               # Application crash
    SETUP_FAILURE = "setup_failure"  # Precondition failed
    UNKNOWN = "unknown"


class Severity(Enum):
    """Severity of an issue."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TestRunResult:
    """Result of a single test execution."""
    test_id: str
    test_title: str
    status: TestStatus
    duration_ms: float
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    screenshot_path: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_id": self.test_id,
            "test_title": self.test_title,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class FailurePattern:
    """A detected pattern in test failures."""
    pattern_type: FailureType
    description: str
    occurrence_count: int
    affected_tests: List[str]
    severity: Severity
    suggested_fix: str
    confidence: float  # 0-1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern_type": self.pattern_type.value,
            "description": self.description,
            "occurrence_count": self.occurrence_count,
            "affected_tests": self.affected_tests,
            "severity": self.severity.value,
            "suggested_fix": self.suggested_fix,
            "confidence": self.confidence,
        }


@dataclass
class Recommendation:
    """A recommendation for improving tests."""
    title: str
    description: str
    priority: Severity
    category: str  # stability, coverage, performance, maintenance
    action_items: List[str]
    estimated_impact: str  # Description of expected improvement

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "category": self.category,
            "action_items": self.action_items,
            "estimated_impact": self.estimated_impact,
        }


@dataclass
class AnalysisReport:
    """Complete analysis report for a test run."""
    run_id: str
    analyzed_at: datetime
    total_tests: int
    passed_count: int
    failed_count: int
    skipped_count: int
    error_count: int
    flaky_count: int
    pass_rate: float
    average_duration_ms: float
    failure_patterns: List[FailurePattern]
    recommendations: List[Recommendation]
    trends: Dict[str, Any]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "run_id": self.run_id,
            "analyzed_at": self.analyzed_at.isoformat(),
            "total_tests": self.total_tests,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "skipped_count": self.skipped_count,
            "error_count": self.error_count,
            "flaky_count": self.flaky_count,
            "pass_rate": self.pass_rate,
            "average_duration_ms": self.average_duration_ms,
            "failure_patterns": [p.to_dict() for p in self.failure_patterns],
            "recommendations": [r.to_dict() for r in self.recommendations],
            "trends": self.trends,
            "summary": self.summary,
        }

    def format_markdown(self) -> str:
        """Format as Markdown report."""
        lines = []

        # Header
        lines.append(f"# Test Analysis Report")
        lines.append(f"\n**Run ID:** {self.run_id}")
        lines.append(f"**Analyzed:** {self.analyzed_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append("")

        # Summary stats
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Tests | {self.total_tests} |")
        lines.append(f"| Passed | {self.passed_count} |")
        lines.append(f"| Failed | {self.failed_count} |")
        lines.append(f"| Skipped | {self.skipped_count} |")
        lines.append(f"| Pass Rate | {self.pass_rate:.1%} |")
        lines.append(f"| Avg Duration | {self.average_duration_ms:.0f}ms |")
        lines.append("")

        # Pass/Fail visualization
        passed_bar = "█" * int(self.pass_rate * 20)
        failed_bar = "░" * (20 - int(self.pass_rate * 20))
        lines.append(f"```")
        lines.append(f"[{passed_bar}{failed_bar}] {self.pass_rate:.1%}")
        lines.append(f"```")
        lines.append("")

        # Failure patterns
        if self.failure_patterns:
            lines.append("## Failure Patterns")
            lines.append("")
            for pattern in self.failure_patterns:
                severity_emoji = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🟢",
                }[pattern.severity]

                lines.append(f"### {severity_emoji} {pattern.pattern_type.value.replace('_', ' ').title()}")
                lines.append(f"\n{pattern.description}")
                lines.append(f"\n**Occurrences:** {pattern.occurrence_count}")
                lines.append(f"**Confidence:** {pattern.confidence:.0%}")
                lines.append(f"\n**Suggested Fix:** {pattern.suggested_fix}")
                lines.append(f"\n**Affected Tests:**")
                for test_id in pattern.affected_tests[:5]:
                    lines.append(f"- {test_id}")
                if len(pattern.affected_tests) > 5:
                    lines.append(f"- ... and {len(pattern.affected_tests) - 5} more")
                lines.append("")

        # Recommendations
        if self.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(self.recommendations, 1):
                priority_emoji = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🟢",
                }[rec.priority]

                lines.append(f"### {i}. {priority_emoji} {rec.title}")
                lines.append(f"\n{rec.description}")
                lines.append(f"\n**Category:** {rec.category}")
                lines.append(f"**Expected Impact:** {rec.estimated_impact}")
                lines.append(f"\n**Action Items:**")
                for item in rec.action_items:
                    lines.append(f"- {item}")
                lines.append("")

        # Trends
        if self.trends:
            lines.append("## Trends")
            lines.append("")
            if "pass_rate_trend" in self.trends:
                trend = self.trends["pass_rate_trend"]
                trend_arrow = "↑" if trend > 0 else "↓" if trend < 0 else "→"
                lines.append(f"- Pass rate {trend_arrow} {abs(trend):.1%} from last run")
            if "duration_trend" in self.trends:
                trend = self.trends["duration_trend"]
                trend_arrow = "↑" if trend > 0 else "↓" if trend < 0 else "→"
                lines.append(f"- Avg duration {trend_arrow} {abs(trend):.0f}ms from last run")
            lines.append("")

        # Summary
        lines.append("## Overall Assessment")
        lines.append("")
        lines.append(self.summary)

        return "\n".join(lines)


class TestResultAnalyzer:
    """
    Analyzes test results and provides insights.

    Tracks test execution history, detects patterns in failures,
    identifies flaky tests, and provides actionable recommendations.

    Usage:
        analyzer = TestResultAnalyzer()

        # Add test results
        analyzer.add_result(TestRunResult(
            test_id="TC-001",
            test_title="Login Test",
            status=TestStatus.FAILED,
            duration_ms=1500,
            error_message="Element not found: #login-button",
        ))

        # Get analysis
        report = analyzer.analyze()
        print(report.format_markdown())
    """

    # Error message patterns for classification
    ERROR_PATTERNS = {
        FailureType.TIMEOUT: [
            r"timeout",
            r"timed?\s*out",
            r"exceeded.*time",
            r"response took too long",
        ],
        FailureType.ELEMENT_NOT_FOUND: [
            r"element.*not found",
            r"selector.*failed",
            r"could not find",
            r"no such element",
            r"unable to locate",
        ],
        FailureType.NETWORK_ERROR: [
            r"network.*error",
            r"connection.*refused",
            r"ECONNREFUSED",
            r"failed to fetch",
            r"net::ERR",
            r"api.*error",
        ],
        FailureType.ASSERTION: [
            r"assertion.*failed",
            r"expected.*but got",
            r"not equal",
            r"does not match",
            r"assert.*error",
        ],
        FailureType.CRASH: [
            r"crash",
            r"segfault",
            r"out of memory",
            r"unhandled.*exception",
        ],
        FailureType.SETUP_FAILURE: [
            r"setup.*failed",
            r"precondition",
            r"before.*hook",
            r"initialization.*error",
        ],
    }

    def __init__(self):
        """Initialize analyzer."""
        self.results: List[TestRunResult] = []
        self.history: List[AnalysisReport] = []
        self._run_counter = 0

    def add_result(self, result: TestRunResult):
        """Add a test result."""
        self.results.append(result)

    def add_results(self, results: List[TestRunResult]):
        """Add multiple test results."""
        self.results.extend(results)

    def add_results_from_dict(self, results: List[Dict[str, Any]]):
        """Add results from dictionary format."""
        for r in results:
            self.add_result(TestRunResult(
                test_id=r.get("test_id", r.get("id", "unknown")),
                test_title=r.get("test_title", r.get("title", "Unknown Test")),
                status=TestStatus(r.get("status", "passed")),
                duration_ms=r.get("duration_ms", 0),
                error_message=r.get("error_message") or r.get("error"),
                metadata=r.get("metadata", {}),
            ))

    def clear(self):
        """Clear current results (keep history)."""
        self.results = []

    def _classify_error(self, error_message: Optional[str]) -> FailureType:
        """Classify an error message into a failure type."""
        if not error_message:
            return FailureType.UNKNOWN

        error_lower = error_message.lower()

        for failure_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_lower, re.IGNORECASE):
                    return failure_type

        return FailureType.UNKNOWN

    def _detect_patterns(self) -> List[FailurePattern]:
        """Detect patterns in test failures."""
        patterns = []

        # Get failed results
        failed = [r for r in self.results if r.status in [TestStatus.FAILED, TestStatus.ERROR]]

        if not failed:
            return patterns

        # Group by failure type
        by_type: Dict[FailureType, List[TestRunResult]] = {}
        for result in failed:
            failure_type = self._classify_error(result.error_message)
            if failure_type not in by_type:
                by_type[failure_type] = []
            by_type[failure_type].append(result)

        # Create patterns for each failure type
        for failure_type, results in by_type.items():
            if len(results) == 0:
                continue

            # Determine severity based on count and type
            if failure_type in [FailureType.CRASH, FailureType.SETUP_FAILURE]:
                severity = Severity.CRITICAL
            elif len(results) >= 5:
                severity = Severity.HIGH
            elif len(results) >= 2:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Generate suggested fix
            suggested_fix = self._suggest_fix(failure_type, results)

            patterns.append(FailurePattern(
                pattern_type=failure_type,
                description=self._describe_pattern(failure_type, results),
                occurrence_count=len(results),
                affected_tests=[r.test_id for r in results],
                severity=severity,
                suggested_fix=suggested_fix,
                confidence=0.8 if failure_type != FailureType.UNKNOWN else 0.5,
            ))

        # Sort by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        patterns.sort(key=lambda p: severity_order[p.severity])

        return patterns

    def _describe_pattern(self, failure_type: FailureType, results: List[TestRunResult]) -> str:
        """Generate a description for a failure pattern."""
        count = len(results)

        descriptions = {
            FailureType.TIMEOUT: f"{count} tests failed due to timeout. Tests may be waiting too long for elements or responses.",
            FailureType.ELEMENT_NOT_FOUND: f"{count} tests failed because elements could not be found. Selectors may be incorrect or elements may not be loaded.",
            FailureType.NETWORK_ERROR: f"{count} tests failed due to network errors. API endpoints may be unreachable or returning errors.",
            FailureType.ASSERTION: f"{count} tests failed assertion checks. Expected values don't match actual values.",
            FailureType.CRASH: f"{count} tests caused crashes. There may be serious bugs in the application.",
            FailureType.SETUP_FAILURE: f"{count} tests failed during setup. Test preconditions may not be met.",
            FailureType.UNKNOWN: f"{count} tests failed with unclassified errors.",
        }

        return descriptions.get(failure_type, f"{count} tests failed with {failure_type.value} errors.")

    def _suggest_fix(self, failure_type: FailureType, results: List[TestRunResult]) -> str:
        """Suggest a fix for a failure pattern."""
        suggestions = {
            FailureType.TIMEOUT: "Increase wait times, add explicit waits, or check if elements are loading slowly.",
            FailureType.ELEMENT_NOT_FOUND: "Verify selectors are correct, add wait for element visibility, or check if the page structure changed.",
            FailureType.NETWORK_ERROR: "Check API availability, verify endpoints are correct, add retry logic for transient failures.",
            FailureType.ASSERTION: "Review expected values, check if application behavior changed, or update test expectations.",
            FailureType.CRASH: "Investigate crash logs, check for memory leaks, review recent code changes.",
            FailureType.SETUP_FAILURE: "Verify test data, check database state, ensure dependencies are available.",
            FailureType.UNKNOWN: "Review error messages in detail, add better error handling and logging.",
        }

        return suggestions.get(failure_type, "Review test implementation and error details.")

    def _generate_recommendations(
        self,
        patterns: List[FailurePattern],
        pass_rate: float,
        avg_duration: float,
    ) -> List[Recommendation]:
        """Generate recommendations based on analysis."""
        recommendations = []

        # Critical recommendations based on pass rate
        if pass_rate < 0.5:
            recommendations.append(Recommendation(
                title="Critical: Low Pass Rate",
                description=f"Only {pass_rate:.0%} of tests are passing. This indicates serious issues that need immediate attention.",
                priority=Severity.CRITICAL,
                category="stability",
                action_items=[
                    "Review and fix critical failure patterns first",
                    "Consider pausing feature development to stabilize tests",
                    "Investigate if recent changes broke the test suite",
                ],
                estimated_impact="Could improve pass rate by 30-50%",
            ))

        # Recommendations based on failure patterns
        for pattern in patterns:
            if pattern.pattern_type == FailureType.ELEMENT_NOT_FOUND and pattern.occurrence_count >= 3:
                recommendations.append(Recommendation(
                    title="Improve Selector Stability",
                    description="Multiple tests are failing due to element selectors not finding elements.",
                    priority=Severity.HIGH,
                    category="stability",
                    action_items=[
                        "Use more stable selectors (data-testid, aria-label)",
                        "Add explicit waits before interacting with elements",
                        "Consider using retry logic for flaky selectors",
                    ],
                    estimated_impact="Could fix 30-50% of failures",
                ))

            if pattern.pattern_type == FailureType.TIMEOUT and pattern.occurrence_count >= 2:
                recommendations.append(Recommendation(
                    title="Address Timeout Issues",
                    description="Tests are timing out, possibly due to slow page loads or unresponsive elements.",
                    priority=Severity.MEDIUM,
                    category="performance",
                    action_items=[
                        "Increase timeout values for slow operations",
                        "Add loading state detection",
                        "Investigate application performance",
                    ],
                    estimated_impact="Could fix 20-30% of failures",
                ))

        # Performance recommendation
        if avg_duration > 10000:  # More than 10 seconds
            recommendations.append(Recommendation(
                title="Optimize Test Duration",
                description=f"Average test duration is {avg_duration/1000:.1f} seconds, which is quite slow.",
                priority=Severity.LOW,
                category="performance",
                action_items=[
                    "Identify slow tests and optimize them",
                    "Consider parallel test execution",
                    "Use faster selectors and reduce waits",
                ],
                estimated_impact="Could reduce total test time by 20-40%",
            ))

        # Flaky test recommendation
        flaky_count = sum(1 for r in self.results if r.status == TestStatus.FLAKY)
        if flaky_count > 0:
            recommendations.append(Recommendation(
                title="Address Flaky Tests",
                description=f"{flaky_count} tests have been marked as flaky, indicating intermittent failures.",
                priority=Severity.MEDIUM,
                category="stability",
                action_items=[
                    "Investigate flaky tests individually",
                    "Add retry logic for known flaky scenarios",
                    "Improve synchronization and waits",
                    "Consider quarantining persistently flaky tests",
                ],
                estimated_impact="Could improve test reliability by 10-20%",
            ))

        # Sort by priority
        priority_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        recommendations.sort(key=lambda r: priority_order[r.priority])

        return recommendations

    def _generate_summary(
        self,
        pass_rate: float,
        patterns: List[FailurePattern],
        recommendations: List[Recommendation],
    ) -> str:
        """Generate a human-readable summary."""
        if pass_rate >= 0.95:
            status = "Excellent"
            emoji = "🎉"
            detail = "The test suite is in great shape."
        elif pass_rate >= 0.80:
            status = "Good"
            emoji = "✅"
            detail = "Most tests are passing, with some areas needing attention."
        elif pass_rate >= 0.60:
            status = "Needs Attention"
            emoji = "⚠️"
            detail = "A significant number of tests are failing."
        else:
            status = "Critical"
            emoji = "🔴"
            detail = "The test suite needs immediate attention."

        lines = [f"{emoji} **{status}**: {detail}"]

        if patterns:
            main_issues = [p.pattern_type.value.replace("_", " ") for p in patterns[:2]]
            lines.append(f"\nMain issues: {', '.join(main_issues)}.")

        if recommendations:
            lines.append(f"\n{len(recommendations)} recommendations have been generated to improve test quality.")

        return "\n".join(lines)

    def analyze(self, run_id: Optional[str] = None) -> AnalysisReport:
        """
        Analyze current results and generate a report.

        Args:
            run_id: Optional run identifier

        Returns:
            AnalysisReport with patterns and recommendations
        """
        if not run_id:
            self._run_counter += 1
            run_id = f"run-{self._run_counter:04d}"

        # Calculate basic stats
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
        skipped = sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
        errors = sum(1 for r in self.results if r.status == TestStatus.ERROR)
        flaky = sum(1 for r in self.results if r.status == TestStatus.FLAKY)

        pass_rate = passed / total if total > 0 else 0.0
        avg_duration = sum(r.duration_ms for r in self.results) / total if total > 0 else 0.0

        # Detect patterns
        patterns = self._detect_patterns()

        # Generate recommendations
        recommendations = self._generate_recommendations(patterns, pass_rate, avg_duration)

        # Calculate trends (compare to last run)
        trends = {}
        if self.history:
            last_report = self.history[-1]
            trends["pass_rate_trend"] = pass_rate - last_report.pass_rate
            trends["duration_trend"] = avg_duration - last_report.average_duration_ms

        # Generate summary
        summary = self._generate_summary(pass_rate, patterns, recommendations)

        report = AnalysisReport(
            run_id=run_id,
            analyzed_at=datetime.now(),
            total_tests=total,
            passed_count=passed,
            failed_count=failed,
            skipped_count=skipped,
            error_count=errors,
            flaky_count=flaky,
            pass_rate=pass_rate,
            average_duration_ms=avg_duration,
            failure_patterns=patterns,
            recommendations=recommendations,
            trends=trends,
            summary=summary,
        )

        # Store in history
        self.history.append(report)

        return report


def create_analyzer() -> TestResultAnalyzer:
    """Create a test result analyzer."""
    return TestResultAnalyzer()


if __name__ == "__main__":
    # Demo
    analyzer = create_analyzer()

    # Simulate test results
    results = [
        TestRunResult("TC-001", "Login with valid credentials", TestStatus.PASSED, 1200),
        TestRunResult("TC-002", "Login with invalid password", TestStatus.PASSED, 1100),
        TestRunResult("TC-003", "Login with empty email", TestStatus.FAILED, 2500, "Element not found: #error-message"),
        TestRunResult("TC-004", "Login with SQL injection", TestStatus.PASSED, 1300),
        TestRunResult("TC-005", "Remember me checkbox", TestStatus.FAILED, 5000, "Timeout waiting for element"),
        TestRunResult("TC-006", "Forgot password link", TestStatus.PASSED, 1000),
        TestRunResult("TC-007", "Social login - Google", TestStatus.FAILED, 3000, "Network error: API unavailable"),
        TestRunResult("TC-008", "Social login - Facebook", TestStatus.FAILED, 3200, "Network error: Connection refused"),
        TestRunResult("TC-009", "Session timeout", TestStatus.PASSED, 1400),
        TestRunResult("TC-010", "Concurrent login", TestStatus.PASSED, 1500),
    ]

    analyzer.add_results(results)
    report = analyzer.analyze()

    print(report.format_markdown())
