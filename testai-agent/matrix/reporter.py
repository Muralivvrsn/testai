"""
TestAI Agent - Matrix Reporter

Reports on cross-browser test execution results and
compatibility issues.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from .generator import TestMatrix, MatrixCell, BrowserType, DeviceType, OSType


class IssueSeverity(Enum):
    """Severity levels for compatibility issues."""
    CRITICAL = "critical"  # Breaks functionality
    MAJOR = "major"  # Significant impact
    MINOR = "minor"  # Small visual/behavior difference
    INFO = "info"  # Just informational


class IssueType(Enum):
    """Types of compatibility issues."""
    VISUAL = "visual"  # Visual rendering differences
    FUNCTIONAL = "functional"  # Feature doesn't work
    PERFORMANCE = "performance"  # Slow on certain configs
    LAYOUT = "layout"  # Layout breaks
    INTERACTION = "interaction"  # Touch/click issues
    API = "api"  # API not supported


@dataclass
class CompatibilityIssue:
    """A compatibility issue found during testing."""
    issue_id: str
    test_id: str
    issue_type: IssueType
    severity: IssueSeverity
    description: str
    affected_browsers: List[BrowserType]
    affected_devices: List[str]
    affected_os: List[OSType]
    workaround: Optional[str] = None
    screenshot_url: Optional[str] = None


@dataclass
class CellResult:
    """Result of a single matrix cell execution."""
    cell: MatrixCell
    passed: bool
    duration_ms: int
    error: Optional[str] = None
    issues: List[CompatibilityIssue] = field(default_factory=list)


@dataclass
class MatrixReport:
    """Complete report of matrix execution."""
    matrix_name: str
    executed_at: datetime
    total_cells: int
    passed_cells: int
    failed_cells: int
    skipped_cells: int
    total_duration_ms: int
    issues: List[CompatibilityIssue]
    browser_results: Dict[str, Dict[str, int]]
    device_results: Dict[str, Dict[str, int]]
    test_results: Dict[str, Dict[str, int]]


class MatrixReporter:
    """
    Reports on matrix execution and compatibility.

    Features:
    - Aggregates results by browser/device/test
    - Identifies patterns in failures
    - Generates compatibility reports
    - Suggests fixes for issues
    """

    def __init__(self):
        """Initialize the reporter."""
        self._results: List[CellResult] = []
        self._issues: List[CompatibilityIssue] = []
        self._issue_counter = 0

    def record_result(
        self,
        cell: MatrixCell,
        passed: bool,
        duration_ms: int,
        error: Optional[str] = None,
    ) -> CellResult:
        """Record a cell execution result."""
        result = CellResult(
            cell=cell,
            passed=passed,
            duration_ms=duration_ms,
            error=error,
        )
        self._results.append(result)
        return result

    def report_issue(
        self,
        test_id: str,
        issue_type: IssueType,
        severity: IssueSeverity,
        description: str,
        browsers: Optional[List[BrowserType]] = None,
        devices: Optional[List[str]] = None,
        os_list: Optional[List[OSType]] = None,
        workaround: Optional[str] = None,
    ) -> CompatibilityIssue:
        """Report a compatibility issue."""
        self._issue_counter += 1

        issue = CompatibilityIssue(
            issue_id=f"ISSUE-{self._issue_counter:04d}",
            test_id=test_id,
            issue_type=issue_type,
            severity=severity,
            description=description,
            affected_browsers=browsers or [],
            affected_devices=devices or [],
            affected_os=os_list or [],
            workaround=workaround,
        )

        self._issues.append(issue)
        return issue

    def generate_report(
        self,
        matrix: TestMatrix,
    ) -> MatrixReport:
        """Generate a comprehensive report."""
        passed = sum(1 for r in self._results if r.passed)
        failed = sum(1 for r in self._results if not r.passed)
        skipped = len(matrix.cells) - len(self._results)

        # Aggregate by browser
        browser_results: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"passed": 0, "failed": 0}
        )
        for result in self._results:
            browser_key = result.cell.browser.browser.value
            if result.passed:
                browser_results[browser_key]["passed"] += 1
            else:
                browser_results[browser_key]["failed"] += 1

        # Aggregate by device
        device_results: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"passed": 0, "failed": 0}
        )
        for result in self._results:
            device_key = result.cell.device.name if result.cell.device else "desktop"
            if result.passed:
                device_results[device_key]["passed"] += 1
            else:
                device_results[device_key]["failed"] += 1

        # Aggregate by test
        test_results: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"passed": 0, "failed": 0}
        )
        for result in self._results:
            if result.passed:
                test_results[result.cell.test_id]["passed"] += 1
            else:
                test_results[result.cell.test_id]["failed"] += 1

        total_duration = sum(r.duration_ms for r in self._results)

        return MatrixReport(
            matrix_name=matrix.name,
            executed_at=datetime.now(),
            total_cells=len(matrix.cells),
            passed_cells=passed,
            failed_cells=failed,
            skipped_cells=skipped,
            total_duration_ms=total_duration,
            issues=self._issues.copy(),
            browser_results=dict(browser_results),
            device_results=dict(device_results),
            test_results=dict(test_results),
        )

    def find_failure_patterns(self) -> List[Dict[str, Any]]:
        """Find patterns in failures."""
        patterns = []

        # Group failures by error
        error_groups: Dict[str, List[CellResult]] = defaultdict(list)
        for result in self._results:
            if not result.passed and result.error:
                # Normalize error message
                error_key = self._normalize_error(result.error)
                error_groups[error_key].append(result)

        for error_key, results in error_groups.items():
            if len(results) >= 2:
                # Analyze affected configs
                browsers = set(r.cell.browser.browser for r in results)
                devices = set(
                    r.cell.device.name if r.cell.device else "desktop"
                    for r in results
                )
                tests = set(r.cell.test_id for r in results)

                patterns.append({
                    "error_pattern": error_key,
                    "occurrence_count": len(results),
                    "affected_browsers": [b.value for b in browsers],
                    "affected_devices": list(devices),
                    "affected_tests": list(tests),
                    "likely_cause": self._infer_cause(error_key, browsers, devices),
                })

        return sorted(patterns, key=lambda p: -p["occurrence_count"])

    def get_browser_compatibility(self) -> Dict[str, float]:
        """Get pass rate by browser."""
        browser_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"passed": 0, "total": 0}
        )

        for result in self._results:
            browser = result.cell.browser.browser.value
            browser_stats[browser]["total"] += 1
            if result.passed:
                browser_stats[browser]["passed"] += 1

        return {
            browser: stats["passed"] / stats["total"] if stats["total"] > 0 else 0
            for browser, stats in browser_stats.items()
        }

    def get_device_compatibility(self) -> Dict[str, float]:
        """Get pass rate by device."""
        device_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"passed": 0, "total": 0}
        )

        for result in self._results:
            device = result.cell.device.name if result.cell.device else "desktop"
            device_stats[device]["total"] += 1
            if result.passed:
                device_stats[device]["passed"] += 1

        return {
            device: stats["passed"] / stats["total"] if stats["total"] > 0 else 0
            for device, stats in device_stats.items()
        }

    def suggest_fixes(self) -> List[Dict[str, Any]]:
        """Suggest fixes based on issues and failures."""
        suggestions = []

        # Analyze issues
        for issue in self._issues:
            suggestion = self._get_fix_suggestion(issue)
            if suggestion:
                suggestions.append({
                    "issue_id": issue.issue_id,
                    "severity": issue.severity.value,
                    "suggestion": suggestion,
                })

        # Analyze failure patterns
        patterns = self.find_failure_patterns()
        for pattern in patterns[:5]:
            suggestion = self._get_pattern_suggestion(pattern)
            if suggestion:
                suggestions.append({
                    "pattern": pattern["error_pattern"],
                    "affected_count": pattern["occurrence_count"],
                    "suggestion": suggestion,
                })

        return suggestions

    def _normalize_error(self, error: str) -> str:
        """Normalize error message for grouping."""
        error = error.lower()

        # Extract key patterns
        if "timeout" in error:
            return "timeout"
        if "element not found" in error or "no such element" in error:
            return "element_not_found"
        if "click intercepted" in error:
            return "click_intercepted"
        if "network" in error or "connection" in error:
            return "network_error"
        if "javascript" in error or "script" in error:
            return "javascript_error"

        return error[:50]  # Truncate for grouping

    def _infer_cause(
        self,
        error: str,
        browsers: Set[BrowserType],
        devices: Set[str],
    ) -> str:
        """Infer likely cause from error and configs."""
        if error == "timeout":
            if len(browsers) == 1:
                return f"Browser-specific performance issue ({list(browsers)[0].value})"
            return "General performance issue - consider increasing timeouts"

        if error == "element_not_found":
            if any("mobile" in d.lower() or "iphone" in d.lower() or "android" in d.lower() for d in devices):
                return "Responsive layout issue - element may be hidden on smaller screens"
            return "Element selector may be browser-specific"

        if error == "click_intercepted":
            return "Overlay or modal blocking interaction - check z-index and visibility"

        if error == "network_error":
            return "Network reliability - add retry logic or check CORS settings"

        if error == "javascript_error":
            if BrowserType.IE in browsers or BrowserType.SAFARI in browsers:
                return "JavaScript compatibility - check for modern features not supported"
            return "JavaScript error - check console for details"

        return "Unknown cause - manual investigation required"

    def _get_fix_suggestion(self, issue: CompatibilityIssue) -> Optional[str]:
        """Get fix suggestion for an issue."""
        suggestions = {
            IssueType.VISUAL: "Add CSS vendor prefixes or use feature detection",
            IssueType.FUNCTIONAL: "Check JavaScript compatibility or add polyfills",
            IssueType.PERFORMANCE: "Optimize for affected browsers/devices",
            IssueType.LAYOUT: "Review responsive breakpoints and CSS grid/flexbox support",
            IssueType.INTERACTION: "Check touch event handling and click targets",
            IssueType.API: "Add feature detection and fallbacks",
        }
        return suggestions.get(issue.issue_type)

    def _get_pattern_suggestion(self, pattern: Dict[str, Any]) -> Optional[str]:
        """Get suggestion for a failure pattern."""
        error = pattern["error_pattern"]

        if error == "timeout":
            return "Increase timeouts or add explicit waits"
        if error == "element_not_found":
            return "Use more robust selectors or add element visibility checks"
        if error == "click_intercepted":
            return "Scroll element into view or wait for overlays to close"
        if error == "network_error":
            return "Add retry logic for network operations"

        return None

    def format_report(self, report: MatrixReport) -> str:
        """Format report as readable text."""
        pass_rate = report.passed_cells / report.total_cells if report.total_cells > 0 else 0

        lines = [
            "=" * 60,
            f"  MATRIX EXECUTION REPORT",
            "=" * 60,
            "",
            f"  Matrix: {report.matrix_name}",
            f"  Executed: {report.executed_at.strftime('%Y-%m-%d %H:%M')}",
            f"  Duration: {report.total_duration_ms / 60000:.1f} minutes",
            "",
            f"  Total Cells: {report.total_cells}",
            f"  Passed: {report.passed_cells}",
            f"  Failed: {report.failed_cells}",
            f"  Skipped: {report.skipped_cells}",
            f"  Pass Rate: {pass_rate:.1%}",
            "",
        ]

        # Browser results
        lines.extend([
            "-" * 60,
            "  BROWSER RESULTS",
            "-" * 60,
        ])

        for browser, stats in sorted(report.browser_results.items()):
            total = stats["passed"] + stats["failed"]
            rate = stats["passed"] / total if total > 0 else 0
            bar = "█" * int(rate * 15) + "░" * (15 - int(rate * 15))
            icon = "✅" if rate == 1 else "⚠️" if rate > 0.8 else "❌"
            lines.append(f"  {icon} {browser:<12} {bar} {rate:.0%}")

        # Device results
        if report.device_results:
            lines.extend([
                "",
                "-" * 60,
                "  DEVICE RESULTS",
                "-" * 60,
            ])

            for device, stats in sorted(report.device_results.items()):
                total = stats["passed"] + stats["failed"]
                rate = stats["passed"] / total if total > 0 else 0
                bar = "█" * int(rate * 15) + "░" * (15 - int(rate * 15))
                icon = "✅" if rate == 1 else "⚠️" if rate > 0.8 else "❌"
                lines.append(f"  {icon} {device:<12} {bar} {rate:.0%}")

        # Issues
        if report.issues:
            lines.extend([
                "",
                "-" * 60,
                "  COMPATIBILITY ISSUES",
                "-" * 60,
            ])

            severity_icons = {
                IssueSeverity.CRITICAL: "🔴",
                IssueSeverity.MAJOR: "🟠",
                IssueSeverity.MINOR: "🟡",
                IssueSeverity.INFO: "🔵",
            }

            for issue in sorted(report.issues, key=lambda i: list(IssueSeverity).index(i.severity)):
                icon = severity_icons.get(issue.severity, "⚪")
                lines.append(f"\n  {icon} [{issue.issue_id}] {issue.issue_type.value}")
                lines.append(f"     {issue.description}")
                if issue.affected_browsers:
                    lines.append(f"     Browsers: {', '.join(b.value for b in issue.affected_browsers)}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_matrix_reporter() -> MatrixReporter:
    """Create a matrix reporter instance."""
    return MatrixReporter()
