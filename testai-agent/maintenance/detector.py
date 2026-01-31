"""
TestAI Agent - Maintenance Detector

Detects when tests need maintenance due to code changes,
UI updates, API changes, or performance degradation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re


class MaintenanceType(Enum):
    """Types of maintenance needed."""
    SELECTOR_UPDATE = "selector_update"
    API_CHANGE = "api_change"
    DATA_UPDATE = "data_update"
    PERFORMANCE = "performance"
    FLAKINESS = "flakiness"
    DEPRECATION = "deprecation"
    SECURITY = "security"
    ACCESSIBILITY = "accessibility"
    CODE_SMELL = "code_smell"
    OUTDATED_DEPENDENCY = "outdated_dependency"


class MaintenancePriority(Enum):
    """Priority levels for maintenance."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MaintenanceIssue:
    """A detected maintenance issue."""
    issue_id: str
    test_id: str
    maintenance_type: MaintenanceType
    priority: MaintenancePriority
    title: str
    description: str
    affected_elements: List[str]
    suggested_action: str
    estimated_effort_minutes: int
    auto_fixable: bool
    detected_at: datetime = field(default_factory=datetime.now)


@dataclass
class TestHealth:
    """Health status of a test."""
    test_id: str
    name: str
    health_score: float  # 0.0 to 1.0
    issues: List[MaintenanceIssue]
    last_passed: Optional[datetime]
    pass_rate_7d: float
    avg_duration_ms: int
    flakiness_score: float


@dataclass
class MaintenanceReport:
    """Complete maintenance report."""
    total_tests: int
    healthy_tests: int
    needs_attention: int
    critical_issues: List[MaintenanceIssue]
    all_issues: List[MaintenanceIssue]
    estimated_total_effort_minutes: int
    summary: str


class MaintenanceDetector:
    """
    Detects tests needing maintenance.

    Features:
    - Selector health monitoring
    - API change detection
    - Performance regression detection
    - Flakiness detection
    - Deprecated pattern detection
    """

    # Selector patterns that indicate fragility
    FRAGILE_SELECTOR_PATTERNS = [
        (r"\.[\w-]+\d+", "Contains dynamic class with numbers"),
        (r"#[\w-]+\d+", "Contains dynamic ID with numbers"),
        (r"\[ng-", "Angular-specific attribute"),
        (r"\[_ngcontent", "Angular generated attribute"),
        (r"\[data-v-", "Vue scoped attribute"),
        (r"\.css-[\w]+", "CSS-in-JS generated class"),
        (r"\.sc-[\w]+", "Styled-components generated class"),
        (r":nth-child\(\d+\)", "Positional selector"),
        (r":nth-of-type\(\d+\)", "Positional selector"),
        (r">\s*>\s*>", "Deep nesting"),
        (r"\.[\w-]{20,}", "Long generated class name"),
    ]

    # Deprecated patterns to detect
    DEPRECATED_PATTERNS = [
        (r"\.click\(\)", "Consider using .click({ force: true }) for reliability"),
        (r"sleep\(", "Replace sleep with explicit waits"),
        (r"time\.sleep", "Replace sleep with explicit waits"),
        (r"Thread\.sleep", "Replace sleep with explicit waits"),
        (r"\.waitForTimeout\(", "Prefer waitForSelector or waitForFunction"),
        (r"page\.evaluate\(.+\)", "Consider using locator methods"),
        (r"\.getAttribute\(", "Consider using expect assertions"),
    ]

    # Code smells in tests
    CODE_SMELL_PATTERNS = [
        (r"try\s*{[\s\S]*catch.*{}",  "Empty catch block"),
        (r"// TODO", "Unresolved TODO comment"),
        (r"// FIXME", "Unresolved FIXME comment"),
        (r"console\.log", "Debug logging left in test"),
        (r"debugger", "Debugger statement left in test"),
        (r"\.only\(", "Test marked as .only"),
        (r"\.skip\(", "Skipped test"),
        (r"test\.skip", "Skipped test"),
    ]

    def __init__(self):
        """Initialize the maintenance detector."""
        self._issue_counter = 0
        self._test_data: Dict[str, Dict[str, Any]] = {}
        self._execution_history: Dict[str, List[Dict[str, Any]]] = {}

    def register_test(
        self,
        test_id: str,
        name: str,
        code: Optional[str] = None,
        selectors: Optional[List[str]] = None,
        api_endpoints: Optional[List[str]] = None,
    ):
        """Register a test for monitoring."""
        self._test_data[test_id] = {
            "name": name,
            "code": code or "",
            "selectors": selectors or [],
            "api_endpoints": api_endpoints or [],
            "registered_at": datetime.now(),
        }

    def record_execution(
        self,
        test_id: str,
        passed: bool,
        duration_ms: int,
        error_message: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ):
        """Record a test execution result."""
        if test_id not in self._execution_history:
            self._execution_history[test_id] = []

        self._execution_history[test_id].append({
            "passed": passed,
            "duration_ms": duration_ms,
            "error_message": error_message,
            "timestamp": timestamp or datetime.now(),
        })

    def detect_issues(
        self,
        test_id: Optional[str] = None,
    ) -> List[MaintenanceIssue]:
        """Detect maintenance issues for test(s)."""
        issues = []

        tests_to_check = [test_id] if test_id else list(self._test_data.keys())

        for tid in tests_to_check:
            if tid not in self._test_data:
                continue

            test_data = self._test_data[tid]

            # Check selectors
            if test_data.get("selectors"):
                issues.extend(self._check_selectors(tid, test_data["selectors"]))

            # Check code quality
            if test_data.get("code"):
                issues.extend(self._check_code_quality(tid, test_data["code"]))

            # Check execution history
            if tid in self._execution_history:
                issues.extend(self._check_execution_health(tid))

        return issues

    def _check_selectors(
        self,
        test_id: str,
        selectors: List[str],
    ) -> List[MaintenanceIssue]:
        """Check selectors for fragility."""
        issues = []

        for selector in selectors:
            for pattern, description in self.FRAGILE_SELECTOR_PATTERNS:
                if re.search(pattern, selector):
                    self._issue_counter += 1
                    issue = MaintenanceIssue(
                        issue_id=f"MAINT-{self._issue_counter:05d}",
                        test_id=test_id,
                        maintenance_type=MaintenanceType.SELECTOR_UPDATE,
                        priority=MaintenancePriority.MEDIUM,
                        title=f"Fragile selector detected",
                        description=f"{description}: {selector[:50]}",
                        affected_elements=[selector],
                        suggested_action="Replace with data-testid or more stable selector",
                        estimated_effort_minutes=15,
                        auto_fixable=False,
                    )
                    issues.append(issue)
                    break  # One issue per selector

        return issues

    def _check_code_quality(
        self,
        test_id: str,
        code: str,
    ) -> List[MaintenanceIssue]:
        """Check code for quality issues."""
        issues = []

        # Check deprecated patterns
        for pattern, suggestion in self.DEPRECATED_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                self._issue_counter += 1
                issue = MaintenanceIssue(
                    issue_id=f"MAINT-{self._issue_counter:05d}",
                    test_id=test_id,
                    maintenance_type=MaintenanceType.DEPRECATION,
                    priority=MaintenancePriority.LOW,
                    title="Deprecated pattern detected",
                    description=suggestion,
                    affected_elements=[pattern],
                    suggested_action=suggestion,
                    estimated_effort_minutes=10,
                    auto_fixable=True,
                )
                issues.append(issue)

        # Check code smells
        for pattern, description in self.CODE_SMELL_PATTERNS:
            if re.search(pattern, code):
                self._issue_counter += 1
                priority = (
                    MaintenancePriority.HIGH
                    if "only" in pattern.lower()
                    else MaintenancePriority.MEDIUM
                )
                issue = MaintenanceIssue(
                    issue_id=f"MAINT-{self._issue_counter:05d}",
                    test_id=test_id,
                    maintenance_type=MaintenanceType.CODE_SMELL,
                    priority=priority,
                    title="Code smell detected",
                    description=description,
                    affected_elements=[pattern],
                    suggested_action=f"Address: {description}",
                    estimated_effort_minutes=10,
                    auto_fixable=".only" in pattern or ".skip" in pattern,
                )
                issues.append(issue)

        return issues

    def _check_execution_health(
        self,
        test_id: str,
    ) -> List[MaintenanceIssue]:
        """Check execution history for health issues."""
        issues = []
        history = self._execution_history.get(test_id, [])

        if len(history) < 3:
            return issues

        # Calculate metrics
        recent = history[-10:]  # Last 10 executions
        pass_count = sum(1 for e in recent if e["passed"])
        pass_rate = pass_count / len(recent)
        durations = [e["duration_ms"] for e in recent]
        avg_duration = sum(durations) / len(durations)

        # Check flakiness
        if 0.3 <= pass_rate <= 0.8:  # Inconsistent results
            self._issue_counter += 1
            issue = MaintenanceIssue(
                issue_id=f"MAINT-{self._issue_counter:05d}",
                test_id=test_id,
                maintenance_type=MaintenanceType.FLAKINESS,
                priority=MaintenancePriority.HIGH,
                title="Flaky test detected",
                description=f"Pass rate is {pass_rate:.0%} in last {len(recent)} runs",
                affected_elements=[],
                suggested_action="Investigate timing issues or add explicit waits",
                estimated_effort_minutes=30,
                auto_fixable=False,
            )
            issues.append(issue)

        # Check performance regression
        if len(history) >= 5:
            old_durations = [e["duration_ms"] for e in history[-10:-5]]
            new_durations = [e["duration_ms"] for e in history[-5:]]

            if old_durations and new_durations:
                old_avg = sum(old_durations) / len(old_durations)
                new_avg = sum(new_durations) / len(new_durations)

                if new_avg > old_avg * 1.5:  # 50% slower
                    self._issue_counter += 1
                    issue = MaintenanceIssue(
                        issue_id=f"MAINT-{self._issue_counter:05d}",
                        test_id=test_id,
                        maintenance_type=MaintenanceType.PERFORMANCE,
                        priority=MaintenancePriority.MEDIUM,
                        title="Performance regression detected",
                        description=f"Test is {((new_avg/old_avg)-1)*100:.0f}% slower than before",
                        affected_elements=[],
                        suggested_action="Review recent changes affecting performance",
                        estimated_effort_minutes=20,
                        auto_fixable=False,
                    )
                    issues.append(issue)

        # Check repeated failures
        if pass_rate == 0 and len(recent) >= 3:
            self._issue_counter += 1
            issue = MaintenanceIssue(
                issue_id=f"MAINT-{self._issue_counter:05d}",
                test_id=test_id,
                maintenance_type=MaintenanceType.SELECTOR_UPDATE,
                priority=MaintenancePriority.CRITICAL,
                title="Test consistently failing",
                description=f"Test has failed {len(recent)} consecutive times",
                affected_elements=[],
                suggested_action="Investigate and fix or disable test",
                estimated_effort_minutes=45,
                auto_fixable=False,
            )
            issues.append(issue)

        return issues

    def get_test_health(self, test_id: str) -> Optional[TestHealth]:
        """Get health status for a test."""
        if test_id not in self._test_data:
            return None

        test_data = self._test_data[test_id]
        issues = self.detect_issues(test_id)
        history = self._execution_history.get(test_id, [])

        # Calculate metrics
        if history:
            recent = history[-10:]
            pass_count = sum(1 for e in recent if e["passed"])
            pass_rate = pass_count / len(recent)
            avg_duration = sum(e["duration_ms"] for e in recent) / len(recent)
            last_passed = None
            for e in reversed(history):
                if e["passed"]:
                    last_passed = e["timestamp"]
                    break

            # Calculate flakiness score
            if len(recent) >= 3:
                # Count transitions (pass->fail or fail->pass)
                transitions = sum(
                    1 for i in range(1, len(recent))
                    if recent[i]["passed"] != recent[i-1]["passed"]
                )
                flakiness = transitions / (len(recent) - 1)
            else:
                flakiness = 0.0
        else:
            pass_rate = 1.0
            avg_duration = 0
            last_passed = None
            flakiness = 0.0

        # Calculate health score
        health_score = 1.0

        # Reduce for issues
        for issue in issues:
            if issue.priority == MaintenancePriority.CRITICAL:
                health_score -= 0.3
            elif issue.priority == MaintenancePriority.HIGH:
                health_score -= 0.2
            elif issue.priority == MaintenancePriority.MEDIUM:
                health_score -= 0.1
            else:
                health_score -= 0.05

        # Reduce for low pass rate
        if pass_rate < 0.5:
            health_score -= 0.3
        elif pass_rate < 0.8:
            health_score -= 0.1

        # Reduce for flakiness
        health_score -= flakiness * 0.2

        health_score = max(0.0, min(1.0, health_score))

        return TestHealth(
            test_id=test_id,
            name=test_data["name"],
            health_score=health_score,
            issues=issues,
            last_passed=last_passed,
            pass_rate_7d=pass_rate,
            avg_duration_ms=int(avg_duration),
            flakiness_score=flakiness,
        )

    def generate_report(self) -> MaintenanceReport:
        """Generate a maintenance report for all tests."""
        all_issues = self.detect_issues()

        # Calculate metrics
        total_tests = len(self._test_data)
        tests_with_issues = set(issue.test_id for issue in all_issues)
        healthy_tests = total_tests - len(tests_with_issues)

        critical_issues = [
            i for i in all_issues
            if i.priority in {MaintenancePriority.CRITICAL, MaintenancePriority.HIGH}
        ]

        total_effort = sum(i.estimated_effort_minutes for i in all_issues)

        # Generate summary
        if not all_issues:
            summary = "All tests are healthy. No maintenance needed."
        elif critical_issues:
            summary = (
                f"Found {len(critical_issues)} critical/high priority issues. "
                f"Estimated effort: {total_effort} minutes."
            )
        else:
            summary = (
                f"Found {len(all_issues)} maintenance items. "
                f"Estimated effort: {total_effort} minutes."
            )

        return MaintenanceReport(
            total_tests=total_tests,
            healthy_tests=healthy_tests,
            needs_attention=len(tests_with_issues),
            critical_issues=critical_issues,
            all_issues=all_issues,
            estimated_total_effort_minutes=total_effort,
            summary=summary,
        )

    def format_report(self, report: MaintenanceReport) -> str:
        """Format maintenance report as readable text."""
        lines = [
            "=" * 60,
            "  TEST MAINTENANCE REPORT",
            "=" * 60,
            "",
            f"  Total Tests: {report.total_tests}",
            f"  Healthy: {report.healthy_tests}",
            f"  Needs Attention: {report.needs_attention}",
            f"  Total Issues: {len(report.all_issues)}",
            f"  Estimated Effort: {report.estimated_total_effort_minutes} minutes",
            "",
            "-" * 60,
            "  SUMMARY",
            "-" * 60,
            f"  {report.summary}",
            "",
        ]

        if report.critical_issues:
            lines.extend([
                "-" * 60,
                "  CRITICAL/HIGH PRIORITY ISSUES",
                "-" * 60,
            ])
            for issue in report.critical_issues[:10]:
                lines.extend([
                    f"",
                    f"  [{issue.priority.value.upper()}] {issue.title}",
                    f"  Test: {issue.test_id}",
                    f"  Type: {issue.maintenance_type.value}",
                    f"  {issue.description}",
                    f"  Action: {issue.suggested_action}",
                ])

        if report.all_issues:
            lines.extend([
                "",
                "-" * 60,
                "  ALL ISSUES BY TYPE",
                "-" * 60,
            ])
            by_type: Dict[MaintenanceType, int] = {}
            for issue in report.all_issues:
                by_type[issue.maintenance_type] = by_type.get(issue.maintenance_type, 0) + 1

            for mtype, count in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(f"  {mtype.value}: {count}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_maintenance_detector() -> MaintenanceDetector:
    """Create a maintenance detector instance."""
    return MaintenanceDetector()
