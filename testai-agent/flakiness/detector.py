"""
TestAI Agent - Flakiness Detector

Detect flaky tests through statistical analysis
of test execution history and patterns.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import math


class FlakinessPattern(Enum):
    """Patterns of flaky behavior."""
    TIMING = "timing"             # Timing-related failures
    ORDERING = "ordering"         # Order-dependent failures
    RESOURCE = "resource"         # Resource contention
    NETWORK = "network"           # Network-related
    STATE = "state"               # State leakage
    CONCURRENCY = "concurrency"   # Race conditions
    ENVIRONMENT = "environment"   # Environment differences
    DATA = "data"                 # Data-dependent
    UNKNOWN = "unknown"


class FlakinessLevel(Enum):
    """Levels of flakiness severity."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TestExecution:
    """A single test execution record."""
    execution_id: str
    test_id: str
    test_name: str
    passed: bool
    duration_ms: float
    timestamp: datetime
    error_message: Optional[str] = None
    environment: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FlakinessReport:
    """A flakiness detection report."""
    report_id: str
    test_id: str
    test_name: str
    flakiness_score: float
    flakiness_level: FlakinessLevel
    total_runs: int
    pass_count: int
    fail_count: int
    patterns_detected: List[FlakinessPattern]
    confidence: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class FlakinessDetector:
    """
    Test flakiness detector.

    Features:
    - Statistical analysis
    - Pattern detection
    - Confidence scoring
    - Historical tracking
    """

    def __init__(
        self,
        min_runs: int = 5,
        flakiness_threshold: float = 0.1,
    ):
        """Initialize the detector."""
        self._min_runs = min_runs
        self._flakiness_threshold = flakiness_threshold
        self._executions: Dict[str, List[TestExecution]] = {}
        self._reports: List[FlakinessReport] = []
        self._execution_counter = 0
        self._report_counter = 0

    def record_execution(
        self,
        test_id: str,
        test_name: str,
        passed: bool,
        duration_ms: float,
        error_message: Optional[str] = None,
        environment: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TestExecution:
        """Record a test execution."""
        self._execution_counter += 1

        execution = TestExecution(
            execution_id=f"EXEC-{self._execution_counter:06d}",
            test_id=test_id,
            test_name=test_name,
            passed=passed,
            duration_ms=duration_ms,
            timestamp=datetime.now(),
            error_message=error_message,
            environment=environment,
            metadata=metadata or {},
        )

        if test_id not in self._executions:
            self._executions[test_id] = []
        self._executions[test_id].append(execution)

        return execution

    def detect(self, test_id: str) -> Optional[FlakinessReport]:
        """Detect flakiness for a specific test."""
        executions = self._executions.get(test_id, [])

        if len(executions) < self._min_runs:
            return None

        self._report_counter += 1
        report_id = f"FLAKE-{self._report_counter:05d}"

        # Calculate basic stats
        total_runs = len(executions)
        pass_count = sum(1 for e in executions if e.passed)
        fail_count = total_runs - pass_count

        # Calculate flakiness score (0-1)
        # A truly flaky test has roughly 50% pass/fail ratio
        pass_rate = pass_count / total_runs
        flakiness_score = 1 - abs(pass_rate - 0.5) * 2

        # If all pass or all fail, not flaky
        if pass_count == 0 or fail_count == 0:
            flakiness_score = 0.0

        # Determine level
        if flakiness_score >= 0.8:
            level = FlakinessLevel.CRITICAL
        elif flakiness_score >= 0.6:
            level = FlakinessLevel.HIGH
        elif flakiness_score >= 0.4:
            level = FlakinessLevel.MEDIUM
        elif flakiness_score >= self._flakiness_threshold:
            level = FlakinessLevel.LOW
        else:
            level = FlakinessLevel.NONE

        # Detect patterns
        patterns = self._detect_patterns(executions)

        # Calculate confidence based on sample size
        confidence = min(1.0, math.sqrt(total_runs / 20))

        test_name = executions[0].test_name if executions else test_id

        report = FlakinessReport(
            report_id=report_id,
            test_id=test_id,
            test_name=test_name,
            flakiness_score=round(flakiness_score, 3),
            flakiness_level=level,
            total_runs=total_runs,
            pass_count=pass_count,
            fail_count=fail_count,
            patterns_detected=patterns,
            confidence=round(confidence, 2),
            timestamp=datetime.now(),
        )

        self._reports.append(report)
        return report

    def _detect_patterns(
        self,
        executions: List[TestExecution],
    ) -> List[FlakinessPattern]:
        """Detect flakiness patterns from execution history."""
        patterns = []

        if len(executions) < 3:
            return [FlakinessPattern.UNKNOWN]

        # Check timing pattern (high duration variance on failures)
        durations_pass = [e.duration_ms for e in executions if e.passed]
        durations_fail = [e.duration_ms for e in executions if not e.passed]

        if durations_pass and durations_fail:
            avg_pass = sum(durations_pass) / len(durations_pass)
            avg_fail = sum(durations_fail) / len(durations_fail)

            if abs(avg_fail - avg_pass) > avg_pass * 0.5:
                patterns.append(FlakinessPattern.TIMING)

        # Check for ordering pattern (consecutive fails/passes)
        streak_changes = 0
        last_result = executions[0].passed
        for e in executions[1:]:
            if e.passed != last_result:
                streak_changes += 1
                last_result = e.passed

        if streak_changes > len(executions) * 0.6:
            patterns.append(FlakinessPattern.ORDERING)

        # Check error messages for patterns
        error_messages = [e.error_message for e in executions if e.error_message]

        if error_messages:
            error_text = " ".join(error_messages).lower()

            if "timeout" in error_text or "timed out" in error_text:
                patterns.append(FlakinessPattern.TIMING)

            if "connection" in error_text or "network" in error_text:
                patterns.append(FlakinessPattern.NETWORK)

            if "race" in error_text or "concurrent" in error_text:
                patterns.append(FlakinessPattern.CONCURRENCY)

            if "resource" in error_text or "memory" in error_text:
                patterns.append(FlakinessPattern.RESOURCE)

            if "state" in error_text or "stale" in error_text:
                patterns.append(FlakinessPattern.STATE)

        # Check environment variance
        env_results: Dict[str, List[bool]] = {}
        for e in executions:
            if e.environment not in env_results:
                env_results[e.environment] = []
            env_results[e.environment].append(e.passed)

        if len(env_results) > 1:
            pass_rates = []
            for env, results in env_results.items():
                if len(results) >= 2:
                    pass_rates.append(sum(results) / len(results))

            if pass_rates and max(pass_rates) - min(pass_rates) > 0.3:
                patterns.append(FlakinessPattern.ENVIRONMENT)

        if not patterns:
            patterns.append(FlakinessPattern.UNKNOWN)

        return list(set(patterns))

    def detect_all(self) -> List[FlakinessReport]:
        """Detect flakiness for all recorded tests."""
        reports = []

        for test_id in self._executions:
            report = self.detect(test_id)
            if report and report.flakiness_level != FlakinessLevel.NONE:
                reports.append(report)

        return reports

    def get_flaky_tests(
        self,
        min_level: FlakinessLevel = FlakinessLevel.LOW,
    ) -> List[FlakinessReport]:
        """Get all flaky tests above a certain level."""
        levels = list(FlakinessLevel)
        min_index = levels.index(min_level)

        return [
            r for r in self._reports
            if levels.index(r.flakiness_level) >= min_index
        ]

    def get_executions(
        self,
        test_id: str,
        limit: int = 100,
    ) -> List[TestExecution]:
        """Get execution history for a test."""
        return self._executions.get(test_id, [])[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        total_executions = sum(len(e) for e in self._executions.values())

        level_counts = {l.value: 0 for l in FlakinessLevel}
        for report in self._reports:
            level_counts[report.flakiness_level.value] += 1

        flaky_tests = sum(
            1 for r in self._reports
            if r.flakiness_level != FlakinessLevel.NONE
        )

        return {
            "total_tests": len(self._executions),
            "total_executions": total_executions,
            "total_reports": len(self._reports),
            "flaky_tests_detected": flaky_tests,
            "flakiness_by_level": level_counts,
        }

    def format_report(self, report: FlakinessReport) -> str:
        """Format a flakiness report for display."""
        level_icons = {
            FlakinessLevel.NONE: "✅",
            FlakinessLevel.LOW: "🟡",
            FlakinessLevel.MEDIUM: "🟠",
            FlakinessLevel.HIGH: "🔴",
            FlakinessLevel.CRITICAL: "⛔",
        }

        icon = level_icons.get(report.flakiness_level, "")

        lines = [
            "=" * 50,
            f"  FLAKINESS REPORT: {icon} {report.flakiness_level.value.upper()}",
            "=" * 50,
            "",
            f"  Test: {report.test_name}",
            f"  ID: {report.test_id}",
            "",
            "-" * 50,
            "  STATISTICS",
            "-" * 50,
            "",
            f"  Total Runs: {report.total_runs}",
            f"  Passed: {report.pass_count}",
            f"  Failed: {report.fail_count}",
            f"  Flakiness Score: {report.flakiness_score:.1%}",
            f"  Confidence: {report.confidence:.0%}",
            "",
        ]

        if report.patterns_detected:
            lines.append("-" * 50)
            lines.append("  PATTERNS DETECTED")
            lines.append("-" * 50)
            lines.append("")
            for pattern in report.patterns_detected:
                lines.append(f"  • {pattern.value}")
            lines.append("")

        lines.append("=" * 50)
        return "\n".join(lines)


def create_flakiness_detector(
    min_runs: int = 5,
    flakiness_threshold: float = 0.1,
) -> FlakinessDetector:
    """Create a flakiness detector instance."""
    return FlakinessDetector(
        min_runs=min_runs,
        flakiness_threshold=flakiness_threshold,
    )
