"""
TestAI Agent - Test Quarantine Manager

Manages quarantined tests that consistently fail
or exhibit extreme flakiness.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict


class QuarantineReason(Enum):
    """Reasons for quarantining a test."""
    CONSISTENTLY_FAILING = "consistently_failing"
    EXTREMELY_FLAKY = "extremely_flaky"
    ENVIRONMENT_DEPENDENT = "environment_dependent"
    RESOURCE_INTENSIVE = "resource_intensive"
    MANUAL_QUARANTINE = "manual_quarantine"
    TIMEOUT_PRONE = "timeout_prone"
    BLOCKING_CI = "blocking_ci"


class QuarantineStatus(Enum):
    """Status of quarantined tests."""
    ACTIVE = "active"  # Currently quarantined
    MONITORING = "monitoring"  # Released but being watched
    RELEASED = "released"  # Fully released
    PERMANENT = "permanent"  # Permanently quarantined


@dataclass
class QuarantinedTest:
    """A quarantined test."""
    test_id: str
    title: str
    reason: QuarantineReason
    status: QuarantineStatus
    quarantined_at: datetime
    quarantined_by: str = "system"
    release_conditions: List[str] = field(default_factory=list)
    failure_count: int = 0
    last_failure: Optional[datetime] = None
    notes: str = ""

    # Monitoring data (when in MONITORING status)
    monitoring_started: Optional[datetime] = None
    monitoring_runs: int = 0
    monitoring_passes: int = 0


@dataclass
class QuarantinePolicy:
    """Policy for automatic quarantine."""
    consecutive_failures_threshold: int = 5
    flakiness_rate_threshold: float = 0.5
    min_runs_before_release: int = 10
    monitoring_pass_rate_threshold: float = 0.9
    auto_release_after_days: Optional[int] = 7


class QuarantineManager:
    """
    Manages quarantined tests.

    Features:
    - Automatic quarantine based on failure patterns
    - Graduated release process (quarantine -> monitoring -> release)
    - Quarantine policies and conditions
    - CI integration support
    """

    def __init__(
        self,
        policy: Optional[QuarantinePolicy] = None,
    ):
        """Initialize the quarantine manager."""
        self.policy = policy or QuarantinePolicy()
        self._quarantined: Dict[str, QuarantinedTest] = {}

        # Tracking data
        self._failure_counts: Dict[str, int] = defaultdict(int)
        self._consecutive_failures: Dict[str, int] = defaultdict(int)
        self._run_history: Dict[str, List[bool]] = defaultdict(list)

    def quarantine(
        self,
        test_id: str,
        title: str,
        reason: QuarantineReason,
        release_conditions: Optional[List[str]] = None,
        quarantined_by: str = "system",
        notes: str = "",
    ) -> QuarantinedTest:
        """Quarantine a test."""
        test = QuarantinedTest(
            test_id=test_id,
            title=title,
            reason=reason,
            status=QuarantineStatus.ACTIVE,
            quarantined_at=datetime.now(),
            quarantined_by=quarantined_by,
            release_conditions=release_conditions or self._get_default_conditions(reason),
            failure_count=self._failure_counts.get(test_id, 0),
            last_failure=datetime.now(),
            notes=notes,
        )

        self._quarantined[test_id] = test
        return test

    def release(
        self,
        test_id: str,
        to_monitoring: bool = True,
    ) -> Optional[QuarantinedTest]:
        """Release a test from quarantine."""
        test = self._quarantined.get(test_id)
        if not test:
            return None

        if to_monitoring:
            test.status = QuarantineStatus.MONITORING
            test.monitoring_started = datetime.now()
            test.monitoring_runs = 0
            test.monitoring_passes = 0
        else:
            test.status = QuarantineStatus.RELEASED
            # Clear tracking data
            self._failure_counts.pop(test_id, None)
            self._consecutive_failures.pop(test_id, None)
            self._run_history.pop(test_id, None)

        return test

    def record_result(
        self,
        test_id: str,
        passed: bool,
        title: str = "",
    ) -> Optional[QuarantinedTest]:
        """Record a test result and check quarantine status."""
        # Update tracking
        if passed:
            self._consecutive_failures[test_id] = 0
        else:
            self._failure_counts[test_id] += 1
            self._consecutive_failures[test_id] += 1

        self._run_history[test_id].append(passed)
        # Keep last 100 runs
        if len(self._run_history[test_id]) > 100:
            self._run_history[test_id].pop(0)

        # Check if test is in monitoring
        test = self._quarantined.get(test_id)
        if test and test.status == QuarantineStatus.MONITORING:
            test.monitoring_runs += 1
            if passed:
                test.monitoring_passes += 1

            # Check if should fully release
            if self._should_fully_release(test):
                test.status = QuarantineStatus.RELEASED
                return test

            # Check if should re-quarantine
            if not passed and self._should_reaquarantine(test):
                test.status = QuarantineStatus.ACTIVE
                test.quarantined_at = datetime.now()
                return test

            return test

        # Check if should auto-quarantine
        if not test and self._should_auto_quarantine(test_id):
            reason = self._detect_quarantine_reason(test_id)
            return self.quarantine(test_id, title or test_id, reason)

        return None

    def is_quarantined(self, test_id: str) -> bool:
        """Check if a test is currently quarantined."""
        test = self._quarantined.get(test_id)
        return test is not None and test.status == QuarantineStatus.ACTIVE

    def is_monitoring(self, test_id: str) -> bool:
        """Check if a test is in monitoring status."""
        test = self._quarantined.get(test_id)
        return test is not None and test.status == QuarantineStatus.MONITORING

    def get_quarantined_tests(
        self,
        status: Optional[QuarantineStatus] = None,
        reason: Optional[QuarantineReason] = None,
    ) -> List[QuarantinedTest]:
        """Get quarantined tests with optional filters."""
        tests = list(self._quarantined.values())

        if status:
            tests = [t for t in tests if t.status == status]

        if reason:
            tests = [t for t in tests if t.reason == reason]

        return tests

    def get_release_candidates(self) -> List[QuarantinedTest]:
        """Get tests that might be ready for release."""
        candidates = []

        for test in self._quarantined.values():
            if test.status != QuarantineStatus.ACTIVE:
                continue

            # Check auto-release time
            if self.policy.auto_release_after_days:
                age = datetime.now() - test.quarantined_at
                if age.days >= self.policy.auto_release_after_days:
                    candidates.append(test)
                    continue

            # Check recent history
            history = self._run_history.get(test.test_id, [])
            if len(history) >= self.policy.min_runs_before_release:
                recent = history[-self.policy.min_runs_before_release:]
                pass_rate = sum(recent) / len(recent)
                if pass_rate >= self.policy.monitoring_pass_rate_threshold:
                    candidates.append(test)

        return candidates

    def _should_auto_quarantine(self, test_id: str) -> bool:
        """Determine if a test should be auto-quarantined."""
        # Check consecutive failures
        if self._consecutive_failures[test_id] >= self.policy.consecutive_failures_threshold:
            return True

        # Check flakiness rate
        history = self._run_history.get(test_id, [])
        if len(history) >= 10:
            pass_rate = sum(history) / len(history)
            if pass_rate < (1 - self.policy.flakiness_rate_threshold):
                return True

        return False

    def _should_fully_release(self, test: QuarantinedTest) -> bool:
        """Determine if a monitored test should be fully released."""
        if test.monitoring_runs < self.policy.min_runs_before_release:
            return False

        pass_rate = test.monitoring_passes / test.monitoring_runs
        return pass_rate >= self.policy.monitoring_pass_rate_threshold

    def _should_reaquarantine(self, test: QuarantinedTest) -> bool:
        """Determine if a monitored test should be re-quarantined."""
        if test.monitoring_runs < 3:
            return False

        pass_rate = test.monitoring_passes / test.monitoring_runs
        return pass_rate < 0.5  # Less than 50% pass rate

    def _detect_quarantine_reason(self, test_id: str) -> QuarantineReason:
        """Detect the most likely quarantine reason."""
        history = self._run_history.get(test_id, [])

        if not history:
            return QuarantineReason.CONSISTENTLY_FAILING

        pass_rate = sum(history) / len(history)

        # Consistently failing (< 10% pass rate)
        if pass_rate < 0.1:
            return QuarantineReason.CONSISTENTLY_FAILING

        # Very flaky (around 50%)
        if 0.3 <= pass_rate <= 0.7:
            return QuarantineReason.EXTREMELY_FLAKY

        return QuarantineReason.CONSISTENTLY_FAILING

    def _get_default_conditions(
        self,
        reason: QuarantineReason,
    ) -> List[str]:
        """Get default release conditions for a reason."""
        conditions = {
            QuarantineReason.CONSISTENTLY_FAILING: [
                "Root cause identified and fixed",
                f"Pass {self.policy.min_runs_before_release} consecutive runs",
            ],
            QuarantineReason.EXTREMELY_FLAKY: [
                "Flakiness root cause addressed",
                f"Achieve {self.policy.monitoring_pass_rate_threshold:.0%} pass rate over {self.policy.min_runs_before_release} runs",
            ],
            QuarantineReason.ENVIRONMENT_DEPENDENT: [
                "Environment dependencies documented",
                "Test can run reliably in CI",
            ],
            QuarantineReason.RESOURCE_INTENSIVE: [
                "Resource requirements reduced",
                "Or moved to nightly/weekly schedule",
            ],
            QuarantineReason.TIMEOUT_PRONE: [
                "Performance optimized",
                "Or timeout increased appropriately",
            ],
            QuarantineReason.BLOCKING_CI: [
                "Issue resolved",
                "CI pipeline stability confirmed",
            ],
        }

        return conditions.get(reason, ["Manual review and approval"])

    def get_summary(self) -> Dict[str, Any]:
        """Get quarantine summary statistics."""
        active = len([t for t in self._quarantined.values() if t.status == QuarantineStatus.ACTIVE])
        monitoring = len([t for t in self._quarantined.values() if t.status == QuarantineStatus.MONITORING])
        released = len([t for t in self._quarantined.values() if t.status == QuarantineStatus.RELEASED])

        # Reasons breakdown
        reasons: Dict[str, int] = defaultdict(int)
        for test in self._quarantined.values():
            if test.status == QuarantineStatus.ACTIVE:
                reasons[test.reason.value] += 1

        return {
            "total_quarantined": len(self._quarantined),
            "active": active,
            "monitoring": monitoring,
            "released": released,
            "release_candidates": len(self.get_release_candidates()),
            "by_reason": dict(reasons),
        }

    def format_report(self) -> str:
        """Format quarantine report as readable text."""
        summary = self.get_summary()

        lines = [
            "=" * 60,
            "  QUARANTINE REPORT",
            "=" * 60,
            "",
            f"  Active: {summary['active']}",
            f"  Monitoring: {summary['monitoring']}",
            f"  Released: {summary['released']}",
            f"  Release Candidates: {summary['release_candidates']}",
            "",
        ]

        # By reason
        if summary['by_reason']:
            lines.extend([
                "-" * 60,
                "  BY REASON",
                "-" * 60,
            ])
            for reason, count in sorted(summary['by_reason'].items()):
                lines.append(f"  • {reason}: {count}")
            lines.append("")

        # Active quarantined tests
        active_tests = self.get_quarantined_tests(QuarantineStatus.ACTIVE)
        if active_tests:
            lines.extend([
                "-" * 60,
                "  ACTIVE QUARANTINE",
                "-" * 60,
            ])
            for test in sorted(active_tests, key=lambda t: t.quarantined_at):
                age = datetime.now() - test.quarantined_at
                lines.append(f"\n  [{test.test_id}] {test.title}")
                lines.append(f"     Reason: {test.reason.value}")
                lines.append(f"     Age: {age.days} days")
                lines.append(f"     Failures: {test.failure_count}")

        # Release candidates
        candidates = self.get_release_candidates()
        if candidates:
            lines.extend([
                "",
                "-" * 60,
                "  RELEASE CANDIDATES",
                "-" * 60,
            ])
            for test in candidates:
                lines.append(f"  • {test.test_id}: {test.title}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_quarantine_manager(
    policy: Optional[QuarantinePolicy] = None,
) -> QuarantineManager:
    """Create a quarantine manager instance."""
    return QuarantineManager(policy)
