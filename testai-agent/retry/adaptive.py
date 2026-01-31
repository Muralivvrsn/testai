"""
TestAI Agent - Adaptive Retry Manager

Intelligently adjusts retry behavior based on
historical patterns and real-time analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from .strategy import RetryStrategy, RetryConfig, RetryResult, BackoffType


class RetryDecision(Enum):
    """Decision on whether to retry."""
    RETRY = "retry"  # Should retry
    SKIP = "skip"  # Skip retry (not worth it)
    QUARANTINE = "quarantine"  # Move to quarantine
    ESCALATE = "escalate"  # Escalate for review


@dataclass
class RetryContext:
    """Context for retry decision making."""
    test_id: str
    current_attempt: int
    error: Optional[str] = None
    duration_ms: int = 0

    # Historical data
    historical_pass_rate: float = 1.0
    recent_failures: int = 0
    consecutive_failures: int = 0
    avg_retry_success_rate: float = 0.5

    # Timing
    time_since_last_success: Optional[timedelta] = None
    run_time_budget_remaining_ms: Optional[int] = None


@dataclass
class TestRetryProfile:
    """Profile of a test's retry behavior."""
    test_id: str
    total_runs: int = 0
    total_retries: int = 0
    retry_successes: int = 0
    optimal_retry_count: int = 3
    recommended_backoff: BackoffType = BackoffType.EXPONENTIAL
    error_patterns: Dict[str, int] = field(default_factory=dict)
    avg_success_attempt: float = 1.0
    last_updated: datetime = field(default_factory=datetime.now)


class AdaptiveRetryManager:
    """
    Manages adaptive retry behavior.

    Features:
    - Learning from historical retry patterns
    - Dynamic retry count adjustment
    - Error pattern recognition
    - Time budget awareness
    - Quarantine recommendations
    """

    # Thresholds for decisions
    QUARANTINE_THRESHOLD = 0.3  # Pass rate below this = quarantine
    SKIP_RETRY_THRESHOLD = 0.1  # Retry success rate below this = skip
    ESCALATE_THRESHOLD = 5  # Consecutive failures to escalate

    def __init__(
        self,
        default_max_retries: int = 3,
        learning_enabled: bool = True,
    ):
        """Initialize the adaptive retry manager."""
        self.default_max_retries = default_max_retries
        self.learning_enabled = learning_enabled

        # Test profiles
        self._profiles: Dict[str, TestRetryProfile] = {}

        # Recent results for learning
        self._recent_results: List[RetryResult] = []
        self._max_recent_results = 1000

    def get_strategy(self, test_id: str) -> RetryStrategy:
        """Get optimized retry strategy for a test."""
        profile = self._profiles.get(test_id)

        if profile and self.learning_enabled:
            config = RetryConfig(
                max_retries=profile.optimal_retry_count,
                backoff_type=profile.recommended_backoff,
                initial_delay_ms=self._calculate_optimal_delay(profile),
            )
        else:
            config = RetryConfig(
                max_retries=self.default_max_retries,
            )

        return RetryStrategy(config)

    def decide(self, context: RetryContext) -> RetryDecision:
        """Make an adaptive retry decision."""
        # Check for quarantine condition
        if context.historical_pass_rate < self.QUARANTINE_THRESHOLD:
            if context.consecutive_failures >= self.ESCALATE_THRESHOLD:
                return RetryDecision.QUARANTINE

        # Check for escalation
        if context.consecutive_failures >= self.ESCALATE_THRESHOLD:
            return RetryDecision.ESCALATE

        # Check if retries are worth it
        if context.avg_retry_success_rate < self.SKIP_RETRY_THRESHOLD:
            return RetryDecision.SKIP

        # Check time budget
        if context.run_time_budget_remaining_ms is not None:
            estimated_retry_time = self._estimate_retry_time(context)
            if estimated_retry_time > context.run_time_budget_remaining_ms:
                return RetryDecision.SKIP

        # Default to retry
        return RetryDecision.RETRY

    def record_result(self, result: RetryResult):
        """Record a retry result for learning."""
        # Update profile
        profile = self._profiles.setdefault(
            result.test_id,
            TestRetryProfile(test_id=result.test_id)
        )

        profile.total_runs += 1
        profile.total_retries += result.total_attempts - 1
        profile.last_updated = datetime.now()

        if result.successful_attempt and result.successful_attempt > 1:
            profile.retry_successes += 1
            # Update average success attempt
            profile.avg_success_attempt = (
                (profile.avg_success_attempt * (profile.retry_successes - 1) +
                 result.successful_attempt) / profile.retry_successes
            )

        # Track error patterns
        if result.error_pattern:
            profile.error_patterns[result.error_pattern] = (
                profile.error_patterns.get(result.error_pattern, 0) + 1
            )

        # Store recent result
        self._recent_results.append(result)
        if len(self._recent_results) > self._max_recent_results:
            self._recent_results.pop(0)

        # Update optimal settings
        if self.learning_enabled:
            self._update_optimal_settings(profile)

    def get_profile(self, test_id: str) -> Optional[TestRetryProfile]:
        """Get retry profile for a test."""
        return self._profiles.get(test_id)

    def get_retry_success_rate(self, test_id: str) -> float:
        """Get retry success rate for a test."""
        profile = self._profiles.get(test_id)
        if not profile or profile.total_retries == 0:
            return 0.5  # Default assumption

        return profile.retry_successes / profile.total_runs if profile.total_runs > 0 else 0

    def get_recommended_retries(self, test_id: str) -> int:
        """Get recommended retry count for a test."""
        profile = self._profiles.get(test_id)
        if profile:
            return profile.optimal_retry_count
        return self.default_max_retries

    def _calculate_optimal_delay(self, profile: TestRetryProfile) -> int:
        """Calculate optimal initial delay based on profile."""
        # If test has high success on first retry, use shorter delays
        if profile.avg_success_attempt < 1.5:
            return 500
        elif profile.avg_success_attempt < 2.5:
            return 1000
        else:
            return 2000

    def _estimate_retry_time(self, context: RetryContext) -> int:
        """Estimate time needed for retries."""
        # Rough estimate: avg test time * remaining retries + backoff
        profile = self._profiles.get(context.test_id)
        max_retries = profile.optimal_retry_count if profile else self.default_max_retries
        remaining = max_retries - context.current_attempt

        # Assume avg test takes similar time + exponential backoff
        estimated = (
            context.duration_ms * remaining +
            sum(1000 * (2 ** i) for i in range(remaining))
        )
        return estimated

    def _update_optimal_settings(self, profile: TestRetryProfile):
        """Update optimal retry settings based on data."""
        # Adjust retry count based on success patterns
        if profile.total_runs >= 10:
            retry_success_rate = (
                profile.retry_successes / profile.total_runs
                if profile.total_runs > 0 else 0
            )

            if retry_success_rate < 0.1:
                # Retries rarely help
                profile.optimal_retry_count = 1
            elif retry_success_rate < 0.3:
                profile.optimal_retry_count = 2
            elif retry_success_rate > 0.7:
                # Retries are very helpful
                profile.optimal_retry_count = 5
            else:
                profile.optimal_retry_count = 3

            # Adjust backoff based on success patterns
            if profile.avg_success_attempt < 2:
                # Quick recovery - use shorter delays
                profile.recommended_backoff = BackoffType.FIXED
            elif profile.avg_success_attempt > 3:
                # Slow recovery - use exponential
                profile.recommended_backoff = BackoffType.EXPONENTIAL
            else:
                profile.recommended_backoff = BackoffType.LINEAR

    def get_insights(self) -> Dict[str, Any]:
        """Get insights from retry patterns."""
        if not self._profiles:
            return {"message": "No data collected yet"}

        total_runs = sum(p.total_runs for p in self._profiles.values())
        total_retries = sum(p.total_retries for p in self._profiles.values())
        total_successes = sum(p.retry_successes for p in self._profiles.values())

        # Find most problematic tests
        problematic = sorted(
            self._profiles.values(),
            key=lambda p: p.total_retries / max(1, p.total_runs),
            reverse=True,
        )[:5]

        # Find most common error patterns
        all_errors: Dict[str, int] = defaultdict(int)
        for profile in self._profiles.values():
            for error, count in profile.error_patterns.items():
                all_errors[error] += count

        return {
            "total_tests_tracked": len(self._profiles),
            "total_runs": total_runs,
            "total_retries": total_retries,
            "retry_success_rate": total_successes / total_runs if total_runs > 0 else 0,
            "avg_retries_per_test": total_retries / total_runs if total_runs > 0 else 0,
            "most_problematic_tests": [
                {
                    "test_id": p.test_id,
                    "retry_rate": p.total_retries / max(1, p.total_runs),
                }
                for p in problematic
            ],
            "common_error_patterns": dict(sorted(
                all_errors.items(),
                key=lambda x: -x[1]
            )[:5]),
        }

    def format_profile(self, test_id: str) -> str:
        """Format test profile as readable text."""
        profile = self._profiles.get(test_id)

        if not profile:
            return f"No profile found for {test_id}"

        lines = [
            "=" * 50,
            f"  RETRY PROFILE: {test_id}",
            "=" * 50,
            "",
            f"  Total Runs: {profile.total_runs}",
            f"  Total Retries: {profile.total_retries}",
            f"  Retry Successes: {profile.retry_successes}",
            "",
            f"  Optimal Retry Count: {profile.optimal_retry_count}",
            f"  Recommended Backoff: {profile.recommended_backoff.value}",
            f"  Avg Success Attempt: {profile.avg_success_attempt:.1f}",
            "",
        ]

        if profile.error_patterns:
            lines.append("-" * 50)
            lines.append("  ERROR PATTERNS")
            lines.append("-" * 50)
            for error, count in sorted(
                profile.error_patterns.items(),
                key=lambda x: -x[1]
            ):
                lines.append(f"  • {error}: {count}")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_adaptive_retry_manager(
    default_max_retries: int = 3,
    learning_enabled: bool = True,
) -> AdaptiveRetryManager:
    """Create an adaptive retry manager instance."""
    return AdaptiveRetryManager(default_max_retries, learning_enabled)
