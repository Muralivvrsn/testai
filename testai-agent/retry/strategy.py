"""
TestAI Agent - Retry Strategy

Configurable retry strategies with different backoff
algorithms and failure handling policies.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import random
import math


class BackoffType(Enum):
    """Types of backoff algorithms."""
    FIXED = "fixed"  # Fixed delay between retries
    LINEAR = "linear"  # Linearly increasing delay
    EXPONENTIAL = "exponential"  # Exponentially increasing delay
    FIBONACCI = "fibonacci"  # Fibonacci sequence delay
    JITTERED = "jittered"  # Exponential with random jitter
    DECORRELATED = "decorrelated"  # Decorrelated jitter (AWS style)


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    backoff_type: BackoffType = BackoffType.EXPONENTIAL
    initial_delay_ms: int = 1000
    max_delay_ms: int = 30000
    jitter_factor: float = 0.1  # 10% jitter
    retry_on_errors: Optional[List[str]] = None  # Specific errors to retry
    skip_on_errors: Optional[List[str]] = None  # Errors that shouldn't retry


@dataclass
class RetryAttempt:
    """A single retry attempt."""
    attempt_number: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    passed: bool = False
    error: Optional[str] = None
    duration_ms: int = 0
    delay_before_ms: int = 0


@dataclass
class RetryResult:
    """Result of retry execution."""
    test_id: str
    final_status: str  # passed, failed, exhausted
    total_attempts: int
    successful_attempt: Optional[int] = None
    attempts: List[RetryAttempt] = field(default_factory=list)
    total_duration_ms: int = 0
    total_delay_ms: int = 0
    error_pattern: Optional[str] = None


class RetryStrategy:
    """
    Implements various retry strategies.

    Supports multiple backoff algorithms:
    - Fixed: Same delay every time
    - Linear: delay = initial * attempt
    - Exponential: delay = initial * 2^attempt
    - Fibonacci: delay follows Fibonacci sequence
    - Jittered: Exponential with random variation
    - Decorrelated: AWS-style decorrelated jitter
    """

    # Fibonacci cache for performance
    _fib_cache = [1, 1]

    def __init__(self, config: Optional[RetryConfig] = None):
        """Initialize the retry strategy."""
        self.config = config or RetryConfig()
        self._last_delay = self.config.initial_delay_ms

    def calculate_delay(self, attempt: int) -> int:
        """Calculate delay before the given attempt."""
        if attempt <= 1:
            return 0  # No delay before first attempt

        base_delay = self._get_base_delay(attempt)

        # Apply jitter if configured
        if self.config.jitter_factor > 0:
            jitter_range = base_delay * self.config.jitter_factor
            jitter = random.uniform(-jitter_range, jitter_range)
            base_delay = int(base_delay + jitter)

        # Clamp to max delay
        delay = min(base_delay, self.config.max_delay_ms)

        # Store for decorrelated jitter
        self._last_delay = delay

        return max(0, delay)

    def _get_base_delay(self, attempt: int) -> int:
        """Get base delay based on backoff type."""
        initial = self.config.initial_delay_ms
        backoff = self.config.backoff_type

        if backoff == BackoffType.FIXED:
            return initial

        elif backoff == BackoffType.LINEAR:
            return initial * attempt

        elif backoff == BackoffType.EXPONENTIAL:
            return initial * (2 ** (attempt - 1))

        elif backoff == BackoffType.FIBONACCI:
            return initial * self._fibonacci(attempt)

        elif backoff == BackoffType.JITTERED:
            # Full jitter: random between 0 and exponential delay
            max_delay = initial * (2 ** (attempt - 1))
            return random.randint(0, max_delay)

        elif backoff == BackoffType.DECORRELATED:
            # Decorrelated jitter: random between initial and 3 * last_delay
            return random.randint(
                initial,
                min(self.config.max_delay_ms, self._last_delay * 3)
            )

        return initial

    def _fibonacci(self, n: int) -> int:
        """Get nth Fibonacci number (cached)."""
        while len(self._fib_cache) <= n:
            self._fib_cache.append(
                self._fib_cache[-1] + self._fib_cache[-2]
            )
        return self._fib_cache[n]

    def should_retry(
        self,
        attempt: int,
        error: Optional[str] = None,
    ) -> bool:
        """Determine if another retry should be attempted."""
        # Check max retries
        if attempt >= self.config.max_retries:
            return False

        # Check error patterns
        if error:
            # Skip specific errors
            if self.config.skip_on_errors:
                for pattern in self.config.skip_on_errors:
                    if pattern.lower() in error.lower():
                        return False

            # Only retry specific errors
            if self.config.retry_on_errors:
                for pattern in self.config.retry_on_errors:
                    if pattern.lower() in error.lower():
                        return True
                return False  # Error didn't match retry patterns

        return True

    def execute_with_retry(
        self,
        test_id: str,
        test_fn: Callable[[], bool],
        error_fn: Optional[Callable[[], Optional[str]]] = None,
    ) -> RetryResult:
        """Execute a test with retry logic."""
        attempts = []
        successful_attempt = None
        error_pattern = None
        errors_seen = []

        for attempt_num in range(1, self.config.max_retries + 2):
            # Calculate delay
            delay = self.calculate_delay(attempt_num)

            # Simulate delay (in real implementation, would use time.sleep)
            attempt = RetryAttempt(
                attempt_number=attempt_num,
                started_at=datetime.now(),
                delay_before_ms=delay,
            )

            try:
                # Execute test
                passed = test_fn()
                attempt.passed = passed
                attempt.ended_at = datetime.now()
                attempt.duration_ms = int(
                    (attempt.ended_at - attempt.started_at).total_seconds() * 1000
                )

                if passed:
                    successful_attempt = attempt_num
                    attempts.append(attempt)
                    break

                # Get error if failed
                if error_fn:
                    attempt.error = error_fn()
                    if attempt.error:
                        errors_seen.append(attempt.error)

            except Exception as e:
                attempt.error = str(e)
                attempt.ended_at = datetime.now()
                attempt.duration_ms = int(
                    (attempt.ended_at - attempt.started_at).total_seconds() * 1000
                )
                errors_seen.append(str(e))

            attempts.append(attempt)

            # Check if should retry
            if not self.should_retry(attempt_num, attempt.error):
                break

        # Determine final status
        if successful_attempt:
            final_status = "passed"
        elif len(attempts) >= self.config.max_retries + 1:
            final_status = "exhausted"
        else:
            final_status = "failed"

        # Find common error pattern
        if errors_seen:
            error_pattern = self._find_error_pattern(errors_seen)

        total_duration = sum(a.duration_ms for a in attempts)
        total_delay = sum(a.delay_before_ms for a in attempts)

        return RetryResult(
            test_id=test_id,
            final_status=final_status,
            total_attempts=len(attempts),
            successful_attempt=successful_attempt,
            attempts=attempts,
            total_duration_ms=total_duration,
            total_delay_ms=total_delay,
            error_pattern=error_pattern,
        )

    def simulate_retries(
        self,
        test_id: str,
        failure_probability: float = 0.5,
    ) -> RetryResult:
        """Simulate retry execution for testing."""
        def test_fn():
            return random.random() > failure_probability

        def error_fn():
            errors = [
                "Element not found",
                "Timeout exceeded",
                "Connection refused",
                "Assertion failed",
            ]
            return random.choice(errors)

        return self.execute_with_retry(test_id, test_fn, error_fn)

    def _find_error_pattern(self, errors: List[str]) -> Optional[str]:
        """Find common pattern in errors."""
        if not errors:
            return None

        # Count error types
        error_types = {}
        keywords = [
            "timeout", "element", "connection", "assertion",
            "network", "not found", "failed", "refused"
        ]

        for error in errors:
            error_lower = error.lower()
            for keyword in keywords:
                if keyword in error_lower:
                    error_types[keyword] = error_types.get(keyword, 0) + 1

        if error_types:
            # Return most common pattern
            return max(error_types.items(), key=lambda x: x[1])[0]

        return None

    def get_delay_sequence(self, max_attempts: int = 5) -> List[int]:
        """Get the sequence of delays for visualization."""
        return [self.calculate_delay(i + 1) for i in range(max_attempts)]

    def format_result(self, result: RetryResult) -> str:
        """Format retry result as readable text."""
        lines = [
            "=" * 50,
            f"  RETRY RESULT: {result.test_id}",
            "=" * 50,
            "",
            f"  Final Status: {result.final_status.upper()}",
            f"  Total Attempts: {result.total_attempts}",
        ]

        if result.successful_attempt:
            lines.append(f"  Successful on Attempt: {result.successful_attempt}")

        lines.extend([
            f"  Total Duration: {result.total_duration_ms}ms",
            f"  Total Delay: {result.total_delay_ms}ms",
            "",
        ])

        if result.error_pattern:
            lines.append(f"  Error Pattern: {result.error_pattern}")
            lines.append("")

        lines.append("-" * 50)
        lines.append("  ATTEMPTS")
        lines.append("-" * 50)

        status_icons = {
            True: "✅",
            False: "❌",
        }

        for attempt in result.attempts:
            icon = status_icons.get(attempt.passed, "⚪")
            lines.append(
                f"  {icon} Attempt {attempt.attempt_number}: "
                f"{attempt.duration_ms}ms"
                f" (delay: {attempt.delay_before_ms}ms)"
            )
            if attempt.error:
                lines.append(f"     Error: {attempt.error[:50]}")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_retry_strategy(
    max_retries: int = 3,
    backoff_type: BackoffType = BackoffType.EXPONENTIAL,
    initial_delay_ms: int = 1000,
) -> RetryStrategy:
    """Create a retry strategy instance."""
    config = RetryConfig(
        max_retries=max_retries,
        backoff_type=backoff_type,
        initial_delay_ms=initial_delay_ms,
    )
    return RetryStrategy(config)
