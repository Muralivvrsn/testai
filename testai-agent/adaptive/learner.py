"""
TestAI Agent - Adaptive Learner

Learns from test execution history to improve
test quality and prediction accuracy.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import math


class InsightType(Enum):
    """Types of learning insights."""
    FLAKINESS_PATTERN = "flakiness_pattern"
    TIMING_ANOMALY = "timing_anomaly"
    FAILURE_CORRELATION = "failure_correlation"
    SELECTOR_STABILITY = "selector_stability"
    ENVIRONMENT_IMPACT = "environment_impact"
    COVERAGE_GAP = "coverage_gap"
    OPTIMIZATION_OPPORTUNITY = "optimization_opportunity"


class ConfidenceLevel(Enum):
    """Confidence levels for insights."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"


@dataclass
class LearningConfig:
    """Configuration for adaptive learning."""
    min_samples: int = 10
    flakiness_threshold: float = 0.1
    timing_variance_threshold: float = 0.3
    correlation_threshold: float = 0.7
    learning_rate: float = 0.1
    decay_factor: float = 0.95
    lookback_days: int = 30


@dataclass
class LearningInsight:
    """An insight from learning."""
    insight_id: str
    insight_type: InsightType
    title: str
    description: str
    confidence: ConfidenceLevel
    confidence_score: float
    affected_tests: List[str]
    recommendations: List[str]
    data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class TestExecution:
    """A test execution record."""
    test_id: str
    test_name: str
    status: str  # passed, failed, skipped
    duration_ms: int
    timestamp: datetime
    browser: str = ""
    environment: str = ""
    error_message: Optional[str] = None
    selectors_used: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class TestPattern:
    """A learned pattern about a test."""
    test_id: str
    total_executions: int
    pass_count: int
    fail_count: int
    avg_duration_ms: float
    duration_variance: float
    flakiness_score: float
    last_failure: Optional[datetime]
    failure_patterns: Dict[str, int]
    environment_results: Dict[str, Dict[str, int]]


class AdaptiveLearner:
    """
    Learns from test execution history.

    Features:
    - Pattern recognition
    - Flakiness detection
    - Timing analysis
    - Failure correlation
    """

    def __init__(self, config: Optional[LearningConfig] = None):
        """Initialize the adaptive learner."""
        self.config = config or LearningConfig()
        self._insight_counter = 0
        self._executions: Dict[str, List[TestExecution]] = {}
        self._patterns: Dict[str, TestPattern] = {}
        self._insights: List[LearningInsight] = []
        self._correlations: Dict[Tuple[str, str], float] = {}

    def record_execution(self, execution: TestExecution):
        """Record a test execution."""
        if execution.test_id not in self._executions:
            self._executions[execution.test_id] = []

        self._executions[execution.test_id].append(execution)

        # Update pattern
        self._update_pattern(execution.test_id)

    def record_batch(self, executions: List[TestExecution]):
        """Record multiple executions."""
        for execution in executions:
            self.record_execution(execution)

    def _update_pattern(self, test_id: str):
        """Update pattern for a test."""
        execs = self._executions.get(test_id, [])
        if not execs:
            return

        # Calculate statistics
        total = len(execs)
        passed = sum(1 for e in execs if e.status == "passed")
        failed = sum(1 for e in execs if e.status == "failed")

        durations = [e.duration_ms for e in execs]
        avg_duration = sum(durations) / len(durations)

        # Calculate variance
        if len(durations) > 1:
            variance = sum((d - avg_duration) ** 2 for d in durations) / len(durations)
            std_dev = math.sqrt(variance)
            duration_variance = std_dev / avg_duration if avg_duration > 0 else 0
        else:
            duration_variance = 0

        # Calculate flakiness
        if total >= self.config.min_samples:
            # Flakiness = ratio of status changes
            changes = sum(
                1 for i in range(1, len(execs))
                if execs[i].status != execs[i - 1].status
            )
            flakiness = changes / (total - 1) if total > 1 else 0
        else:
            flakiness = 0

        # Find last failure
        last_failure = None
        for exec in reversed(execs):
            if exec.status == "failed":
                last_failure = exec.timestamp
                break

        # Count failure patterns
        failure_patterns = {}
        for exec in execs:
            if exec.status == "failed" and exec.error_message:
                # Extract error type
                error_type = self._categorize_error(exec.error_message)
                failure_patterns[error_type] = failure_patterns.get(error_type, 0) + 1

        # Track environment results
        env_results: Dict[str, Dict[str, int]] = {}
        for exec in execs:
            env = exec.environment or "default"
            if env not in env_results:
                env_results[env] = {"passed": 0, "failed": 0}
            if exec.status == "passed":
                env_results[env]["passed"] += 1
            elif exec.status == "failed":
                env_results[env]["failed"] += 1

        self._patterns[test_id] = TestPattern(
            test_id=test_id,
            total_executions=total,
            pass_count=passed,
            fail_count=failed,
            avg_duration_ms=avg_duration,
            duration_variance=duration_variance,
            flakiness_score=flakiness,
            last_failure=last_failure,
            failure_patterns=failure_patterns,
            environment_results=env_results,
        )

    def _categorize_error(self, error_message: str) -> str:
        """Categorize an error message."""
        error_lower = error_message.lower()

        if "timeout" in error_lower:
            return "timeout"
        elif "element" in error_lower and "not found" in error_lower:
            return "element_not_found"
        elif "stale" in error_lower:
            return "stale_element"
        elif "assertion" in error_lower:
            return "assertion"
        elif "network" in error_lower or "connection" in error_lower:
            return "network"
        elif "permission" in error_lower or "auth" in error_lower:
            return "permission"
        else:
            return "other"

    def analyze(self) -> List[LearningInsight]:
        """Analyze patterns and generate insights."""
        insights = []

        # Detect flaky tests
        insights.extend(self._detect_flaky_tests())

        # Detect timing anomalies
        insights.extend(self._detect_timing_anomalies())

        # Detect failure correlations
        insights.extend(self._detect_failure_correlations())

        # Detect environment-specific issues
        insights.extend(self._detect_environment_issues())

        self._insights.extend(insights)
        return insights

    def _detect_flaky_tests(self) -> List[LearningInsight]:
        """Detect flaky tests."""
        insights = []

        for test_id, pattern in self._patterns.items():
            if pattern.total_executions < self.config.min_samples:
                continue

            if pattern.flakiness_score > self.config.flakiness_threshold:
                self._insight_counter += 1

                # Determine confidence
                if pattern.flakiness_score > 0.3:
                    confidence = ConfidenceLevel.HIGH
                    confidence_score = 0.9
                elif pattern.flakiness_score > 0.2:
                    confidence = ConfidenceLevel.MEDIUM
                    confidence_score = 0.7
                else:
                    confidence = ConfidenceLevel.LOW
                    confidence_score = 0.5

                # Generate recommendations
                recommendations = [
                    "Add explicit waits for dynamic elements",
                    "Review test isolation - ensure no shared state",
                    "Check for race conditions in async operations",
                ]

                if pattern.failure_patterns:
                    top_error = max(pattern.failure_patterns, key=pattern.failure_patterns.get)
                    if top_error == "timeout":
                        recommendations.insert(0, "Increase timeout or optimize page load")
                    elif top_error == "stale_element":
                        recommendations.insert(0, "Re-fetch element references after page changes")

                insights.append(LearningInsight(
                    insight_id=f"insight-{self._insight_counter:05d}",
                    insight_type=InsightType.FLAKINESS_PATTERN,
                    title=f"Flaky Test Detected: {test_id}",
                    description=(
                        f"Test shows {pattern.flakiness_score:.1%} flakiness rate "
                        f"over {pattern.total_executions} executions"
                    ),
                    confidence=confidence,
                    confidence_score=confidence_score,
                    affected_tests=[test_id],
                    recommendations=recommendations,
                    data={
                        "flakiness_score": pattern.flakiness_score,
                        "total_executions": pattern.total_executions,
                        "failure_patterns": pattern.failure_patterns,
                    },
                ))

        return insights

    def _detect_timing_anomalies(self) -> List[LearningInsight]:
        """Detect tests with unusual timing patterns."""
        insights = []

        for test_id, pattern in self._patterns.items():
            if pattern.total_executions < self.config.min_samples:
                continue

            if pattern.duration_variance > self.config.timing_variance_threshold:
                self._insight_counter += 1

                insights.append(LearningInsight(
                    insight_id=f"insight-{self._insight_counter:05d}",
                    insight_type=InsightType.TIMING_ANOMALY,
                    title=f"Timing Variance: {test_id}",
                    description=(
                        f"Test duration varies by {pattern.duration_variance:.1%} "
                        f"(avg: {pattern.avg_duration_ms:.0f}ms)"
                    ),
                    confidence=ConfidenceLevel.MEDIUM,
                    confidence_score=0.7,
                    affected_tests=[test_id],
                    recommendations=[
                        "Investigate network dependencies",
                        "Check for resource contention",
                        "Consider mocking external services",
                    ],
                    data={
                        "avg_duration_ms": pattern.avg_duration_ms,
                        "variance": pattern.duration_variance,
                    },
                ))

        return insights

    def _detect_failure_correlations(self) -> List[LearningInsight]:
        """Detect tests that fail together."""
        insights = []
        test_ids = list(self._executions.keys())

        # Build correlation matrix
        for i, test_a in enumerate(test_ids):
            for test_b in test_ids[i + 1:]:
                correlation = self._calculate_correlation(test_a, test_b)
                if correlation > self.config.correlation_threshold:
                    self._correlations[(test_a, test_b)] = correlation

        # Group correlated tests
        groups = self._find_correlation_groups()

        for group in groups:
            if len(group) >= 2:
                self._insight_counter += 1

                insights.append(LearningInsight(
                    insight_id=f"insight-{self._insight_counter:05d}",
                    insight_type=InsightType.FAILURE_CORRELATION,
                    title=f"Correlated Failures ({len(group)} tests)",
                    description=(
                        "These tests tend to fail together, suggesting "
                        "a common dependency or shared state"
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    confidence_score=0.85,
                    affected_tests=list(group),
                    recommendations=[
                        "Identify shared dependencies",
                        "Check for common setup/teardown issues",
                        "Consider running these tests in isolation",
                    ],
                    data={"group_size": len(group)},
                ))

        return insights

    def _calculate_correlation(self, test_a: str, test_b: str) -> float:
        """Calculate failure correlation between two tests."""
        execs_a = self._executions.get(test_a, [])
        execs_b = self._executions.get(test_b, [])

        if not execs_a or not execs_b:
            return 0.0

        # Match executions by timestamp (within 1 hour)
        matches = []
        for ea in execs_a:
            for eb in execs_b:
                if abs((ea.timestamp - eb.timestamp).total_seconds()) < 3600:
                    matches.append((
                        1 if ea.status == "failed" else 0,
                        1 if eb.status == "failed" else 0,
                    ))

        if len(matches) < 5:
            return 0.0

        # Calculate correlation
        a_vals = [m[0] for m in matches]
        b_vals = [m[1] for m in matches]

        both_failed = sum(1 for a, b in zip(a_vals, b_vals) if a == 1 and b == 1)
        either_failed = sum(1 for a, b in zip(a_vals, b_vals) if a == 1 or b == 1)

        if either_failed == 0:
            return 0.0

        return both_failed / either_failed

    def _find_correlation_groups(self) -> List[set]:
        """Find groups of correlated tests."""
        groups = []
        used = set()

        for (test_a, test_b), corr in self._correlations.items():
            if corr < self.config.correlation_threshold:
                continue

            # Find existing group
            found_group = None
            for group in groups:
                if test_a in group or test_b in group:
                    found_group = group
                    break

            if found_group:
                found_group.add(test_a)
                found_group.add(test_b)
            else:
                groups.append({test_a, test_b})

        return groups

    def _detect_environment_issues(self) -> List[LearningInsight]:
        """Detect environment-specific issues."""
        insights = []

        for test_id, pattern in self._patterns.items():
            if len(pattern.environment_results) < 2:
                continue

            # Check for environment-specific failures
            env_pass_rates = {}
            for env, results in pattern.environment_results.items():
                total = results["passed"] + results["failed"]
                if total > 0:
                    env_pass_rates[env] = results["passed"] / total

            if not env_pass_rates:
                continue

            # Find significant differences
            rates = list(env_pass_rates.values())
            if max(rates) - min(rates) > 0.3:
                self._insight_counter += 1

                worst_env = min(env_pass_rates, key=env_pass_rates.get)
                best_env = max(env_pass_rates, key=env_pass_rates.get)

                insights.append(LearningInsight(
                    insight_id=f"insight-{self._insight_counter:05d}",
                    insight_type=InsightType.ENVIRONMENT_IMPACT,
                    title=f"Environment Impact: {test_id}",
                    description=(
                        f"Test performs differently across environments: "
                        f"{best_env} ({env_pass_rates[best_env]:.0%}) vs "
                        f"{worst_env} ({env_pass_rates[worst_env]:.0%})"
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    confidence_score=0.8,
                    affected_tests=[test_id],
                    recommendations=[
                        f"Investigate {worst_env} environment configuration",
                        "Check for environment-specific dependencies",
                        "Ensure consistent test data across environments",
                    ],
                    data={"pass_rates_by_environment": env_pass_rates},
                ))

        return insights

    def get_pattern(self, test_id: str) -> Optional[TestPattern]:
        """Get pattern for a test."""
        return self._patterns.get(test_id)

    def get_insights(
        self,
        insight_type: Optional[InsightType] = None,
    ) -> List[LearningInsight]:
        """Get insights, optionally filtered by type."""
        if insight_type:
            return [i for i in self._insights if i.insight_type == insight_type]
        return list(self._insights)

    def get_recommendations(self, test_id: str) -> List[str]:
        """Get recommendations for a specific test."""
        recommendations = []

        for insight in self._insights:
            if test_id in insight.affected_tests:
                recommendations.extend(insight.recommendations)

        return list(set(recommendations))

    def predict_flakiness(self, test_id: str) -> float:
        """Predict flakiness probability for a test."""
        pattern = self._patterns.get(test_id)
        if not pattern:
            return 0.0

        # Base score on historical flakiness
        score = pattern.flakiness_score

        # Adjust based on recent failures
        if pattern.last_failure:
            days_since = (datetime.now() - pattern.last_failure).days
            if days_since < 7:
                score *= 1.2  # Recent failures increase prediction

        return min(score, 1.0)

    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics."""
        total_tests = len(self._patterns)
        flaky_tests = sum(
            1 for p in self._patterns.values()
            if p.flakiness_score > self.config.flakiness_threshold
        )

        return {
            "total_tests_tracked": total_tests,
            "total_executions": sum(p.total_executions for p in self._patterns.values()),
            "flaky_tests": flaky_tests,
            "total_insights": len(self._insights),
            "insights_by_type": {
                t.value: sum(1 for i in self._insights if i.insight_type == t)
                for t in InsightType
            },
            "correlations_found": len(self._correlations),
        }

    def format_insights(self) -> str:
        """Format insights as readable text."""
        lines = [
            "=" * 60,
            "  ADAPTIVE LEARNING INSIGHTS",
            "=" * 60,
            "",
        ]

        stats = self.get_statistics()
        lines.extend([
            f"  Tests Tracked: {stats['total_tests_tracked']}",
            f"  Total Executions: {stats['total_executions']}",
            f"  Flaky Tests: {stats['flaky_tests']}",
            f"  Insights Generated: {stats['total_insights']}",
            "",
        ])

        if self._insights:
            lines.extend(["-" * 60, "  INSIGHTS", "-" * 60])

            for insight in self._insights[:10]:
                icon = {
                    InsightType.FLAKINESS_PATTERN: "⚠️",
                    InsightType.TIMING_ANOMALY: "⏱️",
                    InsightType.FAILURE_CORRELATION: "🔗",
                    InsightType.ENVIRONMENT_IMPACT: "🌍",
                }.get(insight.insight_type, "💡")

                confidence_icon = {
                    ConfidenceLevel.HIGH: "🟢",
                    ConfidenceLevel.MEDIUM: "🟡",
                    ConfidenceLevel.LOW: "🟠",
                }.get(insight.confidence, "⚪")

                lines.extend([
                    "",
                    f"  {icon} {insight.title}",
                    f"     {confidence_icon} Confidence: {insight.confidence.value}",
                    f"     {insight.description}",
                ])

                if insight.recommendations:
                    lines.append("     Recommendations:")
                    for rec in insight.recommendations[:2]:
                        lines.append(f"       • {rec}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_adaptive_learner(
    config: Optional[LearningConfig] = None,
) -> AdaptiveLearner:
    """Create an adaptive learner instance."""
    return AdaptiveLearner(config)
