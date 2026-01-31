"""
TestAI Agent - Insight Engine

Generates intelligent insights from test data, identifying
patterns, anomalies, and opportunities for improvement.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid
import statistics


class InsightType(Enum):
    """Types of insights."""
    PATTERN = "pattern"
    ANOMALY = "anomaly"
    TREND = "trend"
    OPPORTUNITY = "opportunity"
    WARNING = "warning"
    ACHIEVEMENT = "achievement"


class InsightPriority(Enum):
    """Priority levels for insights."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InsightCategory(Enum):
    """Categories of insights."""
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    COVERAGE = "coverage"
    MAINTENANCE = "maintenance"
    EFFICIENCY = "efficiency"
    QUALITY = "quality"


@dataclass
class TestInsight:
    """An intelligent insight about tests."""
    insight_id: str
    insight_type: InsightType
    priority: InsightPriority
    category: InsightCategory
    title: str
    description: str
    affected_tests: List[str]
    evidence: Dict[str, Any]
    suggestions: List[str]
    created_at: datetime
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestMetric:
    """A test metric data point."""
    test_id: str
    metric_name: str
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class TestEvent:
    """A test event for analysis."""
    event_id: str
    test_id: str
    event_type: str  # pass, fail, skip, flaky
    duration_ms: float
    timestamp: datetime
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class InsightEngine:
    """
    Intelligent insight generation engine.

    Features:
    - Pattern detection
    - Anomaly identification
    - Trend analysis
    - Opportunity discovery
    - Proactive warnings
    """

    # Thresholds for insight generation
    SLOW_TEST_THRESHOLD_MS = 5000
    FLAKY_THRESHOLD = 0.15
    FAILURE_STREAK_THRESHOLD = 3
    PERFORMANCE_DEGRADATION_PCT = 0.20
    HIGH_COVERAGE_GAP_PCT = 0.30

    def __init__(
        self,
        insight_ttl_hours: int = 24,
        min_data_points: int = 10,
    ):
        """Initialize the insight engine."""
        self._insight_ttl = insight_ttl_hours
        self._min_data_points = min_data_points

        self._events: List[TestEvent] = []
        self._metrics: List[TestMetric] = []
        self._insights: List[TestInsight] = []

        self._insight_counter = 0

    def record_event(
        self,
        test_id: str,
        event_type: str,
        duration_ms: float,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TestEvent:
        """Record a test event."""
        event = TestEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8]}",
            test_id=test_id,
            event_type=event_type,
            duration_ms=duration_ms,
            timestamp=datetime.now(),
            error_message=error_message,
            metadata=metadata or {},
        )

        self._events.append(event)

        # Prune old events (keep last 30 days)
        cutoff = datetime.now() - timedelta(days=30)
        self._events = [e for e in self._events if e.timestamp > cutoff]

        return event

    def record_metric(
        self,
        test_id: str,
        metric_name: str,
        value: float,
        tags: Optional[Dict[str, str]] = None,
    ) -> TestMetric:
        """Record a test metric."""
        metric = TestMetric(
            test_id=test_id,
            metric_name=metric_name,
            value=value,
            timestamp=datetime.now(),
            tags=tags or {},
        )

        self._metrics.append(metric)

        # Prune old metrics
        cutoff = datetime.now() - timedelta(days=30)
        self._metrics = [m for m in self._metrics if m.timestamp > cutoff]

        return metric

    def generate_insights(self) -> List[TestInsight]:
        """Generate all insights from current data."""
        insights = []

        # Analyze patterns
        insights.extend(self._analyze_failure_patterns())
        insights.extend(self._analyze_performance_patterns())
        insights.extend(self._analyze_flakiness())

        # Analyze anomalies
        insights.extend(self._detect_duration_anomalies())
        insights.extend(self._detect_failure_spikes())

        # Analyze trends
        insights.extend(self._analyze_reliability_trends())
        insights.extend(self._analyze_performance_trends())

        # Identify opportunities
        insights.extend(self._identify_optimization_opportunities())

        # Store and return
        self._insights.extend(insights)
        return insights

    def get_insights(
        self,
        priority: Optional[InsightPriority] = None,
        category: Optional[InsightCategory] = None,
        limit: int = 20,
    ) -> List[TestInsight]:
        """Get insights with optional filtering."""
        insights = self._insights

        if priority:
            insights = [i for i in insights if i.priority == priority]

        if category:
            insights = [i for i in insights if i.category == category]

        # Filter expired insights
        now = datetime.now()
        insights = [
            i for i in insights
            if not i.expires_at or i.expires_at > now
        ]

        # Sort by priority
        priority_order = {
            InsightPriority.CRITICAL: 0,
            InsightPriority.HIGH: 1,
            InsightPriority.MEDIUM: 2,
            InsightPriority.LOW: 3,
            InsightPriority.INFO: 4,
        }
        insights = sorted(insights, key=lambda i: priority_order[i.priority])

        return insights[:limit]

    def get_insights_for_test(
        self,
        test_id: str,
    ) -> List[TestInsight]:
        """Get insights related to a specific test."""
        return [
            i for i in self._insights
            if test_id in i.affected_tests
        ]

    def _create_insight(
        self,
        insight_type: InsightType,
        priority: InsightPriority,
        category: InsightCategory,
        title: str,
        description: str,
        affected_tests: List[str],
        evidence: Dict[str, Any],
        suggestions: List[str],
    ) -> TestInsight:
        """Create a new insight."""
        self._insight_counter += 1

        return TestInsight(
            insight_id=f"INS-{self._insight_counter:05d}",
            insight_type=insight_type,
            priority=priority,
            category=category,
            title=title,
            description=description,
            affected_tests=affected_tests,
            evidence=evidence,
            suggestions=suggestions,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=self._insight_ttl),
        )

    def _analyze_failure_patterns(self) -> List[TestInsight]:
        """Analyze failure patterns across tests."""
        insights = []

        # Group events by test
        test_events: Dict[str, List[TestEvent]] = {}
        for event in self._events:
            if event.test_id not in test_events:
                test_events[event.test_id] = []
            test_events[event.test_id].append(event)

        for test_id, events in test_events.items():
            if len(events) < self._min_data_points:
                continue

            # Check for failure streaks
            recent = sorted(events, key=lambda e: e.timestamp)[-10:]
            consecutive_failures = 0
            max_streak = 0

            for event in recent:
                if event.event_type == "fail":
                    consecutive_failures += 1
                    max_streak = max(max_streak, consecutive_failures)
                else:
                    consecutive_failures = 0

            if max_streak >= self.FAILURE_STREAK_THRESHOLD:
                insights.append(self._create_insight(
                    insight_type=InsightType.PATTERN,
                    priority=InsightPriority.HIGH,
                    category=InsightCategory.RELIABILITY,
                    title="Consecutive Failure Pattern",
                    description=f"Test {test_id} has {max_streak} consecutive failures",
                    affected_tests=[test_id],
                    evidence={
                        "consecutive_failures": max_streak,
                        "total_events": len(events),
                    },
                    suggestions=[
                        "Review recent changes to this test",
                        "Check for environment issues",
                        "Verify test dependencies are stable",
                    ],
                ))

            # Check for common error patterns
            error_messages = [e.error_message for e in events if e.error_message]
            if len(error_messages) >= 3:
                # Find most common error
                error_counts: Dict[str, int] = {}
                for msg in error_messages:
                    short_msg = msg[:100] if msg else "Unknown"
                    error_counts[short_msg] = error_counts.get(short_msg, 0) + 1

                top_error = max(error_counts.items(), key=lambda x: x[1])
                if top_error[1] >= 3:
                    insights.append(self._create_insight(
                        insight_type=InsightType.PATTERN,
                        priority=InsightPriority.MEDIUM,
                        category=InsightCategory.RELIABILITY,
                        title="Recurring Error Pattern",
                        description=f"Same error occurring repeatedly in {test_id}",
                        affected_tests=[test_id],
                        evidence={
                            "error_message": top_error[0],
                            "occurrences": top_error[1],
                        },
                        suggestions=[
                            "Investigate root cause of recurring error",
                            "Add better error handling",
                        ],
                    ))

        return insights

    def _analyze_performance_patterns(self) -> List[TestInsight]:
        """Analyze performance patterns."""
        insights = []

        # Group events by test
        test_events: Dict[str, List[TestEvent]] = {}
        for event in self._events:
            if event.test_id not in test_events:
                test_events[event.test_id] = []
            test_events[event.test_id].append(event)

        # Find slow tests
        slow_tests = []
        for test_id, events in test_events.items():
            durations = [e.duration_ms for e in events]
            avg_duration = statistics.mean(durations) if durations else 0

            if avg_duration > self.SLOW_TEST_THRESHOLD_MS:
                slow_tests.append((test_id, avg_duration))

        if slow_tests:
            slow_tests.sort(key=lambda x: x[1], reverse=True)
            top_slow = slow_tests[:5]

            insights.append(self._create_insight(
                insight_type=InsightType.PATTERN,
                priority=InsightPriority.MEDIUM,
                category=InsightCategory.PERFORMANCE,
                title="Slow Test Pattern",
                description=f"{len(slow_tests)} tests consistently exceed {self.SLOW_TEST_THRESHOLD_MS}ms",
                affected_tests=[t[0] for t in top_slow],
                evidence={
                    "slow_tests_count": len(slow_tests),
                    "slowest": {t[0]: f"{t[1]:.0f}ms" for t in top_slow},
                },
                suggestions=[
                    "Optimize slow selectors",
                    "Reduce wait times where possible",
                    "Consider parallel execution",
                ],
            ))

        return insights

    def _analyze_flakiness(self) -> List[TestInsight]:
        """Analyze test flakiness."""
        insights = []

        # Group events by test
        test_events: Dict[str, List[TestEvent]] = {}
        for event in self._events:
            if event.test_id not in test_events:
                test_events[event.test_id] = []
            test_events[event.test_id].append(event)

        flaky_tests = []
        for test_id, events in test_events.items():
            if len(events) < self._min_data_points:
                continue

            # Count transitions between pass/fail
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            transitions = 0
            for i in range(1, len(sorted_events)):
                if sorted_events[i].event_type != sorted_events[i - 1].event_type:
                    if sorted_events[i].event_type in ("pass", "fail"):
                        transitions += 1

            flaky_rate = transitions / len(sorted_events)
            if flaky_rate > self.FLAKY_THRESHOLD:
                flaky_tests.append((test_id, flaky_rate))

        if flaky_tests:
            flaky_tests.sort(key=lambda x: x[1], reverse=True)

            insights.append(self._create_insight(
                insight_type=InsightType.WARNING,
                priority=InsightPriority.HIGH,
                category=InsightCategory.RELIABILITY,
                title="Flaky Tests Detected",
                description=f"{len(flaky_tests)} tests show inconsistent results",
                affected_tests=[t[0] for t in flaky_tests],
                evidence={
                    "flaky_tests_count": len(flaky_tests),
                    "worst_offenders": {t[0]: f"{t[1]:.1%}" for t in flaky_tests[:5]},
                },
                suggestions=[
                    "Add retry mechanisms for flaky tests",
                    "Review async operations and race conditions",
                    "Consider quarantining until fixed",
                ],
            ))

        return insights

    def _detect_duration_anomalies(self) -> List[TestInsight]:
        """Detect unusual duration spikes."""
        insights = []

        # Group events by test
        test_events: Dict[str, List[TestEvent]] = {}
        for event in self._events:
            if event.test_id not in test_events:
                test_events[event.test_id] = []
            test_events[event.test_id].append(event)

        for test_id, events in test_events.items():
            if len(events) < self._min_data_points:
                continue

            durations = [e.duration_ms for e in events]
            mean = statistics.mean(durations)
            stdev = statistics.stdev(durations) if len(durations) > 1 else 0

            # Check for outliers (>3 standard deviations)
            recent = sorted(events, key=lambda e: e.timestamp)[-5:]
            outliers = [
                e for e in recent
                if stdev > 0 and abs(e.duration_ms - mean) > 3 * stdev
            ]

            if outliers:
                insights.append(self._create_insight(
                    insight_type=InsightType.ANOMALY,
                    priority=InsightPriority.MEDIUM,
                    category=InsightCategory.PERFORMANCE,
                    title="Duration Anomaly",
                    description=f"Unusual execution times detected for {test_id}",
                    affected_tests=[test_id],
                    evidence={
                        "mean_duration_ms": round(mean, 2),
                        "std_dev_ms": round(stdev, 2),
                        "outlier_count": len(outliers),
                        "outlier_durations": [round(o.duration_ms, 2) for o in outliers],
                    },
                    suggestions=[
                        "Check for resource contention",
                        "Review network conditions",
                        "Verify test environment stability",
                    ],
                ))

        return insights

    def _detect_failure_spikes(self) -> List[TestInsight]:
        """Detect sudden increase in failures."""
        insights = []

        # Group failures by hour
        hour_failures: Dict[str, int] = {}
        for event in self._events:
            if event.event_type == "fail":
                hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
                hour_failures[hour_key] = hour_failures.get(hour_key, 0) + 1

        if len(hour_failures) < 3:
            return insights

        values = list(hour_failures.values())
        avg_failures = statistics.mean(values)
        recent_hour = max(hour_failures.keys())
        recent_failures = hour_failures.get(recent_hour, 0)

        if avg_failures > 0 and recent_failures > avg_failures * 2:
            insights.append(self._create_insight(
                insight_type=InsightType.ANOMALY,
                priority=InsightPriority.HIGH,
                category=InsightCategory.RELIABILITY,
                title="Failure Spike Detected",
                description=f"Failures spiked to {recent_failures} (avg: {avg_failures:.1f})",
                affected_tests=[],
                evidence={
                    "current_failures": recent_failures,
                    "average_failures": round(avg_failures, 2),
                    "spike_factor": round(recent_failures / avg_failures, 2),
                },
                suggestions=[
                    "Check for infrastructure issues",
                    "Review recent deployments",
                    "Verify test data availability",
                ],
            ))

        return insights

    def _analyze_reliability_trends(self) -> List[TestInsight]:
        """Analyze reliability trends over time."""
        insights = []

        if len(self._events) < self._min_data_points:
            return insights

        # Split events into halves
        sorted_events = sorted(self._events, key=lambda e: e.timestamp)
        mid = len(sorted_events) // 2
        first_half = sorted_events[:mid]
        second_half = sorted_events[mid:]

        first_pass_rate = (
            sum(1 for e in first_half if e.event_type == "pass") / len(first_half)
        )
        second_pass_rate = (
            sum(1 for e in second_half if e.event_type == "pass") / len(second_half)
        )

        change = second_pass_rate - first_pass_rate

        if abs(change) > 0.1:
            is_improving = change > 0

            insights.append(self._create_insight(
                insight_type=InsightType.TREND,
                priority=InsightPriority.MEDIUM if is_improving else InsightPriority.HIGH,
                category=InsightCategory.RELIABILITY,
                title="Reliability Trend" + (" Improving" if is_improving else " Declining"),
                description=(
                    f"Pass rate changed from {first_pass_rate:.1%} to {second_pass_rate:.1%}"
                ),
                affected_tests=[],
                evidence={
                    "previous_pass_rate": round(first_pass_rate, 3),
                    "current_pass_rate": round(second_pass_rate, 3),
                    "change": round(change, 3),
                },
                suggestions=[
                    "Continue current practices" if is_improving else "Investigate reliability issues",
                    "Monitor trend closely",
                ],
            ))

        return insights

    def _analyze_performance_trends(self) -> List[TestInsight]:
        """Analyze performance trends over time."""
        insights = []

        if len(self._events) < self._min_data_points:
            return insights

        # Compare durations over time
        sorted_events = sorted(self._events, key=lambda e: e.timestamp)
        mid = len(sorted_events) // 2
        first_half = sorted_events[:mid]
        second_half = sorted_events[mid:]

        first_avg = statistics.mean([e.duration_ms for e in first_half])
        second_avg = statistics.mean([e.duration_ms for e in second_half])

        pct_change = (second_avg - first_avg) / first_avg if first_avg > 0 else 0

        if abs(pct_change) > self.PERFORMANCE_DEGRADATION_PCT:
            is_degrading = pct_change > 0

            insights.append(self._create_insight(
                insight_type=InsightType.TREND,
                priority=InsightPriority.MEDIUM if not is_degrading else InsightPriority.HIGH,
                category=InsightCategory.PERFORMANCE,
                title="Performance Trend" + (" Degrading" if is_degrading else " Improving"),
                description=(
                    f"Average duration changed by {pct_change:+.1%} "
                    f"({first_avg:.0f}ms → {second_avg:.0f}ms)"
                ),
                affected_tests=[],
                evidence={
                    "previous_avg_ms": round(first_avg, 2),
                    "current_avg_ms": round(second_avg, 2),
                    "pct_change": round(pct_change * 100, 2),
                },
                suggestions=[
                    "Profile slow tests" if is_degrading else "Document performance wins",
                    "Review recent code changes affecting performance",
                ],
            ))

        return insights

    def _identify_optimization_opportunities(self) -> List[TestInsight]:
        """Identify opportunities for optimization."""
        insights = []

        # Group events by test
        test_events: Dict[str, List[TestEvent]] = {}
        for event in self._events:
            if event.test_id not in test_events:
                test_events[event.test_id] = []
            test_events[event.test_id].append(event)

        # Find tests that always pass (candidates for parallelization)
        always_pass = []
        for test_id, events in test_events.items():
            if len(events) >= self._min_data_points:
                if all(e.event_type == "pass" for e in events):
                    avg_duration = statistics.mean([e.duration_ms for e in events])
                    always_pass.append((test_id, avg_duration))

        if len(always_pass) >= 5:
            total_time = sum(t[1] for t in always_pass)

            insights.append(self._create_insight(
                insight_type=InsightType.OPPORTUNITY,
                priority=InsightPriority.LOW,
                category=InsightCategory.EFFICIENCY,
                title="Parallelization Opportunity",
                description=(
                    f"{len(always_pass)} stable tests could run in parallel "
                    f"(total: {total_time:.0f}ms)"
                ),
                affected_tests=[t[0] for t in always_pass[:10]],
                evidence={
                    "stable_tests_count": len(always_pass),
                    "total_sequential_time_ms": round(total_time, 2),
                    "potential_parallel_time_ms": round(max(t[1] for t in always_pass), 2),
                },
                suggestions=[
                    "Consider running stable tests in parallel",
                    "Group tests by resource requirements",
                ],
            ))

        return insights

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        priority_counts = {}
        for priority in InsightPriority:
            priority_counts[priority.value] = sum(
                1 for i in self._insights if i.priority == priority
            )

        return {
            "total_events": len(self._events),
            "total_metrics": len(self._metrics),
            "total_insights": len(self._insights),
            "insights_by_priority": priority_counts,
            "unique_tests": len(set(e.test_id for e in self._events)),
        }

    def format_insight(self, insight: TestInsight) -> str:
        """Format an insight for display."""
        priority_emoji = {
            InsightPriority.CRITICAL: "🔴",
            InsightPriority.HIGH: "🟠",
            InsightPriority.MEDIUM: "🟡",
            InsightPriority.LOW: "🟢",
            InsightPriority.INFO: "ℹ️",
        }

        type_emoji = {
            InsightType.PATTERN: "🔄",
            InsightType.ANOMALY: "⚠️",
            InsightType.TREND: "📈",
            InsightType.OPPORTUNITY: "💡",
            InsightType.WARNING: "🚨",
            InsightType.ACHIEVEMENT: "🏆",
        }

        lines = [
            "=" * 60,
            f"  {priority_emoji[insight.priority]} {type_emoji[insight.insight_type]} {insight.title}",
            "=" * 60,
            "",
            f"  {insight.description}",
            "",
            f"  Category: {insight.category.value}",
            f"  Priority: {insight.priority.value}",
            "",
        ]

        if insight.affected_tests:
            lines.append("-" * 60)
            lines.append("  AFFECTED TESTS")
            lines.append("-" * 60)
            for test_id in insight.affected_tests[:5]:
                lines.append(f"  • {test_id}")
            if len(insight.affected_tests) > 5:
                lines.append(f"  ... and {len(insight.affected_tests) - 5} more")
            lines.append("")

        if insight.suggestions:
            lines.append("-" * 60)
            lines.append("  SUGGESTIONS")
            lines.append("-" * 60)
            for suggestion in insight.suggestions:
                lines.append(f"  → {suggestion}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


def create_insight_engine(
    insight_ttl_hours: int = 24,
    min_data_points: int = 10,
) -> InsightEngine:
    """Create an insight engine instance."""
    return InsightEngine(
        insight_ttl_hours=insight_ttl_hours,
        min_data_points=min_data_points,
    )
