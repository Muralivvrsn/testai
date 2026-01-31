"""
TestAI Agent - Test Profiler

Performance profiling for test execution with
timing analysis, bottleneck detection, and trends.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import time
import statistics


class ProfileType(Enum):
    """Types of profiling."""
    EXECUTION_TIME = "execution_time"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    NETWORK_IO = "network_io"
    STEP_TIMING = "step_timing"
    SELECTOR_RESOLUTION = "selector_resolution"
    WAIT_TIME = "wait_time"
    ASSERTION_TIME = "assertion_time"


class BottleneckSeverity(Enum):
    """Severity of a performance bottleneck."""
    CRITICAL = "critical"  # > 5x baseline
    HIGH = "high"  # 3-5x baseline
    MEDIUM = "medium"  # 2-3x baseline
    LOW = "low"  # 1.5-2x baseline


@dataclass
class TimingData:
    """Timing data for a single operation."""
    operation: str
    duration_ms: float
    start_time: datetime
    end_time: datetime
    category: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceMetrics:
    """Performance metrics for a profiled test."""
    total_duration_ms: float
    step_count: int
    avg_step_duration_ms: float
    min_step_duration_ms: float
    max_step_duration_ms: float
    p50_step_duration_ms: float
    p90_step_duration_ms: float
    p99_step_duration_ms: float
    wait_time_ms: float
    assertion_time_ms: float
    selector_time_ms: float
    network_time_ms: float
    idle_time_ms: float


@dataclass
class Bottleneck:
    """A detected performance bottleneck."""
    bottleneck_id: str
    operation: str
    severity: BottleneckSeverity
    actual_duration_ms: float
    expected_duration_ms: float
    slowdown_factor: float
    category: str
    suggestion: str
    detected_at: datetime


@dataclass
class ProfileResult:
    """Result of profiling a test."""
    result_id: str
    test_id: str
    profile_type: ProfileType
    metrics: PerformanceMetrics
    timings: List[TimingData]
    bottlenecks: List[Bottleneck]
    recommendations: List[str]
    profiled_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestProfiler:
    """
    Performance profiler for test execution.

    Features:
    - Step-level timing
    - Bottleneck detection
    - Trend analysis
    - Memory profiling
    - Performance recommendations
    """

    # Baseline expectations for operations (in ms)
    BASELINES = {
        "click": 100,
        "fill": 150,
        "navigate": 3000,
        "wait": 500,
        "assertion": 50,
        "selector": 200,
        "screenshot": 500,
        "hover": 100,
        "select": 150,
        "scroll": 100,
    }

    def __init__(self):
        """Initialize the profiler."""
        self._result_counter = 0
        self._bottleneck_counter = 0
        self._active_profiles: Dict[str, Dict[str, Any]] = {}
        self._history: List[ProfileResult] = []

        # Timing buffer
        self._timings: Dict[str, List[TimingData]] = {}

    def start_profile(self, test_id: str) -> str:
        """Start profiling a test."""
        profile_id = f"PROFILE-{self._result_counter + 1:05d}"

        self._active_profiles[test_id] = {
            "profile_id": profile_id,
            "start_time": datetime.now(),
            "timings": [],
        }

        self._timings[test_id] = []

        return profile_id

    def record_timing(
        self,
        test_id: str,
        operation: str,
        duration_ms: float,
        category: str = "action",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TimingData:
        """Record a timing for an operation."""
        now = datetime.now()
        start_time = now - timedelta(milliseconds=duration_ms)

        timing = TimingData(
            operation=operation,
            duration_ms=duration_ms,
            start_time=start_time,
            end_time=now,
            category=category,
            metadata=metadata or {},
        )

        if test_id in self._timings:
            self._timings[test_id].append(timing)

        return timing

    def start_operation(
        self,
        test_id: str,
        operation: str,
    ) -> Callable[[], TimingData]:
        """Start timing an operation, returns a function to stop timing."""
        start_time = time.perf_counter()
        start_datetime = datetime.now()

        def stop_timing(category: str = "action", metadata: Optional[Dict[str, Any]] = None) -> TimingData:
            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000

            timing = TimingData(
                operation=operation,
                duration_ms=duration_ms,
                start_time=start_datetime,
                end_time=datetime.now(),
                category=category,
                metadata=metadata or {},
            )

            if test_id in self._timings:
                self._timings[test_id].append(timing)

            return timing

        return stop_timing

    def end_profile(
        self,
        test_id: str,
        profile_type: ProfileType = ProfileType.EXECUTION_TIME,
    ) -> ProfileResult:
        """End profiling and generate results."""
        self._result_counter += 1
        result_id = f"PROFILE-{self._result_counter:05d}"

        timings = self._timings.get(test_id, [])
        profile = self._active_profiles.get(test_id, {})

        # Calculate metrics
        metrics = self._calculate_metrics(timings)

        # Detect bottlenecks
        bottlenecks = self._detect_bottlenecks(timings)

        # Generate recommendations
        recommendations = self._generate_recommendations(metrics, bottlenecks)

        result = ProfileResult(
            result_id=result_id,
            test_id=test_id,
            profile_type=profile_type,
            metrics=metrics,
            timings=timings,
            bottlenecks=bottlenecks,
            recommendations=recommendations,
            profiled_at=datetime.now(),
        )

        self._history.append(result)

        # Cleanup
        if test_id in self._active_profiles:
            del self._active_profiles[test_id]
        if test_id in self._timings:
            del self._timings[test_id]

        return result

    def _calculate_metrics(self, timings: List[TimingData]) -> PerformanceMetrics:
        """Calculate performance metrics from timings."""
        if not timings:
            return PerformanceMetrics(
                total_duration_ms=0,
                step_count=0,
                avg_step_duration_ms=0,
                min_step_duration_ms=0,
                max_step_duration_ms=0,
                p50_step_duration_ms=0,
                p90_step_duration_ms=0,
                p99_step_duration_ms=0,
                wait_time_ms=0,
                assertion_time_ms=0,
                selector_time_ms=0,
                network_time_ms=0,
                idle_time_ms=0,
            )

        durations = [t.duration_ms for t in timings]
        sorted_durations = sorted(durations)

        total = sum(durations)
        step_count = len(durations)

        # Percentiles
        p50_idx = int(len(sorted_durations) * 0.5)
        p90_idx = int(len(sorted_durations) * 0.9)
        p99_idx = int(len(sorted_durations) * 0.99)

        # Category breakdowns
        wait_time = sum(t.duration_ms for t in timings if t.category == "wait")
        assertion_time = sum(t.duration_ms for t in timings if t.category == "assertion")
        selector_time = sum(t.duration_ms for t in timings if t.category == "selector")
        network_time = sum(t.duration_ms for t in timings if t.category == "network")

        # Calculate idle time (gaps between operations)
        idle_time = 0.0
        for i in range(1, len(timings)):
            gap = (timings[i].start_time - timings[i-1].end_time).total_seconds() * 1000
            if gap > 0:
                idle_time += gap

        return PerformanceMetrics(
            total_duration_ms=total,
            step_count=step_count,
            avg_step_duration_ms=total / step_count if step_count > 0 else 0,
            min_step_duration_ms=min(durations) if durations else 0,
            max_step_duration_ms=max(durations) if durations else 0,
            p50_step_duration_ms=sorted_durations[p50_idx] if sorted_durations else 0,
            p90_step_duration_ms=sorted_durations[min(p90_idx, len(sorted_durations) - 1)] if sorted_durations else 0,
            p99_step_duration_ms=sorted_durations[min(p99_idx, len(sorted_durations) - 1)] if sorted_durations else 0,
            wait_time_ms=wait_time,
            assertion_time_ms=assertion_time,
            selector_time_ms=selector_time,
            network_time_ms=network_time,
            idle_time_ms=idle_time,
        )

    def _detect_bottlenecks(self, timings: List[TimingData]) -> List[Bottleneck]:
        """Detect performance bottlenecks."""
        bottlenecks = []

        for timing in timings:
            # Get baseline for this operation type
            operation_type = self._categorize_operation(timing.operation)
            baseline = self.BASELINES.get(operation_type, 500)

            # Check if this operation is slow
            slowdown = timing.duration_ms / baseline

            if slowdown > 1.5:  # Anything 1.5x slower than baseline
                self._bottleneck_counter += 1

                severity = BottleneckSeverity.LOW
                if slowdown > 5:
                    severity = BottleneckSeverity.CRITICAL
                elif slowdown > 3:
                    severity = BottleneckSeverity.HIGH
                elif slowdown > 2:
                    severity = BottleneckSeverity.MEDIUM

                bottlenecks.append(Bottleneck(
                    bottleneck_id=f"BN-{self._bottleneck_counter:05d}",
                    operation=timing.operation,
                    severity=severity,
                    actual_duration_ms=timing.duration_ms,
                    expected_duration_ms=baseline,
                    slowdown_factor=slowdown,
                    category=timing.category,
                    suggestion=self._suggest_fix(operation_type, slowdown),
                    detected_at=datetime.now(),
                ))

        return sorted(bottlenecks, key=lambda b: b.slowdown_factor, reverse=True)

    def _categorize_operation(self, operation: str) -> str:
        """Categorize an operation for baseline lookup."""
        operation_lower = operation.lower()

        if "click" in operation_lower:
            return "click"
        if "fill" in operation_lower or "type" in operation_lower or "input" in operation_lower:
            return "fill"
        if "navigate" in operation_lower or "goto" in operation_lower:
            return "navigate"
        if "wait" in operation_lower:
            return "wait"
        if "assert" in operation_lower or "expect" in operation_lower:
            return "assertion"
        if "selector" in operation_lower or "find" in operation_lower or "locate" in operation_lower:
            return "selector"
        if "screenshot" in operation_lower:
            return "screenshot"
        if "hover" in operation_lower:
            return "hover"
        if "select" in operation_lower:
            return "select"
        if "scroll" in operation_lower:
            return "scroll"

        return "action"

    def _suggest_fix(self, operation_type: str, slowdown: float) -> str:
        """Suggest fix for a bottleneck."""
        suggestions = {
            "click": "Consider using a more specific selector or waiting for element to be clickable",
            "fill": "Check for input validation delays or complex event handlers",
            "navigate": "Optimize page load, consider disabling unnecessary resources in tests",
            "wait": "Review wait conditions, consider using explicit waits instead of implicit",
            "assertion": "Simplify assertion logic or reduce DOM queries",
            "selector": "Use more specific selectors (data-testid), avoid complex CSS/XPath",
            "screenshot": "Consider taking fewer screenshots or reducing viewport size",
            "hover": "Check for complex hover event handlers",
            "select": "Ensure dropdown is fully loaded before interacting",
            "scroll": "Check for infinite scroll handlers or heavy DOM updates",
        }

        base_suggestion = suggestions.get(operation_type, "Review the implementation for optimization opportunities")

        if slowdown > 5:
            return f"CRITICAL: {base_suggestion}. Consider breaking into smaller operations."

        return base_suggestion

    def _generate_recommendations(
        self,
        metrics: PerformanceMetrics,
        bottlenecks: List[Bottleneck],
    ) -> List[str]:
        """Generate performance recommendations."""
        recommendations = []

        # Recommendations based on metrics
        if metrics.avg_step_duration_ms > 500:
            recommendations.append(
                "Average step duration is high. Consider optimizing selectors and reducing waits."
            )

        if metrics.wait_time_ms > metrics.total_duration_ms * 0.3:
            recommendations.append(
                "Over 30% of time spent waiting. Use smarter wait strategies."
            )

        if metrics.selector_time_ms > metrics.total_duration_ms * 0.2:
            recommendations.append(
                "Selector resolution is slow. Use data-testid attributes for faster element lookup."
            )

        if metrics.idle_time_ms > metrics.total_duration_ms * 0.1:
            recommendations.append(
                "Significant idle time detected. Consider parallelizing independent operations."
            )

        # Recommendations based on bottlenecks
        critical_count = sum(1 for b in bottlenecks if b.severity == BottleneckSeverity.CRITICAL)
        if critical_count > 0:
            recommendations.append(
                f"Found {critical_count} critical bottlenecks. Address these first for significant improvements."
            )

        # P99 recommendations
        if metrics.p99_step_duration_ms > metrics.avg_step_duration_ms * 3:
            recommendations.append(
                "High variance in step durations (P99 >> average). Investigate outlier operations."
            )

        return recommendations

    def compare_profiles(
        self,
        baseline_result: ProfileResult,
        current_result: ProfileResult,
    ) -> Dict[str, Any]:
        """Compare two profile results."""
        baseline = baseline_result.metrics
        current = current_result.metrics

        def pct_change(old: float, new: float) -> float:
            if old == 0:
                return 0.0 if new == 0 else float('inf')
            return ((new - old) / old) * 100

        return {
            "total_duration_change_pct": pct_change(baseline.total_duration_ms, current.total_duration_ms),
            "avg_step_change_pct": pct_change(baseline.avg_step_duration_ms, current.avg_step_duration_ms),
            "p99_change_pct": pct_change(baseline.p99_step_duration_ms, current.p99_step_duration_ms),
            "new_bottlenecks": len(current_result.bottlenecks) - len(baseline_result.bottlenecks),
            "is_regression": current.total_duration_ms > baseline.total_duration_ms * 1.1,
            "is_improvement": current.total_duration_ms < baseline.total_duration_ms * 0.9,
        }

    def get_history(
        self,
        test_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[ProfileResult]:
        """Get profiling history."""
        results = self._history

        if test_id:
            results = [r for r in results if r.test_id == test_id]

        return results[-limit:]

    def get_trends(
        self,
        test_id: str,
        metric: str = "total_duration_ms",
    ) -> Dict[str, Any]:
        """Get performance trends for a test."""
        history = [r for r in self._history if r.test_id == test_id]

        if len(history) < 2:
            return {"trend": "insufficient_data", "data_points": len(history)}

        values = [getattr(r.metrics, metric, 0) for r in history]

        avg = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0

        # Simple trend detection
        recent = values[-min(5, len(values)):]
        earlier = values[:min(5, len(values))]

        recent_avg = statistics.mean(recent)
        earlier_avg = statistics.mean(earlier) if earlier else recent_avg

        if recent_avg > earlier_avg * 1.1:
            trend = "degrading"
        elif recent_avg < earlier_avg * 0.9:
            trend = "improving"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "average": avg,
            "std_deviation": std,
            "min": min(values),
            "max": max(values),
            "data_points": len(values),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get profiler statistics."""
        if not self._history:
            return {
                "total_profiles": 0,
                "total_bottlenecks_detected": 0,
                "avg_test_duration_ms": 0,
            }

        all_bottlenecks = sum(len(r.bottlenecks) for r in self._history)
        all_durations = [r.metrics.total_duration_ms for r in self._history]

        return {
            "total_profiles": len(self._history),
            "active_profiles": len(self._active_profiles),
            "total_bottlenecks_detected": all_bottlenecks,
            "avg_test_duration_ms": statistics.mean(all_durations) if all_durations else 0,
            "fastest_test_ms": min(all_durations) if all_durations else 0,
            "slowest_test_ms": max(all_durations) if all_durations else 0,
        }

    def format_result(self, result: ProfileResult) -> str:
        """Format a profile result."""
        m = result.metrics

        lines = [
            "=" * 70,
            "  PERFORMANCE PROFILE",
            "=" * 70,
            "",
            f"  Profile ID: {result.result_id}",
            f"  Test ID: {result.test_id}",
            "",
            "-" * 70,
            "  METRICS",
            "-" * 70,
            "",
            f"  Total Duration: {m.total_duration_ms:.1f}ms",
            f"  Steps: {m.step_count}",
            "",
            f"  Avg Step: {m.avg_step_duration_ms:.1f}ms",
            f"  Min Step: {m.min_step_duration_ms:.1f}ms",
            f"  Max Step: {m.max_step_duration_ms:.1f}ms",
            "",
            f"  P50: {m.p50_step_duration_ms:.1f}ms",
            f"  P90: {m.p90_step_duration_ms:.1f}ms",
            f"  P99: {m.p99_step_duration_ms:.1f}ms",
            "",
            "-" * 70,
            "  TIME BREAKDOWN",
            "-" * 70,
            "",
            f"  Wait Time: {m.wait_time_ms:.1f}ms ({m.wait_time_ms/m.total_duration_ms*100:.1f}%)" if m.total_duration_ms > 0 else "  Wait Time: 0ms",
            f"  Selector Time: {m.selector_time_ms:.1f}ms",
            f"  Assertion Time: {m.assertion_time_ms:.1f}ms",
            f"  Network Time: {m.network_time_ms:.1f}ms",
            f"  Idle Time: {m.idle_time_ms:.1f}ms",
            "",
        ]

        if result.bottlenecks:
            lines.extend([
                "-" * 70,
                f"  BOTTLENECKS ({len(result.bottlenecks)})",
                "-" * 70,
                "",
            ])

            severity_icons = {
                BottleneckSeverity.CRITICAL: "🔴",
                BottleneckSeverity.HIGH: "🟠",
                BottleneckSeverity.MEDIUM: "🟡",
                BottleneckSeverity.LOW: "🟢",
            }

            for bn in result.bottlenecks[:5]:
                icon = severity_icons.get(bn.severity, "?")
                lines.extend([
                    f"  {icon} {bn.operation}",
                    f"     {bn.actual_duration_ms:.1f}ms (expected: {bn.expected_duration_ms:.1f}ms)",
                    f"     {bn.suggestion}",
                    "",
                ])

        if result.recommendations:
            lines.extend([
                "-" * 70,
                "  RECOMMENDATIONS",
                "-" * 70,
                "",
            ])

            for rec in result.recommendations:
                lines.append(f"  • {rec}")

        lines.extend(["", "=" * 70])
        return "\n".join(lines)


def create_test_profiler() -> TestProfiler:
    """Create a test profiler instance."""
    return TestProfiler()
