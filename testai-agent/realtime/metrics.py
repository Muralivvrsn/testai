"""
TestAI Agent - Metrics Collector

Collects and aggregates real-time metrics for test execution
with time windowing and statistical analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
from collections import deque
import statistics


class MetricType(Enum):
    """Types of metrics collected."""
    PASS_RATE = "pass_rate"
    FAILURE_RATE = "failure_rate"
    EXECUTION_TIME = "execution_time"
    THROUGHPUT = "throughput"
    FLAKINESS_RATE = "flakiness_rate"
    QUEUE_SIZE = "queue_size"
    ACTIVE_TESTS = "active_tests"
    ERROR_RATE = "error_rate"
    RETRY_RATE = "retry_rate"
    COVERAGE = "coverage"


class TimeWindow(Enum):
    """Time windows for aggregation."""
    SECOND = "1s"
    TEN_SECONDS = "10s"
    MINUTE = "1m"
    FIVE_MINUTES = "5m"
    FIFTEEN_MINUTES = "15m"
    HOUR = "1h"
    DAY = "24h"


@dataclass
class MetricPoint:
    """A single metric data point."""
    metric_type: MetricType
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricAggregation:
    """Aggregated metric statistics."""
    metric_type: MetricType
    window: TimeWindow
    count: int
    min_value: float
    max_value: float
    avg_value: float
    sum_value: float
    std_dev: float
    percentile_50: float
    percentile_90: float
    percentile_99: float
    first_timestamp: datetime
    last_timestamp: datetime


@dataclass
class MetricSeries:
    """Time series of metric points."""
    metric_type: MetricType
    points: List[MetricPoint]
    window: TimeWindow
    aggregation: Optional[MetricAggregation] = None


class MetricsCollector:
    """
    Collects and aggregates real-time metrics.

    Features:
    - Time-windowed collection
    - Statistical aggregation
    - Metric tagging
    - Trend analysis
    """

    WINDOW_SECONDS = {
        TimeWindow.SECOND: 1,
        TimeWindow.TEN_SECONDS: 10,
        TimeWindow.MINUTE: 60,
        TimeWindow.FIVE_MINUTES: 300,
        TimeWindow.FIFTEEN_MINUTES: 900,
        TimeWindow.HOUR: 3600,
        TimeWindow.DAY: 86400,
    }

    def __init__(
        self,
        max_points: int = 10000,
        retention_hours: int = 24,
    ):
        """Initialize the metrics collector."""
        self.max_points = max_points
        self.retention_hours = retention_hours
        self._metrics: Dict[MetricType, deque] = {
            mt: deque(maxlen=max_points) for mt in MetricType
        }
        self._listeners: List[Callable[[MetricPoint], None]] = []
        self._counter = 0

    def record(
        self,
        metric_type: MetricType,
        value: float,
        tags: Optional[Dict[str, str]] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MetricPoint:
        """Record a metric point."""
        self._counter += 1

        point = MetricPoint(
            metric_type=metric_type,
            value=value,
            timestamp=timestamp or datetime.now(),
            tags=tags or {},
            metadata=metadata or {},
        )

        self._metrics[metric_type].append(point)

        # Notify listeners
        for listener in self._listeners:
            try:
                listener(point)
            except Exception:
                pass

        return point

    def record_test_result(
        self,
        test_id: str,
        passed: bool,
        duration_ms: int,
        retried: bool = False,
        flaky: bool = False,
        browser: Optional[str] = None,
        device: Optional[str] = None,
    ):
        """Record metrics for a test result."""
        tags = {
            "test_id": test_id,
        }
        if browser:
            tags["browser"] = browser
        if device:
            tags["device"] = device

        # Record pass/fail
        self.record(MetricType.PASS_RATE, 1.0 if passed else 0.0, tags)
        self.record(MetricType.FAILURE_RATE, 0.0 if passed else 1.0, tags)

        # Record duration
        self.record(MetricType.EXECUTION_TIME, float(duration_ms), tags)

        # Record retry/flakiness
        if retried:
            self.record(MetricType.RETRY_RATE, 1.0, tags)
        if flaky:
            self.record(MetricType.FLAKINESS_RATE, 1.0, tags)

    def record_throughput(self, tests_per_second: float):
        """Record throughput metric."""
        self.record(MetricType.THROUGHPUT, tests_per_second)

    def record_queue_size(self, size: int):
        """Record queue size."""
        self.record(MetricType.QUEUE_SIZE, float(size))

    def record_active_tests(self, count: int):
        """Record active test count."""
        self.record(MetricType.ACTIVE_TESTS, float(count))

    def get_points(
        self,
        metric_type: MetricType,
        window: Optional[TimeWindow] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> List[MetricPoint]:
        """Get metric points with optional filtering."""
        points = list(self._metrics[metric_type])

        # Filter by time window
        if window:
            window_seconds = self.WINDOW_SECONDS[window]
            cutoff = datetime.now() - timedelta(seconds=window_seconds)
            points = [p for p in points if p.timestamp >= cutoff]

        # Filter by explicit time range
        if start_time:
            points = [p for p in points if p.timestamp >= start_time]
        if end_time:
            points = [p for p in points if p.timestamp <= end_time]

        # Filter by tags
        if tags:
            points = [
                p for p in points
                if all(p.tags.get(k) == v for k, v in tags.items())
            ]

        return points

    def aggregate(
        self,
        metric_type: MetricType,
        window: TimeWindow = TimeWindow.MINUTE,
        tags: Optional[Dict[str, str]] = None,
    ) -> Optional[MetricAggregation]:
        """Aggregate metrics for a time window."""
        points = self.get_points(metric_type, window, tags=tags)

        if not points:
            return None

        values = [p.value for p in points]

        # Calculate percentiles
        sorted_values = sorted(values)
        n = len(sorted_values)

        def percentile(pct):
            k = (n - 1) * pct / 100
            f = int(k)
            c = f + 1 if f < n - 1 else f
            return sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f]) if c < n else sorted_values[f]

        std_dev = statistics.stdev(values) if len(values) > 1 else 0.0

        return MetricAggregation(
            metric_type=metric_type,
            window=window,
            count=len(values),
            min_value=min(values),
            max_value=max(values),
            avg_value=statistics.mean(values),
            sum_value=sum(values),
            std_dev=std_dev,
            percentile_50=percentile(50),
            percentile_90=percentile(90),
            percentile_99=percentile(99),
            first_timestamp=points[0].timestamp,
            last_timestamp=points[-1].timestamp,
        )

    def get_series(
        self,
        metric_type: MetricType,
        window: TimeWindow = TimeWindow.MINUTE,
        tags: Optional[Dict[str, str]] = None,
    ) -> MetricSeries:
        """Get a metric series with aggregation."""
        points = self.get_points(metric_type, window, tags=tags)
        aggregation = self.aggregate(metric_type, window, tags)

        return MetricSeries(
            metric_type=metric_type,
            points=points,
            window=window,
            aggregation=aggregation,
        )

    def get_trend(
        self,
        metric_type: MetricType,
        current_window: TimeWindow = TimeWindow.MINUTE,
        previous_window: TimeWindow = TimeWindow.FIVE_MINUTES,
    ) -> Dict[str, Any]:
        """Calculate trend between two time windows."""
        current = self.aggregate(metric_type, current_window)
        previous = self.aggregate(metric_type, previous_window)

        if not current or not previous:
            return {
                "metric_type": metric_type.value,
                "trend": "unknown",
                "change_percent": 0,
                "current_avg": current.avg_value if current else 0,
                "previous_avg": previous.avg_value if previous else 0,
            }

        if previous.avg_value == 0:
            change_pct = 100.0 if current.avg_value > 0 else 0.0
        else:
            change_pct = ((current.avg_value - previous.avg_value) / previous.avg_value) * 100

        if change_pct > 5:
            trend = "increasing"
        elif change_pct < -5:
            trend = "decreasing"
        else:
            trend = "stable"

        return {
            "metric_type": metric_type.value,
            "trend": trend,
            "change_percent": round(change_pct, 2),
            "current_avg": round(current.avg_value, 2),
            "previous_avg": round(previous.avg_value, 2),
        }

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get all metrics for dashboard display."""
        windows = [TimeWindow.MINUTE, TimeWindow.FIVE_MINUTES, TimeWindow.HOUR]

        metrics = {}

        for metric_type in MetricType:
            metric_data = {
                "current": None,
                "aggregations": {},
                "trend": self.get_trend(metric_type),
            }

            # Get latest point
            points = self.get_points(metric_type, TimeWindow.MINUTE)
            if points:
                metric_data["current"] = points[-1].value

            # Get aggregations for each window
            for window in windows:
                agg = self.aggregate(metric_type, window)
                if agg:
                    metric_data["aggregations"][window.value] = {
                        "count": agg.count,
                        "avg": round(agg.avg_value, 2),
                        "min": round(agg.min_value, 2),
                        "max": round(agg.max_value, 2),
                        "p90": round(agg.percentile_90, 2),
                    }

            metrics[metric_type.value] = metric_data

        return metrics

    def add_listener(self, callback: Callable[[MetricPoint], None]):
        """Add a listener for new metric points."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[MetricPoint], None]):
        """Remove a listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    def clear(self, metric_type: Optional[MetricType] = None):
        """Clear metrics."""
        if metric_type:
            self._metrics[metric_type].clear()
        else:
            for mt in MetricType:
                self._metrics[mt].clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get collector statistics."""
        total_points = sum(len(self._metrics[mt]) for mt in MetricType)
        points_by_type = {mt.value: len(self._metrics[mt]) for mt in MetricType}

        return {
            "total_points": total_points,
            "max_points_per_metric": self.max_points,
            "retention_hours": self.retention_hours,
            "points_by_type": points_by_type,
            "listener_count": len(self._listeners),
        }

    def format_metrics(self) -> str:
        """Format metrics for display."""
        lines = [
            "=" * 60,
            "  REAL-TIME METRICS",
            "=" * 60,
            "",
        ]

        for metric_type in MetricType:
            agg = self.aggregate(metric_type, TimeWindow.MINUTE)
            if agg:
                lines.extend([
                    f"  {metric_type.value.upper()}",
                    f"    Count: {agg.count}",
                    f"    Avg: {agg.avg_value:.2f}",
                    f"    Min: {agg.min_value:.2f} / Max: {agg.max_value:.2f}",
                    f"    P90: {agg.percentile_90:.2f} / P99: {agg.percentile_99:.2f}",
                    "",
                ])

        lines.append("=" * 60)
        return "\n".join(lines)


def create_metrics_collector(
    max_points: int = 10000,
    retention_hours: int = 24,
) -> MetricsCollector:
    """Create a metrics collector instance."""
    return MetricsCollector(max_points, retention_hours)
