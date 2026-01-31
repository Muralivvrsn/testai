"""
TestAI Agent - Test Analytics

Advanced analytics for test results including
trend analysis, correlations, and insights.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import statistics


class TrendDirection(Enum):
    """Direction of a metric trend."""
    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"
    VOLATILE = "volatile"


class MetricType(Enum):
    """Types of test metrics."""
    PASS_RATE = "pass_rate"
    FAILURE_RATE = "failure_rate"
    DURATION = "duration"
    COVERAGE = "coverage"
    FLAKINESS = "flakiness"
    THROUGHPUT = "throughput"
    STABILITY = "stability"


@dataclass
class AnalyticsMetric:
    """A computed analytics metric."""
    metric_id: str
    name: str
    metric_type: MetricType
    value: float
    unit: str
    trend: TrendDirection
    change_pct: float
    period: str
    samples: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataPoint:
    """A single data point for analytics."""
    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class TimeSeries:
    """Time series data for a metric."""
    metric_name: str
    points: List[DataPoint]
    aggregation: str  # "avg", "sum", "min", "max"


@dataclass
class Correlation:
    """Correlation between metrics."""
    metric_a: str
    metric_b: str
    coefficient: float
    strength: str  # "strong", "moderate", "weak", "none"
    significance: float


@dataclass
class Anomaly:
    """Detected anomaly in metrics."""
    anomaly_id: str
    metric_name: str
    timestamp: datetime
    expected_value: float
    actual_value: float
    deviation: float
    severity: str  # "low", "medium", "high"


@dataclass
class AnalyticsReport:
    """Complete analytics report."""
    report_id: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    metrics: List[AnalyticsMetric]
    correlations: List[Correlation]
    anomalies: List[Anomaly]
    insights: List[str]
    recommendations: List[str]


class TestAnalytics:
    """
    Analyzes test results and metrics.

    Features:
    - Trend analysis
    - Correlation detection
    - Anomaly detection
    - Actionable insights
    """

    def __init__(
        self,
        lookback_days: int = 30,
        anomaly_threshold: float = 2.0,  # Standard deviations
    ):
        """Initialize analytics."""
        self._lookback_days = lookback_days
        self._anomaly_threshold = anomaly_threshold
        self._time_series: Dict[str, TimeSeries] = {}
        self._metrics: Dict[str, AnalyticsMetric] = {}
        self._anomalies: List[Anomaly] = []
        self._metric_counter = 0
        self._anomaly_counter = 0
        self._report_counter = 0

    def record_data_point(
        self,
        metric_name: str,
        value: float,
        timestamp: Optional[datetime] = None,
        labels: Optional[Dict[str, str]] = None,
    ) -> DataPoint:
        """Record a data point."""
        point = DataPoint(
            timestamp=timestamp or datetime.now(),
            value=value,
            labels=labels or {},
        )

        if metric_name not in self._time_series:
            self._time_series[metric_name] = TimeSeries(
                metric_name=metric_name,
                points=[],
                aggregation="avg",
            )

        self._time_series[metric_name].points.append(point)
        return point

    def compute_metric(
        self,
        metric_name: str,
        metric_type: MetricType,
        unit: str = "",
        period_days: Optional[int] = None,
    ) -> Optional[AnalyticsMetric]:
        """Compute a metric from recorded data."""
        series = self._time_series.get(metric_name)
        if not series or not series.points:
            return None

        period = period_days or self._lookback_days
        cutoff = datetime.now() - timedelta(days=period)

        # Filter points in period
        recent_points = [
            p for p in series.points
            if p.timestamp >= cutoff
        ]

        if not recent_points:
            return None

        # Calculate current value (average of recent points)
        values = [p.value for p in recent_points]
        current_value = statistics.mean(values)

        # Calculate trend
        trend, change_pct = self._calculate_trend(values)

        self._metric_counter += 1
        metric_id = f"MET-{self._metric_counter:05d}"

        metric = AnalyticsMetric(
            metric_id=metric_id,
            name=metric_name,
            metric_type=metric_type,
            value=round(current_value, 2),
            unit=unit,
            trend=trend,
            change_pct=round(change_pct, 2),
            period=f"{period}d",
            samples=len(recent_points),
        )

        self._metrics[metric_id] = metric
        return metric

    def _calculate_trend(
        self,
        values: List[float],
    ) -> Tuple[TrendDirection, float]:
        """Calculate trend from values."""
        if len(values) < 2:
            return TrendDirection.STABLE, 0.0

        # Split into halves
        mid = len(values) // 2
        first_half = values[:mid] if mid > 0 else values[:1]
        second_half = values[mid:] if mid < len(values) else values[-1:]

        first_avg = statistics.mean(first_half)
        second_avg = statistics.mean(second_half)

        if first_avg == 0:
            change_pct = 0.0
        else:
            change_pct = ((second_avg - first_avg) / first_avg) * 100

        # Calculate volatility
        if len(values) >= 3:
            stdev = statistics.stdev(values)
            mean_val = statistics.mean(values)
            cv = (stdev / mean_val * 100) if mean_val != 0 else 0

            if cv > 30:  # High coefficient of variation
                return TrendDirection.VOLATILE, change_pct

        # Determine direction
        if abs(change_pct) < 5:
            return TrendDirection.STABLE, change_pct
        elif change_pct > 0:
            return TrendDirection.IMPROVING, change_pct
        else:
            return TrendDirection.DECLINING, change_pct

    def detect_anomalies(
        self,
        metric_name: str,
    ) -> List[Anomaly]:
        """Detect anomalies in a metric."""
        series = self._time_series.get(metric_name)
        if not series or len(series.points) < 10:
            return []

        values = [p.value for p in series.points]
        mean_val = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0

        if stdev == 0:
            return []

        detected = []
        for point in series.points:
            z_score = abs((point.value - mean_val) / stdev)
            if z_score > self._anomaly_threshold:
                self._anomaly_counter += 1
                anomaly_id = f"ANO-{self._anomaly_counter:05d}"

                severity = "low"
                if z_score > 3:
                    severity = "high"
                elif z_score > 2.5:
                    severity = "medium"

                anomaly = Anomaly(
                    anomaly_id=anomaly_id,
                    metric_name=metric_name,
                    timestamp=point.timestamp,
                    expected_value=round(mean_val, 2),
                    actual_value=round(point.value, 2),
                    deviation=round(z_score, 2),
                    severity=severity,
                )
                detected.append(anomaly)
                self._anomalies.append(anomaly)

        return detected

    def find_correlations(
        self,
        metric_a: str,
        metric_b: str,
    ) -> Optional[Correlation]:
        """Find correlation between two metrics."""
        series_a = self._time_series.get(metric_a)
        series_b = self._time_series.get(metric_b)

        if not series_a or not series_b:
            return None

        # Get overlapping timestamps
        timestamps_a = {p.timestamp: p.value for p in series_a.points}
        timestamps_b = {p.timestamp: p.value for p in series_b.points}

        common_times = set(timestamps_a.keys()) & set(timestamps_b.keys())
        if len(common_times) < 5:
            # Not enough overlapping data
            return None

        values_a = [timestamps_a[t] for t in sorted(common_times)]
        values_b = [timestamps_b[t] for t in sorted(common_times)]

        # Calculate Pearson correlation
        coefficient = self._pearson_correlation(values_a, values_b)

        # Determine strength
        abs_coef = abs(coefficient)
        if abs_coef >= 0.7:
            strength = "strong"
        elif abs_coef >= 0.4:
            strength = "moderate"
        elif abs_coef >= 0.2:
            strength = "weak"
        else:
            strength = "none"

        return Correlation(
            metric_a=metric_a,
            metric_b=metric_b,
            coefficient=round(coefficient, 3),
            strength=strength,
            significance=0.95 if len(common_times) > 20 else 0.80,
        )

    def _pearson_correlation(
        self,
        x: List[float],
        y: List[float],
    ) -> float:
        """Calculate Pearson correlation coefficient."""
        n = len(x)
        if n != len(y) or n == 0:
            return 0.0

        mean_x = sum(x) / n
        mean_y = sum(y) / n

        numerator = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
        sum_sq_x = sum((xi - mean_x) ** 2 for xi in x)
        sum_sq_y = sum((yi - mean_y) ** 2 for yi in y)

        denominator = (sum_sq_x * sum_sq_y) ** 0.5
        if denominator == 0:
            return 0.0

        return numerator / denominator

    def generate_insights(self) -> List[str]:
        """Generate insights from analytics."""
        insights = []

        # Analyze trends
        for metric in self._metrics.values():
            if metric.trend == TrendDirection.DECLINING:
                insights.append(
                    f"⚠️ {metric.name} is declining ({metric.change_pct:+.1f}% over {metric.period})"
                )
            elif metric.trend == TrendDirection.IMPROVING and metric.change_pct > 10:
                insights.append(
                    f"✅ {metric.name} improved significantly ({metric.change_pct:+.1f}%)"
                )
            elif metric.trend == TrendDirection.VOLATILE:
                insights.append(
                    f"⚡ {metric.name} shows high volatility - investigate stability"
                )

        # Analyze anomalies
        recent_anomalies = [
            a for a in self._anomalies
            if a.timestamp > datetime.now() - timedelta(days=7)
        ]
        if recent_anomalies:
            high_sev = [a for a in recent_anomalies if a.severity == "high"]
            if high_sev:
                insights.append(
                    f"🚨 {len(high_sev)} high-severity anomalies detected this week"
                )

        return insights

    def generate_recommendations(self) -> List[str]:
        """Generate recommendations."""
        recommendations = []

        for metric in self._metrics.values():
            if metric.metric_type == MetricType.PASS_RATE and metric.value < 90:
                recommendations.append(
                    "📋 Pass rate below 90% - prioritize fixing failing tests"
                )
            elif metric.metric_type == MetricType.COVERAGE and metric.value < 70:
                recommendations.append(
                    "📋 Coverage below 70% - add tests for uncovered code paths"
                )
            elif metric.metric_type == MetricType.FLAKINESS and metric.value > 5:
                recommendations.append(
                    "📋 Flakiness above 5% - stabilize flaky tests"
                )

        # Check for correlations that suggest issues
        # (simplified - real implementation would analyze correlation data)
        if len(self._time_series) >= 2:
            recommendations.append(
                "📋 Review correlated metrics for root cause analysis"
            )

        return recommendations

    def generate_report(
        self,
        period_days: Optional[int] = None,
    ) -> AnalyticsReport:
        """Generate a complete analytics report."""
        self._report_counter += 1
        report_id = f"RPT-{self._report_counter:05d}"

        period = period_days or self._lookback_days
        now = datetime.now()

        # Collect all metrics
        metrics = list(self._metrics.values())

        # Find correlations between all metric pairs
        correlations = []
        metric_names = list(self._time_series.keys())
        for i, name_a in enumerate(metric_names):
            for name_b in metric_names[i + 1:]:
                corr = self.find_correlations(name_a, name_b)
                if corr and corr.strength != "none":
                    correlations.append(corr)

        # Get anomalies in period
        cutoff = now - timedelta(days=period)
        anomalies = [
            a for a in self._anomalies
            if a.timestamp >= cutoff
        ]

        return AnalyticsReport(
            report_id=report_id,
            generated_at=now,
            period_start=cutoff,
            period_end=now,
            metrics=metrics,
            correlations=correlations,
            anomalies=anomalies,
            insights=self.generate_insights(),
            recommendations=self.generate_recommendations(),
        )

    def get_time_series(
        self,
        metric_name: str,
    ) -> Optional[TimeSeries]:
        """Get time series for a metric."""
        return self._time_series.get(metric_name)

    def get_statistics(self) -> Dict[str, Any]:
        """Get analytics statistics."""
        total_points = sum(
            len(ts.points) for ts in self._time_series.values()
        )

        trend_counts = {t.value: 0 for t in TrendDirection}
        for metric in self._metrics.values():
            trend_counts[metric.trend.value] += 1

        return {
            "time_series_count": len(self._time_series),
            "total_data_points": total_points,
            "computed_metrics": len(self._metrics),
            "detected_anomalies": len(self._anomalies),
            "trends": trend_counts,
        }

    def format_report(self, report: AnalyticsReport) -> str:
        """Format an analytics report for display."""
        lines = [
            "=" * 60,
            f"  ANALYTICS REPORT: {report.report_id}",
            "=" * 60,
            "",
            f"  Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M')}",
            f"  Period: {report.period_start.strftime('%Y-%m-%d')} to {report.period_end.strftime('%Y-%m-%d')}",
            "",
            "-" * 60,
            "  METRICS",
            "-" * 60,
            "",
        ]

        for metric in report.metrics:
            trend_icon = {
                TrendDirection.IMPROVING: "📈",
                TrendDirection.STABLE: "➡️",
                TrendDirection.DECLINING: "📉",
                TrendDirection.VOLATILE: "📊",
            }.get(metric.trend, "")

            lines.append(
                f"  {trend_icon} {metric.name}: {metric.value}{metric.unit} "
                f"({metric.change_pct:+.1f}%)"
            )

        if report.anomalies:
            lines.append("")
            lines.append("-" * 60)
            lines.append("  ANOMALIES")
            lines.append("-" * 60)
            lines.append("")

            for anomaly in report.anomalies[:5]:
                lines.append(
                    f"  ⚠️ {anomaly.metric_name}: {anomaly.actual_value} "
                    f"(expected ~{anomaly.expected_value})"
                )

        if report.insights:
            lines.append("")
            lines.append("-" * 60)
            lines.append("  INSIGHTS")
            lines.append("-" * 60)
            lines.append("")

            for insight in report.insights:
                lines.append(f"  {insight}")

        if report.recommendations:
            lines.append("")
            lines.append("-" * 60)
            lines.append("  RECOMMENDATIONS")
            lines.append("-" * 60)
            lines.append("")

            for rec in report.recommendations:
                lines.append(f"  {rec}")

        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)


def create_analytics(
    lookback_days: int = 30,
    anomaly_threshold: float = 2.0,
) -> TestAnalytics:
    """Create a test analytics instance."""
    return TestAnalytics(
        lookback_days=lookback_days,
        anomaly_threshold=anomaly_threshold,
    )
