"""
TestAI Agent - Real-time Dashboard Module

Provides advanced real-time test monitoring with WebSocket streaming,
metric aggregation, alerting, and performance analytics.
"""

from .metrics import (
    MetricsCollector,
    MetricType,
    MetricPoint,
    TimeWindow,
    create_metrics_collector,
)

from .alerts import (
    AlertManager,
    AlertRule,
    Alert,
    AlertSeverity,
    AlertCondition,
    create_alert_manager,
)

from .streaming import (
    StreamingDashboard,
    DashboardEvent,
    StreamConfig,
    create_streaming_dashboard,
)

__all__ = [
    # Metrics
    "MetricsCollector",
    "MetricType",
    "MetricPoint",
    "TimeWindow",
    "create_metrics_collector",
    # Alerts
    "AlertManager",
    "AlertRule",
    "Alert",
    "AlertSeverity",
    "AlertCondition",
    "create_alert_manager",
    # Streaming
    "StreamingDashboard",
    "DashboardEvent",
    "StreamConfig",
    "create_streaming_dashboard",
]
